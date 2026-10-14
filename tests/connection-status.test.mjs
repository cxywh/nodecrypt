// 连接状态反馈单测
//
// 起因是一个真实的、线上生效的 bug：
// room.js 的连接失败回调里调了一个**根本不存在**的 setStatus()，
// 抛出的 ReferenceError 被 NodeCrypt 的 try/catch 吞掉，
// 于是 onResult(false) 永远执行不到 —— 连接失败时按钮永远停在「连接中...」，
// 用户看不到任何错误，只能自己刷新页面。
//
// 所以这个测试的重点不是「文字对不对」，而是**这些路径一条都不能炸**。
//
// 用法：node tests/connection-status.test.mjs
import {
	ConnectStatus, STAGE, SLOW_AFTER, FAIL_AFTER
} from '../client/js/util.connect.js';

let pass = 0, fail = 0;
const check = (name, fn) => {
	try { fn(); console.log(`  ✓ ${name}`); pass++; }
	catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};
const assert = (cond, msg) => { if (!cond) throw new Error(msg || '断言失败'); };
const eq = (a, b, msg) => { if (a !== b) throw new Error(`${msg || '不相等'}: 期望 ${b}，实际 ${a}`); };

// 假时钟 + 假定时器：真定时器会让测试要么很慢要么不稳定
function makeClock() {
	let t = 0;
	const cbs = new Map();
	let nextId = 1;
	return {
		now: () => t,
		timer: {
			setInterval: (fn) => { const id = nextId++; cbs.set(id, fn); return id; },
			clearInterval: (id) => { cbs.delete(id); }
		},
		// 前进 n 秒，每秒触发一次所有存活定时器
		tick(n) {
			for (let i = 0; i < n; i++) {
				t += 1000;
				for (const fn of [...cbs.values()]) fn();
			}
		},
		pending: () => cbs.size
	};
}

function makeStatus(extra = {}) {
	const clock = makeClock();
	const renders = [];
	const timeouts = [];
	const st = new ConnectStatus({
		onRender: (s) => renders.push(s),
		onTimeout: () => timeouts.push(true),
		now: clock.now,
		timer: clock.timer,
		...extra
	});
	return { st, clock, renders, timeouts };
}

console.log('\n【1】基本阶段推进');

check('未启动时 stage 为空、秒数 0', () => {
	const { st } = makeStatus();
	eq(st.stage, null);
	eq(st.elapsed, 0);
	eq(st.state().stage, null);
});

check('start() 进入 NET 阶段并立刻渲染一次', () => {
	const { st, renders } = makeStatus();
	st.start();
	eq(st.stage, STAGE.NET);
	eq(renders.length, 1, 'start 应当立刻渲染一次（不能等第一秒）');
	eq(renders[0].seconds, 0);
});

check('★ 秒数随时间增长（这是「没卡死」的唯一证据）', () => {
	const { st, clock, renders } = makeStatus();
	st.start();
	clock.tick(1); eq(st.elapsed, 1, '1 秒后');
	clock.tick(2); eq(st.elapsed, 3, '3 秒后');
	clock.tick(4); eq(st.elapsed, 7, '7 秒后');
	assert(renders.length >= 4, `每秒都该渲染，实际 ${renders.length} 次`);
	// 秒数序列必须递增，否则界面上看不出「还在动」
	const secs = renders.map(r => r.seconds);
	for (let i = 1; i < secs.length; i++) {
		assert(secs[i] >= secs[i - 1], `秒数不应倒退: ${secs.join(',')}`);
	}
});

check('advance 到 CRYPTO（已连上服务器，正在协商加密）', () => {
	const { st } = makeStatus();
	st.start();
	st.advance(STAGE.CRYPTO);
	eq(st.stage, STAGE.CRYPTO);
});

check('★ 超过 SLOW_AFTER 秒置 slow 位（用于提示「网络较慢，仍在尝试」）', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(SLOW_AFTER - 1);
	eq(st.state().slow, false, `${SLOW_AFTER - 1} 秒时不该提示`);
	clock.tick(1);
	eq(st.state().slow, true, `${SLOW_AFTER} 秒时应提示`);
});

check('CRYPTO 阶段同样会置 slow（两段都可能慢）', () => {
	const { st, clock } = makeStatus();
	st.start();
	st.advance(STAGE.CRYPTO);
	clock.tick(SLOW_AFTER);
	eq(st.state().slow, true);
});

check('finish() 进入 READY 并冻结秒数', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(5);
	st.finish();
	eq(st.stage, STAGE.READY);
	eq(st.elapsed, 5, '成功时应停在 5 秒');
	clock.tick(10);
	eq(st.elapsed, 5, '结束之后秒数不该继续涨');
	eq(st.state().slow, false, '已连上就不该再提示慢');
});

console.log('\n【2】失败路径（这次要修的 bug 就在这里）');

check('fail() 记录原因并冻结秒数', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(4);
	st.fail('closed');
	eq(st.stage, STAGE.FAILED);
	eq(st.error, 'closed');
	eq(st.elapsed, 4);
	clock.tick(10);
	eq(st.elapsed, 4, '失败后秒数不该继续涨');
});

check('★ fail() 幂等：onError 和 onClose 先后都触发也只算一次', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(3);
	st.fail('error');
	st.fail('close');           // 迟到的第二个回调
	eq(st.elapsed, 3, '第二次 fail 不该把秒数重置或改写');
	eq(st.error, 'error', '第一次的原因应当保留');
});

check('★ 结束之后迟到的 advance 不生效（否则界面会被改回「连接中」）', () => {
	const { st } = makeStatus();
	st.start();
	st.fail('closed');
	st.advance(STAGE.CRYPTO);
	eq(st.stage, STAGE.FAILED, '失败后不该被迟到回调改回去');

	const b = makeStatus();
	b.st.start();
	b.st.finish();
	b.st.advance(STAGE.CRYPTO);
	eq(b.st.stage, STAGE.READY, '成功后同理');
});

check('★ 成功之后迟到的 fail 不生效（连上再断线是另一回事）', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(2);
	st.finish();
	st.fail('closed');
	eq(st.stage, STAGE.READY, '已连上就不该被改判成失败');
	eq(st.error, null, '不该带失败原因');
	eq(st.elapsed, 2, '秒数应停在成功那一刻');
});

check('★ 超时自动判失败并回调 onTimeout（不能无限等）', () => {
	const { st, clock, timeouts } = makeStatus();
	st.start();
	clock.tick(FAIL_AFTER - 1);
	eq(st.stage, STAGE.NET, `${FAIL_AFTER - 1} 秒时还不该超时`);
	eq(timeouts.length, 0);
	clock.tick(1);
	eq(st.stage, STAGE.FAILED, `${FAIL_AFTER} 秒时应判超时`);
	eq(st.error, 'timeout');
	eq(timeouts.length, 1, 'onTimeout 应当被调用一次');
	clock.tick(5);
	eq(timeouts.length, 1, '不该重复触发');
});

check('★ onTimeout 里抛错不会打断（但会被记到 console.error）', () => {
	const clock = makeClock();
	const origError = console.error;
	let logged = 0;
	console.error = () => { logged++; };
	try {
		const st = new ConnectStatus({
			onRender: () => {},
			// 调用方在超时回调里恢复界面，恢复过程中抛错很常见
			onTimeout: () => { throw new Error('调用方炸了'); },
			now: clock.now,
			timer: clock.timer
		});
		st.start();
		clock.tick(FAIL_AFTER);
		eq(st.stage, STAGE.FAILED, '调用方抛错不该影响状态机');
		assert(logged > 0, '异常应当被记录，而不是静默吞掉');
	} finally {
		console.error = origError;
	}
});

check('★ 渲染回调抛错不会打断连接流程，且必须可见', () => {
	const clock = makeClock();
	const origError = console.error;
	let logged = 0;
	console.error = () => { logged++; };
	try {
		const st = new ConnectStatus({
			onRender: () => { throw new Error('DOM 崩了'); },
			now: clock.now,
			timer: clock.timer
		});
		st.start();
		st.advance(STAGE.CRYPTO);
		st.finish();
		eq(st.stage, STAGE.READY, '渲染失败不该影响状态机');
		assert(logged > 0, '渲染异常必须被记录 —— 静默吞掉正是本次 bug 的成因');
	} finally {
		console.error = origError;
	}
});

console.log('\n【3】定时器生命周期');

check('start() 会挂上定时器，finish/fail 会摘掉', () => {
	const { st, clock } = makeStatus();
	eq(clock.pending(), 0);
	st.start();
	eq(clock.pending(), 1, 'start 后应有 1 个定时器');
	st.finish();
	eq(clock.pending(), 0, 'finish 后定时间应被清掉');
});

check('重复 start() 不会漏掉上一个定时器（否则会越跑越快）', () => {
	const { st, clock } = makeStatus();
	st.start();
	st.start();
	st.start();
	eq(clock.pending(), 1, '应当只有 1 个定时器');
});

check('stop() 只停定时器、不改状态（组件销毁时用）', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(2);
	st.stop();
	eq(clock.pending(), 0);
	eq(st.stage, STAGE.NET, 'stop 不该改变阶段');
	// 但秒数是按 now 算的，所以 stop 之后时间继续走、elapsed 还会涨 ——
	// 这是刻意的：stop 只用于不再需要渲染的场景。finish/fail 才冻结。
});

check('重新 start() 会重置秒数与错误', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(9);
	st.fail('closed');
	st.start();
	eq(st.stage, STAGE.NET);
	eq(st.elapsed, 0, '重试应当从 0 重新计时');
	eq(st.error, null, '错误应当被清掉');
});

console.log('\n【4】state() 的形状（渲染层直接吃这个对象）');

check('state() 字段齐全且类型正确', () => {
	const { st, clock } = makeStatus();
	st.start();
	clock.tick(4);
	const s = st.state();
	eq(typeof s.stage, 'string', 'stage');
	eq(typeof s.seconds, 'number', 'seconds');
	eq(typeof s.slow, 'boolean', 'slow');
	assert('error' in s, '应当有 error 字段');
	eq(s.seconds, 4);
	eq(s.slow, true);
});

console.log('\n' + '='.repeat(60));
console.log(`通过 ${pass} / ${pass + fail}${fail ? `，失败 ${fail}` : '，全部通过'}`);
process.exit(fail ? 1 : 0);
