// 连接过程的可见反馈
// Connection progress feedback
//
// 为什么需要这个模块：
//
// 实测国内到 Cloudflare 的 wss 握手在 0.5~10 秒之间大幅抖动（本机对照 8 毫秒），
// 而这段等待期间界面只有一句**静态**的「连接中...」。用户无法区分
// 「正在连」和「已经卡死了」，只能干等或者直接刷新页面。
//
// 所以这里的核心不是「显示一句话」，而是**显示秒数**：一个持续变大的数字
// 是「还活着」最直接的证据。超过 SLOW_AFTER 秒再补一句说明。
//
// 另外两个刻意做的决定：
//
//   1. **超时要主动报错**（FAIL_AFTER）。无限等下去，用户只能自己刷新，
//      那比明确告诉他「失败了，可以重试」更糟。
//
//   2. 本模块**不碰 DOM**，只调 onRender 回调。因为这次改造的起因就是一个
//      连接路径上的 bug：room.js 里调了一个根本不存在的 setStatus()，
//      抛出的 ReferenceError 被 NodeCrypt 的 try/catch 吞掉，
//      导致连接失败时 onResult(false) 永远执行不到、按钮永远停在「连接中...」。
//      把逻辑抽成纯函数式的类，才能在 Node 里直接单测这条路径。

export const STAGE = {
	VERIFY: 'verify',  // 等人机验证（Turnstile）—— 等的是人，不是网，不计时
	NET: 'net',        // TCP/TLS + WebSocket 握手（最慢的一段）
	CRYPTO: 'crypto',  // 服务端密钥协商 + 对端密钥交换
	READY: 'ready',
	FAILED: 'failed'
};

/** 超过这么多秒就提示「网络较慢，仍在尝试」。 */
export const SLOW_AFTER = 3;

/** 超过这么多秒主动判超时，而不是无限等。 */
export const FAIL_AFTER = 30;

const defaultTimer = {
	setInterval: (fn, ms) => setInterval(fn, ms),
	clearInterval: (id) => clearInterval(id)
};

export class ConnectStatus {
	/**
	 * @param {object}   opts
	 * @param {function} opts.onRender  每次状态变化时回调 state()
	 * @param {function} opts.onTimeout 判超时时回调（调用方据此恢复界面）
	 * @param {function} opts.now       取当前时间（测试可注入假时钟）
	 * @param {object}   opts.timer     定时器（测试可注入假定时器）
	 */
	constructor({ onRender, onTimeout, now, timer } = {}) {
		this.onRender = typeof onRender === 'function' ? onRender : () => {};
		this.onTimeout = typeof onTimeout === 'function' ? onTimeout : () => {};
		this.now = typeof now === 'function' ? now : () => Date.now();
		this.timer = timer || defaultTimer;

		this.stage = null;
		this.startedAt = null;
		this.stoppedAt = null;
		this.error = null;
		this._timerId = null;
	}

	/**
	 * 进入「等待用户完成人机验证」阶段。
	 *
	 * 这一段**刻意不计时**：长短取决于用户什么时候动手点那个复选框，
	 * 把它算进网络耗时会同时犯两个错 —— 一边显示「网络较慢，仍在尝试」
	 * 冤枉用户的网，一边在 FAIL_AFTER 秒后直接判超时，等于催人。
	 *
	 * startedAt 置空，state() 里 seconds 因此恒为 0、slow 恒为 false；
	 * 定时器一并停掉（超时判定依据的是 elapsed，置空后本来也判不动，
	 * 但不停掉就是白跑一个每秒的定时器）。
	 */
	waitForVerify() {
		this._disarm();
		this.startedAt = null;
		this.stoppedAt = null;
		this.stage = STAGE.VERIFY;
		this.error = null;
		this._emit();
		return this;
	}

	/** 开始等待。从 STAGE.NET 起算，并启动每秒一次的秒数刷新。 */
	start() {
		this.startedAt = this.now();
		this.stoppedAt = null;
		this.stage = STAGE.NET;
		this.error = null;
		this._arm();
		this._emit();
		return this;
	}

	/** 进入下一阶段。已经结束（成功/失败）就不再改动，避免迟到的回调把界面改回去。 */
	advance(stage) {
		if (this.stage === STAGE.READY || this.stage === STAGE.FAILED) {
			return this;
		}
		this.stage = stage;
		this._emit();
		return this;
	}

	/**
	 * 标记失败。**幂等** —— NodeCrypt 的 onError 和 onClose 可能先后都触发，
	 * 重复调用不该让秒数被重置或状态被改写。
	 *
	 * 已经成功的不再改判：连上之后再断线是另一回事（该在聊天区提示，
	 * 而不是把登录表单的状态行改回「连接失败」—— 那时表单已经隐藏了）。
	 */
	fail(reason = '') {
		if (this.stage === STAGE.FAILED || this.stage === STAGE.READY) {
			return this;
		}
		this.stoppedAt = this.now();
		this.stage = STAGE.FAILED;
		this.error = String(reason || '');
		this._disarm();
		this._emit();
		return this;
	}

	/** 成功。 */
	finish() {
		if (this.stage === STAGE.READY) {
			return this;
		}
		this.stoppedAt = this.now();
		this.stage = STAGE.READY;
		this.error = null;
		this._disarm();
		this._emit();
		return this;
	}

	/** 只停定时器，不改状态（组件销毁时用）。 */
	stop() {
		this._disarm();
		return this;
	}

	/** 已经过去的秒数。结束后就冻结在结束那一刻，不再增长。 */
	get elapsed() {
		if (this.startedAt === null) {
			return 0;
		}
		const end = this.stoppedAt === null ? this.now() : this.stoppedAt;
		return Math.max(0, Math.round((end - this.startedAt) / 1000));
	}

	/** 给渲染层用的纯数据。 */
	state() {
		const seconds = this.elapsed;
		const waiting = this.stage === STAGE.NET || this.stage === STAGE.CRYPTO;
		return {
			stage: this.stage,
			seconds,
			// 用「仍在尝试」而不是「请检查网络」：实测这条链路本来就慢，
			// 一上来就怪用户的网络是错的。
			slow: waiting && seconds >= SLOW_AFTER,
			error: this.error
		};
	}

	_arm() {
		this._disarm();
		this._timerId = this.timer.setInterval(() => {
			this._emit();
			if (this.elapsed >= FAIL_AFTER) {
				this.fail('timeout');
				try {
					this.onTimeout();
				} catch (error) {
					console.error('connect-status onTimeout failed:', error);
				}
			}
		}, 1000);
	}

	_disarm() {
		if (this._timerId !== null) {
			this.timer.clearInterval(this._timerId);
			this._timerId = null;
		}
	}

	_emit() {
		try {
			this.onRender(this.state());
		} catch (error) {
			// 渲染失败不该打断连接流程，但**必须可见** —— 静默吞掉异常正是
			// 这次要修的那个 bug 的成因（setStatus 的 ReferenceError 被吞了）。
			console.error('connect-status render failed:', error);
		}
	}
}
