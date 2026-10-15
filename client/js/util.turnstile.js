/**
 * Turnstile 人机验证。
 *
 * 目的：挡住机器人和顺手来蹭免费额度的人 —— 免费版额度一旦超了是**直接拒绝服务**
 * （不是降速），所以被蹭的代价是「你自己所有正常用户一起用不了」。
 *
 * 三个必须做对的地方：
 *
 *  1. **没配 sitekey 就完全空转**。返回的 enabled 是 false、getToken() 给空串，
 *     连接逻辑跟改造前一模一样。本地开发和还没开通时不受任何影响。
 *
 *  2. **token 是一次性的**。服务端 siteverify 校验过即作废，而连接失败会自动重连
 *     （NodeCrypt.startReconnect，3 秒一次）。所以每次 connect 都必须 reset 之后
 *     现取一枚，**绝不能缓存复用** —— 复用第二枚必然被服务端拒，表现为
 *     「能连上一次，之后反复重连失败」。
 *
 *  3. **取不到 token 也不能卡死连接**。超时/报错就返回空串，让服务端去拒，
 *     界面走既有的「连接失败 · 请重试」状态行 —— 而不是让 UI 永远停在「连接中」。
 */

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const TOKEN_TIMEOUT_MS = 20000;

export function createTurnstileGate(sitekey) {
	if (!sitekey) {
		return { enabled: false, getToken: async () => '' };
	}

	let scriptPromise = null;
	let widgetIds = [];
	let waiters = [];
	let inflight = null;

	// 把拿到的 token（或错误）派发给当前在等的那一次 getToken()。
	function settle(token, error) {
		const list = waiters;
		waiters = [];
		for (const w of list) {
			if (error) w.reject(error);
			else w.resolve(token);
		}
	}

	function loadScript() {
		if (scriptPromise) return scriptPromise;
		scriptPromise = new Promise((resolve, reject) => {
			if (window.turnstile) return resolve(window.turnstile);
			const s = document.createElement('script');
			s.src = SCRIPT_SRC;
			s.async = true;
			s.defer = true;
			s.onload = () => window.turnstile
				? resolve(window.turnstile)
				: reject(new Error('turnstile api missing after load'));
			s.onerror = () => reject(new Error('turnstile script failed to load'));
			document.head.appendChild(s);
		});
		return scriptPromise;
	}

	// 每个 .turnstile-slot 渲染一个 widget。主页表单和弹窗表单可能同时存在，
	// 两个都渲染；哪个先回调都算数（一轮只有一次 getToken 在等）。
	function renderSlots(ts) {
		for (const el of document.querySelectorAll('.turnstile-slot')) {
			if (el.dataset.turnstileRendered) continue;
			el.dataset.turnstileRendered = '1';
			widgetIds.push(ts.render(el, {
				sitekey,
				theme: 'auto',
				callback: (token) => settle(token, null),
				'error-callback': () => settle(null, new Error('turnstile error')),
				'expired-callback': () => { /* 下次 getToken 会 reset 重取 */ },
			}));
		}
		if (widgetIds.length === 0) throw new Error('no .turnstile-slot in DOM');
	}

	// 拿一枚**新的** token。并发调用共享同一次请求 —— token 一次性，
	// 同时发两枚出去只会让其中一条连接拿到废 token。
	function getToken() {
		if (inflight) return inflight;
		inflight = (async () => {
			const ts = await loadScript();
			renderSlots(ts);
			for (const id of widgetIds) {
				try { ts.reset(id); } catch { /* 重置失败就等回调，不致命 */ }
			}
			return await new Promise((resolve, reject) => {
				let settled = false;
				const timer = setTimeout(() => {
					if (settled) return;
					settled = true;
					reject(new Error('turnstile timeout'));
				}, TOKEN_TIMEOUT_MS);
				// reset() 引发的回调一定是异步的，所以这里 push 不会漏掉。
				waiters.push({
					resolve: (t) => { if (settled) return; settled = true; clearTimeout(timer); resolve(t); },
					reject: (e) => { if (settled) return; settled = true; clearTimeout(timer); reject(e); },
				});
			});
		})();
		return inflight.finally(() => { inflight = null; });
	}

	return { enabled: true, getToken };
}
