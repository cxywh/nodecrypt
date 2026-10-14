// 诊断探针：记录握手阶段到达的每一个原始 WebSocket 帧。
//
// 背景：线上（经代理打 SJC 节点）偶发 fromHex 收到奇数长度字符串，
// 说明握手响应帧被截断或畸形。本地零延迟连跑 5 次全过，所以怀疑传输层。
// 这个探针不做任何解密，只如实记录「收到了什么字节」，用来判定是
// 服务端发了畸形帧，还是链路把好帧弄坏了。
//
// 用法：WS_URL="wss://chat.cxywh.cn/" node tests/probe-frames.mjs

import * as c from '../client/js/aead.js';

const WS_URL = process.env.WS_URL || 'ws://127.0.0.1:8787/';
const PROTO = c.PROTOCOL_VERSION;
const RUN_MS = Number(process.env.RUN_MS || 12000);

const frames = [];
let malformed = 0;

function describe(raw) {
	if (typeof raw !== 'string') {
		const kind = raw && raw.constructor ? raw.constructor.name : typeof raw;
		malformed++;
		return `<非字符串: ${kind}>`;
	}
	const parts = raw.split('|');
	const info = {
		len: raw.length,
		parts: parts.length,
		head: JSON.stringify(raw.slice(0, 48)),
	};

	// 握手响应应为 NC2|<98 位十六进制>|<签名>
	if (raw.startsWith(PROTO + '|')) {
		const partLens = parts.map((p) => p.length);
		const keyPart = parts[1] || '';
		const okKey = /^[0-9a-fA-F]*$/.test(keyPart) && keyPart.length % 2 === 0;
		if (!okKey) malformed++;
		return `握手帧 总长=${info.len} 各段长度=[${partLens.join(',')}]` +
			` 公钥段偶数=${okKey ? '是' : '否 ← 畸形'} 头=${info.head}`;
	}

	// 明文 JSON（服务端公钥）
	if (raw.startsWith('{')) {
		const ok = /"type"\s*:\s*"server-key"/.test(raw);
		if (!ok) malformed++;
		return `JSON 帧 总长=${info.len} 是server-key=${ok ? '是' : '否 ← 畸形'}`;
	}

	// 其余按密文看待：base64 应当只含 [A-Za-z0-9+/=]
	const okB64 = /^[A-Za-z0-9+/=]*$/.test(raw);
	if (!okB64) malformed++;
	return `密文帧 总长=${info.len} 合法base64=${okB64 ? '是' : '否 ← 畸形'} 头=${info.head}`;
}

const ws = new WebSocket(WS_URL);
const t0 = Date.now();
const stamp = () => String(Date.now() - t0).padStart(6) + 'ms';

ws.addEventListener('open', async () => {
	const keys = await c.generateEcdhKeyPair('P-384');
	const pub = await c.exportEcdhPublic(keys);
	const first = PROTO + '|' + pub;
	console.log(`${stamp()}  连接建立，发送首帧 长度=${first.length} 公钥段=${pub.length}`);
	ws.send(first);
});

ws.addEventListener('message', (ev) => {
	const d = describe(ev.data);
	frames.push(d);
	const bad = d.includes('畸形') || d.includes('非字符串');
	console.log(`${stamp()}  [帧 ${String(frames.length).padStart(2)}] ${bad ? '⚠ ' : '  '}${d}`);
});

ws.addEventListener('error', () => console.log(`${stamp()}  ws error`));
ws.addEventListener('close', (e) => console.log(`${stamp()}  连接关闭 code=${e.code}`));

setTimeout(() => {
	try { ws.close(); } catch (e) {}
	console.log(`\n===== 汇总：共 ${frames.length} 帧，其中畸形 ${malformed} 帧 =====`);
	process.exit(0);
}, RUN_MS);
