// 发送端：给房间里的**另一个客户端**（通常是安卓壳里跑着的那个）发一个真实文件。
//
// 存在的理由：安卓壳的「接收 → 保存」链路没法用浏览器验。浏览器里点下载就是
// 普通的 blob 下载，而壳里走的是 NCryptNative 原生桥 —— 只有让一个真实的
// 对端按协议把分卷发过来，才能从「收到」一路验到「落进系统下载目录」。
//
// 报文格式照抄 client/js/util.file.js 的发送端（compressFileToVolumes /
// sendVolumes），一个字都不能差，否则接收端 inflate 或 hash 校验会挂：
//   file_start   : JSON {type,fileId,fileName,originalSize,compressedSize,totalVolumes,originalHash}
//   分卷         : 二进制帧 [0]=0x02 | 目标clientId(16字节hex) | IV(12)|密文|tag(16)
//                  明文 = fileIdLen | fileId | volumeIndex(2) | totalVolumes(2) | payload
//   file_complete: JSON {type,fileId}
//
// 运行：
//   WS_URL="wss://chat.cxywh.cn/" ROOM="xxx" PASSWORD="" TARGET_NAME="手机" \
//     node tests/send-file-to-peer.mjs
import * as c from '../client/js/aead.js';
import { deflate } from 'fflate';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const WS_URL = process.env.WS_URL || 'ws://127.0.0.1:8787/';
const ROOM = process.env.ROOM;
const PASSWORD = process.env.PASSWORD || '';
const TARGET_NAME = process.env.TARGET_NAME || '';
// FILE_PATH 优先：发大文件时命令行塞不下，也用来测多分卷重组。
const FILE_PATH = process.env.FILE_PATH || '';
const FILE_NAME = process.env.FILE_NAME || (FILE_PATH ? basename(FILE_PATH) : 'recv-test.txt');
const FILE_TEXT = process.env.FILE_TEXT ?? '这是对端发来的测试文件。\nHello from the peer.\n';
const VOLUME_SIZE = Number(process.env.VOLUME_SIZE) || 256 * 1024;
// 逐帧诊断。对端不回包时（表现为 username=null），靠这个看是哪一步断了。
const DEBUG = process.env.DEBUG_FRAMES === '1';

if (!ROOM) {
	console.error('缺少 ROOM');
	process.exit(2);
}

const PROTO = c.PROTOCOL_VERSION;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const channelId = await c.sha256Hex('nodecrypt-v2|channel|' + ROOM);
const pwKey = await c.derivePasswordKey(PASSWORD, ROOM);

/** 只保留发送端需要的东西 —— 不抄 e2e 测试里那套接收/断言逻辑。 */
class Sender {
	constructor(name) {
		this.name = name;
		this.peers = {};
		this.messages = [];
		this.errors = [];
	}

	async connect(attempt = 1) {
		this.ws = new WebSocket(WS_URL);
		this.ws.binaryType = 'arraybuffer';
		this._queue = Promise.resolve();
		this.ws.addEventListener('message', (ev) => {
			this._queue = this._queue
				.then(() => this._onMessage(ev.data))
				.catch((e) => {
					this.errors.push(String(e?.message ?? e));
					if (DEBUG) console.log(`    [错误] ${e?.message ?? e}`);
				});
		});
		// 记下真实原因：只写 'ws error' 的话，分卷发一半就断会查不出所以然。
		this.ws.addEventListener('error', (e) => this.errors.push(
			'ws error: ' + (e?.message || e?.error?.message || e?.error || 'unknown')));
		try {
			await new Promise((res, rej) => {
				this.ws.addEventListener('open', res);
				setTimeout(() => rej(new Error('连接超时: ' + WS_URL)), 60000);
			});
		} catch (e) {
			try { this.ws.close(); } catch {}
			if (attempt < 3) {
				await sleep(1500);
				return this.connect(attempt + 1);
			}
			throw e;
		}
		this.keys = await c.generateEcdhKeyPair('P-384');
		this.ws.send(PROTO + '|' + await c.exportEcdhPublic(this.keys));
	}

	async _send(obj) {
		if (DEBUG) {
			const p = obj.p;
			const desc = (typeof p === 'object' && p !== null && !Array.isArray(p))
				? `obj{${Object.keys(p).join(',')}}` : typeof p;
			console.log(`    [我→服务端] a=${obj.a} c=${obj.c ?? '-'} p=${desc}`);
		}
		this.ws.send(await c.encryptAead(this.serverShared, obj));
	}

	peerIdOf(name) {
		for (const id in this.peers) {
			if (this.peers[id].username === name) return id;
		}
		return null;
	}

	async _onMessage(raw) {
		if (typeof raw !== 'string') return;   // 发送端不接二进制

		if (DEBUG) {
			if (/^\s*\{/.test(raw)) {
				const d = JSON.parse(raw);
				console.log(`    [帧] 明文 JSON type=${d.type ?? '-'}`
					+ (d.type === 'server-key' ? ` keylen=${String(d.key || '').length}` : ''));
			} else if (raw.startsWith(PROTO)) {
				console.log(`    [帧] 握手响应 parts=${String(raw).split('|').length}`);
			} else {
				console.log(`    [帧] 密文 len=${raw.length}  shared=${!!this.serverShared}`);
			}
		}

		try {
			const d = JSON.parse(raw);
			if (d.type === 'server-key') { this.rsaPublic = d.key; return; }
		} catch {}

		if (!this.serverShared) {
			const parts = String(raw).split('|');
			if (parts[0] !== PROTO) throw new Error('响应帧版本不对: ' + parts[0]);
			const rsaKey = await crypto.subtle.importKey('spki', c.fromB64(this.rsaPublic),
				{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, ['verify']);
			if (!await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, rsaKey,
				c.fromB64(parts[2]), c.fromHex(parts[1]))) throw new Error('RSA 签名校验失败');
			const secret = await c.deriveEcdhSecret(this.keys.privateKey, parts[1], 'P-384');
			this.serverShared = await c.deriveServerSessionKey(secret);
			await this._send({ a: 'j', p: channelId });
			return;
		}

		const msg = await c.decryptAead(this.serverShared, raw);
		if (!msg || !msg.a) return;
		if (DEBUG) {
			const p = msg.p;
			const desc = Array.isArray(p) ? `list[${p.length}]`
				: (typeof p === 'object' && p !== null) ? `obj{${Object.keys(p).length}}`
				: `${typeof p}:${String(p).slice(0, 24)}`;
			console.log(`    [服务端→我] a=${msg.a} c=${msg.c ?? '-'} p=${desc}`);
		}

		if (msg.a === 'l' && Array.isArray(msg.p)) {
			const payloads = {};
			for (const id of msg.p) {
				if (!this.peers[id]) {
					this.peers[id] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
					payloads[id] = await c.exportEcdhPublic(this.peers[id].keys);
				}
			}
			if (Object.keys(payloads).length) {
				console.log(`    → 对 ${Object.keys(payloads).length} 个新对端广播我的公钥: ${Object.keys(payloads).join(',')}`);
				await this._send({ a: 'w', p: payloads });
				console.log('    → 已发出，等对方回公钥…');
			} else if (DEBUG) {
				console.log('    （列表里没有新对端，不发公钥）');
			}
			return;
		}

		if (msg.a === 'c' && msg.c) {
			let peer = this.peers[msg.c];
			if (!peer) {
				peer = this.peers[msg.c] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
				await this._send({ a: 'c', p: await c.exportEcdhPublic(peer.keys), c: msg.c });
			}
			if (!peer.shared) {
				console.log(`    ← 收到 ${msg.c} 的公钥，派生会话密钥并回我的用户名`);
				const secret = await c.deriveEcdhSecret(peer.keys.privateKey, msg.p, 'P-256');
				peer.shared = await c.derivePeerSessionKey(secret, pwKey, channelId);
				await this._send({ a: 'c', c: msg.c, p: await c.encryptAead(peer.shared, { a: 'u', p: this.name }) });
				return;
			}
			console.log(`    ← 收到 ${msg.c} 的密文，尝试解密`);
			const inner = await c.decryptAead(peer.shared, msg.p);
			if (inner.a === 'u' && !peer.username) peer.username = inner.p;
			else if (inner.a === 'm') this.messages.push({ from: peer.username, t: inner.t });
		}
	}

	/** 给某个对端发业务消息（等价于前端 NodeCrypt 的 broadcast 单发）。 */
	async to(peerId, type, data) {
		const peer = this.peers[peerId];
		await this._send({ a: 'w', p: { [peerId]: await c.encryptAead(peer.shared, { a: 'm', t: type, d: data }) } });
	}

	/** 二进制分卷：只按对端密钥加密一次，不套服务端信封 —— 与前端一致。 */
	async volume(peerId, fileId, index, total, payload) {
		const record = c.packVolumeRecord(fileId, index, total, payload);
		this.ws.send(c.packBinaryFrame(peerId, await c.encryptRaw(this.peers[peerId].shared, record)));
	}
}

// ---------------------------------------------------------------------------
const fileBytes = FILE_PATH ? new Uint8Array(readFileSync(FILE_PATH)) : new TextEncoder().encode(FILE_TEXT);
const fileId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
	.map((b) => b.toString(16).padStart(2, '0')).join('');

console.log(`\n=== 发送端 → ${WS_URL}`);
console.log(`房间: ${ROOM}   目标: ${TARGET_NAME || '(第一个对端)'}`);
console.log(`文件: ${FILE_NAME}  ${fileBytes.length} 字节\n`);

// 按 util.file.js compressFileToVolumes 的做法压缩（level 6 / mem 8）
const compressed = await new Promise((res, rej) =>
	deflate(fileBytes, { level: 6, mem: 8 }, (e, d) => e ? rej(e) : res(d)));
const volumes = [];
for (let i = 0; i < compressed.length; i += VOLUME_SIZE) {
	volumes.push(compressed.slice(i, i + VOLUME_SIZE));
}
const originalHash = await c.sha256Hex(fileBytes);

console.log(`  压缩: ${fileBytes.length} → ${compressed.length} 字节`);
console.log(`  分卷: ${volumes.length} 卷（每卷 ≤ ${VOLUME_SIZE}）`);
console.log(`  哈希: ${originalHash.slice(0, 16)}…`);

const me = new Sender('发送端');
await me.connect();
console.log('  已连接服务端，等对端出现…');

// 等一个**完成握手**的对端。只认 username 已协商出来的 —— 房间里可能有
// 僵死连接（早先脚本硬退出留下的），它们的 username 永远是 null 且不会回包。
const WAIT_MS = Number(process.env.WAIT_PEER_SECONDS || 60) * 1000;
const deadline = Date.now() + WAIT_MS;
let targetId = null;
let lastReport = 0;
while (Date.now() < deadline) {
	targetId = TARGET_NAME ? me.peerIdOf(TARGET_NAME) : Object.keys(me.peers).find((id) => me.peers[id].username);
	if (targetId) break;
	if (Date.now() - lastReport > 5000) {
		lastReport = Date.now();
		const seen = Object.entries(me.peers).map(([id, p]) => `${id}:${p.username ?? '未协商'}`);
		console.log(`    [等对端 ${Math.round((Date.now() - (deadline - WAIT_MS)) / 1000)}s] 房间里 ${seen.length} 个: ${seen.join(', ') || '无'}`);
	}
	await sleep(250);
}
if (!targetId) {
	console.error(`  没等到完成握手的对端。房间里 ${Object.keys(me.peers).length} 个客户端:`);
	for (const [id, p] of Object.entries(me.peers)) {
		console.error(`    ${id}  username=${p.username ?? 'null（未回包 —— 僵死连接，或对端没进房间）'}`);
	}
	process.exit(1);
}
console.log(`  对端就绪: ${me.peers[targetId].username} (${targetId})`);

// 对端虽然已经回了用户名，但它那侧的 UI 是**先收到 binary 帧**才把 userMap 里的
// 名字补全的 —— 立刻发 file_start 会让文件卡片渲染成「匿名用户」。
// 留一点余量（SETTLE_MS）让对端先把用户名落到界面状态里。
const SETTLE_MS = Number(process.env.SETTLE_MS || 0);
if (SETTLE_MS > 0) {
	console.log(`  等对端界面落定 ${SETTLE_MS}ms…`);
	await sleep(SETTLE_MS);
}

// 1) file_start
await me.to(targetId, 'file_start', {
	type: 'file_start',
	fileId,
	fileName: FILE_NAME,
	originalSize: fileBytes.length,
	compressedSize: compressed.length,
	totalVolumes: volumes.length,
	originalHash
});
console.log(`  [1] file_start 已发`);

// 2) 分卷
for (let i = 0; i < volumes.length; i++) {
	await me.volume(targetId, fileId, i, volumes.length, volumes[i]);
}
console.log(`  [2] ${volumes.length} 个分卷已发`);

// 3) file_complete
await me.to(targetId, 'file_complete', { type: 'file_complete', fileId });
console.log(`  [3] file_complete 已发`);

// 等发送缓冲真正排空 —— Node 的 ws.send 是异步排队进内核缓冲的，
// 直接 close/exit 会把还没出去的帧一起带走（实测 3 卷只到 1 卷就是栽在这）。
// 用 bufferedAmount 判空，最多等 30 秒。
const waitDrain = () => new Promise((res) => {
	const t0 = Date.now();
	const iv = setInterval(() => {
		if (!me.ws || me.ws.bufferedAmount === 0 || Date.now() - t0 > 30000) {
			clearInterval(iv);
			res({ 剩余缓冲: me.ws ? me.ws.bufferedAmount : -1, 等待毫秒: Date.now() - t0 });
		}
	}, 100);
});
const drained = await waitDrain();
console.log(`\n  缓冲排空: ${JSON.stringify(drained)}`);

// 优雅关闭：等 close 事件真的回来，再退出。socket 还开着时对端才能确认收完。
await new Promise((res) => {
	me.ws.addEventListener('close', res);
	me.ws.close();
	setTimeout(res, 5000);
});
await sleep(300);

console.log(`  对端侧错误: ${me.errors.length ? me.errors.join(' / ') : '无'}`);
console.log(`  fileId = ${fileId}\n`);
process.exit(0);
