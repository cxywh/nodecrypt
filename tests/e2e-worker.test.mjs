// P0 端到端测试：对着**真的 Worker**（wrangler dev）跑完整协议
//
// 与 p0-interop.test.mjs 的分工：
//   那个测「两边的加密代码能不能互解」（纯函数级，不用起服务）
//   这个测「真 Worker + Durable Object 的转发链路能不能跑通」（系统级）
//
// 本文件同时充当**协议一致性参考实现**：它不 import NodeCrypt.js，
// 而是照协议独立写一遍。NodeCrypt.js 若哪里写错，两边会对不上。
//
// 运行： node tests/e2e-worker.test.mjs
// 前置： 另开终端 npx wrangler dev --port 8787

import * as c from '../client/js/aead.js';
import {
	uploadToR2, downloadFromR2, newFileKey, exportFileKey, importFileKey, decryptChunk
} from '../client/js/util.blob.js';

const WS_URL = process.env.WS_URL || 'ws://127.0.0.1:8787/';

// util.blob.js 用的是相对路径 /blob/...，Node 的 fetch 解析不了，补上基址。
// （WS 握手走 WebSocket，不受影响）
const HTTP_BASE = process.env.BASE_URL
	|| WS_URL.replace(/^ws/, 'http').replace(/\/$/, '');
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts) =>
	realFetch(typeof url === 'string' && url.startsWith('/') ? HTTP_BASE + url : url, opts);

function randomBytes(n) {
	const b = new Uint8Array(n);
	for (let i = 0; i < n; i += 65536) {
		crypto.getRandomValues(b.subarray(i, Math.min(i + 65536, n)));
	}
	return b;
}

function sameBytes(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
const PROTO = c.PROTOCOL_VERSION;
const ROOM = 'e2e-' + Math.random().toString(36).slice(2, 10);
const PASSWORD = 'e2e-test-password';

let passed = 0, failed = 0;
const check = (name, ok, note = '') => {
	if (ok) { passed++; console.log(`  \u2713 ${name}${note ? '  ' + note : ''}`); }
	else { failed++; console.log(`  \u2717 ${name}  <<< 失败  ${note}`); }
};
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const channelId = await c.sha256Hex('nodecrypt-v2|channel|' + ROOM);
const pwKey = await c.derivePasswordKey(PASSWORD, ROOM);

class TestClient {
	constructor(name) {
		this.name = name;
		this.peers = {};          // peerId -> { keys, shared, username }
		this.messages = [];       // 收到的业务消息
		this.securePeers = 0;
		this.serverShared = null;
		this.rsaPublic = null;
		this.fingerprint = null;
		this.errors = [];
		this.ready = new Promise((res) => { this._resolveReady = res; });
	}

	async connect() {
		this.ws = new WebSocket(WS_URL);
		// 串行化消息处理：a:'c' 帧既可能是对端公钥、也可能是业务密文，
		// 代码靠 peer.shared 区分。并发处理会让后启动的 handler 看到 shared
		// 仍是 null，于是把密文当公钥 -> fromHex 抛错。帧本身按序到达，串行即可。
		this._queue = Promise.resolve();
		this.ws.addEventListener('message', (ev) => {
			this._queue = this._queue
				.then(() => this._onMessage(ev.data))
				.catch((e) => this.errors.push(String(e && e.message ? e.message : e)));
		});
		this.ws.addEventListener('error', () => this.errors.push('ws error'));
		await new Promise((res, rej) => {
			this.ws.addEventListener('open', res);
			setTimeout(() => rej(new Error('连接超时: ' + WS_URL)), 15000);
		});
		// 客户端首帧：版本前缀 + P-384 公钥
		this.keys = await c.generateEcdhKeyPair('P-384');
		this.ws.send(PROTO + '|' + await c.exportEcdhPublic(this.keys));
	}

	async _send(obj) {
		this.ws.send(await c.encryptAead(this.serverShared, obj));
	}

	async _onMessage(raw) {
		// 1) 服务端公钥（明文 JSON）
		try {
			const d = JSON.parse(raw);
			if (d.type === 'server-key') {
				this.rsaPublic = d.key;
				this.fingerprint = await c.keyFingerprint(d.key);
				return;
			}
		} catch (e) {}

		// 2) 握手响应： NC2 | 服务端ECDH公钥 | RSA签名
		if (!this.serverShared) {
			const parts = String(raw).split('|');
			if (parts[0] !== PROTO) throw new Error('响应帧版本不对: ' + parts[0]);
			const rsaKey = await crypto.subtle.importKey('spki', c.fromB64(this.rsaPublic),
				{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, ['verify']);
			if (!await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, rsaKey,
				c.fromB64(parts[2]), c.fromHex(parts[1]))) throw new Error('RSA 签名校验失败');
			const secret = await c.deriveEcdhSecret(this.keys.privateKey, parts[1], 'P-384');
			this.serverShared = await c.deriveServerSessionKey(secret);
			await this._send({ a: 'j', p: channelId });   // 入房
			return;
		}

		// 3) 加密的业务帧
		const msg = await c.decryptAead(this.serverShared, raw);
		if (!msg || !msg.a) return;

		// 成员列表（服务端已排除自己）
		if (msg.a === 'l' && Array.isArray(msg.p)) {
			const payloads = {};
			for (const id of msg.p) {
				if (!this.peers[id]) {
					this.peers[id] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
					payloads[id] = await c.exportEcdhPublic(this.peers[id].keys);
				}
			}
			if (Object.keys(payloads).length) await this._send({ a: 'w', p: payloads });
			return;
		}

		// 转发帧
		if (msg.a === 'c' && msg.c) {
			let peer = this.peers[msg.c];
			if (!peer) {
				// 第一次见这个对端：建 P-256 并回发自己的公钥（只发这一次）
				peer = this.peers[msg.c] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
				await this._send({ a: 'c', p: await c.exportEcdhPublic(peer.keys), c: msg.c });
			}
			if (!peer.shared) {
				// 收到的是对端公钥 -> 派生端到端会话密钥
				const secret = await c.deriveEcdhSecret(peer.keys.privateKey, msg.p, 'P-256');
				peer.shared = await c.derivePeerSessionKey(secret, pwKey, channelId);
				await this._send({ a: 'c', c: msg.c, p: await c.encryptAead(peer.shared, { a: 'u', p: this.name }) });
				return;
			}
			// 已有密钥 -> 正常业务消息
			const inner = await c.decryptAead(peer.shared, msg.p);
			if (inner.a === 'u') {
				if (!peer.username) {
					peer.username = inner.p;
					this.securePeers++;
					if (this.securePeers >= 1) this._resolveReady();
				}
				return;
			}
			if (inner.a === 'm') { this.messages.push({ from: peer.username, t: inner.t, d: inner.d }); }
		}
	}

	async broadcast(type, data) {
		const payloads = {};
		for (const id in this.peers) {
			if (this.peers[id].shared && this.peers[id].username) {
				payloads[id] = await c.encryptAead(this.peers[id].shared, { a: 'm', t: type, d: data });
			}
		}
		const n = Object.keys(payloads).length;
		if (!n) throw new Error(this.name + ' 还没有已建立密钥的对端');
		await this._send({ a: 'w', p: payloads });
		return n;
	}

	async waitFor(pred, ms = 8000) {
		for (let i = 0; i < ms / 100; i++) {
			const hit = pred();
			if (hit) return hit;
			await sleep(100);
		}
		return null;
	}
}

// ---------------------------------------------------------------------------
console.log(`\n=========== 端到端测试（真 Worker @ ${WS_URL}）===========`);
console.log(`房间: ${ROOM}\n`);

const alice = new TestClient('Alice');
const bob = new TestClient('Bob');

try {
	await alice.connect();
	await bob.connect();

	console.log('[1] 服务端握手');
	// 这里以前是 sleep(400) 后直接断言，跨洋链路（经代理打 SJC 节点）下必然假失败：
	// 握手要走 WS 连接 -> 服务端发公钥 -> 客户端发公钥 -> 服务端 P-384 ECDH + RSA 签名
	// -> 客户端 RSA 验签 + PBKDF2 60 万次，往返远不止 400ms。改成等待条件成立。
	const hsA = await alice.waitFor(() => alice.serverShared || null, 20000);
	const hsB = await bob.waitFor(() => bob.serverShared || null, 20000);
	check('Alice 完成握手并拿到会话密钥', !!hsA);
	check('Bob 完成握手并拿到会话密钥', !!hsB);
	check('拿到服务端公钥指纹', /^([0-9A-F]{4} ){15}[0-9A-F]{4}$/.test(alice.fingerprint || ''),
		alice.fingerprint);

	console.log('\n[2] 端到端密钥协商（公钥经真 Worker 中继）');
	const bothReady = await Promise.race([
		Promise.all([alice.ready, bob.ready]).then(() => true),
		sleep(20000).then(() => false)
	]);
	check('双方互相看到对方用户名（密钥协商成功）', bothReady === true,
		`Alice 安全对端 ${alice.securePeers} 个 / Bob ${bob.securePeers} 个`);
	check('协商过程无异常', alice.errors.length === 0 && bob.errors.length === 0,
		[...alice.errors, ...bob.errors].join(' | '));

	if (bothReady) {
		console.log('\n[3] 经真 Worker 中继收发');
		const text = 'A->B ' + Date.now();
		const recipients = await alice.broadcast('text', text);
		const got = await bob.waitFor(() => bob.messages.find(m => m.d === text));
		check('Bob 收到 Alice 的消息', !!got,
			`加密给 ${recipients} 个对端；收到: ${got ? got.from + ': ' + got.d : '(无)'}`);

		const reply = 'B->A ' + Date.now();
		await bob.broadcast('text', reply);
		const got2 = await alice.waitFor(() => alice.messages.find(m => m.d === reply));
		check('Alice 收到 Bob 的回复（双向往返）', !!got2, got2 ? got2.from + ': ' + got2.d : '(无)');

		// 图片/文件那种体积的载荷
		const big = 'X'.repeat(200 * 1024);
		await alice.broadcast('image', big);
		const gotBig = await bob.waitFor(() => bob.messages.find(m => m.t === 'image'), 20000);
		check('200KB 载荷穿过中继并完整解出', !!gotBig && gotBig.d.length === big.length,
			gotBig ? `${gotBig.d.length} 字节` : '(无)');
	}

	console.log('\n[4] 第三个客户端加入');
	const carol = new TestClient('Carol');
	await carol.connect();
	const carolReady = await Promise.race([carol.ready.then(() => true), sleep(15000).then(() => false)]);
	check('Carol 能与已在房间的客户端协商成功', carolReady === true,
		`Carol 安全对端 ${carol.securePeers} 个`);
	const aliceSawCarol = await alice.waitFor(() => alice.securePeers >= 2 ? alice.securePeers : null, 15000);
	check('Alice 感知到新成员', aliceSawCarol === 2, `Alice 安全对端 ${alice.securePeers} 个`);
	carol.ws.close();

	check('全程无异常', alice.errors.length === 0 && bob.errors.length === 0,
		[...alice.errors, ...bob.errors].join(' | '));

	// -----------------------------------------------------------------------
	// R2 大文件：安全关键路径
	//
	// 这里验的是整个 P1 后半段的核心不变式 ——
	//   密文走 R2（公开存储），密钥走既有的端到端加密通道（只有房间成员能解）。
	// 所以除了「能不能传」，更要验「**没有密钥的人拿到 blobId 也读不出任何东西**」。
	// -----------------------------------------------------------------------
	console.log('\n[5] R2 大文件：密文走存储，密钥走 E2EE 通道');

	const fileBytes = randomBytes(6 * 1024 * 1024);   // 跨 2 块（块大小 4 MiB）
	const file = new File([fileBytes], '大文件 测试.bin', { type: 'application/octet-stream' });

	const manifest = await uploadToR2(file);
	check('本地分块加密并直传 R2', manifest.total === 2,
		`${manifest.total} 块 / 明文 ${manifest.size} 字节`);

	// 清单（含解密密钥）走和 text 消息完全相同的通道。
	// 字段与 util.file.js 的 uploadFilesViaR2 发出的 file_offer 完全一致 ——
	// 这里刻意逐字段写死而不用 ...manifest，这样任何一方改了字段名都会被立刻抓住。
	await alice.broadcast('file_offer', {
		type: 'file_offer',
		fileId: 'r2-test-1',
		blobId: manifest.blobId,
		key: manifest.key,
		fileName: manifest.fileName,
		originalSize: manifest.size,
		total: manifest.total,
		chunkSize: manifest.chunkSize,
		mime: manifest.mime
	});

	const offer = await bob.waitFor(() => bob.messages.find(m => m.t === 'file_offer'), 20000);
	check('Bob 收到 file_offer（密钥经 E2EE 通道送达）', !!offer,
		offer ? `来自 ${offer.from}` : '(无)');

	if (offer) {
		const m = offer.d;
		// 逐字段校验协议契约（含命名）
		check('清单字段完整且命名符合协议', !!(m.blobId && m.key && m.fileName && m.total && m.chunkSize && m.mime),
			`blobId=${String(m.blobId).slice(0, 12)}… total=${m.total} 文件名=${m.fileName}`);
		check('blobId 是 64 位小写 hex（R2 端点的强制格式）',
			/^[0-9a-f]{64}$/.test(String(m.blobId)), String(m.blobId).slice(0, 16) + '…');

		const blob = await downloadFromR2({
			blobId: m.blobId, key: m.key, name: m.fileName, mime: m.mime,
			size: m.size, total: m.total, chunkSize: m.chunkSize
		});
		const got = new Uint8Array(await blob.arrayBuffer());
		check('Bob 从 R2 下载并解密，内容逐字节一致', sameBytes(got, fileBytes),
			`${got.length} 字节`);

		// 关键安全断言：只有 blobId、没有密钥的攻击者
		console.log('\n[6] 安全性质：没有密钥就拿不到内容');
		const rawCipher = new Uint8Array(
			await (await fetch(`/blob/${m.blobId}/0`)).arrayBuffer()
		);
		check('R2 上的对象确实是密文（与明文前 1 MiB 不重合）',
			!sameBytes(rawCipher.subarray(0, 1024 * 1024), fileBytes.subarray(0, 1024 * 1024)));

		let wrongKeyFailed = false;
		try {
			// 换一把全新的随机密钥 —— 模拟「只拿到 blobId、没有正确密钥」的人
			const bogusKey = await exportFileKey(await newFileKey());
			await downloadFromR2({
				blobId: m.blobId, key: bogusKey, name: 'x', mime: 'x',
				size: m.size, total: m.total, chunkSize: m.chunkSize
			});
		} catch {
			wrongKeyFailed = true;
		}
		check('用错误的密钥解密必然失败（不是安静返回垃圾）', wrongKeyFailed);

		let tamperFailed = false;
		try {
			const tampered = new Uint8Array(rawCipher);
			tampered[tampered.length - 1] ^= 0x01;
			await decryptChunk(await importFileKey(m.key), m.blobId, 0, m.total, tampered);
		} catch {
			tamperFailed = true;
		}
		check('篡改密文后解密失败（AEAD 认证生效）', tamperFailed);
	}

	alice.ws.close();
	bob.ws.close();

} catch (err) {
	failed++;
	console.log(`\n  \u2717 测试过程抛出异常: ${err && err.message ? err.message : err}`);
	console.log(`    连接地址: ${WS_URL} —— 确认 wrangler dev 已在本机 8787 运行。`);
}

console.log(`\n=========== ${passed} 项通过, ${failed} 项失败 ===========\n`);
process.exit(failed === 0 ? 0 : 1);
