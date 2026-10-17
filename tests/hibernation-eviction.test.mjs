// Hibernation 驱逐测试：验证「DO 内存被清空后能否从 socket attachment 自愈」
//
// 为什么需要这个测试：
//   改用 Hibernation API 后，DO 空闲会被驱逐，内存状态全部丢失。整个改造的正确性
//   都压在一条纪律上 —— state.getWebSockets() + serializeAttachment() 是唯一可信
//   来源，内存只是缓存。E2E 测试用的是真 wrangler dev，但**没法强制驱逐**，
//   所以那条纪律不会被真正挑战到。
//
//   这里换一种打法：在 Node 里直接 import 真的 ChatRoom 类，配上 mock 的 DO state，
//   跑完握手和入房之后，**原地换一个全新的 ChatRoom 实例**（内存清零，等价于驱逐
//   后重新唤醒），看它能不能仅凭 socket 身上的 attachment 把状态重建起来。
//
// 附带验证：mock 的 serializeAttachment 用的是真的 structuredClone，
//   它对 CryptoKey 会直接抛 DataCloneError —— 这正是不能把 CryptoKey 直接塞进
//   attachment 的原因，顺带把「为什么必须存原始字节」也测了。
//
// 运行： node tests/hibernation-eviction.test.mjs

import * as c from '../client/js/aead.js';
import { ChatRoom } from '../worker/index.js';

const PROTO = c.PROTOCOL_VERSION;
const ROOM = 'evict-' + Math.random().toString(36).slice(2, 10);
const PASSWORD = 'evict-test-password';

let passed = 0, failed = 0;
const check = (name, ok, note = '') => {
	if (ok) { passed++; console.log(`  \u2713 ${name}${note ? '  ' + note : ''}`); }
	else { failed++; console.log(`  \u2717 ${name}  <<< 失败  ${note}`); }
};

// ---------------------------------------------------------------------------
// Mock Durable Object state
// ---------------------------------------------------------------------------

class MockStorage {
	constructor() { this.m = new Map(); }
	async get(k) { return this.m.get(k); }
	async put(k, v) { this.m.set(k, v); }
	async delete(k) { this.m.delete(k); }
}

class MockSocket {
	constructor(label) {
		this.label = label;
		this.readyState = 1;
		this._att = null;
		this.outbox = [];    // 服务端发往这个客户端的所有帧，按序
		this.closed = false;
	}
	send(m) { this.outbox.push(m); }
	close() { this.readyState = 3; this.closed = true; }
	// 用真的结构化克隆语义：CryptoKey 之类不可克隆的对象会直接抛
	serializeAttachment(a) { this._att = structuredClone(a); }
	deserializeAttachment() { return this._att ? structuredClone(this._att) : null; }
}

class MockState {
	constructor() {
		this.storage = new MockStorage();
		this.sockets = [];
	}
	getWebSockets() { return this.sockets.filter((s) => s.readyState === 1); }
	acceptWebSocket(ws) { this.sockets.push(ws); }
}

// 打开一个会话：完全走真 ChatRoom 的代码路径（fetch 里做的就是这两步）
async function openSession(room, state, label) {
	// 和真 DO 的 fetch 走同一条前置：确保 RSA 密钥已就绪再开会话
	if (!room.keyPair) await room.initRSAKeyPair();
	const server = new MockSocket(label);
	state.acceptWebSocket(server);
	await room.onOpenSession(server);
	return server;
}

// ---------------------------------------------------------------------------
// 客户端：协议照 e2e-worker.test.mjs 那份参考实现写
// ---------------------------------------------------------------------------

class Client {
	constructor(name, room, server) {
		this.name = name;
		this.room = room;
		this.server = server;
		this.cursor = 0;
		this.peers = {};
		this.messages = [];
		this.securePeers = 0;
		this.serverShared = null;
		this.rsaPublic = null;
		this.fingerprint = null;
		this.errors = [];
	}

	// 处理 socket 上还没读过的帧。处理过程中产生的出站帧会由 pump 的循环继续消费。
	async pump() {
		while (this.cursor < this.server.outbox.length) {
			const raw = this.server.outbox[this.cursor++];
			try {
				await this._onMessage(raw);
			} catch (e) {
				this.errors.push(String(e && e.message ? e.message : e));
			}
		}
	}

	// 出站：交给真 DO 的入口方法，和线上走的是同一段代码
	async sendRaw(raw) { await this.room.webSocketMessage(this.server, raw); }
	async send(obj) { await this.sendRaw(await c.encryptAead(this.serverShared, obj)); }

	async _onMessage(raw) {
		// 1) 服务端公钥（明文 JSON）
		try {
			const d = JSON.parse(raw);
			if (d.type === 'server-key') {
				this.rsaPublic = d.key;
				this.fingerprint = await c.keyFingerprint(d.key);
				return;
			}
		} catch (e) { }

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
			await this.send({ a: 'j', p: this.channelId });
			return;
		}

		// 3) 加密的业务帧
		const msg = await c.decryptAead(this.serverShared, raw);
		if (!msg || !msg.a) return;

		if (msg.a === 'l' && Array.isArray(msg.p)) {
			if (msg.c) this.myId = msg.c;
			const payloads = {};
			for (const id of msg.p) {
				if (!this.peers[id]) {
					this.peers[id] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
					payloads[id] = await c.exportEcdhPublic(this.peers[id].keys);
				}
			}
			if (Object.keys(payloads).length) await this.send({ a: 'w', p: payloads });
			return;
		}

		if (msg.a === 'c' && msg.c) {
			let peer = this.peers[msg.c];
			if (!peer) {
				peer = this.peers[msg.c] = { keys: await c.generateEcdhKeyPair('P-256'), shared: null, username: null };
				await this.send({ a: 'c', p: await c.exportEcdhPublic(peer.keys), c: msg.c });
			}
			if (!peer.shared) {
				const secret = await c.deriveEcdhSecret(peer.keys.privateKey, msg.p, 'P-256');
				peer.shared = await c.derivePeerSessionKeys(secret, this.pwKey, this.channelId, this.myId, msg.c);
				peer.seqOut = 1;
				await this.send({ a: 'c', c: msg.c, p: await c.encryptAead(peer.shared.send,
					{ a: 'u', p: this.name, s: peer.seqOut }, c.peerAadBytes(this.channelId, this.myId)) });
				return;
			}
			const inner = await c.decryptAead(peer.shared.recv, msg.p, c.peerAadBytes(this.channelId, msg.c));
			if (!inner || typeof inner.s !== 'number' || inner.s <= (peer.seqIn || 0)) return;
			peer.seqIn = inner.s;
			if (inner.a === 'u') {
				if (!peer.username) { peer.username = inner.p; this.securePeers++; }
				return;
			}
			if (inner.a === 'm') { this.messages.push({ from: peer.username, t: inner.t, d: inner.d }); }
		}
	}

	async broadcast(type, data) {
		const payloads = {};
		for (const id in this.peers) {
			if (this.peers[id].shared && this.peers[id].username) {
				const peer = this.peers[id];
				peer.seqOut = (peer.seqOut || 0) + 1;
				payloads[id] = await c.encryptAead(peer.shared.send, { a: 'm', t: type, d: data, s: peer.seqOut },
					c.peerAadBytes(this.channelId, this.myId));
			}
		}
		const n = Object.keys(payloads).length;
		if (!n) throw new Error(this.name + ' 还没有已建立密钥的对端');
		await this.send({ a: 'w', p: payloads });
		return n;
	}

	async handshake() {
		this.keys = await c.generateEcdhKeyPair('P-384');
		await this.sendRaw(PROTO + '|' + await c.exportEcdhPublic(this.keys));
	}
}

// 反复泵所有客户端，直到没有新帧产生（协议是纯消息驱动的）
async function settle(clients, maxRounds = 60) {
	for (let r = 0; r < maxRounds; r++) {
		const before = clients.reduce((n, cl) => n + cl.server.outbox.length, 0);
		for (const cl of clients) await cl.pump();
		const after = clients.reduce((n, cl) => n + cl.server.outbox.length, 0);
		if (after === before) return r;
	}
	throw new Error('settle 未收敛（可能有回环）');
}

// ---------------------------------------------------------------------------
console.log(`\n=========== Hibernation 驱逐测试 ===========`);
console.log(`房间: ${ROOM}\n`);

const channelId = await c.sha256Hex('nodecrypt-v2|channel|' + ROOM);
const pwKey = await c.derivePasswordKey(PASSWORD, ROOM);

const state = new MockState();
let room = new ChatRoom(state, {});

console.log('[1] 建立会话并完成握手');
const sockA = await openSession(room, state, 'A');
const sockB = await openSession(room, state, 'B');
check('两个 socket 已被 acceptWebSocket 托管', state.getWebSockets().length === 2,
	`getWebSockets() = ${state.getWebSockets().length}`);

const alice = new Client('Alice', room, sockA); alice.channelId = channelId; alice.pwKey = pwKey;
const bob = new Client('Bob', room, sockB); bob.channelId = channelId; bob.pwKey = pwKey;

await alice.handshake();
await bob.handshake();
await settle([alice, bob]);
check('Alice 拿到服务端会话密钥', !!alice.serverShared);
check('Bob 拿到服务端会话密钥', !!bob.serverShared);
check('RSA 指纹格式正确', /^([0-9A-F]{4} ){15}[0-9A-F]{4}$/.test(alice.fingerprint || ''), alice.fingerprint);

console.log('\n[2] 密钥协商 + 入房 + 中继（驱逐前的基线）');
await settle([alice, bob]);
check('双方互认（密钥协商成功）', alice.securePeers === 1 && bob.securePeers === 1,
	`Alice ${alice.securePeers} / Bob ${bob.securePeers}`);

const t1 = '驱逐前 ' + Date.now();
await alice.broadcast('text', t1);
await settle([alice, bob]);
check('驱逐前：Bob 收到 Alice 的消息', bob.messages.some((m) => m.d === t1),
	bob.messages.map((m) => m.d).join(' | ') || '(无)');

console.log('\n[3] attachment 里的内容');
const attA = sockA.deserializeAttachment();
check('attachment 里有 clientId', typeof attA.clientId === 'string', attA.clientId);
check('attachment 里有 channel', attA.channel === channelId);
check('attachment 里存的是会话密钥**字节**而不是 CryptoKey',
	attA.sharedBytes && (attA.sharedBytes instanceof Uint8Array || Array.isArray(attA.sharedBytes)),
	`${attA.sharedBytes && attA.sharedBytes.length} 字节`);
check('attachment 里没有任何 CryptoKey（不可克隆对象）',
	![attA.sharedBytes].some((v) => typeof CryptoKey !== 'undefined' && v instanceof CryptoKey));
// 说明：Node 的 structuredClone 恰好能克隆 CryptoKey，所以别拿 Node 去断言这件事。
// 实测证据（真 workerd，wrangler dev 与线上同一运行时）：
//   serializeAttachment({ k: cryptoKey })
//   -> DataCloneError: Could not serialize object of type "CryptoKey".
//      This type does not support serialization.
// 这就是 attachment 里存字节、而不是存 CryptoKey 的原因。
check('attachment 可被 JSON 无损往返（体积小、只含原始类型）',
	JSON.stringify(attA) === JSON.stringify(JSON.parse(JSON.stringify(attA))),
	`${JSON.stringify(attA).length} 字符`);

console.log('\n[★] 模拟驱逐：换一个全新的 ChatRoom 实例，内存全部清零');
const oldRoom = room;
room = new ChatRoom(state, {});      // 同一个 state（socket 与 storage 都还在），新对象
alice.room = room; bob.room = room;  // 客户端后续帧交给"被唤醒后"的实例处理

check('新实例内存确实是空的（clients 未重建）', Object.keys(room.clients).length === 0);
check('新实例的 channels 也是空的', Object.keys(room.channels).length === 0);
check('但 socket 仍在 getWebSockets() 里', state.getWebSockets().length === 2);

await room.syncClients();
check('syncClients() 从 attachment 重建出 2 个客户端', Object.keys(room.clients).length === 2);
check('频道成员表也重建出来了',
	room.channels[channelId] && room.channels[channelId].length === 2,
	JSON.stringify(room.channels[channelId] || null));

const rebuiltKey = await room.getSharedKey(attA.clientId);
check('会话密钥能从字节还原成可用的 CryptoKey', !!rebuiltKey && rebuiltKey.type === 'secret');

console.log('\n[4] 驱逐后继续收发（这才是关键）');
const t2 = '驱逐后 ' + Date.now();
await alice.broadcast('text', t2);
await settle([alice, bob]);
check('驱逐后：Bob 仍收到 Alice 的消息', bob.messages.some((m) => m.d === t2),
	bob.messages.map((m) => m.d).join(' | ') || '(无)');

const t3 = '回程 ' + Date.now();
await bob.broadcast('text', t3);
await settle([alice, bob]);
check('驱逐后：反方向也通', alice.messages.some((m) => m.d === t3),
	alice.messages.map((m) => m.d).join(' | ') || '(无)');

console.log('\n[5] 再驱逐一次，并且换个新成员加入');
room = new ChatRoom(state, {});
alice.room = room; bob.room = room;
await room.syncClients();
check('第二次驱逐后仍能重建 2 个客户端', Object.keys(room.clients).length === 2);

const sockC = await openSession(room, state, 'C');
const carol = new Client('Carol', room, sockC); carol.channelId = channelId; carol.pwKey = pwKey;
await carol.handshake();
await settle([alice, bob, carol]);
check('驱逐后新客户端 Carol 也能协商成功', carol.securePeers >= 1, `Carol 安全对端 ${carol.securePeers} 个`);
check('老客户端感知到 Carol', alice.securePeers === 2, `Alice 安全对端 ${alice.securePeers} 个`);

const t4 = '三方 ' + Date.now();
await alice.broadcast('text', t4);
await settle([alice, bob, carol]);
check('驱逐后三方广播可达', bob.messages.some((m) => m.d === t4) && carol.messages.some((m) => m.d === t4));

console.log('\n[6] 关闭连接后状态清理');
sockC.readyState = 3;                 // 模拟 socket 断开
await room.webSocketClose(sockC, 1005, '', true);
await room.syncClients();
check('断开的客户端已从重建结果里消失', Object.keys(room.clients).length === 2,
	`剩 ${Object.keys(room.clients).length} 个`);
check('Carol 已移出频道', room.channels[channelId].length === 2,
	`频道剩 ${room.channels[channelId].length} 人`);

const t5 = 'C 走后 ' + Date.now();
await alice.broadcast('text', t5);
await settle([alice, bob]);
check('Carol 离开后剩下两人仍能通信', bob.messages.some((m) => m.d === t5));

console.log('\n[7] 全程无异常');
check('客户端无异常', alice.errors.length === 0 && bob.errors.length === 0 && carol.errors.length === 0,
	[...alice.errors, ...bob.errors, ...carol.errors].join(' | ') || '(无)');

console.log(`\n=========== ${passed} 项通过, ${failed} 项失败 ===========\n`);
process.exit(failed === 0 ? 0 : 1);
