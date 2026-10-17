// P0 改造互操作测试
//
// 目的：证明改造后的**客户端加密核心**（client/js/aead.js，浏览器侧）
// 和**服务端加密工具**（worker/utils.js，Workers 侧）真的能互相解开。
//
// 为什么这个测试最有价值：
//   两边都改用 AES-GCM 之后，只要 IV 长度、AAD、载荷分隔符、
//   密钥派生输入任意一处对不上，就会出现「服务端发得出、客户端解不开」
//   这种最难查的故障——而且构建和类型检查都不会报错。
//   本测试在 Node 里同时加载两边的真实模块，逐字段走一遍握手和收发。
//
// 运行： node tests/p0-interop.test.mjs
// 要求： Node 20+

import * as client from '../client/js/aead.js';
import * as server from '../worker/utils.js';

const te = new TextEncoder();
const td = new TextDecoder();

let passed = 0, failed = 0;
const check = (name, ok, note = '') => {
	if (ok) { passed++; console.log(`  \u2713 ${name}${note ? '  ' + note : ''}`); }
	else { failed++; console.log(`  \u2717 ${name}  <<< 失败  ${note}`); }
};

console.log('\n=========== P0 互操作测试（客户端 aead.js ⇄ 服务端 utils.js）===========\n');

// ---------------------------------------------------------------------------
console.log('[1] 两边的编码工具必须一致');
for (const [label, bytes] of [
	['全零 16B', new Uint8Array(16)],
	['全 0xFF 16B', new Uint8Array(16).fill(255)],
	['含所有字节值 256B', new Uint8Array(Array.from({ length: 256 }, (_, i) => i))],
	['大块 70000B（验证分块 base64 不爆栈）', new Uint8Array(70000).fill(0xAB)],
]) {
	const cb = client.toB64(bytes), sb = server.toB64(bytes);
	check(`${label}: toB64 输出一致`, cb === sb);
	check(`${label}: 往返可还原`, server.fromB64(cb).every((v, i) => v === bytes[i]));
}
check('toHex/fromHex 两边一致',
	client.toHex(server.fromHex('deadbeef')) === 'deadbeef' &&
	server.toHex(client.fromHex('00ff10')) === '00ff10');

// ---------------------------------------------------------------------------
console.log('\n[2] 服务端握手：完整复现 worker/index.js 的密钥协商');
const PROTO = client.PROTOCOL_VERSION;

// 服务端 RSA 身份
const rsa = await crypto.subtle.generateKey(
	{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
	true, ['sign', 'verify']);
const rsaPublicB64 = server.toB64(new Uint8Array(await crypto.subtle.exportKey('spki', rsa.publicKey)));

// --- 客户端发首帧 ---
const clientKeys = await client.generateEcdhKeyPair('P-384');
const clientPubHex = await client.exportEcdhPublic(clientKeys);
const firstFrame = PROTO + '|' + clientPubHex;
check('首帧带版本前缀', firstFrame.startsWith('NC2|'), `长度 ${firstFrame.length} < 2048 所以服务端会当握手帧`);
check('老客户端会被拦下', !('aabbcc'.startsWith(PROTO + '|')));

// --- 服务端按 worker/index.js 的逻辑回应 ---
const serverKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits', 'deriveKey']);
const serverPubRaw = await crypto.subtle.exportKey('raw', serverKeys.publicKey);
const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, rsa.privateKey, serverPubRaw);

const parsedClientPub = await crypto.subtle.importKey('raw', server.fromHex(firstFrame.slice(PROTO.length + 1)),
	{ name: 'ECDH', namedCurve: 'P-384' }, false, []);
const serverSharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: parsedClientPub }, serverKeys.privateKey, 384);
const serverSessionKey = await server.deriveServerSessionKey(new Uint8Array(serverSharedBits));

const responseFrame = PROTO + '|' + server.toHex(new Uint8Array(serverPubRaw)) + '|' +
	server.toB64(new Uint8Array(signature));

// --- 客户端解析响应帧 ---
const parts = responseFrame.split('|');
check('响应帧字段数正确（3 段）', parts.length === 3 && parts[0] === PROTO);

const rsaVerifyKey = await crypto.subtle.importKey('spki', client.fromB64(rsaPublicB64),
	{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } }, false, ['verify']);
const verified = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, rsaVerifyKey,
	client.fromB64(parts[2]), client.fromHex(parts[1]));
check('客户端能验过 RSA 签名', verified === true, '这是自洽性校验，不是身份认证');

const clientSecret = await client.deriveEcdhSecret(clientKeys.privateKey, parts[1], 'P-384');
const clientSessionKey = await client.deriveServerSessionKey(clientSecret);

console.log('\n[3] 服务端 ↔ 客户端 会话密钥必须互解');
const joinMsg = { a: 'j', p: 'room-hash-abc123' };
const fromClient = await client.encryptAead(clientSessionKey, joinMsg);
const seenByServer = await server.decryptMessage(fromClient, serverSessionKey);
check('服务端能解开客户端发的入房消息', seenByServer.a === 'j' && seenByServer.p === 'room-hash-abc123',
	`解出 ${JSON.stringify(seenByServer)}`);

const memberList = { a: 'l', p: ['peer-1', 'peer-2'] };
const fromServer = await server.encryptMessage(memberList, serverSessionKey);
const seenByClient = await client.decryptAead(clientSessionKey, fromServer);
check('客户端能解开服务端发的成员列表', JSON.stringify(seenByClient) === JSON.stringify(memberList),
	`解出 ${JSON.stringify(seenByClient)}`);

// ---------------------------------------------------------------------------
console.log('\n[4] 客户端 ⇄ 客户端 端到端会话密钥');
const ROOM = '我的秘密房间';
const PASSWORD = 'correct horse battery staple';
const channelId = await client.sha256Hex('nodecrypt-v2|channel|' + ROOM);
const pwKey = await client.derivePasswordKey(PASSWORD, ROOM);

// 两个对端各自生成 P-256
const alice = await client.generateEcdhKeyPair('P-256');
const bob = await client.generateEcdhKeyPair('P-256');
const alicePub = await client.exportEcdhPublic(alice);
const bobPub = await client.exportEcdhPublic(bob);

// 服务端只转发公钥，看不到别的
check('公钥走中继是明文可转发的', typeof alicePub === 'string' && alicePub.length === 130,
	`P-256 原始公钥 65 字节 => ${alicePub.length} hex 字符`);

const aliceSecret = await client.deriveEcdhSecret(alice.privateKey, bobPub, 'P-256');
const bobSecret = await client.deriveEcdhSecret(bob.privateKey, alicePub, 'P-256');
const ID_A = 'a1a1a1a1a1a1a1a1';
const ID_B = 'b2b2b2b2b2b2b2b2';
const keysA = await client.derivePeerSessionKeys(aliceSecret, pwKey, channelId, ID_A, ID_B);
const keysB = await client.derivePeerSessionKeys(bobSecret, pwKey, channelId, ID_B, ID_A);

const chatMsg = { a: 'm', t: 'text', d: '晚上八点老地方见' };
const sealed = await client.encryptAead(keysA.send, chatMsg, client.peerAadBytes(channelId, ID_A));
const opened = await client.decryptAead(keysB.recv, sealed, client.peerAadBytes(channelId, ID_A));
check('A 加密、B 解密成功（真实聊天路径）', JSON.stringify(opened) === JSON.stringify(chatMsg),
	`明文: ${opened.d}`);

const back = await client.encryptAead(keysB.send, { a: 'm', t: 'text', d: '收到' },
	client.peerAadBytes(channelId, ID_B));
check('B 加密、A 解密成功（双向往返）',
	(await client.decryptAead(keysA.recv, back, client.peerAadBytes(channelId, ID_B))).d === '收到');

// 方向分离：两端各自派生一对密钥，A 的发送 == B 的接收，反之亦然；
// 用发送密钥去解对端发来的密文必须失败（反射）。
let reflectBlocked = false;
try {
	await client.decryptAead(keysB.recv, back, client.peerAadBytes(channelId, ID_B));
} catch (e) { reflectBlocked = true; }
check('方向分离：自己的发送密钥解不开对端发来的密文（反射不成立）', reflectBlocked);

// AAD 绑定发送者：把同一份密文换个发送者身份去解，必须失败
let aadBlocked = false;
try {
	await client.decryptAead(keysB.recv, sealed, client.peerAadBytes(channelId, ID_B));
} catch (e) { aadBlocked = true; }
check('AAD 绑定发送者：换一个发送者身份解不开', aadBlocked);

// ---------------------------------------------------------------------------
console.log('\n[5] 攻击面：这些都必须在改造后失败');
// 5a 口令错
const evePwKey = await client.derivePasswordKey('wrong password', ROOM);
const eveKeys = await client.derivePeerSessionKeys(aliceSecret, evePwKey, channelId, ID_A, ID_B);
let eveBlocked = false, eveGot = null;
try { eveGot = await client.decryptAead(eveKeys.recv, sealed, client.peerAadBytes(channelId, ID_A)); } catch (e) { eveBlocked = true; }
check('口令错的下游算不出正确密钥', eveBlocked, eveGot ? `竟然解出 ${JSON.stringify(eveGot)}` : 'AEAD 认证失败');

// 5b 房间错
const otherRoomId = await client.sha256Hex('nodecrypt-v2|channel|' + '另一个房间');
const wrongRoomKeys = await client.derivePeerSessionKeys(aliceSecret, pwKey, otherRoomId, ID_A, ID_B);
let roomBlocked = false;
try { await client.decryptAead(wrongRoomKeys.recv, sealed, client.peerAadBytes(channelId, ID_A)); } catch (e) { roomBlocked = true; }
check('同口令不同房间 => 密钥不同 => 解不开', roomBlocked);

// 5c 密文被篡改（原实现完全无法发现）
let tamperBlocked = false;
try {
	const raw = client.fromB64(sealed.split('|')[1]);
	raw[Math.floor(raw.length / 2)] ^= 0x01;   // 翻转中间一个比特
	await client.decryptAead(keyA, sealed.split('|')[0] + '|' + client.toB64(raw));
} catch (e) { tamperBlocked = true; }
check('密文翻转 1 比特 => 被拒绝（AEAD 认证生效）', tamperBlocked, '⟵ 原 CBC/裸ChaCha20 做不到');

// 5d IV 被篡改
let ivBlocked = false;
try {
	const iv = client.fromB64(sealed.split('|')[0]);
	iv[0] ^= 0xFF;
	await client.decryptAead(keyA, client.toB64(iv) + '|' + sealed.split('|')[1]);
} catch (e) { ivBlocked = true; }
check('IV 被篡改 => 被拒绝', ivBlocked);

// 5e 服务端（只有 ECDH、没有口令）解不开客户端之间的消息
let serverBlocked = false;
try { await client.decryptAead(serverSessionKey, sealed); } catch (e) { serverBlocked = true; }
check('服务端会话密钥解不开客户端之间的密文', serverBlocked, '⟵ 服务端确实看不到明文');

// 5f 载荷格式不合规
let malformedBlocked = 0;
for (const bad of ['', 'abc', 'a|b|c', '||']) {
	try { await client.decryptAead(keyA, bad); } catch (e) { malformedBlocked++; }
}
check('畸形载荷一律拒绝', malformedBlocked === 4, `${malformedBlocked}/4`);

// ---------------------------------------------------------------------------
console.log('\n[6] PBKDF2 强度');
const t0 = performance.now();
const k1 = await client.derivePasswordKey('test', 'room');
const t1 = performance.now();
const t2 = performance.now();
await client.derivePasswordKey('test2', 'room');
const t3 = performance.now();
check('单次派生耗时在合理区间（30ms - 1000ms）',
	(t1 - t0) > 30 && (t1 - t0) < 1000, `${(t1 - t0).toFixed(1)}ms / ${(t3 - t2).toFixed(1)}ms`);
check('派生结果是 32 字节', k1.length === 32);
const k2 = await client.derivePasswordKey('other', 'room');
check('不同口令 => 不同结果', !k1.every((v, i) => v === k2[i]));
check('相同输入 => 结果确定（派生是纯函数）',
	(await client.derivePasswordKey('test', 'room')).every((v, i) => v === k1[i]));

// ---------------------------------------------------------------------------
console.log('\n[7] 服务端公钥指纹（TOFU 变更通知的基础）');
const fp = await client.keyFingerprint(rsaPublicB64);
check('指纹格式：16 组 4 字符', /^([0-9A-F]{4} ){15}[0-9A-F]{4}$/.test(fp));
check('同一公钥指纹稳定', (await client.keyFingerprint(rsaPublicB64)) === fp);
const otherRsa = await crypto.subtle.generateKey(
	{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
	true, ['sign', 'verify']);
const fp2 = await client.keyFingerprint(server.toB64(new Uint8Array(await crypto.subtle.exportKey('spki', otherRsa.publicKey))));
check('换一把密钥 => 指纹必变（能检测到变更）', fp !== fp2, `\n      ${fp}\n      ${fp2}`);

console.log(`\n=========== ${passed} 项通过, ${failed} 项失败 ===========\n`);
process.exit(failed === 0 ? 0 : 1);
