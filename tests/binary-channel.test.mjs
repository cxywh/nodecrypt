// 二进制通道单测：裸 AEAD + 帧编解码 + 分卷记录
//
// 重点验三件事：
//   1. 正确性   加解密往返、边界（空载荷、最大分卷号）
//   2. 安全性   换密钥必失败、篡改必失败、**两个通道的密文不能互换**（域分离）
//   3. 收益     链路上的膨胀从 1.78× 降到多少 —— 这是本次改造的全部理由
//
// 用法：node tests/binary-channel.test.mjs
import {
	encryptRaw, decryptRaw, packBinaryFrame, unpackBinaryFrame,
	packVolumeRecord, unpackVolumeRecord, encodeClientId,
	BIN_FRAME_CHANNEL, CLIENT_ID_BYTES,
	encryptAead, decryptAead, toB64,
	generateEcdhKeyPair, exportEcdhPublic, deriveEcdhSecret,
	derivePasswordKey, derivePeerSessionKeys
} from '../client/js/aead.js';

let pass = 0, fail = 0;
const check = async (name, fn) => {
	try { await fn(); console.log(`  ✓ ${name}`); pass++; }
	catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};
const assert = (cond, msg) => { if (!cond) throw new Error(msg || '断言失败'); };
const eq = (a, b, msg) => { if (a !== b) throw new Error(`${msg || '不相等'}: 期望 ${b}，实际 ${a}`); };
const throws = async (fn, msg) => {
	try { await fn(); } catch { return; }
	throw new Error(msg || '本应抛异常但没有');
};

// crypto.getRandomValues 单次上限 65536 字节（Node 与浏览器一致），
// 所以大载荷必须分块填充 —— 直接传 256KB 会抛
// "The requested length exceeds 65,536 bytes"。
const randomBytes = (n) => {
	const out = new Uint8Array(n);
	const CHUNK = 65536;
	for (let i = 0; i < n; i += CHUNK) {
		crypto.getRandomValues(out.subarray(i, Math.min(i + CHUNK, n)));
	}
	return out;
};

const PASSWORD = 'binary-channel-test-password';
const ROOM = 'binary-channel-room';

// 造一把真的会话密钥：走完整的 ECDH + PBKDF2 + HKDF 派生，而不是随手造一个
// 随机密钥 import 进来 —— 后者会掩盖「派生参数不匹配」这类真问题。
const ID_A = 'a1a1a1a1a1a1a1a1';
const ID_B = 'b2b2b2b2b2b2b2b2';

async function makeSessionKeys(channelId = 'deadbeefdeadbeef') {
	const pwKey = await derivePasswordKey(PASSWORD, ROOM);
	const a = await generateEcdhKeyPair('P-256');
	const b = await generateEcdhKeyPair('P-256');
	const secretA = await deriveEcdhSecret(a.privateKey, await exportEcdhPublic(b));
	const secretB = await deriveEcdhSecret(b.privateKey, await exportEcdhPublic(a));
	// 方向分离：A（id 小）用 c2s 发送，B 用同一把 c2s 接收，
	// 因此 keyA == keyB 的原始密钥，但 keyB.send 是另一把（用于反射断言）。
	const keysA = await derivePeerSessionKeys(secretA, pwKey, channelId, ID_A, ID_B);
	const keysB = await derivePeerSessionKeys(secretB, pwKey, channelId, ID_B, ID_A);
	return { keyA: keysA.send, keyB: keysB.recv, keysA, keysB };
}

console.log('\n【1】裸 AEAD（encryptRaw / decryptRaw）');

const { keyA, keyB, keysA, keysB } = await makeSessionKeys();

await check('往返：256KB 载荷原样还原', async () => {
	const data = randomBytes(256 * 1024);
	const packed = await encryptRaw(keyA, data);
	const out = await decryptRaw(keyB, packed);
	assert(out.length === data.length, `长度不符 ${out.length}`);
	assert(out.every((v, i) => v === data[i]), '内容不符');
});

await check('方向分离：反射密文（对端用自己的发送密钥加密）解不开', async () => {
	const packed = await encryptRaw(keysB.send, randomBytes(64));
	await throws(() => decryptRaw(keysA.send, packed), '反射密文竟然解开了');
});

await check('往返：空载荷（0 字节）', async () => {
	const packed = await encryptRaw(keyA, new Uint8Array(0));
	eq(packed.length, 12 + 16, '空载荷密文应为 IV+标签');
	const out = await decryptRaw(keyB, packed);
	eq(out.length, 0, '应解出 0 字节');
});

await check('往返：1 字节边界', async () => {
	const packed = await encryptRaw(keyA, new Uint8Array([0x42]));
	const out = await decryptRaw(keyB, packed);
	eq(out.length, 1);
	eq(out[0], 0x42);
});

await check('换一把密钥必然解密失败', async () => {
	const other = await makeSessionKeys();
	const packed = await encryptRaw(keyA, randomBytes(1024));
	await throws(() => decryptRaw(other.keyB, packed), '换了密钥居然能解开');
});

await check('篡改密文任意一个字节必然失败', async () => {
	const packed = await encryptRaw(keyA, randomBytes(1024));
	let tamperFailed = 0;
	for (const pos of [12, 20, packed.length - 1]) {
		const t = new Uint8Array(packed);
		t[pos] ^= 0x01;
		try { await decryptRaw(keyB, t); } catch { tamperFailed++; }
	}
	eq(tamperFailed, 3, `${tamperFailed}/3 处篡改被检出`);
});

await check('篡改 IV 也必然失败', async () => {
	const packed = await encryptRaw(keyA, randomBytes(1024));
	const t = new Uint8Array(packed);
	t[0] ^= 0x80;
	await throws(() => decryptRaw(keyB, t), 'IV 被改还能解开');
});

await check('长度不足的载荷直接拒（不进入 AES）', async () => {
	await throws(() => decryptRaw(keyB, randomBytes(27)), '27 字节应被拒');
});

await check('★ 域分离：JSON 通道密文丢进二进制通道必失败', async () => {
	const jsonPacked = await encryptAead(keyA, { a: 'm', t: 'file_volume', d: { x: 1 } });
	// JSON 通道是 "base64(iv)|base64(ct)" 的字符串，二进制通道要裸字节。
	// 把它的密文部分当二进制帧载荷喂进去，必须解不开。
	const raw = Uint8Array.from(atob(jsonPacked.split('|')[1]), c => c.charCodeAt(0));
	await throws(() => decryptRaw(keyB, raw), 'JSON 通道密文不应能走二进制通道解出');
});

console.log('\n【2】二进制帧编解码');

await check('往返：帧头 + 载荷原样还原', async () => {
	const packed = await encryptRaw(keyA, randomBytes(1024));
	const frame = packBinaryFrame('829c98ee9de4b41e', packed);
	eq(frame[0], BIN_FRAME_CHANNEL, '帧类型字节');
	eq(frame.length, 1 + CLIENT_ID_BYTES + packed.length);
	const { peerClientId, packed: got } = unpackBinaryFrame(frame);
	eq(peerClientId, '829c98ee9de4b41e');
	assert(got.every((v, i) => v === packed[i]), '载荷不符');
});

await check('帧头 17 字节，固定开销可忽略', async () => {
	const packed = await encryptRaw(keyA, randomBytes(256 * 1024));
	const frame = packBinaryFrame('0000000000000000', packed);
	eq(frame.length - packed.length, 17, '帧头应为 1+16 字节');
});

await check('unpackBinaryFrame 对垃圾返回 null 而非抛错', async () => {
	eq(unpackBinaryFrame(new Uint8Array(0)), null, '空');
	eq(unpackBinaryFrame(randomBytes(10)), null, '太短');
	eq(unpackBinaryFrame(randomBytes(64)), null, '类型字节不对');
	const bad = new Uint8Array(64);
	bad[0] = BIN_FRAME_CHANNEL;
	bad.fill(0x2a, 1, 17);   // '****...' 非 hex
	eq(unpackBinaryFrame(bad), null, 'id 非 hex');
});

await check('clientId 校验：非 16 位小写 hex 一律拒', async () => {
	await throws(() => encodeClientId('ABC'), '太短');
	await throws(() => encodeClientId('829C98EE9DE4B41E'), '大写应拒（服务端恒小写，大写说明来源可疑）');
	await throws(() => encodeClientId('829c98ee9de4b41g'), '含非 hex 字符');
	eq(encodeClientId('829c98ee9de4b41e').length, 16);
});

await check('★ 收到别人的帧时，用错密钥解不开（防止跨对端串读）', async () => {
	const third = await makeSessionKeys();
	const packed = await encryptRaw(keyA, randomBytes(512));
	const frame = packBinaryFrame('829c98ee9de4b41e', packed);
	const { packed: got } = unpackBinaryFrame(frame);
	const out = await decryptRaw(keyB, got, undefined).catch(() => null);
	assert(out !== null, '本对端应能解开');
	await throws(() => decryptRaw(third.keyB, got), '第三方不应能解开');
});

console.log('\n【3】分卷记录');

await check('往返：fileId / index / total / 载荷', async () => {
	const payload = randomBytes(4096);
	const rec = packVolumeRecord('6f1c0b2a9d3e4f58', 7, 120, payload);
	const { fileId, volumeIndex, totalVolumes, payload: got } = unpackVolumeRecord(rec);
	eq(fileId, '6f1c0b2a9d3e4f58');
	eq(volumeIndex, 7);
	eq(totalVolumes, 120);
	assert(got.every((v, i) => v === payload[i]), '载荷不符');
});

await check('边界：index 0、totals 65535（2 字节上限）', async () => {
	const r1 = unpackVolumeRecord(packVolumeRecord('aa', 0, 1, new Uint8Array(0)));
	eq(r1.volumeIndex, 0); eq(r1.totalVolumes, 1); eq(r1.payload.length, 0);

	const r2 = unpackVolumeRecord(packVolumeRecord('aa', 65535, 65535, new Uint8Array([9])));
	eq(r2.volumeIndex, 65535); eq(r2.totalVolumes, 65535); eq(r2.payload[0], 9);
});

await check('非 ASCII 的 fileId（中文文件名场景）', async () => {
	const id = '文档-2026-最终版.pdf';
	const rec = packVolumeRecord(id, 3, 50, randomBytes(100));
	eq(unpackVolumeRecord(rec).fileId, id, '中文 fileId 应无损');
});

await check('截断的记录抛错（不能让调用方拿到半个头）', async () => {
	await throws(() => unpackVolumeRecord(new Uint8Array([5, 0x61])), '声明 5 字节 id 但只有 1 字节');
	await throws(() => unpackVolumeRecord(new Uint8Array([])), '空');
});

await check('整个记录进一次 AEAD：元数据也被认证，改不动分卷号', async () => {
	const rec = packVolumeRecord('file-1', 2, 10, randomBytes(256));
	const packed = await encryptRaw(keyA, rec);
	const out = unpackVolumeRecord(await decryptRaw(keyB, packed));
	eq(out.volumeIndex, 2, '序号应正确还原');

	// 篡改密文里任意一处，元数据或载荷整体失效
	const t = new Uint8Array(packed);
	t[packed.length - 1] ^= 1;
	await throws(() => decryptRaw(keyB, t), '篡改后不应解出');
});

console.log('\n【4】收益实测：链路膨胀');

await check('★ 256KB 分卷的链路膨胀 < 0.1%（改造前 78%）', async () => {
	const PLAIN = 256 * 1024;
	const data = randomBytes(PLAIN);
	const packed = await encryptRaw(keyA, data);
	const frame = packBinaryFrame('829c98ee9de4b41e', packed);
	const ratio = frame.length / PLAIN;
	console.log(`      明文 ${PLAIN} → 链路 ${frame.length} 字节，膨胀 ${((ratio - 1) * 100).toFixed(3)}%`);
	assert(ratio < 1.001, `膨胀 ${ratio.toFixed(4)} 超标`);
});

await check('★ 对比：真跑一遍旧路径（base64 ① + JSON + AES-GCM + base64 ②）', async () => {
	const PLAIN = 256 * 1024;
	const data = randomBytes(PLAIN);

	// 旧路径的每一步都用**真实函数**跑，不手算 —— 手算容易把某层漏掉或算错，
	// 而这次改造的全部理由就是这条链路的膨胀，数字必须站得住。
	//   base64 ①：分卷转 base64（用代码库自己的 toB64，它分块规避了栈溢出）
	const step1 = toB64(data);
	//   塞进 JSON，每对端整体 AES-GCM → "base64(iv)|base64(ct)"
	const inner = await encryptAead(keyA, {
		a: 'm', t: 'file_volume',
		d: { fileId: 'f', volumeIndex: 0, volumeData: step1 }
	});
	//   外层服务端信封再整体 AES-GCM → base64 ②
	const outer = await encryptAead(keyA, { a: 'w', p: { '829c98ee9de4b41e': inner } });

	const oldRatio = outer.length / PLAIN;
	console.log(`      旧路径：明文 ${PLAIN} → 链路 ${outer.length} 字节，膨胀 ${((oldRatio - 1) * 100).toFixed(1)}%`);

	const packed = await encryptRaw(keyA, data);
	const frame = packBinaryFrame('829c98ee9de4b41e', packed);
	const newRatio = frame.length / PLAIN;
	console.log(`      新路径：明文 ${PLAIN} → 链路 ${frame.length} 字节，膨胀 ${((newRatio - 1) * 100).toFixed(3)}%`);
	console.log(`      流量降到原来的 ${(newRatio / oldRatio * 100).toFixed(1)}%（省 ${((1 - newRatio / oldRatio) * 100).toFixed(1)}%）`);

	assert(oldRatio > 1.7, `旧路径膨胀应约 1.78×，实测 ${oldRatio.toFixed(3)}`);
	assert(newRatio < 1.001, `新路径膨胀应 < 0.1%，实测 ${newRatio.toFixed(4)}`);
	assert(newRatio < oldRatio * 0.6, '新路径应显著低于旧路径');
});

console.log('\n【5】客户端 / 服务端 常量一致性');

await check('★ 两边的二进制帧常量必须一致（防漂移）', async () => {
	// Worker 与客户端是两个独立构建产物，没法共享模块，只能各写一份常量。
	// 这条断言把「改了一边忘另一边」从静默的协议错乱变成一条红灯。
	const w = await import('../worker/utils.js');
	eq(w.BIN_FRAME_CHANNEL, BIN_FRAME_CHANNEL, 'BIN_FRAME_CHANNEL 不一致');
	eq(w.CLIENT_ID_BYTES, CLIENT_ID_BYTES, 'CLIENT_ID_BYTES 不一致');
});

await check('★ 服务端的帧解析逻辑与客户端打包逻辑对得上', async () => {
	// 直接复刻 worker/index.js relayBinary 的取目标逻辑，验它确实能读出
	// 客户端 packBinaryFrame 写进去的 clientId —— 两边各自改格式时这条会红。
	const w = await import('../worker/utils.js');
	const peer = 'a1b2c3d4e5f60718';
	const frame = packBinaryFrame(peer, await encryptRaw(keyA, randomBytes(64)));
	eq(frame[0], w.BIN_FRAME_CHANNEL, '帧类型字节两边不一致');

	let targetId = '';
	for (let i = 1; i <= w.CLIENT_ID_BYTES; i++) {
		targetId += String.fromCharCode(frame[i]);
	}
	eq(targetId, peer, '服务端读出的目标 clientId 与写入的不符');
});

console.log('\n' + '='.repeat(60));
console.log(`通过 ${pass} / ${pass + fail}${fail ? `，失败 ${fail}` : '，全部通过'}`);
process.exit(fail ? 1 : 0);
