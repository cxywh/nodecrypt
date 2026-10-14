// R2 文件传输端到端测试
//
// 跑法（先起本地 dev：npx wrangler dev --port 8787）：
//   node tests/blob-e2e.test.mjs
//   BASE_URL=http://127.0.0.1:8787 node tests/blob-e2e.test.mjs
//
// 测的是**真代码**：真的分块加密、真的 PUT 到 R2、真的 GET 回来解密。不是 mock。

import {
	uploadToR2,
	downloadFromR2,
	encryptChunk,
	decryptChunk,
	newBlobId,
	newFileKey,
	importFileKey,
	exportFileKey,
	saveBlob,
} from '../client/js/util.blob.js';

const BASE = process.env.BASE_URL || 'http://127.0.0.1:8787';

// 模块里用的是相对路径 /blob/...，Node 的 fetch 解析不了，这里补上 base。
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts) =>
	realFetch(typeof url === 'string' && url.startsWith('/') ? BASE + url : url, opts);

// ---------------------------------------------------------------------------
let pass = 0, fail = 0;
const failures = [];

async function check(name, fn) {
	try {
		await fn();
		pass++;
		console.log(`  ✓ ${name}`);
	} catch (error) {
		fail++;
		failures.push({ name, error });
		console.log(`  ✗ ${name}\n      ${error.message}`);
	}
}

function assert(cond, message) {
	if (!cond) throw new Error(message || '断言失败');
}

function assertEq(actual, expected, message) {
	if (actual !== expected) {
		throw new Error(`${message || '不相等'}（实际 ${actual}，期望 ${expected}）`);
	}
}

function randomBytes(n) {
	const b = new Uint8Array(n);
	for (let i = 0; i < n; i += 65536) {
		crypto.getRandomValues(b.subarray(i, Math.min(i + 65536, n)));
	}
	return b;
}

function makeFile(bytes, name = 'sample.bin', type = 'application/octet-stream') {
	return new File([bytes], name, { type });
}

async function blobToBytes(blob) {
	return new Uint8Array(await blob.arrayBuffer());
}

function sameBytes(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

/** 直接问服务器对象是否存在 / 多大 */
async function statChunk(blobId, index) {
	const response = await fetch(`/blob/${blobId}/${index}`, { method: 'HEAD' });
	if (!response.ok) return null;
	return Number(response.headers.get('content-length'));
}

// ---------------------------------------------------------------------------
console.log(`\n目标：${BASE}\n`);

// 0. 服务可达
console.log('【0】前置检查');
await check('本地 dev 可达且根路径正常', async () => {
	const response = await realFetch(BASE + '/');
	assertEq(response.status, 200, '根路径状态码');
});

// 1. 分块加解密本身
console.log('\n【1】分块加解密');
await check('单块往返', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const plain = randomBytes(4096);
	const packed = await encryptChunk(key, blobId, 0, 1, plain);
	assertEq(await (async () => (await decryptChunk(key, blobId, 0, 1, packed)).length)(), 4096, '解密后长度');
	assert(sameBytes(await decryptChunk(key, blobId, 0, 1, packed), plain), '内容不一致');
});

await check('密文与明文无重合（确认真的加密了）', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const plain = new Uint8Array(1024).fill(0x41); // 全是 'A'
	const packed = await encryptChunk(key, blobId, 0, 1, plain);
	const body = packed.subarray(12); // 去掉 iv
	assert(!sameBytes(body.subarray(0, 1024), plain), '密文里能直接读出明文');
});

await check('空明文（0 字节文件）可往返', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(key, blobId, 0, 1, new Uint8Array(0));
	assertEq(packed.length, 28, '空块长度应为 iv+tag');
	assertEq((await decryptChunk(key, blobId, 0, 1, packed)).length, 0, '解密后长度');
});

console.log('\n【2】AAD 绑定（防重排 / 防替换）');
await check('块序号错 → 解密失败', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(key, blobId, 3, 5, randomBytes(256));
	let threw = false;
	try { await decryptChunk(key, blobId, 4, 5, packed); } catch { threw = true; }
	assert(threw, '换了序号竟然还能解密');
});

await check('blobId 错 → 解密失败', async () => {
	const key = await newFileKey();
	const a = newBlobId(), b = newBlobId();
	const packed = await encryptChunk(key, a, 0, 2, randomBytes(256));
	let threw = false;
	try { await decryptChunk(key, b, 0, 2, packed); } catch { threw = true; }
	assert(threw, '换了 blobId 竟然还能解密');
});

await check('总数错 → 解密失败', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(key, blobId, 0, 2, randomBytes(256));
	let threw = false;
	try { await decryptChunk(key, blobId, 0, 3, packed); } catch { threw = true; }
	assert(threw, '换了总数竟然还能解密');
});

await check('密钥错 → 解密失败', async () => {
	const a = await newFileKey(), b = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(a, blobId, 0, 1, randomBytes(256));
	let threw = false;
	try { await decryptChunk(b, blobId, 0, 1, packed); } catch { threw = true; }
	assert(threw, '换了密钥竟然还能解密');
});

await check('篡改 1 个字节 → 解密失败', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(key, blobId, 0, 1, randomBytes(256));
	packed[packed.length - 1] ^= 0x01;
	let threw = false;
	try { await decryptChunk(key, blobId, 0, 1, packed); } catch { threw = true; }
	assert(threw, '篡改后竟然还能解密');
});

await check('密文被截断 → 解密失败', async () => {
	const key = await newFileKey();
	const blobId = newBlobId();
	const packed = await encryptChunk(key, blobId, 0, 1, randomBytes(256));
	let threw = false;
	try { await decryptChunk(key, blobId, 0, 1, packed.subarray(0, packed.length - 8)); } catch { threw = true; }
	assert(threw, '截断后竟然还能解密');
});

// 3. 真上传/真下载（走 R2）
console.log('\n【3】端到端上传 + 下载（真 R2）');

await check('空文件', async () => {
	const data = new Uint8Array(0);
	const manifest = await uploadToR2(makeFile(data, 'empty.bin'));
	assertEq(manifest.total, 1, '块数');
	assertEq(manifest.size, 0, '大小');
	const got = await blobToBytes(await downloadFromR2(manifest));
	assertEq(got.length, 0, '下载后长度');
});

await check('小文件（1 字节）', async () => {
	const data = new Uint8Array([0x5a]);
	const manifest = await uploadToR2(makeFile(data, 'one.bin'));
	assertEq(manifest.total, 1, '块数');
	const got = await blobToBytes(await downloadFromR2(manifest));
	assert(sameBytes(got, data), '内容不一致');
});

await check('未跨块（100 KB）', async () => {
	const data = randomBytes(100 * 1024);
	const manifest = await uploadToR2(makeFile(data));
	assertEq(manifest.total, 1, '块数');
	assertEq(await statChunk(manifest.blobId, 0), data.length + 28, 'R2 上对象大小应为明文+iv+tag');
	const got = await blobToBytes(await downloadFromR2(manifest));
	assert(sameBytes(got, data), '内容不一致');
});

await check('跨多块（9 MiB，3 块，最后一块不满）', async () => {
	const data = randomBytes(9 * 1024 * 1024);
	const manifest = await uploadToR2(makeFile(data, 'big.bin'));
	assertEq(manifest.total, 3, '块数');
	const got = await blobToBytes(await downloadFromR2(manifest));
	assertEq(got.length, data.length, '下载后长度');
	assert(sameBytes(got, data), '内容不一致');
});

await check('恰好整数块（8 MiB，正好 2 块）', async () => {
	const data = randomBytes(8 * 1024 * 1024);
	const manifest = await uploadToR2(makeFile(data, 'exact.bin'));
	assertEq(manifest.total, 2, '块数不该多出一块空的');
	const got = await blobToBytes(await downloadFromR2(manifest));
	assert(sameBytes(got, data), '内容不一致');
});

await check('文件名 / MIME 保留在清单里', async () => {
	const manifest = await uploadToR2(makeFile(randomBytes(64), '照片 中文.png', 'image/png'));
	assertEq(manifest.fileName, '照片 中文.png', '文件名');
	assertEq(manifest.mime, 'image/png', 'MIME');
});

await check('R2 上看不到明文（抽查 512 字节已知内容）', async () => {
	const marker = new Uint8Array(512).fill(0xAB);
	const manifest = await uploadToR2(makeFile(marker, 'marker.bin'));
	const response = await fetch(`/blob/${manifest.blobId}/0`);
	const cipher = new Uint8Array(await response.arrayBuffer());
	assert(!sameBytes(cipher.subarray(0, 512), marker), 'R2 上能直接读到明文标记');
	assert(sameBytes(await blobToBytes(await downloadFromR2(manifest)), marker), '往返内容不一致');
});

// 4. 进度与清单
console.log('\n【4】进度回调与清单');
await check('上传进度单调递增且收尾等于总块数', async () => {
	const data = randomBytes(5 * 1024 * 1024); // 2 块
	const seen = [];
	const manifest = await uploadToR2(makeFile(data), { onProgress: p => seen.push(p) });
	assert(seen.length >= 2, `进度回调次数太少（${seen.length}）`);
	for (let i = 1; i < seen.length; i++) {
		assert(seen[i].doneChunks >= seen[i - 1].doneChunks, '进度回退了');
	}
	assertEq(seen[seen.length - 1].doneChunks, manifest.total, '收尾块数');
	assertEq(seen[seen.length - 1].uploaded, seen[seen.length - 1].total, '收尾字节数');
});

await check('下载进度收尾等于总块数', async () => {
	const data = randomBytes(5 * 1024 * 1024);
	const manifest = await uploadToR2(makeFile(data));
	const seen = [];
	await downloadFromR2(manifest, { onProgress: p => seen.push(p) });
	assert(seen.length >= 1, '没有进度回调');
	assertEq(seen[seen.length - 1].completed, manifest.total, '收尾块数');
});

await check('清单不含明文内容，只有元数据 + 密钥', async () => {
	const manifest = await uploadToR2(makeFile(randomBytes(256), 'meta.bin'));
	const keys = Object.keys(manifest).sort();
	assertEq(keys.join(','), 'blobId,chunkSize,fileName,key,mime,size,total', '清单字段');
	let threw = false;
	try { await importFileKey('not-a-key'); } catch { threw = true; }
	assert(threw, '非法密钥应当被拒');
});

// 5. 续传
console.log('\n【5】下载续传（模拟中途中断）');
await check('取消后重下能拿到完整内容', async () => {
	const data = randomBytes(9 * 1024 * 1024);
	const manifest = await uploadToR2(makeFile(data));

	const controller = new AbortController();
	let chunksDone = 0;
	try {
		await downloadFromR2(manifest, {
			signal: controller.signal,
			onProgress: p => {
				chunksDone = p.completed;
				if (p.completed >= 1) controller.abort();
			},
		});
	} catch {
		// 预期会因取消而失败
	}
	assert(chunksDone >= 1, '取消前应该至少完成一块');

	// 重来一次，应当成功（IndexedDB 不可用时走内存，同样要能完整下完）
	const got = await blobToBytes(await downloadFromR2(manifest));
	assert(sameBytes(got, data), '中断重下后内容不一致');
});

// 6. 错误处理
console.log('\n【6】错误处理');
await check('清单指向不存在的 blob 时失败而不是静默返回空', async () => {
	const key = await newFileKey();
	const bogus = { blobId: newBlobId(), key: await exportFileKey(key), name: 'x.bin', mime: 'x', size: 100, total: 1, chunkSize: 4096 };
	let threw = false;
	try { await downloadFromR2(bogus); } catch { threw = true; }
	assert(threw, '不存在的数据竟然没报错');
});

// ---------------------------------------------------------------------------
console.log(`\n${'='.repeat(60)}`);
console.log(`通过 ${pass} / ${pass + fail}`);
if (fail) {
	console.log('\n失败项：');
	for (const f of failures) console.log(`  · ${f.name}\n    ${f.error.message}`);
	process.exit(1);
}
console.log('全部通过');
