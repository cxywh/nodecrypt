// 大文件：客户端分块加密后直传 R2
// ============================================================================
//
// 和安全模型的关系
// ----------------------------------------------------------------------------
// R2 上放的全是密文，而且**解密密钥从不经过服务端**：
//
//   1. 发送方为每个文件生成一把随机 AES-256-GCM 密钥（fileKey）。
//   2. 文件按 4 MiB 分块，每块单独加密，密文 PUT 到 /blob/<blobId>/<块号>。
//   3. 只有一份「清单」（blobId + fileKey + 文件名 + 大小 + 块数）通过**既有的
//      端到端加密通道**（DO 中继，客户端↔客户端 ECDH 会话密钥）发给房间成员。
//
// 所以：Cloudflare 侧看到的是 64 位随机 hex 目录名 + 一串解不开的字节，既不知道
// 文件属于谁、也不知道文件名和类型，更解不开。这是「服务端零知识」的延续，而不是
// 新增一个信任点。
//
// 为什么不像原来那样直接走 WebSocket 中继
// ----------------------------------------------------------------------------
// 原实现把整个文件 base64 塞进中继消息：发送方上行一份，服务端要为**每个**接收方
// 再转发一份（4 人 = 4 倍），且接收方全在内存里攒着，刷新即废。实测每 256 KB 原始
// 数据在链路上膨胀到 455 KB（1.78×）。文件一大就同时压垮内存、时长计费和带宽。
//
// 走 R2 之后：发送方上行一次、接收方各自下行一次，与房间人数解耦；R2 出网免费。

import { toB64, fromB64, toHex, fromHex } from './aead.js';

/** 明文分块大小。4 MiB 在「请求数」和「单请求内存占用」之间取平衡。 */
export const CHUNK_SIZE = 4 * 1024 * 1024;

/** 同一时刻在飞的请求数。太小跑不满带宽，太大在移动端容易把内存顶爆。 */
const CONCURRENCY = 3;

/** 单块重试次数（网络抖动、R2 偶发 5xx 都靠它兜）。 */
const MAX_RETRY = 3;

/** 超过这个大小才走 R2。更小的走中继更划算：少两个来回，且不留任何存储。 */
export const R2_THRESHOLD = 1024 * 1024;

const IV_BYTES = 12;
const TAG_BYTES = 16;

const te = new TextEncoder();

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

export function newBlobId() {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return toHex(bytes);
}

/** 每个文件一把新密钥。extractable=true 才有后面导出 raw 字节通过 E2EE 通道发送。 */
export async function newFileKey() {
	return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportFileKey(key) {
	return toB64(await crypto.subtle.exportKey('raw', key));
}

export async function importFileKey(b64) {
	return crypto.subtle.importKey('raw', fromB64(b64), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * 把「哪一次传输 + 第几块 + 共几块」绑进 AEAD 的认证范围。
 *
 * 为什么需要：没有 AAD 的话，每一块都是独立可解的密文，攻击者（或 R2 本身）可以把
 * A 文件的第 3 块换到 B 文件的第 3 块上，或者把同一文件里的块乱序 —— 解密都会成功，
 * 但拼出来的文件是错的。绑上 AAD 之后，只要 blobId / 序号 / 总数对不上，GCM 校验
 * 就失败，改一块都做不到。
 */
function chunkAad(blobId, index, total) {
	return te.encode(`${blobId}|${index}|${total}`);
}

function concat(...parts) {
	const total = parts.reduce((sum, p) => sum + p.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const p of parts) {
		out.set(p, offset);
		offset += p.length;
	}
	return out;
}

/** 带退避的重试。只在网络层失败时用，解密失败不重试（重试也不会变好）。 */
async function withRetry(fn, attempts = MAX_RETRY) {
	let lastError;
	for (let i = 0; i < attempts; i++) {
		try {
			return await fn();
		} catch (error) {
			lastError = error;
			if (i < attempts - 1) {
				await new Promise(r => setTimeout(r, 300 * Math.pow(2, i)));
			}
		}
	}
	throw lastError;
}

// ---------------------------------------------------------------------------
// 分块加解密
// ---------------------------------------------------------------------------

/**
 * 加密一块。输出布局： iv(12) ‖ 密文 ‖ GCM tag(16)
 * 把 iv 放在密文前面，这样 R2 上单块对象自带解密所需的一切，不需要额外元数据。
 */
export async function encryptChunk(key, blobId, index, total, plaintext) {
	const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv, additionalData: chunkAad(blobId, index, total), tagLength: 128 },
		key,
		plaintext
	);
	return concat(iv, new Uint8Array(ciphertext));
}

/**
 * 解密一块。顺序错、blobId 错、块数错、被篡改 —— 都会在这里抛错，
 * 而不是安静地返回垃圾数据。这是 AEAD 相比原来「零填充 + 裸加密」的关键差别。
 */
export async function decryptChunk(key, blobId, index, total, packed) {
	// 空明文加密后是 iv(12) + tag(16) = 28 字节，所以下界要用 <，不能用 <=
	if (packed.length < IV_BYTES + TAG_BYTES) {
		throw new Error(`分块 ${index} 长度异常（${packed.length} 字节）`);
	}
	const iv = packed.subarray(0, IV_BYTES);
	const ciphertext = packed.subarray(IV_BYTES);
	const plaintext = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv, additionalData: chunkAad(blobId, index, total), tagLength: 128 },
		key,
		ciphertext
	);
	return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// 上传
// ---------------------------------------------------------------------------

/**
 * 把文件分块加密后上传到 R2。
 *
 * 内存特征：全程只持有 CONCURRENCY 块明文 + 密文（默认 4 MiB × 3 左右的峰值），
 * 文件本身多大都不影响 —— 这正是原来那套「整文件读进内存再分卷」做不到的。
 *
 * @returns {Promise<object>} 清单（要发给接收方的那份）
 */
export async function uploadToR2(file, { onProgress, signal, chunkSize = CHUNK_SIZE } = {}) {
	const blobId = newBlobId();
	const key = await newFileKey();
	const total = Math.max(1, Math.ceil(file.size / chunkSize));

	let uploaded = 0;
	let doneChunks = 0;
	const uploadedBytes = new Array(total).fill(0);

	const report = () => {
		if (onProgress) onProgress({ uploaded, total: file.size, doneChunks, totalChunks: total });
	};

	const indices = Array.from({ length: total }, (_, i) => i);
	let cursor = 0;

	async function worker() {
		while (cursor < indices.length) {
			const index = indices[cursor++];
			const start = index * chunkSize;
			const end = Math.min(start + chunkSize, file.size);

			// 只切这一块读进来，不碰文件其余部分
			const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
			const packed = await encryptChunk(key, blobId, index, total, plaintext);

			await withRetry(async () => {
				if (signal && signal.aborted) throw new Error('已取消');
				const response = await fetch(`/blob/${blobId}/${index}`, {
					method: 'PUT',
					headers: { 'content-type': 'application/octet-stream' },
					body: packed,
					signal,
				});
				if (!response.ok) {
					throw new Error(`上传第 ${index} 块失败：HTTP ${response.status}`);
				}
			});

			// 进度按**明文**字节记：分母 file.size 也是明文，两者同量纲才能算出
			// 正确的百分比。若记密文字节，每块会多出 iv+tag 共 28 字节，
			// 进度永远冲不到 100%。
			uploadedBytes[index] = end - start;
			uploaded = uploadedBytes.reduce((a, b) => a + b, 0);
			doneChunks++;
			report();
		}
	}

	await Promise.all(Array.from({ length: Math.min(CONCURRENCY, total) }, worker));

	return {
		blobId,
		key: await exportFileKey(key),
		// 线上协议字段统一叫 fileName（不是 name）—— 曾经这里叫 name 而
		// file_offer 里叫 fileName，中间靠一层手工映射，很容易漏。统一掉。
		fileName: file.name,
		mime: file.type || 'application/octet-stream',
		size: file.size,
		total,
		chunkSize,
	};
}

// ---------------------------------------------------------------------------
// 下载（含断点续传）
// ---------------------------------------------------------------------------

// 已完成的分块密文落到 IndexedDB。
//
// 为什么存密文而不是明文：密文本来就在 R2 上，存在本地不增加任何暴露面；而明文
// 落盘会让人意外。刷新后接着下，下完才解密拼装。
const DB_NAME = 'nodecrypt-blobs';
const STORE = 'chunks';
const MANIFEST_STORE = 'manifests';

function openDb() {
	return new Promise((resolve, reject) => {
		if (typeof indexedDB === 'undefined') {
			reject(new Error('IndexedDB 不可用'));
			return;
		}
		const request = indexedDB.open(DB_NAME, 2);
		request.onupgradeneeded = () => {
			const db = request.result;
			if (!db.objectStoreNames.contains(STORE)) {
				db.createObjectStore(STORE);
			}
			if (!db.objectStoreNames.contains(MANIFEST_STORE)) {
				db.createObjectStore(MANIFEST_STORE);
			}
		};
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}

/**
 * 把清单（含解密密钥）落地。
 *
 * 为什么必须存：密钥只存在于清单里，不存的话接收方一刷新页面就永远下不了这个文件
 * —— 密文还躺在 R2 上，但没人能解开了。存的是用户自己设备上的自己的解密材料，
 * 和「把文件存到下载目录」是一个性质的信任边界；不存则功能不可用。
 */
export async function saveManifest(manifest) {
	try {
		const db = await openDb();
		await idbPut(db, manifest.fileId, manifest, MANIFEST_STORE);
	} catch {
		// 存不了不影响本次会话内的下载
	}
}

export async function loadManifest(fileId) {
	try {
		const db = await openDb();
		return await idbGet(db, fileId, MANIFEST_STORE);
	} catch {
		return null;
	}
}

async function idbPut(db, key, value, storeName = STORE) {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(storeName, 'readwrite');
		tx.objectStore(storeName).put(value, key);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}

async function idbGet(db, key, storeName = STORE) {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(storeName, 'readonly');
		const request = tx.objectStore(storeName).get(key);
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}

async function idbDeletePrefix(db, prefix) {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE, 'readwrite');
		const store = tx.objectStore(STORE);
		const request = store.openKeyCursor();
		request.onsuccess = () => {
			const cursor = request.result;
			if (!cursor) return;
			if (String(cursor.key).startsWith(prefix)) store.delete(cursor.key);
			cursor.continue();
		};
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}

/** 丢弃某个文件已缓存的分块（用户取消、或解密失败需要重来时用）。 */
export async function discardDownload(blobId) {
	try {
		const db = await openDb();
		await idbDeletePrefix(db, `${blobId}/`);
	} catch {
		// 清缓存失败不该影响主流程
	}
}

/**
 * 从 R2 下载并解密。
 *
 * 续传：每一块下完立刻写进 IndexedDB。中途关掉页面再打开，已完成的分块不会重下。
 * 块级续传已经覆盖了绝大多数场景；块内续传（Range）属于更细一层，这里不做 ——
 * 一块只有 4 MiB，重下代价可接受。
 */
export async function downloadFromR2(manifest, { onProgress, signal } = {}) {
	const { blobId, key: keyB64, total } = manifest;
	const key = await importFileKey(keyB64);

	let db = null;
	try {
		db = await openDb();
	} catch {
		db = null; // 无 IndexedDB（隐私模式等）时退化为纯内存
	}

	const chunks = new Array(total);
	let completed = 0;

	// 先把上次已经下好的块捞回来
	if (db) {
		for (let i = 0; i < total; i++) {
			const cached = await idbGet(db, `${blobId}/${i}`);
			if (cached) {
				chunks[i] = cached;
				completed++;
			}
		}
		if (completed) report();
	}

	function report() {
		if (onProgress) onProgress({ completed, total, bytes: chunks.reduce((s, c) => s + (c ? c.length : 0), 0) });
	}

	const pending = [];
	for (let i = 0; i < total; i++) {
		if (!chunks[i]) pending.push(i);
	}

	let cursor = 0;

	async function worker() {
		while (cursor < pending.length) {
			const index = pending[cursor++];

			const packed = await withRetry(async () => {
				if (signal && signal.aborted) throw new Error('已取消');
				const response = await fetch(`/blob/${blobId}/${index}`, { signal });
				if (!response.ok) {
					throw new Error(`下载第 ${index} 块失败：HTTP ${response.status}`);
				}
				return new Uint8Array(await response.arrayBuffer());
			});

			chunks[index] = packed;
			if (db) {
				try {
					await idbPut(db, `${blobId}/${index}`, packed);
				} catch {
					// 缓存写失败不影响本次下载
				}
			}
			completed++;
			report();
		}
	}

	await Promise.all(Array.from({ length: Math.min(CONCURRENCY, Math.max(pending.length, 1)) }, worker));

	// 拼装 + 逐块解密。
	// 按序号顺序解密，AAD 里的 index/total 保证顺序错了立刻报错。
	const parts = [];
	for (let i = 0; i < total; i++) {
		const packed = chunks[i];
		if (!packed) throw new Error(`第 ${i} 块缺失`);
		const plaintext = await decryptChunk(key, blobId, i, total, packed);
		parts.push(plaintext);
	}

	const blob = new Blob(parts, { type: manifest.mime || 'application/octet-stream' });

	// 交付成功才清缓存，失败则保留以便续传
	if (db) {
		await discardDownload(blobId);
	}

	return blob;
}

// ---------------------------------------------------------------------------
// 保存到本地
// ---------------------------------------------------------------------------

export function saveBlob(blob, fileName) {
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = fileName;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	// 立刻 revoke 会让部分浏览器来不及取数据，延后释放
	setTimeout(() => URL.revokeObjectURL(url), 30000);
}
