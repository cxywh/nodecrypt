// 前端接线测试：在 Node 里用最小 DOM 垫片真跑 util.file.js
//
// 为什么需要这个：blob-e2e 测的是 util.blob.js（纯逻辑），e2e-worker 测的是协议。
// 但「点附件 -> 分块加密 -> 发 file_offer」和「收到 file_offer -> 点下载」
// 这两段接线此前一行都没跑过 —— 而这恰恰是决定功能对用户能不能用的那一层。
//
// 做法：
//   · 装一套最小 DOM/window 垫片
//   · 用 Node 的 module.register 钩子把 ./util.fileUpload.js 换成桩
//     （否则会去建真模态框，`showFileUploadModal` 拿不到文件）
//   · 然后直接调真实的 setupFileSend / handleFileMessage / downloadFile
//
// 跑法（先起 wrangler dev 在 8787）：
//   node tests/frontend-r2.test.mjs

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

const BASE = process.env.BASE_URL || 'http://127.0.0.1:8787';

// ---------------------------------------------------------------------------
// 1) 把 util.fileUpload.js 换成桩，这样能直接喂文件给 handleFilesUpload
// ---------------------------------------------------------------------------
const STUB_URL = pathToFileURL('./tests/stub-fileupload.mjs').href;

register(
	'data:text/javascript,' + encodeURIComponent(`
		export async function resolve(specifier, context, next) {
			if (specifier.endsWith('util.fileUpload.js')) {
				return { url: ${JSON.stringify(STUB_URL)}, shortCircuit: true };
			}
			return next(specifier, context);
		}
	`)
);

// ---------------------------------------------------------------------------
// 2) DOM / window 垫片
// ---------------------------------------------------------------------------
const listeners = {};

function makeElement(tag = 'div') {
	const el = {
		tagName: tag,
		style: {},
		dataset: {},
		children: [],
		classList: {
			_added: new Set(),
			add(...c) { c.forEach(x => this._added.add(x)); },
			remove(...c) { c.forEach(x => this._added.delete(x)); },
			contains(c) { return this._added.has(c); },
		},
		_textContent: '',
		_html: '',
		get textContent() { return this._textContent; },
		set textContent(v) { this._textContent = String(v); },
		get innerHTML() { return this._html; },
		set innerHTML(v) { this._html = String(v); },
		appendChild(c) { this.children.push(c); return c; },
		removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
		addEventListener(type, fn) { (listeners[`${tag}:${type}`] ||= []).push(fn); },
		removeEventListener() {},
		querySelector() { return makeElement(); },
		querySelectorAll() { return []; },
		click() { (listeners[`${tag}:click`] || []).forEach(fn => fn({ preventDefault() {}, stopPropagation() {} })); },
		remove() {},
		setAttribute() {},
		getAttribute() { return null; },
	};
	return el;
}

globalThis.window = globalThis;
globalThis.self = globalThis;
// Node 26 的 globalThis.navigator 是只读 getter，直接赋值会抛 TypeError
Object.defineProperty(globalThis, 'navigator', {
	value: { userAgent: 'node', language: 'zh-CN', languages: ['zh-CN'] },
	configurable: true,
	writable: true,
});
globalThis.localStorage = {
	_store: {},
	getItem(k) { return this._store[k] ?? null; },
	setItem(k, v) { this._store[k] = String(v); },
	removeItem(k) { delete this._store[k]; },
};
globalThis.document = {
	body: makeElement('body'),
	documentElement: makeElement('html'),
	createElement: (t) => makeElement(t),
	getElementById: () => null,
	// 记忆化：setupFileSend 会 querySelector 附件按钮并绑 click，
	// 测试需要拿到同一个元素去 click，否则整段绑定会被跳过。
	querySelector: (sel) => (selectorCache[sel] ||= makeElement('div')),
	querySelectorAll: () => [],
	addEventListener() {},
	removeEventListener() {},
	execCommand() { return true; },
	queryCommandSupported() { return false; },
};
const selectorCache = {};
// FileReader 在 Node 里没有，而中继路径（小文件）的 compressFileToVolumes 依赖它。
// 垫一个最小实现，否则「小文件仍走中继」这条根本跑不到。
globalThis.FileReader = class FileReader {
	readAsArrayBuffer(file) {
		file.arrayBuffer()
			.then((buf) => {
				this.result = buf;
				if (this.onload) this.onload({ target: { result: buf } });
			})
			.catch((err) => { if (this.onerror) this.onerror(err); });
	}
	readAsText(file) { return this.readAsArrayBuffer(file); }
};

// 有些模块在模块级就注册监听，这里补上
globalThis.addEventListener = () => {};
globalThis.dispatchEvent = () => {};

// util.blob.js 用相对路径 /blob/...，Node 解析不了
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts) =>
	realFetch(typeof url === 'string' && url.startsWith('/') ? BASE + url : url, opts);

// URL.createObjectURL 在 Node 里没有 —— saveBlob 会用到
const savedBlobs = [];
globalThis.URL.createObjectURL = (blob) => {
	const id = 'blob:stub/' + savedBlobs.length;
	savedBlobs.push({ id, blob });
	return id;
};
globalThis.URL.revokeObjectURL = () => {};

// ---------------------------------------------------------------------------
// 3) 测试
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

function assertEq(a, b, message) {
	if (a !== b) throw new Error(`${message || '不相等'}（实际 ${a}，期望 ${b}）`);
}

function randomBytes(n) {
	const b = new Uint8Array(n);
	for (let i = 0; i < n; i += 65536) crypto.getRandomValues(b.subarray(i, Math.min(i + 65536, n)));
	return b;
}

function sameBytes(a, b) {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

const { uploadToR2 } = await import('../client/js/util.blob.js');
const fileMod = await import('../client/js/util.file.js');

console.log(`\n目标：${BASE}\n`);

// ---------------------------------------------------------------------------
console.log('【1】发送路径：大文件 -> R2 -> 发 file_offer');

// 卡片渲染相关的全局钩子必须在发送前就装好（uploadFilesViaR2 会调 window.addMsg）
const cardCalls = [];
globalThis.window.addMsg = (...args) => { cardCalls.push(['me', ...args]); };
globalThis.window.addOtherMsg = (...args) => { cardCalls.push(['other', ...args]); };
globalThis.window.addSystemMsg = (t) => { cardCalls.push(['sys', t]); };
globalThis.window.roomsData = [];
globalThis.window.activeRoomIndex = -1;

const sent = [];
const sentBinary = [];   // 走二进制通道的分卷记录（裸字节，不是 base64 字符串）
await fileMod.setupFileSend({
	inputSelector: '.input-message-input',
	attachBtnSelector: '.chat-attach-btn',
	fileInputSelector: 'input[type="file"]',
	onSend: async (msg) => { sent.push(msg); },
	onSendBinary: async (record) => { sentBinary.push(record); },
});

// 点一次附件按钮：setupFileSend 内部才会把回调交给 showFileUploadModal（我们的桩）
const attachBtn = selectorCache['.chat-attach-btn'];
assert(attachBtn, '垫片没给出附件按钮元素');
attachBtn.click();

const { __feedFiles, __hasCallback } = await import('./stub-fileupload.mjs');
assert(__hasCallback(), '点击附件按钮后，桩没有拿到回调 —— setupFileSend 的绑定没生效');

const bigBytes = randomBytes(5 * 1024 * 1024);   // 2 块
const bigFile = new File([bigBytes], '前端 测试.bin', { type: 'application/octet-stream' });

await check('大文件走 R2 并发出 file_offer（不是 file_start）', async () => {
	await __feedFiles([bigFile]);
	const offer = sent.find(m => m.type === 'file_offer');
	assert(offer, `没有发出 file_offer，收到的是: ${sent.map(m => m.type).join(',') || '(空)'}`);
	assertEq(offer.fileName, '前端 测试.bin', 'fileName 字段');
	assert(offer.blobId && /^[0-9a-f]{64}$/.test(offer.blobId), 'blobId 格式不对');
	assert(offer.key, '清单里必须带密钥');
	assertEq(offer.total, 2, '块数');
	assertEq(offer.originalSize, bigBytes.length, '原始大小');
	assertEq(offer.mime, 'application/octet-stream', 'MIME');
	assert(!sent.some(m => m.type === 'file_start'), '大文件不该走中继路径');
});

await check('发送方自己的卡片进了聊天区（本地渲染，不经中继）', () => {
	assert(globalThis.window.fileTransfers.size >= 1, 'fileTransfers 里没有记录');
	const transfer = [...globalThis.window.fileTransfers.values()].find(t => t.isR2);
	assert(transfer, '没有 R2 传输记录');
	assertEq(transfer.status, 'completed', '上传完成后状态');
	assertEq(transfer.isSender, true, '应标记为发送方');
});

await check('小文件仍走中继（保持原行为）', async () => {
	sent.length = 0;
	sentBinary.length = 0;
	const small = new File([randomBytes(1024)], 'small.bin');
	await __feedFiles([small]);
	assert(sent.some(m => m.type === 'file_start'), '小文件应当走 file_start 中继路径');
	assert(!sent.some(m => m.type === 'file_offer'), '小文件不该走 R2');
});

await check('★ 分卷改走二进制通道：裸字节，不再是 base64 + JSON', async () => {
	const aead = await import('../client/js/aead.js');
	sent.length = 0;
	sentBinary.length = 0;
	const small = new File([randomBytes(64 * 1024)], 'vol.bin');
	await __feedFiles([small]);

	// 关键回归断言：改成二进制通道后，JSON 通道里不该再出现 file_volume。
	// 之前这里没断言，导致 onSendBinary 没接线时测试照样「全绿」——
	// 而实际分卷已经抛 TypeError 了。
	assert(!sent.some(m => m.type === 'file_volume'),
		'分卷不该再走 JSON 通道（那会叠三层 base64，链路膨胀 137%）');
	assert(sentBinary.length > 0, '分卷应当走二进制通道');
	assert(sentBinary[0] instanceof Uint8Array,
		`分卷记录应当是裸字节，实际是 ${Object.prototype.toString.call(sentBinary[0])}`);

	const rec = aead.unpackVolumeRecord(sentBinary[0]);
	assert(rec.fileId, 'fileId 应随记录一起传（元数据与载荷同一次 AEAD）');
	assertEq(rec.volumeIndex, 0, '首卷卷号');
	assertEq(rec.totalVolumes, sentBinary.length, '总卷数应与实发卷数一致');
	assert(rec.payload.length > 0, '负载不应为空');
});

await check('★ 接收侧：handleBinaryVolume 落到正确的传输状态', async () => {
	// 造一个接收中的传输条目，totalVolumes 故意留空 ——
	// 验「分卷自带的数字会把进度条分母补上」（否则界面显示 NaN）
	const fileId = 'rx-binary-1';
	globalThis.window.fileTransfers.set(fileId, {
		fileId, fileName: 'in.bin', originalSize: 100, compressedSize: 100,
		totalVolumes: 0, sentVolumes: 0, status: 'receiving',
		receivedVolumes: new Set(), volumeData: []
	});

	fileMod.handleBinaryVolume({
		fileId, volumeIndex: 0, totalVolumes: 2,
		payload: new Uint8Array([1, 2, 3])
	});
	fileMod.handleBinaryVolume({
		fileId, volumeIndex: 1, totalVolumes: 2,
		payload: new Uint8Array([4, 5])
	});

	const t = globalThis.window.fileTransfers.get(fileId);
	assertEq(t.receivedVolumes.size, 2, '两卷都应记录');
	assertEq(t.totalVolumes, 2, '总卷数应由分卷补上（file_start 未到的情况）');
	assertEq(t.volumeData[0].length, 3, '第 0 卷负载应原样存下');
	assertEq(t.volumeData[1][0], 4, '第 1 卷负载应原样存下');

	// 未知 fileId 的卷应当安静丢弃，而不是建垃圾状态或抛错
	const sizeBefore = globalThis.window.fileTransfers.size;
	fileMod.handleBinaryVolume({ fileId: 'nope', volumeIndex: 0, totalVolumes: 1, payload: new Uint8Array(1) });
	assertEq(globalThis.window.fileTransfers.size, sizeBefore, '未知 fileId 不该新建状态');
});

await check('R2 可用性探测返回布尔值且被缓存（只发一次请求）', async () => {
	const { isR2Available, __resetR2Probe } = await import('../client/js/util.blob.js');
	__resetR2Probe();   // 前面第 1 节已经探过一次，这里要先清掉缓存才数得准
	let probeCalls = 0;
	const origFetch = globalThis.fetch;
	globalThis.fetch = (url, opts) => {
		if (opts && opts.method === 'HEAD' && String(url).includes('/blob/')) probeCalls++;
		return origFetch(url, opts);
	};
	const [a, b, c] = await Promise.all([isR2Available(), isR2Available(), isR2Available()]);
	globalThis.fetch = origFetch;
	assertEq(typeof a, 'boolean', '应当返回布尔值');
	assertEq(a, b, '并发调用结果应当一致');
	assertEq(b, c, '并发调用结果应当一致');
	assertEq(probeCalls, 1, `探测请求应当只发一次（实际 ${probeCalls}）`);
});

// ---------------------------------------------------------------------------
console.log('\n【1.5】R2 不可用时的降级（没有境外卡的实际情况）');

await check('R2 不可用时大文件自动退回中继，不撞 503', async () => {
	const { isR2Available: probe, __resetR2Probe } = await import('../client/js/util.blob.js');
	const origFetch = globalThis.fetch;

	// 模拟 Worker 上没有 FILES 绑定时的响应
	globalThis.fetch = (url, opts) => {
		if (opts && opts.method === 'HEAD' && String(url).includes('/blob/')) {
			return Promise.resolve(new Response(null, { status: 503 }));
		}
		return origFetch(url, opts);
	};

	__resetR2Probe();
	assertEq(await probe(), false, '应当判定 R2 不可用');

	sent.length = 0;
	await __feedFiles([new File([randomBytes(3 * 1024 * 1024)], 'big-relay.bin')]);
	globalThis.fetch = origFetch;

	assert(sent.some(m => m.type === 'file_start'), 'R2 不可用时大文件应该走中继');
	assert(!sent.some(m => m.type === 'file_offer'), 'R2 不可用时不该发 file_offer');
});

await check('R2 恢复可用后自动切回 R2（无需改代码）', async () => {
	const { __resetR2Probe } = await import('../client/js/util.blob.js');
	__resetR2Probe();
	sent.length = 0;
	await __feedFiles([new File([randomBytes(3 * 1024 * 1024)], 'big-r2.bin')]);
	assert(sent.some(m => m.type === 'file_offer'), 'R2 可用时大文件应该走 R2');
	assert(!sent.some(m => m.type === 'file_start'), 'R2 可用时不该退化成中继');
});

// ---------------------------------------------------------------------------
console.log('\n【2】接收路径：file_offer -> 卡片 -> 下载解密');

// 重新上传一次，拿一份干净的清单（上一节把 sent 清空了）
const manifest = await uploadToR2(new File([bigBytes], '收件 测试.bin'));

await check('收到 file_offer 后注册传输并渲染卡片', () => {
	fileMod.handleFileMessage({
		type: 'file_offer',
		fileId: 'rx-1',
		blobId: manifest.blobId,
		key: manifest.key,
		fileName: manifest.fileName,
		originalSize: manifest.size,
		total: manifest.total,
		chunkSize: manifest.chunkSize,
		mime: manifest.mime,
		userName: 'Alice',
	}, false);

	const transfer = globalThis.window.fileTransfers.get('rx-1');
	assert(transfer, '没有注册传输状态');
	assertEq(transfer.status, 'ready', '收到清单后应当是可下载状态');
	assertEq(transfer.fileName, '收件 测试.bin', '文件名');
	assert(transfer.isR2, '应标记为 R2 传输');
	assert(cardCalls.length > 0, '没有渲染任何卡片');
});

await check('点下载：下载 -> 解密 -> 保存，内容一致', async () => {
	const before = savedBlobs.length;
	await fileMod.downloadFile('rx-1');
	assert(savedBlobs.length > before, '没有调用保存');

	const saved = savedBlobs[savedBlobs.length - 1].blob;
	const bytes = new Uint8Array(await saved.arrayBuffer());
	assert(sameBytes(bytes, bigBytes), `下载内容与原文不一致（${bytes.length} vs ${bigBytes.length}）`);

	const transfer = globalThis.window.fileTransfers.get('rx-1');
	assertEq(transfer.status, 'completed', '下载后状态');
});

await check('清单字段缺失时安静忽略（不抛错、不建垃圾状态）', () => {
	const sizeBefore = globalThis.window.fileTransfers.size;
	fileMod.handleFileMessage({ type: 'file_offer', fileId: 'bad-1' }, false);
	assertEq(globalThis.window.fileTransfers.size, sizeBefore, '不该为残缺清单建状态');
});

// ---------------------------------------------------------------------------
console.log('\n【3】错误路径');
await check('下载不存在的 blob 时给出错误提示且状态可重试', async () => {
	fileMod.handleFileMessage({
		type: 'file_offer',
		fileId: 'rx-404',
		blobId: 'f'.repeat(64),          // 合法格式但不存在
		key: manifest.key,
		fileName: 'ghost.bin',
		originalSize: 100,
		total: 1,
		chunkSize: 4096,
		mime: 'x',
		userName: 'Bob',
	}, false);

	const sysBefore = cardCalls.filter(c => c[0] === 'sys').length;
	await fileMod.downloadFile('rx-404');

	const transfer = globalThis.window.fileTransfers.get('rx-404');
	assertEq(transfer.status, 'ready', '失败后应当退回可重试状态');
	const sysAfter = cardCalls.filter(c => c[0] === 'sys').length;
	assert(sysAfter > sysBefore, '没有给出失败提示');
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
