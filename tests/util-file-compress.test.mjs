// 临时自检：直接调用真实的 util.file.js，验证压缩跳过与回环完整性。
// 通过构造 window/FileReader 垫片让浏览器模块在 Node 里跑起来。
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const SRC = 'client/js/util.file.js';
const TMP = 'client/js/.uf-selftest.mjs';

// 1) 复制真实模块并临时导出被测函数
const src = readFileSync(SRC, 'utf8');
writeFileSync(TMP, src + '\nexport { compressFileToVolumes, assembleFileBytes };\n');

// 2) 浏览器垫片
const noopEl = () => ({
	style: {}, classList: { add: () => {}, remove: () => {}, toggle: () => {} },
	addEventListener: () => {}, removeEventListener: () => {},
	appendChild: () => {}, setAttribute: () => {}, remove: () => {},
	querySelector: () => null, querySelectorAll: () => [],
});

globalThis.document = {
	addEventListener: () => {}, removeEventListener: () => {},
	querySelector: () => null, querySelectorAll: () => [],
	getElementById: () => null, createElement: noopEl,
	body: noopEl(), head: noopEl(), documentElement: noopEl(),
};

globalThis.window = {
	fileTransfers: new Map(),
	addSystemMsg: () => {},
	addEventListener: () => {},
	removeEventListener: () => {},
	document: globalThis.document,
};
globalThis.FileReader = class {
	readAsArrayBuffer(f) {
		this.result = f._bytes.buffer;
		queueMicrotask(() => this.onload({ target: this }));
	}
};

const fakeFile = (name, type, bytes) => ({ name, type, size: bytes.length, _bytes: bytes });

const results = [];
const check = (label, cond, detail) => {
	results.push({ label, ok: !!cond, detail });
	console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
};

try {
	// import() 的相对路径按本文件解析，必须转成绝对 file URL，
	// 否则从 tests/ 启动时会去找 tests/client/js/。
	const { compressFileToVolumes, assembleFileBytes } = await import(pathToFileURL(resolve(TMP)).href);

	// --- 用例 1：文本文件，应走 deflate ---
	const text = new TextEncoder().encode('nodecrypt self-test '.repeat(40000)); // 约 760 KB 高压缩比
	const r1 = await compressFileToVolumes(fakeFile('notes.txt', 'text/plain', text));
	check('文本文件选择 deflate', r1.compression === 'deflate', `compression=${r1.compression}`);
	check('文本文件被压缩变小', r1.compressedSize < text.length,
		`${text.length} → ${r1.compressedSize}`);
	check('分卷覆盖全部压缩字节',
		r1.volumes.reduce((s, v) => s + v.length, 0) === r1.compressedSize,
		`${r1.volumes.length} 卷`);
	const back1 = await assembleFileBytes(r1.volumes, r1.originalHash, r1.compression);
	check('文本文件回环字节一致', Buffer.compare(Buffer.from(back1), Buffer.from(text)) === 0);

	// --- 用例 2：视频文件，应跳过 deflate ---
	const rnd = new Uint8Array(3 * 1024 * 1024 + 12345);
	for (let i = 0; i < rnd.length; i += 65536) {
		crypto.getRandomValues(rnd.subarray(i, Math.min(i + 65536, rnd.length)));
	}
	const r2 = await compressFileToVolumes(fakeFile('clip.mp4', 'video/mp4', rnd));
	check('视频文件跳过 deflate', r2.compression === 'none', `compression=${r2.compression}`);
	check('视频文件体量不变', r2.compressedSize === rnd.length,
		`${rnd.length} → ${r2.compressedSize}`);
	const back2 = await assembleFileBytes(r2.volumes, r2.originalHash, r2.compression);
	check('视频文件回环字节一致', Buffer.compare(Buffer.from(back2), Buffer.from(rnd)) === 0);

	// --- 用例 3：分卷是视图而非复制（内存修复的核心） ---
	const viewSharesBuffer = r2.volumes[0].buffer === r2.volumes[1].buffer;
	check('分卷共享同一底层缓冲（零拷贝）', viewSharesBuffer);

	// --- 用例 4：哈希不符必须抛错 ---
	let threw = false;
	try {
		await assembleFileBytes(r2.volumes, 'deadbeef', 'none');
	} catch { threw = true; }
	check('哈希不符被拒绝', threw);

	// --- 用例 5：缺省按 deflate（旧对端不带该字段） ---
	const back3 = await assembleFileBytes(r1.volumes, r1.originalHash);
	check('缺省 compression 保持 deflate 行为',
		Buffer.compare(Buffer.from(back3), Buffer.from(text)) === 0);

	const failed = results.filter((r) => !r.ok).length;
	console.log(`\n  ===== ${results.length - failed} / ${results.length} 通过 =====`);
	process.exitCode = failed ? 1 : 0;
} finally {
	try { unlinkSync(TMP); } catch {}
}
