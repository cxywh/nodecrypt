// NodeCrypt v2 加密核心
// NodeCrypt v2 cryptographic core
//
// 这是 P0 改造的全部密码学实现。设计原则：只用 WebCrypto 原生原语，
// 不引任何第三方加密库，所有对称加密一律 AEAD。
//
// 与原实现（改造前）的对照：
//   原：AES-256-CBC + 零填充 + 无 MAC        → 新：AES-GCM（自带认证）
//   原：裸 ChaCha20（无 Poly1305），计数器是 4 个随机字节相乘
//                                            → 新：AES-GCM，12 字节随机 IV
//   原：口令 = sha256(password)，与 ECDH 秘密「异或」
//                                            → 新：PBKDF2 60 万次 + HKDF 混合
//   原：Curve25519 走 elliptic（纯 JS，非恒定时间）
//                                            → 新：P-256 ECDH（WebCrypto 原生）
//
// 威胁模型说明（重要，别被 README 误导）：
//   本文件不解决「服务端中间人」问题。真正的信任锚是**房间口令**——
//   它作为 IKM 的一部分参与派生，所以即使中继完全冒充服务端，
//   因为不知道口令，也算不出任何会话密钥，读不到任何消息内容。
//   服务端公钥指纹只提供「变更通知」，不提供身份认证。

export const PROTOCOL_VERSION = 'NC2';
const PBKDF2_ITERATIONS = 600000;
const KDF_SALT_PREFIX = 'nodecrypt-v2|';
const AEAD_AAD = new TextEncoder().encode('nodecrypt-v2');
const NONCE_BYTES = 12;

const te = new TextEncoder();
const td = new TextDecoder();

// ---------------------------------------------------------------------------
// 编码工具（不依赖 Buffer / btoa 展开栈溢出）
// ---------------------------------------------------------------------------

export function toBytes(input) {
	if (input instanceof Uint8Array) {
		return input;
	}
	if (input instanceof ArrayBuffer) {
		return new Uint8Array(input);
	}
	return te.encode(String(input));
}

export function toB64(input) {
	const bytes = toBytes(input);
	let binary = '';
	const CHUNK = 0x8000; // 分块，避免 String.fromCharCode(...bytes) 在大数据上爆栈
	for (let i = 0; i < bytes.length; i += CHUNK) {
		binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
	}
	return btoa(binary);
}

export function fromB64(value) {
	const binary = atob(String(value));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

export function toHex(input) {
	const bytes = toBytes(input);
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i].toString(16).padStart(2, '0');
	}
	return out;
}

export function fromHex(value) {
	if (typeof value !== 'string') {
		throw new TypeError(`fromHex 需要字符串，收到 ${value === null ? 'null' : typeof value}`);
	}
	if (value.length % 2 !== 0 || /[^0-9a-fA-F]/.test(value)) {
		throw new Error(`fromHex: 非法十六进制字符串（长度 ${value.length}）`);
	}
	const bytes = new Uint8Array(value.length >> 1);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(value.substr(i * 2, 2), 16);
	}
	return bytes;
}

// ---------------------------------------------------------------------------
// 哈希与密钥派生
// ---------------------------------------------------------------------------

/** SHA-256 的十六进制摘要。仅用于生成房间标识，不作为安全边界。 */
export async function sha256Hex(value) {
	const digest = await crypto.subtle.digest('SHA-256', toBytes(value));
	return toHex(digest);
}

/**
 * HKDF-SHA256（extract-then-expand）。
 * 用它替代原来的「异或」，因为异或的语义是「两个密钥流相加」——
 * 口令那半熵本来就低，一旦 ECDH 秘密泄漏就彻底失效。
 * HKDF 让两个因子都成为 IKM 的必需组成部分，缺一不可。
 */
export async function hkdf(ikm, salt, info, bits = 256) {
	const baseKey = await crypto.subtle.importKey('raw', toBytes(ikm), 'HKDF', false, ['deriveBits']);
	return new Uint8Array(await crypto.subtle.deriveBits({
		name: 'HKDF',
		hash: 'SHA-256',
		salt: toBytes(salt),
		info: toBytes(info)
	}, baseKey, bits));
}

/**
 * 房间口令 -> 32 字节密钥材料。
 * 原实现是一次无盐 sha256(password)，GPU 每秒能试几十亿次；
 * PBKDF2 60 万次把单次尝试成本抬到 ~70ms 量级。
 *
 * 注意：口令只在内存里派生一次，之后按房间缓存复用（见 NodeCrypt.js），
 * 否则每加一个对端都要重跑 60 万次，房间里人一多就卡。
 */
export async function derivePasswordKey(password, roomName) {
	const baseKey = await crypto.subtle.importKey('raw', toBytes(password), 'PBKDF2', false, ['deriveBits']);
	return new Uint8Array(await crypto.subtle.deriveBits({
		name: 'PBKDF2',
		hash: 'SHA-256',
		salt: te.encode(KDF_SALT_PREFIX + 'pw|' + roomName),
		iterations: PBKDF2_ITERATIONS
	}, baseKey, 256));
}

async function importAesKey(rawBytes) {
	return crypto.subtle.importKey('raw', rawBytes, {
		name: 'AES-GCM',
		length: 256
	}, false, ['encrypt', 'decrypt']);
}

/**
 * 客户端 ↔ 服务端会话密钥。
 * ikm = ECDH 共享秘密（P-384 => 48 字节）
 */
export async function deriveServerSessionKey(ecdhSecret) {
	const raw = await hkdf(ecdhSecret, KDF_SALT_PREFIX + 'server', 'server-session', 256);
	return importAesKey(raw);
}

/**
 * 客户端 ↔ 客户端会话密钥。
 * ikm = ECDH 共享秘密（P-256 => 32 字节）‖ PBKDF2(口令)  <- 两个因子都必需
 * salt = 房间标识（同口令不同房间 => 不同密钥）
 */
export async function derivePeerSessionKey(ecdhSecret, passwordKey, channelId) {
	const ikm = new Uint8Array(ecdhSecret.length + passwordKey.length);
	ikm.set(ecdhSecret, 0);
	ikm.set(passwordKey, ecdhSecret.length);
	const raw = await hkdf(ikm, channelId, 'peer-session', 256);
	return importAesKey(raw);
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

export async function generateEcdhKeyPair(namedCurve = 'P-256') {
	return crypto.subtle.generateKey({
		name: 'ECDH',
		namedCurve
	}, false, ['deriveBits']);
}

export async function exportEcdhPublic(keyPair) {
	return toHex(await crypto.subtle.exportKey('raw', keyPair.publicKey));
}

export async function importEcdhPublic(hex, namedCurve = 'P-256') {
	return crypto.subtle.importKey('raw', fromHex(hex), {
		name: 'ECDH',
		namedCurve
	}, false, []);
}

export async function deriveEcdhSecret(privateKey, publicKeyHex, namedCurve = 'P-256') {
	const publicKey = await importEcdhPublic(publicKeyHex, namedCurve);
	const bits = namedCurve === 'P-384' ? 384 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits({
		name: 'ECDH',
		public: publicKey
	}, privateKey, bits));
}

// ---------------------------------------------------------------------------
// AEAD 载荷
// 格式： base64(iv) + '|' + base64(ciphertext ‖ tag)
// 与原格式的差别：原来是 base64(iv) + '|' + base64(密文)（且零填充、无 tag）
// ---------------------------------------------------------------------------

export async function encryptAead(key, message) {
	if (!key) {
		throw new Error('encryptAead: missing key');
	}
	const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
	const plaintext = te.encode(JSON.stringify(message));
	const ciphertext = await crypto.subtle.encrypt({
		name: 'AES-GCM',
		iv,
		additionalData: AEAD_AAD
	}, key, plaintext);
	return toB64(iv) + '|' + toB64(ciphertext);
}

/**
 * 解密失败会抛异常 —— 这是 AEAD 的价值所在。
 * 原实现（CBC 零填充 / 裸 ChaCha20）会安静地返回垃圾或抛解析错，
 * 调用方无法区分「被篡改」和「还没协商好」。
 */
export async function decryptAead(key, packed) {
	if (!key) {
		throw new Error('decryptAead: missing key');
	}
	const parts = String(packed).split('|');
	if (parts.length !== 2 || !parts[0] || !parts[1]) {
		throw new Error('decryptAead: malformed payload');
	}
	const plaintext = await crypto.subtle.decrypt({
		name: 'AES-GCM',
		iv: fromB64(parts[0]),
		additionalData: AEAD_AAD
	}, key, fromB64(parts[1]));
	return JSON.parse(td.decode(plaintext));
}

// ---------------------------------------------------------------------------
// 服务端公钥指纹（供人工核对 / 变更通知）
// ---------------------------------------------------------------------------

/** 把原始公钥字节的 SHA-256 打印成 16 组 4 字符，便于人眼比对。 */
export async function keyFingerprint(rawPublicKey) {
	const bytes = typeof rawPublicKey === 'string' ? fromB64(rawPublicKey) : toBytes(rawPublicKey);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	const hex = toHex(digest).toUpperCase();
	return (hex.match(/.{4}/g) || []).slice(0, 16).join(' ');
}

export const aeadConstants = {
	PROTOCOL_VERSION,
	PBKDF2_ITERATIONS,
	KDF_SALT_PREFIX,
	NONCE_BYTES
};
