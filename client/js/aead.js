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
// 二进制通道（大批量数据，如文件分卷）
// ---------------------------------------------------------------------------
//
// 动机：文件分卷原先走 JSON 文本帧，链路是
//
//   原始字节 → base64 ① → JSON → AES-GCM → base64 ② → 文本帧
//
// 两次 base64 各 1.33×，叠起来链路上 1.78×（实测）。但载荷反正要整体加密，
// base64 ① 纯属浪费 —— 密文本来就是二进制的，没必要先转成文本再塞进 JSON。
//
// 于是给批量数据单开一条二进制通道：
//
//   [0]       0x02            帧类型
//   [1..16]   目标/来源 clientId（固定 16 字节 ASCII，generateClientId 恒为 16 位 hex）
//   [17..28]  IV
//   [29..]    密文 + 认证标签
//
// 发送方按每个对端各自的会话密钥加密一次，服务端**只按目标 ID 原样转发**，
// 不再套服务端信封 —— 那层本来也只是把同一份密文再加密一次，去掉不损失机密性
// （载荷自始至终是对端密钥的 AEAD 密文），但省掉服务端每卷一次 AES 运算。
// 链路上只剩 12 字节 IV + 16 字节标签，膨胀从 78% 降到 0.01%。

export const BIN_FRAME_CHANNEL = 0x02;
export const CLIENT_ID_BYTES = 16;
const AEAD_AAD_BIN = new TextEncoder().encode('nodecrypt-v2|bin');
const TAG_BYTES = 16;

/**
 * 加密任意字节，返回 `IV || 密文||标签` 的裸二进制（不做 base64）。
 *
 * AAD 用独立的 `nodecrypt-v2|bin`，与 JSON 通道的 AEAD_AAD 域分离 ——
 * 否则两个通道的密文可以互换，等于凭空多出一条本不该存在的解析路径。
 */
export async function encryptRaw(key, bytes, aad = AEAD_AAD_BIN) {
	if (!key) {
		throw new Error('encryptRaw: missing key');
	}
	const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv, additionalData: aad },
		key,
		toBytes(bytes)
	);
	const out = new Uint8Array(NONCE_BYTES + ciphertext.byteLength);
	out.set(iv, 0);
	out.set(new Uint8Array(ciphertext), NONCE_BYTES);
	return out;
}

/** encryptRaw 的逆运算。长度不对或认证标签不匹配一律抛异常。 */
export async function decryptRaw(key, packed, aad = AEAD_AAD_BIN) {
	if (!key) {
		throw new Error('decryptRaw: missing key');
	}
	const buf = toBytes(packed);
	// 空明文加密后正好是 IV+标签 = 28 字节，所以边界用 < 而不是 <=
	if (buf.length < NONCE_BYTES + TAG_BYTES) {
		throw new Error(`decryptRaw: payload too short (${buf.length})`);
	}
	const plaintext = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: buf.subarray(0, NONCE_BYTES), additionalData: aad },
		key,
		buf.subarray(NONCE_BYTES)
	);
	return new Uint8Array(plaintext);
}

/** 把 16 位十六进制 clientId 编成定长 ASCII 字段。 */
export function encodeClientId(clientId) {
	const s = String(clientId);
	if (!/^[0-9a-f]{16}$/.test(s)) {
		throw new Error(`encodeClientId: 需要 16 位小写 hex，收到 "${s}"`);
	}
	const out = new Uint8Array(CLIENT_ID_BYTES);
	for (let i = 0; i < CLIENT_ID_BYTES; i++) {
		out[i] = s.charCodeAt(i);
	}
	return out;
}

/** 组装二进制帧：`0x02 | 对端 clientId | IV | 密文`。 */
export function packBinaryFrame(peerClientId, packed) {
	const head = encodeClientId(peerClientId);
	const body = toBytes(packed);
	const frame = new Uint8Array(1 + CLIENT_ID_BYTES + body.length);
	frame[0] = BIN_FRAME_CHANNEL;
	frame.set(head, 1);
	frame.set(body, 1 + CLIENT_ID_BYTES);
	return frame;
}

/** 拆二进制帧，返回 `{ peerClientId, packed }`。形状不对返回 null（不是抛错）。 */
export function unpackBinaryFrame(bytes) {
	const buf = toBytes(bytes);
	if (buf.length < 1 + CLIENT_ID_BYTES || buf[0] !== BIN_FRAME_CHANNEL) {
		return null;
	}
	let id = '';
	for (let i = 1; i <= CLIENT_ID_BYTES; i++) {
		id += String.fromCharCode(buf[i]);
	}
	if (!/^[0-9a-f]{16}$/.test(id)) {
		return null;
	}
	return { peerClientId: id, packed: buf.subarray(1 + CLIENT_ID_BYTES) };
}

/**
 * 分卷的二进制记录（加密前的明文）：
 * `fileIdLen(1) | fileId | volumeIndex(2) | totalVolumes(2) | payload`
 *
 * 元数据跟着载荷一起进同一次 AEAD，所以只需一次加解密，
 * 而且元数据也被认证 —— 改不动分卷序号。
 * index/total 用 2 字节：上限 65536 卷 × 256KB ≈ 16GB，够用。
 */
export function packVolumeRecord(fileId, volumeIndex, totalVolumes, payload) {
	const idBytes = te.encode(String(fileId));
	if (idBytes.length > 255) {
		throw new Error('packVolumeRecord: fileId too long');
	}
	const body = toBytes(payload);
	const out = new Uint8Array(1 + idBytes.length + 4 + body.length);
	let o = 0;
	out[o++] = idBytes.length;
	out.set(idBytes, o); o += idBytes.length;
	out[o++] = (volumeIndex >> 8) & 0xff;
	out[o++] = volumeIndex & 0xff;
	out[o++] = (totalVolumes >> 8) & 0xff;
	out[o++] = totalVolumes & 0xff;
	out.set(body, o);
	return out;
}

/** packVolumeRecord 的逆运算。 */
export function unpackVolumeRecord(bytes) {
	const buf = toBytes(bytes);
	if (buf.length < 5) {
		throw new Error('unpackVolumeRecord: too short');
	}
	const idLen = buf[0];
	if (buf.length < 1 + idLen + 4) {
		throw new Error('unpackVolumeRecord: truncated header');
	}
	const fileId = td.decode(buf.subarray(1, 1 + idLen));
	let o = 1 + idLen;
	const volumeIndex = (buf[o] << 8) | buf[o + 1]; o += 2;
	const totalVolumes = (buf[o] << 8) | buf[o + 1]; o += 2;
	return { fileId, volumeIndex, totalVolumes, payload: buf.subarray(o) };
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
