// NodeCrypt v2 服务端工具
//
// P0 改造：
//   - AES-256-CBC（零填充、无 MAC） -> AES-GCM（AEAD）
//   - node:crypto 的 createCipheriv/randomBytes -> WebCrypto
//   - 会话密钥从「ECDH 秘密 slice(8,40)」-> HKDF-SHA256
//
// 服务端**永远拿不到明文消息内容**：客户端↔客户端那层用的是
// HKDF(ECDH ‖ PBKDF2(房间口令))，服务端既没有口令也没有对应的私钥。

const te = new TextEncoder();
const td = new TextDecoder();

const KDF_SALT_PREFIX = 'nodecrypt-v2|';
const AEAD_AAD = te.encode('nodecrypt-v2');
const NONCE_BYTES = 12;

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

export const toB64 = (input) => {
	const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
	let binary = '';
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
	}
	return btoa(binary);
};

export const fromB64 = (value) => {
	const binary = atob(String(value));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
};

export const toHex = (input) => {
	const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i].toString(16).padStart(2, '0');
	}
	return out;
};

export const fromHex = (value) => {
	const hex = String(value);
	const bytes = new Uint8Array(hex.length >> 1);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	}
	return bytes;
};

// ---------------------------------------------------------------------------
// 密钥派生
// ---------------------------------------------------------------------------

/** HKDF-SHA256，替代原来的 slice(8, 40) 取字节。 */
export const hkdf = async (ikm, salt, info, bits = 256) => {
	const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
	return new Uint8Array(await crypto.subtle.deriveBits({
		name: 'HKDF',
		hash: 'SHA-256',
		salt: te.encode(salt),
		info: te.encode(info)
	}, baseKey, bits));
};

export const importAesKey = async (rawBytes) => {
	return crypto.subtle.importKey('raw', rawBytes, {
		name: 'AES-GCM',
		length: 256
	}, false, ['encrypt', 'decrypt']);
};

/** 客户端 ↔ 服务端会话密钥。ikm = P-384 ECDH 共享秘密（48 字节）。 */
export const deriveServerSessionKey = async (ecdhSecret) => {
	return importAesKey(await hkdf(ecdhSecret, KDF_SALT_PREFIX + 'server', 'server-session', 256));
};

// ---------------------------------------------------------------------------
// AEAD
// 格式： base64(iv) + '|' + base64(ciphertext ‖ tag)
// ---------------------------------------------------------------------------

export const encryptMessage = async (message, key) => {
	try {
		const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
		const ciphertext = await crypto.subtle.encrypt({
			name: 'AES-GCM',
			iv,
			additionalData: AEAD_AAD
		}, key, te.encode(JSON.stringify(message)));
		return toB64(iv) + '|' + toB64(ciphertext);
	} catch (error) {
		logEvent('encryptMessage', error, 'error');
		return ('');
	}
};

export const decryptMessage = async (message, key) => {
	try {
		const parts = String(message).split('|');
		if (parts.length !== 2 || !parts[0] || !parts[1]) {
			return ({});
		}
		const plaintext = await crypto.subtle.decrypt({
			name: 'AES-GCM',
			iv: fromB64(parts[0]),
			additionalData: AEAD_AAD
		}, key, fromB64(parts[1]));
		return JSON.parse(td.decode(plaintext));
	} catch (error) {
		// AEAD 认证失败：密文被篡改或密钥不对，一律当空处理
		logEvent('decryptMessage', error, 'error');
		return ({});
	}
};

// ---------------------------------------------------------------------------
// 杂项
// ---------------------------------------------------------------------------

export const generateClientId = () => {
	try {
		return (toHex(crypto.getRandomValues(new Uint8Array(8))));
	} catch (error) {
		logEvent('generateClientId', error, 'error');
		return (null);
	}
};

export const logEvent = (source, message, level) => {
	if (
		level !== 'debug' ||
		true // config.debug would go here
	) {

		const date = new Date(),
			dateString = date.getFullYear() + '-' +
			('0' + (date.getMonth() + 1)).slice(-2) + '-' +
			('0' + date.getDate()).slice(-2) + ' ' +
			('0' + date.getHours()).slice(-2) + ':' +
			('0' + date.getMinutes()).slice(-2) + ':' +
			('0' + date.getSeconds()).slice(-2);

		console.log('[' + dateString + ']', (level ? level.toUpperCase() : 'INFO'), source + (message ? ':' : ''), (message ? message : ''));

	}
};

export const getTime = () => {
	return (new Date().getTime());
};

export const isString = (value) => {
	return (
		value &&
		Object.prototype.toString.call(value) === '[object String]' ?
		true :
		false
	);
};

export const isArray = (value) => {
	return (
		value &&
		Object.prototype.toString.call(value) === '[object Array]' ?
		true :
		false
	);
};

export const isObject = (value) => {
	return (
		value &&
		Object.prototype.toString.call(value) === '[object Object]' ?
		true :
		false
	);
};

export const aeadConstants = {
	KDF_SALT_PREFIX,
	NONCE_BYTES
};
