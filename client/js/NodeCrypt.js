// NodeCrypt core cryptographic client for secure chat
// NodeCrypt 安全聊天的核心加密客户端
//
// P0 改造：所有密码学原语迁到 WebCrypto + AEAD（见 ./aead.js）。
// 已移除的依赖：js-sha256、elliptic、aes-js、js-chacha20、buffer。
// 已移除的全局污染：window.Buffer = Buffer

import {
	PROTOCOL_VERSION,
	sha256Hex,
	toHex,
	toB64,
	fromB64,
	fromHex,
	generateEcdhKeyPair,
	exportEcdhPublic,
	deriveEcdhSecret,
	deriveServerSessionKey,
	derivePeerSessionKey,
	derivePasswordKey,
	encryptAead,
	decryptAead,
	keyFingerprint
} from './aead.js';

// Main NodeCrypt class for secure communication
// 用于安全通信的 NodeCrypt 主类
class NodeCrypt {
	// Initialize NodeCrypt instance
	// 初始化 NodeCrypt 实例
	constructor(config = {}, callbacks = {}) {
		this.config = {
			rsaPublic: config.rsaPublic || '',
			wsAddress: config.wsAddress || '',
			reconnectDelay: config.reconnectDelay || 3000,
			pingInterval: config.pingInterval || 20000,
			debug: config.debug || false,
		};
		this.callbacks = {
			onServerClosed: callbacks.onServerClosed || null,
			onServerSecured: callbacks.onServerSecured || null,
			onClientSecured: callbacks.onClientSecured || null,
			onClientList: callbacks.onClientList || null,
			onClientMessage: callbacks.onClientMessage || null,
			// 新增：拿到服务端公钥指纹时回调（指纹, 是否与上次不同）
			onServerKeyFingerprint: callbacks.onServerKeyFingerprint || null,
		};
		this.SERVER_KEY_STORAGE = 'nodecrypt_server_key_fingerprint';
		this.serverKeys = null;
		this.serverShared = null;
		this.serverKeyFingerprint = null;
		this.serverKeyChanged = false;
		this.credentials = null;
		this.connection = null;
		this.reconnect = null;
		this.ping = null;
		this.channel = {};
		this.passwordKey = null;
		this.setCredentials = this.setCredentials.bind(this);
		this.connect = this.connect.bind(this);
		this.destruct = this.destruct.bind(this);
		this.onOpen = this.onOpen.bind(this);
		this.onMessage = this.onMessage.bind(this);
		this.onError = this.onError.bind(this);
		this.onClose = this.onClose.bind(this);
		this.logEvent = this.logEvent.bind(this);
		this.isOpen = this.isOpen.bind(this);
		this.isClosed = this.isClosed.bind(this);
		this.startReconnect = this.startReconnect.bind(this);
		this.stopReconnect = this.stopReconnect.bind(this);
		this.startPing = this.startPing.bind(this);
		this.stopPing = this.stopPing.bind(this);
		this.disconnect = this.disconnect.bind(this);
		this.sendMessage = this.sendMessage.bind(this);
		this.sendChannelMessage = this.sendChannelMessage.bind(this);
		this.encryptServerMessage = this.encryptServerMessage.bind(this);
		this.decryptServerMessage = this.decryptServerMessage.bind(this);
		this.encryptClientMessage = this.encryptClientMessage.bind(this);
		this.decryptClientMessage = this.decryptClientMessage.bind(this)
	}

	// Set user credentials (username, channel, password)
	// 设置用户凭证（用户名、频道、密码）
	// 注意：不再在这里做 sha256(password)。房间标识和口令派生都是异步的，
	// 放到 onOpen 里算（那里是 async 上下文）。
	setCredentials(username, channel, password) {
		this.logEvent('setCredentials');
		try {
			this.credentials = {
				username: username,
				channelName: channel,
				channelId: null,
				password: password
			};
			this.passwordKey = null;
		} catch (error) {
			this.logEvent('setCredentials', error, 'error');
			return (false)
		}
		return (true)
	}

	// Connect to the server
	// 连接到服务器
	connect() {
		if (!this.credentials) {
			return (false)
		}
		this.logEvent('connect', this.config.wsAddress);
		this.stopReconnect();
		this.stopPing();
		this.serverKeys = null;
		this.serverShared = null;
		this.channel = {};
		try {
			this.connection = new WebSocket(this.config.wsAddress);
			this.connection.onopen = this.onOpen;
			// 串行化 onMessage —— 这是必须的，不是优化。
			//
			// a:'c' 帧承载两种含义：对端公钥(hex) 和 业务密文(base64)，
			// 而代码靠 channel[id].shared 这个可变标志来区分。
			// onMessage 是 async，而 onmessage 不会被 await，所以多个消息会并发执行。
			// 并发窗口里后启动的 handler 看到 shared 仍是 null，就会把密文当公钥
			// 送进 deriveEcdhSecret -> fromHex 抛错；错误又被 catch 吞进日志，
			// 对外表现是「两个人几乎同时进房，互相看不见」，且界面毫无提示。
			//
			// 帧本身按 WebSocket 顺序到达，串行处理即可保证
			// 「某个对端的第一条 a:'c' 必定携带它的公钥」这个不变式成立。
			this._msgQueue = Promise.resolve();
			this.connection.onmessage = (event) => {
				this._msgQueue = this._msgQueue
					.then(() => this.onMessage(event))
					.catch(() => {})
			};
			this.connection.onerror = this.onError;
			this.connection.onclose = this.onClose
		} catch (error) {
			this.logEvent('connect', error, 'error');
			return (false)
		}
		return (true)
	}

	// Clean up and disconnect
	// 清理并断开连接
	destruct() {
		this.logEvent('destruct');
		this.stopReconnect();
		this.stopPing();
		this.reconnect = null;
		this.ping = null;
		this.config = {
			rsaPublic: '',
			wsAddress: '',
			reconnectDelay: 3000,
			pingInterval: 15000,
			debug: false,
		};
		this.callbacks.onServerClosed = null;
		this.callbacks.onServerSecured = null;
		this.callbacks.onClientSecured = null;
		this.callbacks.onClientList = null;
		this.callbacks.onClientMessage = null;
		this.callbacks.onServerKeyFingerprint = null;
		this.serverKeys = null;
		this.serverShared = null;
		this.passwordKey = null;
		this.credentials = null;
		this.connection.onopen = null;
		this.connection.onmessage = null;
		this.connection.onerror = null;
		this.connection.onclose = null;
		try {
			this.connection.removeAllListeners()
		} catch (error) {
			this.logEvent('destruct', error, 'error')
		}
		try {
			this.connection.close()
		} catch (error) {
			this.logEvent('destruct', error, 'error')
		}
		this.connection = null;
		this.channel = {};
		return (true)
	}

	// WebSocket open event handler
	// WebSocket 连接打开事件处理
	async onOpen() {
		this.logEvent('onOpen');
		this.startPing();
		try {
			// 房间标识：服务端只用它当不透明的房间桶名，不是安全边界
			this.credentials.channelId = await sha256Hex('nodecrypt-v2|channel|' + this.credentials.channelName);
			// 口令派生一次就缓存，后面每个对端复用（否则每加一个人重跑 60 万次 PBKDF2）
			this.passwordKey = await derivePasswordKey(this.credentials.password, this.credentials.channelName);
			this.serverKeys = await generateEcdhKeyPair('P-384');
			this.serverShared = null;
			// 握手首帧带协议版本前缀，服务端据此拒绝老客户端，避免静默错乱
			this.sendMessage(PROTOCOL_VERSION + '|' + await exportEcdhPublic(this.serverKeys));
		} catch (error) {
			this.logEvent('onOpen', error, 'error')
		}
	}

	// WebSocket message event handler
	// WebSocket 消息事件处理
	async onMessage(event) {
		if (!event || !this.isString(event.data)) {
			return
		}
		if (event.data === 'pong') {
			return
		}
		this.logEvent('onMessage', event.data);
		try {
			const data = JSON.parse(event.data);
			if (data.type === 'server-key') {
				const result = await this.handleServerKey(data.key);
				if (!result) {
					return
				}
			}
		} catch (e) {}
		if (!this.serverShared) {
			const parts = event.data.split('|');
			// 格式： NC2 | 服务端 ECDH 公钥(hex) | RSA 签名(b64)
			if (parts[0] !== PROTOCOL_VERSION || !parts[1] || !parts[2]) {
				this.logEvent('onMessage', '握手首帧不是 ' + PROTOCOL_VERSION + ' 格式，忽略（可能是老客户端或中间人）', 'error');
				return
			}
			try {
				const verified = await crypto.subtle.verify({
						name: 'RSASSA-PKCS1-v1_5'
					},
					await crypto.subtle.importKey('spki', fromB64(this.config.rsaPublic), {
						name: 'RSASSA-PKCS1-v1_5',
						hash: {
							name: 'SHA-256'
						}
					}, false, ['verify']),
					fromB64(parts[2]),
					fromHex(parts[1])
				);
				// 说明：这一步只证明「持该 RSA 私钥者同时持这把 ECDH 私钥」= 自洽性。
				// RSA 公钥本身未经认证，所以它**不是**身份认证，更不防中间人。
				// 真正的保护来自房间口令（见 aead.js 顶部说明）。
				if (verified === true) {
					const secret = await deriveEcdhSecret(this.serverKeys.privateKey, parts[1], 'P-384');
					this.serverShared = await deriveServerSessionKey(secret);
					this.sendMessage(await this.encryptServerMessage({
						a: 'j',
						p: this.credentials.channelId
					}, this.serverShared));
					if (this.callbacks.onServerSecured) {
						try {
							this.callbacks.onServerSecured()
						} catch (error) {
							this.logEvent('onMessage-server-secured-callback', error, 'error')
						}
					}
				}
			} catch (error) {
				this.logEvent('onMessage', error, 'error')
			}
			return
		}
		const serverDecrypted = await this.decryptServerMessage(event.data, this.serverShared);
		this.logEvent('onMessage-server-decrypted', serverDecrypted);
		if (!this.isObject(serverDecrypted) || !this.isString(serverDecrypted.a)) {
			return
		}
		if (serverDecrypted.a === 'l' && this.isArray(serverDecrypted.p)) {
			try {
				for (const clientId in this.channel) {
					if (serverDecrypted.p.indexOf(clientId) < 0) {
						delete(this.channel[clientId])
					}
				}
				let payloads = {};
				for (const clientId of serverDecrypted.p) {
					if (!this.channel[clientId]) {
						this.channel[clientId] = {
							username: null,
							keys: await generateEcdhKeyPair('P-256'),
							shared: null,
						};
						payloads[clientId] = await exportEcdhPublic(this.channel[clientId].keys)
					}
				}
				if (Object.keys(payloads).length > 0) {
					this.sendMessage(await this.encryptServerMessage({
						a: 'w',
						p: payloads,
					}, this.serverShared))
				}
			} catch (error) {
				this.logEvent('onMessage-list', error, 'error')
			}
			if (this.callbacks.onClientList) {
				let clients = [];
				for (const clientId in this.channel) {
					if (this.channel[clientId].shared && this.channel[clientId].username) {
						clients.push({
							clientId: clientId,
							username: this.channel[clientId].username
						})
					}
				}
				try {
					this.callbacks.onClientList(clients)
				} catch (error) {
					this.logEvent('onMessage-client-list-callback', error, 'error')
				}
			}
			return
		}
		if (!this.isString(serverDecrypted.p) || !this.isString(serverDecrypted.c)) {
			return
		}
		if (serverDecrypted.a === 'c' && (!this.channel[serverDecrypted.c] || !this.channel[serverDecrypted.c].shared)) {
			try {
				if (!this.channel[serverDecrypted.c]) {
					this.channel[serverDecrypted.c] = {
						username: null,
						keys: await generateEcdhKeyPair('P-256'),
						shared: null,
					};
					this.sendMessage(await this.encryptServerMessage({
						a: 'c',
						p: await exportEcdhPublic(this.channel[serverDecrypted.c].keys),
						c: serverDecrypted.c
					}, this.serverShared))
				}
				// 会话密钥 = HKDF(ikm = ECDH秘密 ‖ PBKDF2(口令), salt = 房间标识)
				// 两个因子缺一不可：中继冒充服务端也拿不到口令
				const secret = await deriveEcdhSecret(
					this.channel[serverDecrypted.c].keys.privateKey,
					serverDecrypted.p,
					'P-256'
				);
				this.channel[serverDecrypted.c].shared = await derivePeerSessionKey(
					secret,
					this.passwordKey,
					this.credentials.channelId
				);
				this.sendMessage(await this.encryptServerMessage({
					a: 'c',
					p: await this.encryptClientMessage({
						a: 'u',
						p: this.credentials.username
					}, this.channel[serverDecrypted.c].shared),
					c: serverDecrypted.c
				}, this.serverShared))
			} catch (error) {
				this.logEvent('onMessage-client', error, 'error')
			}
			return
		}
		if (serverDecrypted.a === 'c' && this.channel[serverDecrypted.c] && this.channel[serverDecrypted.c].shared) {
			const clientDecrypted = await this.decryptClientMessage(serverDecrypted.p, this.channel[serverDecrypted.c].shared);
			this.logEvent('onMessage-client-decrypted', clientDecrypted);
			if (!this.isObject(clientDecrypted) || !this.isString(clientDecrypted.a)) {
				return
			}
			if (clientDecrypted.a === 'u' && this.isString(clientDecrypted.p) && clientDecrypted.p.match(/\S+/) && !this.channel[serverDecrypted.c].username) {
				this.channel[serverDecrypted.c].username = clientDecrypted.p.replace(/^\s+/, '').replace(/\s+$/, '');
				if (this.callbacks.onClientSecured) {
					try {
						this.callbacks.onClientSecured({
							clientId: serverDecrypted.c,
							username: this.channel[serverDecrypted.c].username
						})
					} catch (error) {
						this.logEvent('onMessage-client-secured-callback', error, 'error')
					}
				}
				return
			}
			if (!this.channel[serverDecrypted.c].username) {
				return
			}
			if (clientDecrypted.a === 'm' && this.isString(clientDecrypted.t) && (this.isString(clientDecrypted.d) || this.isObject(clientDecrypted.d))) {
				if (this.callbacks.onClientMessage) {
					try {
						this.callbacks.onClientMessage({
							clientId: serverDecrypted.c,
							username: this.channel[serverDecrypted.c].username,
							type: clientDecrypted.t,
							data: clientDecrypted.d
						})
					} catch (error) {
						this.logEvent('onMessage-client-message-callback', error, 'error')
					}
				}
				return
			}
		}
	}

	// WebSocket error event handler
	// WebSocket 错误事件处理
	async onError(event) {
		this.logEvent('onError', event, 'error');
		this.disconnect();
		if (this.credentials) {
			this.startReconnect()
		}
		if (this.callbacks.onServerClosed) {
			try {
				this.callbacks.onServerClosed()
			} catch (error) {
				this.logEvent('onError-server-closed-callback', error, 'error')
			}
		}
	}

	// WebSocket close event handler
	// WebSocket 关闭事件处理
	async onClose(event) {
		this.logEvent('onClose', event);
		this.disconnect();
		if (this.credentials) {
			this.startReconnect()
		}
		if (this.callbacks.onServerClosed) {
			try {
				this.callbacks.onServerClosed()
			} catch (error) {
				this.logEvent('onClose-server-closed-callback', error, 'error')
			}
		}
	}

	// Log events for debugging
	// 记录事件日志用于调试
	logEvent(source, message, level) {
		if (this.config.debug) {
			const date = new Date(),
				dateString = date.getFullYear() + '-' + ('0' + (date.getMonth() + 1)).slice(-2) + '-' + ('0' + date.getDate()).slice(-2) + ' ' + ('0' + date.getHours()).slice(-2) + ':' + ('0' + date.getMinutes()).slice(-2) + ':' + ('0' + date.getSeconds()).slice(-2);
			console.log('[' + dateString + ']', (level ? level.toUpperCase() : 'INFO'), source + (message ? ':' : ''), (message ? message : ''))
		}
	}

	// Check if connection is open
	// 检查连接是否已打开
	isOpen() {
		return (this.connection && this.connection.readyState && this.connection.readyState === WebSocket.OPEN ? true : false)
	}

	// Check if connection is closed
	// 检查连接是否已关闭
	isClosed() {
		return (!this.connection || !this.connection.readyState || this.connection.readyState === WebSocket.CLOSED ? true : false)
	}

	// Start reconnect timer
	// 启动重连定时器
	startReconnect() {
		this.stopReconnect();
		this.logEvent('startReconnect');
		this.reconnect = setTimeout(() => {
			this.reconnect = null;
			this.connect()
		}, this.config.reconnectDelay)
	}

	// Stop reconnect timer
	// 停止重连定时器
	stopReconnect() {
		if (this.reconnect) {
			this.logEvent('stopReconnect');
			clearTimeout(this.reconnect);
			this.reconnect = null
		}
	}

	// Start ping timer
	// 启动心跳定时器
	startPing() {
		this.stopPing();
		this.logEvent('startPing');
		this.ping = setInterval(() => {
			this.sendMessage('ping')
		}, this.config.pingInterval)
	}

	// Stop ping timer
	// 停止心跳定时器
	stopPing() {
		if (this.ping) {
			this.logEvent('stopPing');
			clearInterval(this.ping);
			this.ping = null
		}
	}

	// Disconnect from server
	// 从服务器断开连接
	disconnect() {
		this.stopReconnect();
		this.stopPing();
		if (!this.isClosed()) {
			try {
				this.logEvent('disconnect');
				this.connection.close()
			} catch (error) {
				this.logEvent('disconnect', error, 'error')
			}
		}
	}

	// Send a message to the server
	// 向服务器发送消息
	sendMessage(message) {
		try {
			if (this.isOpen()) {
				this.connection.send(message);
				return (true)
			}
		} catch (error) {
			this.logEvent('sendMessage', error, 'error')
		}
		return (false)
	}

	// Send a message to all channels
	// 向所有频道发送消息
	async sendChannelMessage(type, data) {
		if (this.serverShared) {
			try {
				let payloads = {};
				for (const clientId in this.channel) {
					if (this.channel[clientId].shared && this.channel[clientId].username) {
						payloads[clientId] = await this.encryptClientMessage({
							a: 'm',
							t: type,
							d: data
						}, this.channel[clientId].shared);
						if (payloads[clientId].length === 0) {
							return (false)
						}
					}
				}
				if (Object.keys(payloads).length > 0) {
					const payload = await this.encryptServerMessage({
						a: 'w',
						p: payloads,
					}, this.serverShared);
					if (!this.isOpen() || payload.length === 0 || payload.length > (8 * 1024 * 1024)) {
						return (false)
					}
					this.connection.send(payload)
				}
				return (true)
			} catch (error) {
				this.logEvent('sendChannelMessage', error, 'error')
			}
		}
		return (false)
	}

	// Encrypt a message for the server
	// 加密发送给服务器的消息
	async encryptServerMessage(message, key) {
		try {
			return await encryptAead(key, message)
		} catch (error) {
			this.logEvent('encryptServerMessage', error, 'error')
			return ('')
		}
	}

	// Decrypt a message from the server
	// 解密来自服务器的消息
	async decryptServerMessage(message, key) {
		try {
			return await decryptAead(key, message)
		} catch (error) {
			// AEAD 认证失败会走到这里（密文被篡改 / 密钥不对）
			this.logEvent('decryptServerMessage', error, 'error')
			return ({})
		}
	}

	// Encrypt a message for a client
	// 加密发送给客户端的消息
	async encryptClientMessage(message, key) {
		try {
			return await encryptAead(key, message)
		} catch (error) {
			this.logEvent('encryptClientMessage', error, 'error')
			return ('')
		}
	}

	// Decrypt a message from a client
	// 解密来自客户端的消息
	async decryptClientMessage(message, key) {
		try {
			return await decryptAead(key, message)
		} catch (error) {
			this.logEvent('decryptClientMessage', error, 'error')
			return ({})
		}
	}

	// Check if value is a string
	// 检查值是否为字符串
	isString(value) {
		return (value && Object.prototype.toString.call(value) === '[object String]' ? true : false)
	}

	// Check if value is an array
	// 检查值是否为数组
	isArray(value) {
		return (value && Object.prototype.toString.call(value) === '[object Array]' ? true : false)
	}

	// Check if value is an object
	// 检查值是否为对象
	isObject(value) {
		return (value && Object.prototype.toString.call(value) === '[object Object]' ? true : false)
	}

	// Handle server public key
	// 处理服务器公钥
	//
	// 改造说明（原实现的问题）：
	//   原来直接 localStorage.setItem(SERVER_KEY_STORAGE, serverKey)，
	//   存了但从不比对 —— 等于没存。所以 README 声称的「防止中间人攻击」并未实现。
	//
	// 现在：存指纹 + 比对 + 变更时明确告知。但要说清楚它**只提供变更通知**：
	//   服务端每 24 小时轮换一次 RSA 密钥，所以指纹变化是常态；
	//   而且初次连接的指纹本身就是未认证的，无法证明「换成了对的」。
	//   真正的保护是房间口令（见 aead.js 顶部）。
	async handleServerKey(serverKey) {
		this.logEvent('handleServerKey', 'Received server key');
		try {
			const fingerprint = await keyFingerprint(serverKey);
			let previous = null;
			try {
				previous = localStorage.getItem(this.SERVER_KEY_STORAGE);
			} catch (error) {
				// 隐私模式 / 禁用存储：降级为「本次会话内不比对」
			}
			this.serverKeyFingerprint = fingerprint;
			this.serverKeyChanged = (previous !== null && previous !== fingerprint);
			try {
				localStorage.setItem(this.SERVER_KEY_STORAGE, fingerprint);
			} catch (error) {}
			this.config.rsaPublic = serverKey;
			if (this.serverKeyChanged) {
				this.logEvent('handleServerKey',
					'服务端公钥指纹与上次不同：' + previous + ' -> ' + fingerprint +
					'（可能是服务端轮换了密钥，也可能是中间人）。注意：这条提示只能说明「换了」，不能证明「换成了对的」。'
				, 'error');
			} else {
				this.logEvent('handleServerKey', '服务端公钥指纹: ' + fingerprint);
			}
			if (this.callbacks.onServerKeyFingerprint) {
				try {
					this.callbacks.onServerKeyFingerprint(fingerprint, this.serverKeyChanged)
				} catch (error) {
					this.logEvent('handleServerKey-callback', error, 'error')
				}
			}
		} catch (error) {
			this.logEvent('handleServerKey', error, 'error');
			return (false)
		}
		return true
	}
};

if (typeof window !== 'undefined') {
	window.NodeCrypt = NodeCrypt
}
