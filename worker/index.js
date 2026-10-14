import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime, deriveServerSessionKeyBytes, importAesKey, fromHex, toHex } from './utils.js';

// 协议版本。首帧必须带这个前缀，否则直接关连接（见 webSocketMessage）。
const PROTOCOL_VERSION = 'NC2';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');
    const isWebSocket = upgradeHeader === 'websocket';

    // http -> https 强制跳转。
    //
    // 为什么必须做：加密层依赖 crypto.subtle，而它只在「安全上下文」可用。
    // 用 http:// 打开时页面能正常渲染，但 crypto.subtle === undefined，
    // 表现是「页面好好的、一发消息就报错」——极难排查，所以在这里堵死。
    //
    // 两点排除：
    //   · WebSocket 升级请求不跳（ws 客户端不跟随 301，会把握手直接打断）。
    //     页面被跳转到 https 之后，客户端自然改用 wss://。
    //   · 本地开发不跳（wrangler dev 在 http://127.0.0.1:8787 上跑）。
    const isLocalHost = url.hostname === 'localhost'
      || url.hostname === '127.0.0.1'
      || url.hostname === '[::1]';
    const scheme = request.headers.get('X-Forwarded-Proto')
      || url.protocol.replace(':', '');
    if (!isWebSocket && !isLocalHost && scheme === 'http') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }

    // 处理WebSocket请求
    if (isWebSocket) {
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 处理API请求
    if (url.pathname.startsWith('/api/')) {
      // ...API 逻辑...
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }

    // 其余全部交给 ASSETS 处理（自动支持 hash 文件名和 SPA fallback）
    return env.ASSETS.fetch(request);
  }
};

// =============================================================================
// ChatRoom —— Durable Object
//
// 用 **Hibernation API**（state.acceptWebSocket + webSocketMessage / webSocketClose /
// webSocketError 三个方法），而不是 connection.accept() + addEventListener。
//
// 为什么值得改：非休眠写法下，只要有一个 WebSocket 连着，这个 DO 就常驻内存持续
// 计费。按 128 MB 算，单房间 24 小时常驻一个月 = 324,000 GB-s，占免费额度
// （13,000 GB-s/天，约 390,000 GB-s/月）的 83%。改 Hibernation 后空闲的 DO 会被
// 驱逐，不计时长费。
//
// 代价：**内存状态会被清空**。所以这里有一条硬性纪律：
//
//     state.getWebSockets() + ws.serializeAttachment() 是唯一可信来源；
//     内存里的 clients / channels / keyCache 全部只是缓存，随时可以丢。
//
// 每个入口（fetch / webSocketMessage / webSocketClose）都先 syncClients() 从
// attachment 重建视图。这样正确性不依赖「有没有真的被驱逐」，也就没有那种
// 「本机好好的、上线就偶发」的幽灵问题。
//
// 另一个坑：会话密钥是 CryptoKey，而 CryptoKey **不能结构化克隆**，直接写进
// serializeAttachment 会失败。所以 attachment 里存的是 HKDF 的原始字节，
// 由 getSharedKey() 按需 import 并缓存。
// =============================================================================
export class ChatRoom {
  constructor(state, env) {
    this.state = state;

    // 以下三者都是纯缓存，每次进入都会由 syncClients() 重建
    this.clients = {};
    this.channels = {};
    this.keyCache = {};

    this.config = {
      seenTimeout: 60000,
      debug: false
    };

    // 初始化 RSA 密钥对（存在 storage 里，驱逐后能自愈）
    this.initRSAKeyPair();
  }

  /**
   * 初始化 RSA 密钥对。**幂等**。
   *
   * 构造函数会不 await 地调一次，fetch / 消息路径还会再调一次。并发跑两遍会各自
   * 生成一把密钥并互相覆盖 —— storage 里和内存里可能是两把不同的密钥，之后冷启动
   * 用的和客户端拿到的对不上，签名校验就会莫名其妙失败。用共享 promise 保证同一
   * 时刻只有一次初始化在跑（失败则清掉，允许重试）。
   */
  initRSAKeyPair() {
    if (!this._keyInitPromise) {
      this._keyInitPromise = this._initRSAKeyPairInternal().catch((error) => {
        this._keyInitPromise = null;
        throw error;
      });
    }
    return this._keyInitPromise;
  }

  async _initRSAKeyPairInternal() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        console.log('Generating new RSA keypair...');
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['sign', 'verify']
        );

        // 并行导出公钥和私钥以提高性能
        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
          crypto.subtle.exportKey('spki', keyPair.publicKey),
          crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
        ]);

        stored = {
          rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
          rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)),
          createdAt: Date.now() // 记录密钥创建时间，用于后续判断是否需要轮换
        };

        await this.state.storage.put('rsaKeyPair', stored);
        console.log('RSA key pair generated and stored');
      }

      // Reconstruct the private key
      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);

        stored.rsaPrivate = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBuffer,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
          },
          false,
          ['sign']
        );
      }
      this.keyPair = stored;

      // 检查密钥是否需要轮换（如果已创建超过24小时）
      if (stored.createdAt && (Date.now() - stored.createdAt > 24 * 60 * 60 * 1000)) {
        // 判据用「当前活着的 socket 数」而不是内存缓存 —— Hibernation 下内存缓存
        // 随时可能是空的（被驱逐过），用它会误判成「没人在线」而错误轮换密钥，
        // 导致在线客户端和新连接验签失败。
        const liveSockets = this.state.getWebSockets().length;
        if (liveSockets === 0) {
          console.log('密钥已使用24小时，进行轮换...');
          await this.state.storage.delete('rsaKeyPair');
          this.keyPair = null;
          this._keyInitPromise = null; // 清掉记忆，让下面的递归真的重新生成
          await this.initRSAKeyPair();
        } else {
          // 否则标记需要在客户端全部断开后进行轮换
          await this.state.storage.put('pendingKeyRotation', true);
        }
      }
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
      throw error;
    }
  }

  async fetch(request) {
    // Check for WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    // Ensure RSA keys are initialized
    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    // Hibernation API：把 socket 交给运行时托管。
    // 此后消息不再走 addEventListener，而是回调本类的
    // webSocketMessage / webSocketClose / webSocketError。
    // 关键收益：没人说话时 DO 可以被驱逐，socket 本身由运行时维持，唤醒后仍在。
    this.state.acceptWebSocket(server);

    await this.onOpenSession(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // ---------------------------------------------------------------------------
  // 状态同步 —— Hibernation 的核心
  // ---------------------------------------------------------------------------

  deserialize(ws) {
    try {
      return ws.deserializeAttachment() || {};
    } catch (error) {
      logEvent('deserialize-attachment', error, 'error');
      return {};
    }
  }

  /**
   * 从活着的 socket + 它身上的 attachment 重建内存视图。
   *
   * 每次进入都必须先做这一步：DO 被驱逐过之后内存是空的，唯一能还原状态的地方
   * 就是 socket 自己。把内存当纯缓存、每次都重建，就不必去猜「这次到底被驱逐了没」。
   */
  async syncClients() {
    const sockets = this.state.getWebSockets();
    const clients = {};
    const channels = {};

    for (const ws of sockets) {
      const att = this.deserialize(ws);
      if (!att.clientId) continue;

      clients[att.clientId] = {
        connection: ws,               // 沿用原字段名，其余方法不必改
        seen: att.seen || 0,
        channel: att.channel || null,
        sharedBytes: att.sharedBytes || null,
      };

      if (att.channel) {
        if (!channels[att.channel]) channels[att.channel] = [];
        channels[att.channel].push(att.clientId);
      }
    }

    this.clients = clients;
    this.channels = channels;

    // 清掉已经不在场的密钥缓存
    for (const id of Object.keys(this.keyCache)) {
      if (!clients[id]) delete this.keyCache[id];
    }

    return clients;
  }

  /** 取会话密钥（CryptoKey）。attachment 里存的是原始字节，这里按需还原并缓存。 */
  async getSharedKey(clientId) {
    if (this.keyCache[clientId]) return this.keyCache[clientId];

    const client = this.clients[clientId];
    if (!client || !client.sharedBytes) return null;

    const bytes = client.sharedBytes instanceof Uint8Array
      ? client.sharedBytes
      : new Uint8Array(client.sharedBytes);

    const key = await importAesKey(bytes);
    this.keyCache[clientId] = key;
    return key;
  }

  /** 把字段写回 attachment。写不进去只记日志，不中断流程。 */
  updateAttachment(ws, patch) {
    const att = this.deserialize(ws);
    Object.assign(att, patch);
    try {
      ws.serializeAttachment(att);
    } catch (error) {
      logEvent('serialize-attachment', error, 'error');
    }
    return att;
  }

  // ---------------------------------------------------------------------------
  // 会话生命周期
  // ---------------------------------------------------------------------------

  async onOpenSession(ws) {
    await this.syncClients();
    await this.cleanupOldConnections();

    const clientId = generateClientId();

    if (!clientId || this.clients[clientId]) {
      this.closeConnection(ws);
      return;
    }

    // 先把身份写进 attachment —— 这是驱逐后唯一能存活的地方
    const att = this.updateAttachment(ws, {
      clientId,
      seen: getTime(),
      channel: null,
      sharedBytes: null,
    });

    this.clients[clientId] = {
      connection: ws,
      seen: att.seen,
      channel: null,
      sharedBytes: null,
    };

    logEvent('connection', clientId, 'debug');

    // Send RSA public key
    try {
      logEvent('sending-public-key', clientId, 'debug');
      this.sendMessage(ws, JSON.stringify({
        type: 'server-key',
        key: this.keyPair.rsaPublic
      }));
    } catch (error) {
      logEvent('sending-public-key', error, 'error');
    }
  }

  /** Hibernation 回调：收到消息。取代原来的 connection.addEventListener('message')。 */
  async webSocketMessage(ws, message) {
    await this.syncClients();

    const att = this.deserialize(ws);
    const clientId = att.clientId;

    if (!isString(message) || !clientId || !this.clients[clientId]) {
      return;
    }

    // 刷新活跃时间。内存和 attachment 都要写 —— attachment 才是驱逐后还活着的那个。
    const now = getTime();
    this.clients[clientId].seen = now;
    this.updateAttachment(ws, { seen: now });

    if (message === 'ping') {
      this.sendMessage(ws, 'pong');
      return;
    }

    // 只记长度，不记内容：密文单条可达数百 KB，全量打进日志既刷屏又会把
    // 消息内容落到 tail/日志里（即使是密文，也没必要留）。
    logEvent('message', [clientId, message.length], 'debug');

    const sharedKey = await this.getSharedKey(clientId);

    // Handle key exchange
    // 首帧格式： NC2 | 客户端 ECDH 公钥(hex)
    // 版本前缀必须匹配，否则直接关连接。老客户端走 v1 协议，
    // 不拦的话会在后面的 AEAD 解密阶段静默错乱，报错毫无指向性。
    if (!sharedKey && message.length < 2048) {
      if (!message.startsWith(PROTOCOL_VERSION + '|')) {
        logEvent('message-key-version', [clientId, 'unexpected handshake prefix'], 'error');
        this.closeConnection(ws);
        return;
      }
      try {
        // Generate ECDH key pair using P-384 curve (equivalent to secp384r1)
        const keys = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-384'
          },
          true,
          ['deriveBits', 'deriveKey']
        );

        const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);

        // 用 RSA 私钥对这把 ECDH 公钥签名：把「临时 ECDH 身份」绑到「RSA 身份」上。
        // 但 RSA 公钥本身未经认证，所以这是自洽性校验，不是身份认证。
        const signature = await crypto.subtle.sign(
          {
            name: 'RSASSA-PKCS1-v1_5'
          },
          this.keyPair.rsaPrivate,
          publicKeyBuffer
        );

        // Convert hex string to Uint8Array for client public key
        const clientPublicKeyHex = message.slice(PROTOCOL_VERSION.length + 1);

        // Import client's public key
        const clientPublicKey = await crypto.subtle.importKey(
          'raw',
          fromHex(clientPublicKeyHex),
          { name: 'ECDH', namedCurve: 'P-384' },
          false,
          []
        );

        // Derive shared secret bits (equivalent to computeSecret in Node.js)
        const sharedSecretBits = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: clientPublicKey
          },
          keys.privateKey,
          384 // P-384 produces 48 bytes (384 bits)
        );

        // 原实现： new Uint8Array(sharedSecretBits).slice(8, 40) —— 直接切字节当 AES 密钥。
        // 现在过 HKDF-SHA256，把非均匀的 ECDH 输出提取成均匀密钥材料。
        //
        // 存字节而不是 CryptoKey：CryptoKey 不能结构化克隆，写进 attachment 会直接失败。
        const sharedBytes = await deriveServerSessionKeyBytes(new Uint8Array(sharedSecretBits));

        this.clients[clientId].sharedBytes = sharedBytes;
        this.keyCache[clientId] = await importAesKey(sharedBytes);
        this.updateAttachment(ws, { sharedBytes });

        const response = PROTOCOL_VERSION + '|' +
          toHex(new Uint8Array(publicKeyBuffer)) +
          '|' + btoa(String.fromCharCode(...new Uint8Array(signature)));

        this.sendMessage(ws, response);

      } catch (error) {
        logEvent('message-key', [clientId, error], 'error');
        this.closeConnection(ws);
      }

      return;
    }

    // Handle encrypted messages
    if (sharedKey && message.length <= (8 * 1024 * 1024)) {
      await this.processEncryptedMessage(clientId, message);
    }
  }

  /** Hibernation 回调：连接关闭。取代原来的 connection.addEventListener('close')。 */
  async webSocketClose(ws, code, reason, wasClean) {
    await this.syncClients();

    const att = this.deserialize(ws);
    const clientId = att.clientId;
    if (!clientId) return;

    logEvent('close', [clientId, { code, reason, wasClean }], 'debug');

    const channel = this.clients[clientId]
      ? this.clients[clientId].channel
      : (att.channel || null);

    if (channel && this.channels[channel]) {
      // 先把自己从成员里摘掉，再把新名单广播给剩下的人
      this.channels[channel] = this.channels[channel].filter((id) => id !== clientId);

      if (this.channels[channel].length === 0) {
        delete (this.channels[channel]);
      } else {
        try {
          await this.broadcastMemberList(channel);
        } catch (error) {
          logEvent('close-list', [clientId, error], 'error');
        }
      }
    }

    delete (this.clients[clientId]);
    delete (this.keyCache[clientId]);
  }

  /** Hibernation 回调：socket 报错。 */
  async webSocketError(ws, error) {
    const att = this.deserialize(ws);
    logEvent('ws-error', [att.clientId || 'unknown', String(error)], 'error');
  }

  // Process encrypted messages
  async processEncryptedMessage(clientId, message) {
    let decrypted = null;

    try {
      const sharedKey = await this.getSharedKey(clientId);
      if (!sharedKey) return;

      decrypted = await decryptMessage(message, sharedKey);

      if (!isObject(decrypted) || !isString(decrypted.a)) {
        return;
      }

      // 只记动作类型，不记解密后的内容 —— 明文不该进日志。
      logEvent('message-decrypted', [clientId, decrypted.a], 'debug');

      const action = decrypted.a;

      if (action === 'j') {
        await this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        await this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        await this.handleChannelMessage(clientId, decrypted);
      }

    } catch (error) {
      logEvent('process-encrypted-message', [clientId, error], 'error');
    } finally {
      decrypted = null;
    }
  }

  // Handle channel join requests
  async handleJoinChannel(clientId, decrypted) {
    const client = this.clients[clientId];
    if (!isString(decrypted.p) || !client || client.channel) {
      return;
    }

    try {
      const channel = decrypted.p;

      client.channel = channel;
      this.updateAttachment(client.connection, { channel });

      if (!this.channels[channel]) {
        this.channels[channel] = [clientId];
      } else {
        this.channels[channel].push(clientId);
      }

      await this.broadcastMemberList(channel);

    } catch (error) {
      logEvent('message-join', [clientId, error], 'error');
    }
  }

  // Handle client messages
  async handleClientMessage(clientId, decrypted) {
    const client = this.clients[clientId];
    if (!isString(decrypted.p) || !isString(decrypted.c) || !client || !client.channel) {
      return;
    }

    try {
      const channel = client.channel;
      const targetClient = this.clients[decrypted.c];

      if (this.isClientInChannel(targetClient, channel)) {
        const targetKey = await this.getSharedKey(decrypted.c);
        if (!targetKey) return;

        const messageObj = {
          a: 'c',
          p: decrypted.p,
          c: clientId
        };

        const encrypted = await encryptMessage(messageObj, targetKey);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-client', [clientId, error], 'error');
    }
  }

  // Handle channel messages
  async handleChannelMessage(clientId, decrypted) {
    const client = this.clients[clientId];
    if (!isObject(decrypted.p) || !client || !client.channel) {
      return;
    }

    try {
      const channel = client.channel;
      // 过滤有效的目标成员
      const validMembers = Object.keys(decrypted.p).filter(member => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });

      // 处理所有有效的目标成员
      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const targetKey = await this.getSharedKey(member);
        if (!targetKey) continue;

        const messageObj = {
          a: 'c',
          p: decrypted.p[member],
          c: clientId
        };

        const encrypted = await encryptMessage(messageObj, targetKey);
        this.sendMessage(targetClient.connection, encrypted);

        messageObj.p = null;
      }

    } catch (error) {
      logEvent('message-channel', [clientId, error], 'error');
    }
  }

  // Broadcast member list to channel
  async broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];
      if (!members) return;

      for (const member of members) {
        const client = this.clients[member];

        if (this.isClientInChannel(client, channel)) {
          const key = await this.getSharedKey(member);
          if (!key) continue;

          const messageObj = {
            a: 'l',
            p: members.filter((value) => {
              return (value !== member ? true : false);
            })
          };

          const encrypted = await encryptMessage(messageObj, key);
          this.sendMessage(client.connection, encrypted);

          messageObj.p = null;
        }
      }
    } catch (error) {
      logEvent('broadcast-member-list', error, 'error');
    }
  }

  // Check if client is in channel
  isClientInChannel(client, channel) {
    return (
      client &&
      client.connection &&
      client.sharedBytes &&
      client.channel &&
      client.channel === channel ?
      true :
      false
    );
  }

  // Send message helper
  sendMessage(connection, message) {
    try {
      // In Cloudflare Workers, WebSocket.READY_STATE_OPEN is 1
      if (connection.readyState === 1) {
        connection.send(message);
      }
    } catch (error) {
      logEvent('sendMessage', error, 'error');
    }
  }

  // Close connection helper
  closeConnection(connection) {
    try {
      connection.close();
    } catch (error) {
      logEvent('closeConnection', error, 'error');
    }
  }

  // 连接清理方法
  async cleanupOldConnections() {
    await this.syncClients();

    const seenThreshold = getTime() - this.config.seenTimeout;
    const clientsToRemove = [];

    // 先收集需要移除的客户端，避免在迭代时修改对象
    for (const clientId in this.clients) {
      if (this.clients[clientId].seen < seenThreshold) {
        clientsToRemove.push(clientId);
      }
    }

    // 然后一次性移除所有过期客户端
    for (const clientId of clientsToRemove) {
      try {
        logEvent('connection-seen', clientId, 'debug');
        this.clients[clientId].connection.close();
        delete this.clients[clientId];
        delete this.keyCache[clientId];
      } catch (error) {
        logEvent('connection-seen', error, 'error');
      }
    }

    // 如果没有任何存活 socket 和房间，检查是否需要轮换密钥。
    // 判据用 getWebSockets()：Hibernation 下内存缓存随时可能是空的，不能用它判断。
    if (this.state.getWebSockets().length === 0 && Object.keys(this.channels).length === 0) {
      const pendingRotation = await this.state.storage.get('pendingKeyRotation');
      if (pendingRotation) {
        console.log('没有活跃客户端或房间，执行密钥轮换...');
        await this.state.storage.delete('rsaKeyPair');
        await this.state.storage.delete('pendingKeyRotation');
        this.keyPair = null;
        this._keyInitPromise = null; // 清掉记忆，让下面的递归真的重新生成
        await this.initRSAKeyPair();
      }
    }

    return clientsToRemove.length; // 返回清理的连接数量
  }
}
