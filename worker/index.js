import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime, deriveServerSessionKeyBytes, importAesKey, fromHex, toHex, BIN_FRAME_CHANNEL, CLIENT_ID_BYTES } from './utils.js';
import { handleBlob } from './blob.js';

// 协议版本。首帧必须带这个前缀，否则直接关连接（见 webSocketMessage）。
const PROTOCOL_VERSION = 'NC2';

// Turnstile 服务端校验端点。
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/**
 * 校验一枚 Turnstile token。
 *
 * 几个刻意的设计：
 *
 *  · **TURNSTILE_BYPASS 是给自动化脚本用的服务口令，不是 Turnstile token**。
 *    本项目所有测试（e2e-worker / send-file-to-peer / 房间规模压测）都直连线上，
 *    没有浏览器可以解 Turnstile。用一条独立的长随机串放行它们，它存在 Worker
 *    secret 里、不进仓库；泄露了随时换一个即可。**这是刻意留的口子，不是疏漏。**
 *
 *  · **fail-closed**：siteverify 网络失败 / 返回非 2xx / JSON 解析失败，一律拒绝。
 *    宁可挡掉一次正常连接（用户刷新即可），也不能让验证形同虚设。
 *
 *  · **token 由 Cloudflare 保证一次性**，所以这里不需要自己去重。
 */
async function verifyTurnstile(token, env, ip) {
  if (!isString(token) || token === '') {
    return false;
  }
  // 测试通道（见上方说明）
  if (env.TURNSTILE_BYPASS && safeEqual(token, env.TURNSTILE_BYPASS)) {
    return true;
  }
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  let res;
  try {
    res = await fetch(TURNSTILE_VERIFY_URL, { method: 'POST', body: form });
  } catch (error) {
    logEvent('turnstile-fetch', error, 'error');
    return false;
  }
  if (!res.ok) {
    logEvent('turnstile-http', res.status, 'error');
    return false;
  }
  let data;
  try {
    data = await res.json();
  } catch (error) {
    logEvent('turnstile-json', error, 'error');
    return false;
  }
  if (data.success !== true) {
    // error-codes 例如 invalid-input-response（token 重复用/过期）、
    // timeout-or-duplicate。记下来，不然线上被拒时无从查起。
    logEvent('turnstile-reject', data['error-codes']);
    return false;
  }
  return true;
}

// =============================================================================
// 来源（Origin）白名单
//
// **开源后保护自己实例的第一道闸。**
//
// 为什么必须有：客户端源码一旦公开，任何人都能拿它 fork 一版、把连接地址改指到
// 你这台服务器 —— 你的免费额度替他扛。浏览器**无法伪造** Origin 头，所以这一层
// 能干净地挡掉「网页壳一改就直连我」这条路径。
//
// 它不是万能墙：非浏览器客户端（curl / Node / 脚本）可以随手写一个 Origin 头。
// 所以它必须和 Turnstile **叠着用**，两者互补：
//   · Origin 白名单  -> 挡「网页 fork 一版指向我」
//   · Turnstile      -> 挡「脚本批量连」（要求真实浏览器、在我域名上解出挑战）
// 单用任何一个都有明显缺口，合起来才能把成本抬到「不值得」。
//
// 配置：wrangler.toml 的 [vars] ALLOWED_ORIGINS（逗号分隔多个）。
//   · **留空 = 完全不校验**。这样自建者 clone 下来开箱可用，也保住本地开发。
//   · 生产务必配上，否则该限制等于没有。
// =============================================================================

function allowedOriginList(env) {
  return String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * 这个请求的来源是否在白名单里。
 *
 * 注意「没带 Origin」的处理：浏览器发 WebSocket 时**一定**会带 Origin，
 * 所以缺这个头基本等于「不是网页客户端」。但为了不让自建者莫名其妙连不上，
 * 缺头时**不直接判死** —— 交给 Turnstile 去挡（那才是真正难伪造的一层）。
 * 只做「带了但不认识」的拒绝，误伤面最小。
 */
function originAllowed(request, env) {
  const allowed = allowedOriginList(env);
  if (allowed.length === 0) return true;        // 没配 = 不校验

  const origin = request.headers.get('Origin');
  if (!origin) return true;                     // 没带 -> 交给 Turnstile
  return allowed.includes(origin);
}

// =============================================================================
// 举报收件箱
//
// 为什么自建而不是在页面上留个邮箱：
//   · `cxywh.cn` **没有 MX 记录**（实测），`@cxywh.cn` 的信收不到；
//   · 把站长的私人邮箱印在公开页面上也不合适。
// 所以举报走 Worker -> DO storage：零成本、不依赖任何外部服务、不暴露邮箱、
// 不用额外申请任何东西。
//
// 必须说清的局限：**E2EE 意味着服务端读不到聊天内容**（这正是这应用存在的理由）。
// 所以举报人要自己提供证据（房间名/对方昵称/时间/截图）；没有证据时，
// 运营方能做的只有封出口 IP、封房间号。
//
// 存储放在既有的 ChatRoom DO 里（它已经是全局单实例），不新开 DO 类 ——
// 新开类要加 migration，为几张举报记录不值得动部署配置。
// =============================================================================

const REPORT_KEEP = 500;          // 最多保留多少条，超出丢最旧的
const REPORT_SHORT_MAX = 200;     // 房间名 / 昵称 / 时间 / 联系方式 的上限
const REPORT_DETAIL_MAX = 2000;   // 描述上限
const REPORT_PER_HOUR = 10;       // 同一 IP 每小时最多提交多少条
const REPORT_WINDOW_MS = 3600000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

/**
 * 定长比较。用 `!==` 比密钥会在第一个不同的字符处短路，比较耗时随匹配前缀变化，
 * 理论上能被逐字节猜出来。这里永远走满整串。
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** 取字符串字段并夹住长度。非字符串一律当空串。 */
function field(value, max) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

/** UTC 日界，形如 `2026-10-15`。用 UTC 而不是本地时区，免得跟着时区漂。 */
function dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

function reportStub(env) {
  return env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName('chat-room'));
}

/** 举报页的 HTML 转义。举报内容是对端可控的文本，直接拼进页面就是 XSS。 */
function esc(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function handleReportPost(request, env, clientIp) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'bad_json' }, 400);
  }

  const record = {
    ts: Date.now(),
    ip: clientIp,
    room: field(body.room, REPORT_SHORT_MAX),
    peer: field(body.peer, REPORT_SHORT_MAX),
    when: field(body.when, REPORT_SHORT_MAX),
    contact: field(body.contact, REPORT_SHORT_MAX),
    detail: field(body.detail, REPORT_DETAIL_MAX),
  };

  // 只有描述是必填 —— 房间名可能没记、昵称可能没看清，
  // 但这些都没记住不等于没被骚扰。描述是唯一无法替代的信息。
  if (record.detail.length < 10) {
    return json({ ok: false, error: 'detail_too_short' }, 400);
  }

  const res = await reportStub(env).fetch('https://chat-room.internal/internal/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(record),
  });
  const data = await res.json();
  return json(data, res.status);
}

/**
 * 清空收件箱。用 **POST** 而不是带副作用的 GET —— GET 有可能被浏览器预取、
 * 被爬虫抓、被放进历史记录里重放；带副作用的操作必须是显式的 POST。
 */
async function handleAdminClear(env, url) {
  if (!env.ADMIN_KEY) return new Response('Not Found', { status: 404 });
  if (!safeEqual(url.searchParams.get('key') || '', env.ADMIN_KEY)) {
    return new Response('Not Found', { status: 404 });
  }
  await reportStub(env).fetch('https://chat-room.internal/internal/reports', { method: 'DELETE' });
  return Response.redirect(url.origin + url.pathname + '?key=' + encodeURIComponent(env.ADMIN_KEY), 303);
}

async function handleAdminReports(env, url) {
  // 没配 ADMIN_KEY 就当作这个端点不存在 —— 别泄露「有这么个后台」。
  if (!env.ADMIN_KEY) return new Response('Not Found', { status: 404 });
  if (!safeEqual(url.searchParams.get('key') || '', env.ADMIN_KEY)) {
    return new Response('Not Found', { status: 404 });
  }

  const res = await reportStub(env).fetch('https://chat-room.internal/internal/reports');
  const data = await res.json();
  const reports = data.reports || [];

  const rows = reports.map((r) => `<tr>
    <td>${esc(new Date(r.ts).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }))}</td>
    <td>${esc(r.ip)}</td>
    <td>${esc(r.room)}</td>
    <td>${esc(r.peer)}</td>
    <td>${esc(r.when)}</td>
    <td>${esc(r.contact)}</td>
    <td class="d">${esc(r.detail)}</td>
  </tr>`).join('');

  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>举报收件箱</title><style>
body{margin:0;padding:20px;background:#fff;color:#333;
  font-family:'Roboto',Arial,'Microsoft YaHei',sans-serif;font-size:14px}
h1{font-size:18px;margin:0 0 4px}
p.n{color:#888;margin:0 0 16px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #e3e6ea;padding:7px 9px;text-align:left;vertical-align:top}
th{background:#fafbfc;font-weight:600;white-space:nowrap}
td.d{white-space:pre-wrap;max-width:460px}
tr:nth-child(even) td{background:#fcfdfe}
form{margin:0 0 14px}
button{padding:7px 16px;border:1px solid #d64545;background:#fff;color:#d64545;
  border-radius:4px;font-size:13px;font-family:inherit;cursor:pointer}
button:hover{background:#d64545;color:#fff}
</style></head><body>
<h1>举报收件箱</h1>
<p class="n">共 ${reports.length} 条（最多保留 ${REPORT_KEEP} 条，新的在前）</p>
<form method="post" onsubmit="return confirm('确定清空全部举报记录？此操作不可撤销。')">
  <button type="submit">清空全部</button>
</form>
<table><thead><tr><th>收到时间</th><th>来源 IP</th><th>房间</th><th>对方昵称</th>
<th>事发时间</th><th>联系方式</th><th>描述</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">暂无举报</td></tr>'}</tbody></table>
</body></html>`;

  // 后台密钥以查询串形式出现在 URL 中，因此该页面必须禁止缓存并禁止外发 Referer ——
  // 否则密钥会随页面进入浏览器磁盘缓存，或在页面内任何外链跳转时进入 Referer 头。
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    },
  });
}

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
    //
    // 注意：本地判据必须用 cf-connecting-ip，**不能用 hostname**：
    //    因为 wrangler.toml 里有 [[routes]] custom_domain = "chat.cxywh.cn"，
    //    wrangler dev 会把 request.url 的 host 和 Host 头**一起改写成 chat.cxywh.cn**。
    //    实测：请求 http://127.0.0.1:8787/ 时，Worker 看到的是
    //      url.hostname === 'chat.cxywh.cn'、host 头 === 'chat.cxywh.cn'
    //    所以按域名判断「是不是本地」在 dev 下永远为 false —— 会导致本机所有
    //    普通 HTTP 请求（含 /blob/ 上传下载）被 301 到线上，本地根本没法测。
    //
    //    request.cf / cf-colo 也不行：miniflare 会模拟（实测 colo='HKG'，
    //    request.cf 存在），同样区分不出。
    //    而 cf-connecting-ip 在生产恒为客户端公网 IP，dev 下是 127.0.0.1 —— 可用。
    const clientIp = request.headers.get('cf-connecting-ip') || '';
    const isLocalDev = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';
    const scheme = request.headers.get('X-Forwarded-Proto')
      || url.protocol.replace(':', '');
    if (!isWebSocket && !isLocalDev && scheme === 'http') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }

    // 处理WebSocket请求
    if (isWebSocket) {
      // 人机验证。门槛只放在**建连**这一步，消息路径完全不动。
      //
      // 为什么必须挡在这里：免费版额度一旦超了是直接拒绝服务（不是降速），
      // 所以被机器人/机会性滥用者都代价是「所有正常用户一起用不了」。
      // 而建连是唯一一次性的、便宜的校验点 —— 每条消息都验的话，
      // siteverify 的往返会把聊天延迟拖垮。
      //
      // 两种不校验的情况：
      //   · 本地开发（wrangler dev，cf-connecting-ip 是回环）—— 没有真实 Turnstile 可解
      //   · 没配 TURNSTILE_SECRET —— 行为与接入前完全一致，方便灰度
      const rawToken = url.searchParams.get('t') || '';
      // 测试通道：token 命中 TURNSTILE_BYPASS。这个值只有我们自己知道，
      // 它决定 DO 侧的 IP 限流是否豁免（拿给自动化脚本用）。
      const isTestChannel = !!(env.TURNSTILE_BYPASS && safeEqual(rawToken, env.TURNSTILE_BYPASS));
      // 本地开发也当测试通道 —— cf-connecting-ip 是回环，所有本地测试共用一个 key。
      const testChannel = isTestChannel || isLocalDev;

      // 来源白名单。排在 Turnstile **之前** —— 它是本地的字符串比对，成本几乎为零，
      // 让明显不该来的请求连 siteverify 的往返都不用付。
      //
      // **必须排在 `isTestChannel` 声明之后**。它要用到这个 const，放前面会踩暂时性
      // 死区（TDZ），整个 WS 分支报 `Cannot access 'isTestChannel' before initialization`
      // —— 线上表现是**所有建连 500**，而不是 403，容易误判为"部署故障"。（已实测复现）
      //
      // 测试通道与本地开发跳过 —— 自动化脚本从命令行发起，不带 Origin。
      if (!isLocalDev && !isTestChannel && !originAllowed(request, env)) {
        logEvent('origin-rejected', request.headers.get('Origin') || '(none)', 'error');
        return new Response('本站只服务于自己的前端页面。若你在使用第三方客户端，请改连你自己的服务器。', {
          status: 403,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }
      if (!isLocalDev && env.TURNSTILE_SECRET) {
        if (!await verifyTurnstile(rawToken, env, clientIp)) {
          return new Response('人机验证未通过，请刷新页面重试。', {
            status: 403,
            headers: { 'content-type': 'text/plain; charset=utf-8' },
          });
        }
      }
      // 把「这是测试通道吗」告诉 DO：DO 里要据此豁免 IP 限流（自动化脚本会从同一个
      // 出口 IP 开上百条连接）。
      //
      // **必须先 delete 再 set**：入站请求可能自带一个伪造的 x-nc-test-channel，
      // 如果不删就直接 set，客户端只要手写这个头就能直接取得豁免。
      // 这里先无条件删掉，再根据**我们自己的** Turnstile 校验结果决定是否设置。
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      const fwdHeaders = new Headers(request.headers);
      fwdHeaders.delete('x-nc-test-channel');
      if (testChannel) fwdHeaders.set('x-nc-test-channel', '1');
      return stub.fetch(new Request(request, { headers: fwdHeaders }));
    }

    // 文件密文端点（R2）。只在路径匹配 /blob/... 时接管，其余交回下面的路由。
    // 放在这里而不是 DO 里：文件密文不该经过 Durable Object —— 那会把时长计费
    // 和单对象吞吐都拖进大文件传输路径。
    const blobResponse = await handleBlob(request, env, url);
    if (blobResponse) return blobResponse;

    // 举报入口的后端。**必须放在下面 /api/ 回退之前** —— 那个回退只返回 {ok:true}，
    // 写在它后面会被吃掉，表现为「提交成功但什么都没存」。
    if (url.pathname === '/api/report') {
      return handleReportPost(request, env, clientIp);
    }
    if (url.pathname === '/admin/reports') {
      if (request.method === 'POST') return handleAdminClear(env, url);
      return handleAdminReports(env, url);
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
      // 连接活跃超时：超过该时长未收到任何消息的连接，由 cleanupOldConnections()
      // 关闭并回收。服务端在收到任何消息时刷新该连接的时间戳，客户端以 pingInterval
      // 周期发送 'ping' 维持活跃。取 180 秒是为了容忍移动端页面进入后台后定时器被
      // 系统节流的情况。该值同时决定异常断线（未收到 close 帧）的最长滞留时间，
      // 因此不宜过大。
      seenTimeout: 180000,
      debug: false,

      // IP 级建连频率限制（精确计数，见 allowConnection 的说明）
      connWindowMs: 60000,      // 滑动窗口长度
      maxConnPerMinute: 60,     // 窗口内单个 IP 允许的建连次数
      maxTrackedIps: 5000,      // ipHits 的规模上限，防止无界增长

      // 每 IP 每日建连上限。**这条和上面那个 60/分钟是两种不同的保护**，都要有：
      //   · 60/分钟  -> 挡「瞬时洪水」，防的是把 DO 打爆
      //   · 每日上限 -> 挡「细水长流」，防的是单个 IP 把一整天的免费额度耗光
      // 只靠分钟限制的话：60 × 60 × 24 = 86,400 次/天，一个 IP 就能吃掉全天额度。
      // 3000 的取值理由：校园/机房 NAT 后面几十人共用出口 IP，每人每天重连十几次
      // 大约几百次，3000 有十倍余量；而一个滥用的 IP 被压到全天额度的 3% 上下。
      // 有真实用户被误伤就调大它 —— 这个数字是运营参数，不是安全边界。
      maxConnPerIpPerDay: 3000,

      // ── 房间人数封顶 ────────────────────────────────────────────────────
      // 实测依据（N 个客户端**同时**进房 = 最坏情况；本机 i7 桌面、Node）：
      //     N= 50 -> 全体握手  6.8s   ✓
      //     N= 80 -> 全体握手 12.7s   ✓
      //     N= 90 -> 全体握手 15.2s   ✓
      //     N= 95 -> 握手超时未完成   ✗   ← 不稳定区从这里开始
      //    N=100 -> 一次 19.1s 成功、一次超时   ← 同一参数掷硬币
      //    N=150 -> 连接本身就 48.7s，握手从未完成
      //
      // 关键：90 以上**不是稳定地崩，是偶发失败**。这比稳定崩更糟 —— 用户进了
      // 个坏房间却看不出原因（每个客户端只握到 0~94 个对端，密钥倒是握了 122 套），
      // 只会觉得「这软件时好时坏」。封顶因此必须落在**稳定区**内。
      //
      // 取 50 而不是 80/90：上面那组数跑在桌面 CPU 上、且 N 个客户端挤在一个
      // Node 进程里；真实用户是手机，ARM 上的 WebCrypto 明显更慢，而**手机上的
      // 断点没有实测过**。50 相对不稳定区（95+）留了近一倍余量，足以吸收客户端
      // 变慢而不必改这个数。要放开就改这一个值 —— 改完请重跑容量测试。
      //
      // 为什么这拦得住：判定只读 state.getWebSockets() 上活 socket 的 attachment
      // （syncClients 重建出的 channels），客户端改源码也伪造不了。
      maxRoomMembers: 50,

      // 全站并发保险丝。所有房间共用**同一个 DO 实例**（idFromName('chat-room')），
      // 单点风险就落在它身上：硬上限 32,768 个 socket、软上限约 1,000 req/s。
      // 500 是**策略值不是容量值** —— 远低于硬上限，同时让转发负载可控。
      // 有真实用量后再回头调。
      maxTotalMembers: 500,
    };

    // ip -> 窗口内的建连时间戳数组。由 storage 支撑（Hibernation 会驱逐内存，
    // 见 loadIpHits 的说明），`ipHitsLoaded` 保证每个实例只读一次 storage。
    this.ipHits = new Map();
    // ip -> { d: 'YYYY-MM-DD'(UTC), n: 当日计数 }。同样由 storage 支撑。
    this.ipDaily = new Map();
    this.ipHitsLoaded = false;

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

  /**
   * 收一条举报。
   *
   * 两个上限都是为了防止「举报接口自己被拿来刷」：
   *   · 同一 IP 每小时 REPORT_PER_HOUR 条 —— 靠**扫描已存记录**算出来，不额外存计数器：
   *     数组最多 REPORT_KEEP 条，扫一遍很便宜，少一份要维护的状态。
   *   · 总量封顶 REPORT_KEEP 条，超出丢最旧的。举报是**给人看的**，不是审计日志，
   *     没有无限留存的必要；留 500 条足够，也免得存储无限长大。
   */
  async handleReportSubmit(request) {
    let record;
    try {
      record = await request.json();
    } catch {
      return Response.json({ ok: false, error: 'bad_json' }, { status: 400 });
    }

    const now = Date.now();
    const stored = (await this.state.storage.get('reports')) || [];

    const recent = stored.filter((r) => r.ip === record.ip && now - r.ts < REPORT_WINDOW_MS);
    if (recent.length >= REPORT_PER_HOUR) {
      return Response.json({ ok: false, error: 'too_many' }, { status: 429 });
    }

    const next = [record, ...stored].slice(0, REPORT_KEEP);
    await this.state.storage.put('reports', next);
    return Response.json({ ok: true, total: next.length });
  }

  /**
   * IP 级建连频率限制 —— **精确计数**，滑动窗口。
   *
   * 为什么不用 Workers 的 `[[ratelimits]]` binding：本机线上实测，它在可用的阈值
   * 区间里根本不执法（limit=30 和 60 时，同一 IP 连打 200 次全部放行；只有压到
   * limit=1 才拦得住）。详见 wrangler.toml 顶部那张实测表。
   *
   * 为什么放 DO 里：连接本来就要进这个 DO，**不增加额外往返**；计数确定性，
   * 不受「机房本地缓存 + 异步同步」的滞后影响。
   *
   * **必须落 storage，只靠内存不行**（实测打回）：Hibernation 下 DO 在没有活
   * socket 时会被驱逐，内存里的 Map 直接没了。实测表现是「同一 IP 连打 90 次全部
   * 放行」—— 因为每次 curl 建完就连断，DO 每次都当新实例启动，计数永远累不起来。
   *
   * 所以：**load 一次到内存 -> 同步判定/累加 -> 落盘**。判定在内存里同步做，
   * 避免多个 fetch 交错 await 时读到同一份旧值（那正是洪水场景）。
   *
   * 代价是每次建连 1 读 + 1 写 storage。建连是低频事件（不是每条消息），
   * 这个量级可以接受。
   *
   * 判据是**建连次数**，不是并发数 —— 并发封顶是另一件事。
   */
  async loadIpHits() {
    if (this.ipHitsLoaded) return;
    try {
      const [stored, daily] = await Promise.all([
        this.state.storage.get('ipRate'),
        this.state.storage.get('ipDaily'),
      ]);
      this.ipHits = new Map(Object.entries(stored || {}));
      this.ipDaily = new Map(Object.entries(daily || {}));
    } catch (error) {
      logEvent('ratelimit-load', error, 'error');
      // 读失败当空表：宁可漏放，不能把所有人挡在门外。
      this.ipHits = new Map();
      this.ipDaily = new Map();
    }
    this.ipHitsLoaded = true;
  }

  /** 把裁剪后的窗口写回 storage。失败只记日志，不影响放行结果。 */
  async persistIpHits() {
    const now = getTime();
    // 一并清理窗口外已经全空的条目 —— 否则「来过一次就再没来的 IP」会永久占着
    // storage，表只会单向增长。
    const alive = {};
    for (const [ip, hits] of this.ipHits) {
      const fresh = hits.filter((t) => now - t < this.config.connWindowMs);
      if (fresh.length > 0) alive[ip] = fresh;
    }
    // 日计数：只留今天的。过了一天就归零 —— 用 UTC 日界而不是本地时区，
    // 免得跟着运营商/机器时区漂。
    const today = dayKey(now);
    const daily = {};
    for (const [ip, rec] of this.ipDaily) {
      if (rec && rec.d === today) daily[ip] = rec;
    }

    try {
      await this.state.storage.put({ ipRate: alive, ipDaily: daily });
    } catch (error) {
      logEvent('ratelimit-persist', error, 'error');
    }
  }

  allowConnection(ip) {
    // 拿不到 IP 就放行。这条路径上 cf-connecting-ip 一定存在（Cloudflare 注入），
    // 真为空说明是异常请求 —— 宁可放过一次，也不要因为判据缺失把所有人挡在外面。
    if (!ip) return true;

    const now = getTime();

    // ① 日上限。跨天就重置 —— 存的是日期字符串，比时间戳好读、也不会被闰秒之类的影响。
    const today = dayKey(now);
    const dayRec = this.ipDaily.get(ip);
    const dayCount = dayRec && dayRec.d === today ? dayRec.n : 0;
    if (dayCount >= this.config.maxConnPerIpPerDay) {
      return false;                // 跨天了不写回，留着让 persist 清掉
    }

    // ② 分钟窗口。
    const hits = (this.ipHits.get(ip) || []).filter((t) => now - t < this.config.connWindowMs);
    if (hits.length >= this.config.maxConnPerMinute) {
      this.ipHits.set(ip, hits);   // 写回裁剪后的数组，别让窗口外的旧时间戳一直占着
      return false;
    }

    // 两条都过了才记账 —— 被拒的那次不该占用配额。
    hits.push(now);
    this.ipHits.set(ip, hits);
    this.ipDaily.set(ip, { d: today, n: dayCount + 1 });
    this.pruneIpHits(now);
    return true;
  }

  /** 只在表太大时才做全表清理：正常规模下没必要每次都遍历。 */
  pruneIpHits(now) {
    if (this.ipHits.size <= this.config.maxTrackedIps) return;
    for (const [ip, hits] of this.ipHits) {
      if (!hits.some((t) => now - t < this.config.connWindowMs)) {
        this.ipHits.delete(ip);
      }
    }
  }

  async fetch(request) {
    // 举报收件箱的内部端点。**只由 Worker 转发进来**（公网无法直达 DO 实例），
    // 所以这里不再重复鉴权 —— 鉴权在 Worker 层（见 handleAdminReports）。
    const path = new URL(request.url).pathname;
    if (path === '/internal/report') {
      return this.handleReportSubmit(request);
    }
    if (path === '/internal/reports') {
      if (request.method === 'DELETE') {
        await this.state.storage.delete('reports');
        return Response.json({ ok: true, cleared: true });
      }
      const stored = await this.state.storage.get('reports');
      return Response.json({ reports: stored || [] });
    }

    // Check for WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    // IP 级建连频率限制。放在**创建 socket 之前** —— 被拒的连接不该占用 socket、
    // 不该触发密钥协商，更不该开始计 DO 时长。
    //
    // 测试通道豁免：本项目的自动化脚本（room-scale 压 150 连接、e2e-worker）本来就从
    // 同一个出口 IP 开上百条连接，被拦就没法测了。这个标志由 Worker 侧根据
    // TURNSTILE_BYPASS 校验结果设置，并且**转发前先 delete 掉同名头**，
    // 所以客户端伪造不了（见 worker/index.js 里 WS 分支的转发处）。
    const ip = request.headers.get('cf-connecting-ip') || '';
    const isTestChannel = request.headers.get('x-nc-test-channel') === '1';
    if (!isTestChannel) {
      await this.loadIpHits();
      if (!this.allowConnection(ip)) {
        logEvent('ratelimit-conn', ip, 'error');
        return new Response('连接过于频繁，请等一分钟再试。', {
          status: 429,
          headers: {
            'content-type': 'text/plain; charset=utf-8',
            'retry-after': '60',
          },
        });
      }
      // 放行了才落盘 —— 被拒的连接不该产生写。
      await this.persistIpHits();
    }

    // 全站并发保险丝。数活着的 socket —— DO 被驱逐过这个数依然可信
    // （socket 由运行时托管，不随内存消失）。放在 RSA 初始化之前，最便宜。
    const liveSockets = this.state.getWebSockets();
    if (liveSockets.length >= this.config.maxTotalMembers) {
      logEvent('total-cap-reached', [liveSockets.length, this.config.maxTotalMembers], 'error');
      return new Response('服务当前连接数已达上限，请稍后再试。', {
        status: 503,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
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

    if (!clientId || !this.clients[clientId]) {
      return;
    }

    // 二进制帧 = 批量数据通道（文件分卷）。服务端**不做任何加解密**，只读帧头
    // 16 字节的路由信息然后原样转发：载荷自始至终是发送方与接收方之间的 AEAD
    // 密文，服务端既解不开也不需要解。
    //
    // 省掉的不只是服务端每卷一次 AES，更是链路上的两次 base64 —— 实测膨胀
    // 从 137% 降到 0.017%（见 client/js/aead.js「二进制通道」）。
    if (typeof message !== 'string') {
      await this.relayBinary(ws, clientId, message);
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
      const members = this.channels[channel] || [];

      // 房间已满就拒绝。数的是**频道内活着的成员** —— 每次进到 DO 都先跑过
      // syncClients()，channels 是从 socket 的 attachment 重建的，所以这个数
      // 既准又伪造不了（客户端自称的名单一概不采信）。
      if (members.length >= this.config.maxRoomMembers) {
        logEvent('room-full', [channel, members.length, this.config.maxRoomMembers]);
        await this.rejectJoin(clientId, 'room-full', this.config.maxRoomMembers);
        return;
      }

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

  /**
   * 拒绝入房：先把理由发出去，再主动断开。**顺序不能反** ——
   * WebSocket 保证有序，先发后断客户端才收得到；反过来客户端只看到「莫名其妙
   * 被断开」，会触发它自己的自动重连（reconnectDelay 3s），把满房间反复撞。
   *
   * 客户端收到 a='err' 后置 _rejected 标志、停在失败态不再重连
   * （见 NodeCrypt.js 的 err 分支与 room.js 的 onServerError）。
   */
  async rejectJoin(clientId, code, limit) {
    const client = this.clients[clientId];
    if (!client) return;

    try {
      const key = await this.getSharedKey(clientId);
      if (key) {
        const encrypted = await encryptMessage({ a: 'err', code, p: limit }, key);
        this.sendMessage(client.connection, encrypted);
      }
    } catch (error) {
      logEvent('reject-join-send', error, 'error');
    }

    try {
      client.connection.close(4001, code);
    } catch (error) {
      logEvent('reject-join-close', error, 'error');
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

  // 转发二进制帧（批量数据）。
  //
  // 帧格式（客户端侧定义见 client/js/aead.js）：
  //   [0]       0x02   帧类型
  //   [1..16]   目标 clientId（发往服务端时）/ 来源 clientId（转发给接收方时）
  //   [17..]    IV || 密文 || 认证标签
  //
  // 服务端只做两件事：读帧头找目标、把来源字段换掉。**不解析、不解密、不改动**
  // 后面任何一个字节 —— 所以它既看不到内容，也没有机会篡改而不被发现
  // （AEAD 认证会兜住）。
  async relayBinary(ws, clientId, message) {
    try {
      const bytes = message instanceof ArrayBuffer
        ? new Uint8Array(message)
        : new Uint8Array(message.buffer, message.byteOffset || 0, message.byteLength);

      if (bytes.length < 1 + CLIENT_ID_BYTES || bytes[0] !== BIN_FRAME_CHANNEL) {
        // 不是本协议认识的二进制帧。不记内容（可能是任意字节，打进日志等于
        // 把用户数据落到日志里），只记长度。
        logEvent('binary-unknown', [clientId, bytes.length], 'debug');
        return;
      }

      const sender = this.clients[clientId];
      if (!sender || !sender.channel) {
        return;
      }

      let targetId = '';
      for (let i = 1; i <= CLIENT_ID_BYTES; i++) {
        targetId += String.fromCharCode(bytes[i]);
      }

      const target = this.clients[targetId];
      // 目标必须存在**且在同一频道**。少了后半句，A 就能把数据塞进别的房间 ——
      // 密文虽然解不开，但这种「跨房间投递」本身就不该被允许。
      if (!target || !this.isClientInChannel(target, sender.channel)) {
        return;
      }

      const out = new Uint8Array(bytes.length);
      out[0] = BIN_FRAME_CHANNEL;
      for (let i = 0; i < CLIENT_ID_BYTES; i++) {
        out[i + 1] = clientId.charCodeAt(i);
      }
      out.set(bytes.subarray(1 + CLIENT_ID_BYTES), 1 + CLIENT_ID_BYTES);

      this.sendMessage(target.connection, out);
    } catch (error) {
      logEvent('binary-relay', [clientId, error], 'error');
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
