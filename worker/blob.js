// 文件密文端点（R2）
//
// 设计要点：
//
// 1. **这里经手的全是密文。** 客户端在浏览器里用 AES-GCM 分块加密，密钥从不
//    发到服务端，只通过既有的端到端加密通道（DO 中继）发给房间里的其他人。
//    所以这个端点不需要鉴权 —— 拿到 blobId 也只能下到一堆解不开的字节。
//
// 2. **对象名不含任何身份信息。** blobId 是 32 字节随机数的十六进制，对象名是
//    `<blobId>/<块号>`。没有文件名、没有房间号、没有用户 id，服务端无法把存储
//    里的对象关联回任何人。
//
// 3. **Range 透传。** 下载支持断点续传，浏览器刷新后能接着下，不用从头再来。
//
// 4. **绝不回传真实 MIME。** 一律 application/octet-stream，避免"服务端知道这是
//    图片还是视频"这类泄漏。

const MAX_CHUNK = 16 * 1024 * 1024;   // 单块密文上限（明文块 4 MiB + GCM tag，留足余量）
const BLOB_ID_RE = /^[0-9a-f]{64}$/;   // 32 字节随机数的 hex
const INDEX_RE = /^\d{1,6}$/;

/**
 * 处理 /blob/<blobId>/<index>
 * @returns {Response|null} 不匹配则返回 null，交给后面的路由
 */
export async function handleBlob(request, env, url) {
  if (!url.pathname.startsWith('/blob/')) return null;

  const parts = url.pathname.split('/').filter(Boolean);   // ['blob', blobId, index]
  if (parts.length !== 3) return jsonErr('bad path', 400);

  const [, blobId, index] = parts;
  // 严格校验：blobId 必须是 64 位小写 hex。不合法就直接拒，绝不把用户输入
  // 拼进对象名 —— 否则 `../` 之类有可能越界到别的键空间。
  //
  // 放在绑定检查**之前**：拒绝垃圾输入不该依赖环境，同一个请求在有没有 R2 的
  // 部署上都该得到同样的 400，而不是一处 400、另一处 503。
  if (!BLOB_ID_RE.test(blobId) || !INDEX_RE.test(index)) {
    return jsonErr('bad path', 400);
  }

  // 绑定没配好时给出明确诊断，而不是 500 "undefined is not an object"。
  // R2 需要在控制台绑定支付方式才能启用，所以生产上这里很可能就是 503 ——
  // 客户端 isR2Available() 正是靠这个 503 判定「走降级路径」。
  if (!env.FILES) {
    return jsonErr('R2 binding "FILES" is not configured', 503);
  }

  const objectKey = `${blobId}/${index}`;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  if (request.method === 'PUT') {
    return putChunk(request, env, objectKey);
  }

  if (request.method === 'GET' || request.method === 'HEAD') {
    return getChunk(request, env, objectKey);
  }

  return jsonErr('method not allowed', 405);
}

/** 上传一块密文 */
async function putChunk(request, env, objectKey) {
  const len = Number(request.headers.get('content-length') || 0);

  if (!len) return jsonErr('content-length required', 411);
  if (len > MAX_CHUNK) return jsonErr('chunk too large', 413);
  if (!request.body) return jsonErr('empty body', 400);

  try {
    // 流式写进 R2，不在 Worker 里把整块读进内存
    await env.FILES.put(objectKey, request.body, {
      httpMetadata: { contentType: 'application/octet-stream' },  // 永不暴露真实 MIME
    });
  } catch (error) {
    return jsonErr('r2 put failed: ' + (error && error.message ? error.message : error), 502);
  }

  return new Response(null, { status: 204, headers: corsHeaders() });
}

/** 下载一块密文（支持 Range 续传） */
async function getChunk(request, env, objectKey) {
  // 只在客户端真的带了 Range 时才把 range 选项传给 R2。
  // 无条件传 request.headers 会让 R2 把普通 GET 也当成区间请求，返回 206 —— 虽然
  // 合法，但语义不对，也会让「全量下载」和「续传」两种情况难以区分。
  const rangeHeader = request.headers.get('range');

  let obj;
  try {
    obj = await env.FILES.get(objectKey, rangeHeader ? { range: request.headers } : {});
  } catch (error) {
    return jsonErr('r2 get failed: ' + (error && error.message ? error.message : error), 502);
  }

  if (!obj) return jsonErr('not found', 404);

  const headers = corsHeaders();
  headers.set('content-type', 'application/octet-stream');
  headers.set('accept-ranges', 'bytes');
  headers.set('etag', obj.httpEtag);
  headers.set('cache-control', 'public, max-age=31536000, immutable');
  // 密文内容由客户端认证（AES-GCM），这里只是搬运工，标记一下便于排查
  headers.set('x-blob-encrypted', 'aes-256-gcm');

  const isHead = request.method === 'HEAD';

  if (obj.range) {
    const start = obj.range.offset ?? 0;
    const end = obj.range.end ?? (obj.size - 1);
    headers.set('content-range', `bytes ${start}-${end}/${obj.size}`);
    headers.set('content-length', String(end - start + 1));
    return new Response(isHead ? null : obj.body, { status: 206, headers });
  }

  headers.set('content-length', String(obj.size));
  return new Response(isHead ? null : obj.body, { status: 200, headers });
}

function corsHeaders() {
  // 前端和端点同源（都在 chat.cxywh.cn），这里加 CORS 只是为了将来套壳 App 或
  // 自定义域不同时能用上，不构成安全边界 —— 安全边界是「密钥不在服务端」。
  return new Headers({
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, HEAD, PUT, OPTIONS',
    'access-control-allow-headers': 'content-type, content-length, range',
    'access-control-expose-headers': 'content-range, content-length, etag, accept-ranges',
    'access-control-max-age': '86400',
  });
}

function jsonErr(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
