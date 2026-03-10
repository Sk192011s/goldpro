// =====================================================
// R2 M3U8 Streaming Proxy for Deno Deploy
// Memory-efficient: pipe/stream based, no full buffering
// Hardened: path traversal, XSS, rate-limit, auth, cache limits
// Fixed: APK player compatibility, concurrent multi-user streaming,
//        API key propagation to segments, relative path rewriting
// =====================================================

const R2_BASE_URL = Deno.env.get("R2_BASE_URL") || "";

// ---------- Security Config ----------
const API_KEY = Deno.env.get("PROXY_API_KEY") || "";

const ALLOWED_DOMAINS = [
  "pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  "pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
];

// Allowed file extensions for streaming
const ALLOWED_EXTENSIONS = new Set([
  "m3u8", "ts", "mp4", "fmp4", "m4s", "key", "vtt", "srt",
]);

// ---------- Rate Limiting (per-IP, adaptive for concurrent users) ----------
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW = 60_000;
// TS segment တွေ အများကြီးရှိတဲ့အတွက် per-IP limit ကို မြှင့်ထားပါတယ်
// user တစ်ယောက်ကြည့်ရင် ~60-120 segment requests/min ဖြစ်တတ်
const RATE_LIMIT_MAX = 600;
const RATE_LIMIT_CLEANUP_INTERVAL = 2 * 60_000;

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW * 2) {
      rateLimitMap.delete(key);
    }
  }
}, RATE_LIMIT_CLEANUP_INTERVAL);

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }

  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

// ---------- M3U8 Cache (size-limited) ----------
interface M3U8CacheEntry {
  raw: string;
  cachedAt: number;
}

const m3u8Cache = new Map<string, M3U8CacheEntry>();
const M3U8_CACHE_TTL = 5 * 60 * 1000;
const M3U8_CACHE_MAX_SIZE = 1000; // concurrent users များရင် cache entry ပိုလို

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of m3u8Cache) {
    if (now - entry.cachedAt > M3U8_CACHE_TTL) {
      m3u8Cache.delete(key);
    }
  }
}, 3 * 60 * 1000);

function cacheM3U8(key: string, raw: string): void {
  if (m3u8Cache.size >= M3U8_CACHE_MAX_SIZE) {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [k, entry] of m3u8Cache) {
      if (entry.cachedAt < oldestTime) {
        oldestTime = entry.cachedAt;
        oldestKey = k;
      }
    }
    if (oldestKey) m3u8Cache.delete(oldestKey);
  }
  m3u8Cache.set(key, { raw, cachedAt: Date.now() });
}

// ---------- Active connection tracking ----------
let activeConnections = 0;
// concurrent users ပိုများအောင် connection limit မြှင့်
const MAX_ACTIVE_CONNECTIONS = 500;

// ---------- Helpers ----------

function validateConfig(): boolean {
  if (!R2_BASE_URL) return false;
  try {
    const url = new URL(R2_BASE_URL);
    return ALLOWED_DOMAINS.includes(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Path ကို sanitize လုပ်ပြီး path traversal attack ကာကွယ်
 */
function sanitizePath(rawPath: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return null;
  }

  if (decoded.includes("..") || decoded.includes("\\")) {
    return null;
  }

  const normalized = "/" + decoded.replace(/\/+/g, "/").replace(/^\/+/, "");

  const ext = normalized.split(".").pop()?.toLowerCase() || "";
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return null;
  }

  if (normalized.includes("\0")) {
    return null;
  }

  return normalized;
}

/**
 * API Key authentication
 * Header: X-API-Key: <key>
 * OR query param: ?key=<key>
 */
function authenticateRequest(req: Request, url: URL): boolean {
  if (!API_KEY) return true;

  const headerKey = req.headers.get("X-API-Key");
  if (headerKey && timingSafeCompare(headerKey, API_KEY)) return true;

  const queryKey = url.searchParams.get("key");
  if (queryKey && timingSafeCompare(queryKey, API_KEY)) return true;

  return false;
}

/**
 * Timing-safe string comparison
 */
function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    let result = a.length ^ b.length;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
    }
    return result === 0;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * CORS headers - APK players နဲ့ compatible ဖြစ်အောင် ပြင်ထား
 */
function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers":
      "Range, Content-Type, X-API-Key, Authorization, Accept, Accept-Encoding, User-Agent",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Range, Content-Type, Accept-Ranges, X-Cache",
    "Access-Control-Max-Age": "86400",
  };
}

/**
 * Content-Type - APK player compatible types
 */
function getContentType(path: string, userAgent: string = ""): string {
  const ext = path.split(".").pop()?.toLowerCase() || "";

  // m3u8 အတွက် APK player compatibility
  if (ext === "m3u8") {
    // အချို့ Android player တွေက apple.mpegurl ကို နားမလည်
    const ua = userAgent.toLowerCase();
    if (
      ua.includes("android") ||
      ua.includes("exoplayer") ||
      ua.includes("okhttp") ||
      ua.includes("stagefright")
    ) {
      return "application/x-mpegURL";
    }
    return "application/vnd.apple.mpegurl";
  }

  const types: Record<string, string> = {
    ts: "video/mp2t",
    mp4: "video/mp4",
    fmp4: "video/mp4",
    m4s: "video/iso.segment",
    key: "application/octet-stream",
    json: "application/json",
    vtt: "text/vtt",
    srt: "text/plain",
  };
  return types[ext] || "application/octet-stream";
}

function getClientIP(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * M3U8 rewrite - absolute URLs, relative URLs, URI attributes အားလုံး ပြောင်းပေး
 * API key ကိုလည်း segment URL တိုင်းမှာ ထည့်ပေး
 *
 * @param content - raw m3u8 content
 * @param proxyBase - proxy server base URL (e.g., https://yourproxy.deno.dev)
 * @param currentDir - current m3u8 file ရဲ့ directory path (relative path resolve အတွက်)
 * @param apiKey - API key (segment URLs မှာ ထည့်ဖို့)
 */
function rewriteM3U8(
  content: string,
  proxyBase: string,
  currentDir: string,
  apiKey: string | null,
): string {
  const lines = content.split("\n");
  const out: string[] = [];
  const keyQuery = apiKey ? `?key=${encodeURIComponent(apiKey)}` : "";

  for (const line of lines) {
    const trimmed = line.trim();

    // Empty line → keep
    if (trimmed === "") {
      out.push(line);
      continue;
    }

    // HLS tags that contain URI attribute (e.g., #EXT-X-KEY, #EXT-X-MAP)
    if (trimmed.startsWith("#") && trimmed.includes('URI="')) {
      const replaced = trimmed.replace(
        /URI="([^"]+)"/g,
        (_match, uri: string) => {
          const resolvedPath = resolveAndRewriteUri(
            uri,
            proxyBase,
            currentDir,
            keyQuery,
          );
          return `URI="${resolvedPath}"`;
        },
      );
      out.push(replaced);
      continue;
    }

    // Comment / tag lines without URI → keep as-is
    if (trimmed.startsWith("#")) {
      out.push(line);
      continue;
    }

    // Non-comment line = segment/playlist URL → rewrite
    const rewritten = resolveAndRewriteUri(
      trimmed,
      proxyBase,
      currentDir,
      keyQuery,
    );
    out.push(rewritten);
    continue;
  }

  return out.join("\n");
}

/**
 * URI string ကို proxy URL အဖြစ် ပြောင်း
 * - Absolute URLs (http/https) → proxy path
 * - Relative URLs → current directory base နဲ့ resolve ပြီး proxy path
 */
function resolveAndRewriteUri(
  uri: string,
  proxyBase: string,
  currentDir: string,
  keyQuery: string,
): string {
  // Absolute URL
  if (uri.startsWith("http://") || uri.startsWith("https://")) {
    try {
      const u = new URL(uri);
      if (ALLOWED_DOMAINS.includes(u.hostname)) {
        return `${proxyBase}/stream${u.pathname}${keyQuery}`;
      }
    } catch {
      // malformed URL → return as-is
    }
    return uri;
  }

  // Relative URL → resolve against current directory
  let resolvedPath: string;
  if (uri.startsWith("/")) {
    // Absolute path relative (starts with /)
    resolvedPath = uri;
  } else {
    // Relative path → join with current dir
    resolvedPath = currentDir.endsWith("/")
      ? currentDir + uri
      : currentDir + "/" + uri;
  }

  // Normalize path (resolve any ./ or redundant slashes, but we already blocked ..)
  resolvedPath = resolvedPath.replace(/\/+/g, "/");

  return `${proxyBase}/stream${resolvedPath}${keyQuery}`;
}

/**
 * m3u8 path ကနေ directory path ကို ထုတ်ယူ
 * e.g., /movies/abc/master.m3u8 → /movies/abc
 */
function getDirectoryFromPath(path: string): string {
  const lastSlash = path.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return path.substring(0, lastSlash);
}

// ---------- Streaming Fetch from R2 ----------

async function streamFromR2(
  r2Path: string,
  rangeHeader: string | null,
  userAgent: string,
): Promise<Response> {
  if (activeConnections >= MAX_ACTIVE_CONNECTIONS) {
    return new Response("Too many active streams. Try again shortly.", {
      status: 503,
      headers: {
        "Retry-After": "3",
        ...corsHeaders(),
      },
    });
  }

  const r2Url = `${R2_BASE_URL}${r2Path}`;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const reqHeaders: Record<string, string> = {};
      if (rangeHeader) reqHeaders["Range"] = rangeHeader;

      const r2Resp = await fetch(r2Url, {
        headers: reqHeaders,
        signal: AbortSignal.timeout(30_000),
      });

      if (r2Resp.status === 404) {
        return new Response("Not Found", {
          status: 404,
          headers: corsHeaders(),
        });
      }

      if (!r2Resp.ok && r2Resp.status !== 206) {
        throw new Error(`R2 ${r2Resp.status}`);
      }

      const respHeaders: Record<string, string> = {
        "Content-Type":
          r2Resp.headers.get("Content-Type") || getContentType(r2Path, userAgent),
        "Accept-Ranges": "bytes",
        ...corsHeaders(),
      };

      const cl = r2Resp.headers.get("Content-Length");
      if (cl) respHeaders["Content-Length"] = cl;

      const cr = r2Resp.headers.get("Content-Range");
      if (cr) respHeaders["Content-Range"] = cr;

      // TS/m4s segments → aggressive cache (immutable content)
      if (r2Path.endsWith(".ts") || r2Path.endsWith(".m4s") || r2Path.endsWith(".fmp4")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      }

      // mp4 files → moderate cache
      if (r2Path.endsWith(".mp4")) {
        respHeaders["Cache-Control"] = "public, max-age=3600";
      }

      if (!r2Resp.body) {
        return new Response(null, {
          status: r2Resp.status,
          headers: respHeaders,
        });
      }

      // Stream pipe with connection tracking
      const { readable, writable } = new TransformStream();

      (async () => {
        activeConnections++;
        try {
          await r2Resp.body!.pipeTo(writable);
        } catch (_e) {
          try {
            await writable.abort(
              _e instanceof Error ? _e.message : "pipe error",
            );
          } catch {
            // writable already closed — safe to ignore
          }
        } finally {
          activeConnections--;
        }
      })();

      return new Response(readable, {
        status: r2Resp.status,
        headers: respHeaders,
      });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) {
        await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
      }
    }
  }

  console.error(`R2 fetch failed for ${r2Path}: ${lastError?.message}`);
  return new Response("Upstream error", {
    status: 502,
    headers: corsHeaders(),
  });
}

// ---------- M3U8 Handler ----------

async function handleM3U8(
  r2Path: string,
  proxyBase: string,
  apiKey: string | null,
  userAgent: string,
): Promise<Response> {
  const cacheKey = r2Path;
  const currentDir = getDirectoryFromPath(r2Path);

  // Determine content type based on User-Agent
  const m3u8ContentType = getContentType(r2Path, userAgent);

  // Cache hit
  const cached = m3u8Cache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < M3U8_CACHE_TTL) {
    const rewritten = rewriteM3U8(cached.raw, proxyBase, currentDir, apiKey);
    return new Response(rewritten, {
      status: 200,
      headers: {
        "Content-Type": m3u8ContentType,
        "Cache-Control": "no-cache",
        "X-Cache": "HIT",
        ...corsHeaders(),
      },
    });
  }

  const r2Url = `${R2_BASE_URL}${r2Path}`;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const resp = await fetch(r2Url, {
        signal: AbortSignal.timeout(15_000),
      });
      if (resp.status === 404) {
        return new Response("Not Found", {
          status: 404,
          headers: corsHeaders(),
        });
      }
      if (!resp.ok) throw new Error(`R2 ${resp.status}`);

      const raw = await resp.text();

      if (raw.length > 1_048_576) {
        return new Response("Playlist too large", {
          status: 413,
          headers: corsHeaders(),
        });
      }

      cacheM3U8(cacheKey, raw);

      const rewritten = rewriteM3U8(raw, proxyBase, currentDir, apiKey);
      return new Response(rewritten, {
        status: 200,
        headers: {
          "Content-Type": m3u8ContentType,
          // m3u8 ကို no-cache ထားတာက player ကို အမြဲ fresh copy ယူခိုင်း
          // (ဒါပေမယ့် server side cache ရှိတဲ့အတွက် R2 ကို ထပ်မခေါ်ပါ)
          "Cache-Control": "no-cache",
          "X-Cache": "MISS",
          ...corsHeaders(),
        },
      });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) {
        await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
      }
    }
  }

  console.error(`M3U8 fetch failed for ${r2Path}: ${lastError?.message}`);
  return new Response("Upstream error", {
    status: 502,
    headers: corsHeaders(),
  });
}

// ---------- Main Handler ----------

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const userAgent = req.headers.get("User-Agent") || "";

  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: corsHeaders(),
    });
  }

  // --- Rate Limit ---
  const clientIP = getClientIP(req);
  if (isRateLimited(clientIP)) {
    return new Response("Rate limit exceeded", {
      status: 429,
      headers: {
        "Retry-After": "60",
        ...corsHeaders(),
      },
    });
  }

  // --- Health ---
  if (path === "/" || path === "/health") {
    if (!authenticateRequest(req, url)) {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }
    return new Response(
      JSON.stringify({
        status: "ok",
        active_streams: activeConnections,
        max_connections: MAX_ACTIVE_CONNECTIONS,
        m3u8_cache_entries: m3u8Cache.size,
        rate_limit_entries: rateLimitMap.size,
        timestamp: new Date().toISOString(),
      }),
      {
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      },
    );
  }

  // --- Stream Proxy ---
  if (path.startsWith("/stream/")) {
    // Auth check
    if (!authenticateRequest(req, url)) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "WWW-Authenticate": "API-Key",
          ...corsHeaders(),
        },
      });
    }

    if (!validateConfig()) {
      return new Response("Server misconfigured", {
        status: 500,
        headers: corsHeaders(),
      });
    }

    const rawR2Path = path.slice("/stream".length);

    const r2Path = sanitizePath(rawR2Path);
    if (!r2Path) {
      return new Response("Invalid path", {
        status: 400,
        headers: corsHeaders(),
      });
    }

    // Extract API key for propagation to m3u8 rewriting
    const apiKey = API_KEY
      ? (url.searchParams.get("key") || req.headers.get("X-API-Key") || null)
      : null;

    // m3u8 → buffer + rewrite (with API key propagation)
    if (r2Path.endsWith(".m3u8")) {
      const proxyBase = `${url.protocol}//${url.host}`;
      return handleM3U8(r2Path, proxyBase, apiKey, userAgent);
    }

    // everything else → stream pipe
    return streamFromR2(r2Path, req.headers.get("Range"), userAgent);
  }

  // --- Built-in Player ---
  if (path === "/player") {
    const v = url.searchParams.get("v");
    if (!v) {
      return new Response("Missing ?v= parameter", {
        status: 400,
        headers: corsHeaders(),
      });
    }

    if (!/^[a-zA-Z0-9\/_\-\.]+$/.test(v)) {
      return new Response("Invalid video path", {
        status: 400,
        headers: corsHeaders(),
      });
    }

    const safeV = escapeHtml(v);
    const keyParam = url.searchParams.get("key");
    const keyQuery = keyParam
      ? `?key=${encodeURIComponent(keyParam)}`
      : "";
    const fullM3U8Url = `${url.protocol}//${url.host}/stream/${safeV}${keyQuery}`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Stream Player</title>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}
    video{max-width:100%;max-height:100vh;width:100%}
    #stats{position:fixed;top:10px;right:10px;color:#0f0;font:12px monospace;
           background:rgba(0,0,0,.7);padding:8px;border-radius:4px;z-index:9999}
    #error{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);color:#f44;
           font:14px sans-serif;background:rgba(0,0,0,.8);padding:12px 20px;
           border-radius:8px;display:none;z-index:9999}
  </style>
</head>
<body>
  <video id="v" controls autoplay playsinline></video>
  <div id="stats"></div>
  <div id="error"></div>
  <script>
    var src = ${JSON.stringify(fullM3U8Url)};
    var video = document.getElementById("v");
    var stats = document.getElementById("stats");
    var errorDiv = document.getElementById("error");

    function showError(msg) {
      errorDiv.textContent = msg;
      errorDiv.style.display = "block";
      setTimeout(function() { errorDiv.style.display = "none"; }, 5000);
    }

    if (Hls.isSupported()) {
      var hls = new Hls({
        maxBufferLength: 30,
        maxMaxBufferLength: 120,
        maxBufferSize: 120 * 1024 * 1024,
        startLevel: -1,
        testBandwidth: true,
        progressive: true,
        lowLatencyMode: false,
        fragLoadingMaxRetry: 6,
        fragLoadingRetryDelay: 1000,
        manifestLoadingMaxRetry: 4,
        manifestLoadingRetryDelay: 1000,
        levelLoadingMaxRetry: 4,
        levelLoadingRetryDelay: 1000
      });

      hls.loadSource(src);
      hls.attachMedia(video);

      hls.on(Hls.Events.MANIFEST_PARSED, function() {
        video.play().catch(function() {});
      });

      hls.on(Hls.Events.ERROR, function(event, data) {
        if (data.fatal) {
          switch(data.type) {
            case Hls.ErrorTypes.NETWORK_ERROR:
              showError("Network error - retrying...");
              setTimeout(function() { hls.startLoad(); }, 1000);
              break;
            case Hls.ErrorTypes.MEDIA_ERROR:
              showError("Media error - recovering...");
              hls.recoverMediaError();
              break;
            default:
              showError("Fatal error - reloading...");
              setTimeout(function() {
                hls.destroy();
                hls = new Hls({
                  maxBufferLength: 30,
                  maxMaxBufferLength: 120,
                  startLevel: -1,
                  fragLoadingMaxRetry: 6,
                  fragLoadingRetryDelay: 1000
                });
                hls.loadSource(src);
                hls.attachMedia(video);
              }, 2000);
              break;
          }
        }
      });

      setInterval(function() {
        var level = hls.levels[hls.currentLevel];
        var bufferInfo = "0s";
        if (video.buffered.length > 0) {
          bufferInfo = (video.buffered.end(video.buffered.length - 1) - video.currentTime).toFixed(1) + "s";
        }
        stats.textContent = "Level: " + (level ? level.height + "p" : "-")
          + " | Buffer: " + bufferInfo
          + " | Streams: " + (hls.levels ? hls.levels.length : 0);
      }, 1000);

    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = src;
      video.addEventListener("loadedmetadata", function() {
        video.play().catch(function() {});
      });
    } else {
      showError("HLS playback not supported in this browser");
    }
  <\/script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        "Content-Type": "text/html;charset=utf-8",
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; connect-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        ...corsHeaders(),
      },
    });
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders() });
}

// ---------- Start ----------
Deno.serve({ port: 8000 }, handleRequest);
