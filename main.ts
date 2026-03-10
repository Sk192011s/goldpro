const R2_BASE_URL = Deno.env.get("R2_BASE_URL") || "";

const ALLOWED_DOMAINS = [
  "pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  "pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
];

const ALLOWED_EXTENSIONS = new Set([
  "m3u8", "ts", "mp4", "fmp4", "m4s", "key", "vtt", "srt",
]);

// ---------- Rate Limiting (per-IP, sliding window) ----------
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW = 60_000;
// *** concurrent streaming အတွက် limit ကို မြှင့်ထားပါတယ် ***
// HLS player က segment တစ်ခုလျှင် request 1 ခုပါတ်တယ်
// 2-second segments ဆိုရင် 30 req/min/stream, 10 users = 300
// headroom ထည့်ပြီး 1200 ထားတယ်
const RATE_LIMIT_MAX = 1200;
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

// ---------- M3U8 Cache (LRU-like) ----------
interface M3U8CacheEntry {
  raw: string;
  cachedAt: number;
  lastAccess: number;
}

const m3u8Cache = new Map<string, M3U8CacheEntry>();
const M3U8_CACHE_TTL = 5 * 60 * 1000;
const M3U8_CACHE_MAX_SIZE = 2000;

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
    // Evict least recently accessed entry
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [k, entry] of m3u8Cache) {
      if (entry.lastAccess < oldestTime) {
        oldestTime = entry.lastAccess;
        oldestKey = k;
      }
    }
    if (oldestKey) m3u8Cache.delete(oldestKey);
  }
  const now = Date.now();
  m3u8Cache.set(key, { raw, cachedAt: now, lastAccess: now });
}

function getCachedM3U8(key: string): M3U8CacheEntry | null {
  const entry = m3u8Cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > M3U8_CACHE_TTL) {
    m3u8Cache.delete(key);
    return null;
  }
  // Update last access for LRU
  entry.lastAccess = Date.now();
  return entry;
}

// ---------- Active Connections (atomic-safe counter) ----------
let activeConnections = 0;
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

function sanitizePath(rawPath: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return null;
  }
  if (decoded.includes("..") || decoded.includes("\\")) return null;
  const normalized = "/" + decoded.replace(/\/+/g, "/").replace(/^\/+/, "");
  const ext = normalized.split(".").pop()?.toLowerCase() || "";
  if (!ALLOWED_EXTENSIONS.has(ext)) return null;
  if (normalized.includes("\0")) return null;
  return normalized;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers":
      "Range, Content-Type, Accept, Accept-Encoding, User-Agent",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Range, Content-Type, Accept-Ranges",
    "Access-Control-Max-Age": "86400",
  };
}

function getContentType(path: string, userAgent: string = ""): string {
  const ext = path.split(".").pop()?.toLowerCase() || "";
  if (ext === "m3u8") {
    const ua = userAgent.toLowerCase();
    if (
      ua.includes("android") ||
      ua.includes("exoplayer") ||
      ua.includes("okhttp") ||
      ua.includes("stagefright") ||
      ua.includes("lavf") ||
      ua.includes("libmpv")
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

function getDirectoryFromPath(path: string): string {
  const lastSlash = path.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return path.substring(0, lastSlash);
}

// ---------- M3U8 Rewrite ----------

function resolveAndRewriteUri(
  uri: string,
  proxyBase: string,
  currentDir: string,
): string {
  // Absolute URL
  if (uri.startsWith("http://") || uri.startsWith("https://")) {
    try {
      const u = new URL(uri);
      if (ALLOWED_DOMAINS.includes(u.hostname)) {
        return `${proxyBase}/stream${u.pathname}`;
      }
    } catch { /* keep original */ }
    return uri;
  }
  // Relative URL
  let resolvedPath: string;
  if (uri.startsWith("/")) {
    resolvedPath = uri;
  } else {
    resolvedPath = currentDir.endsWith("/")
      ? currentDir + uri
      : currentDir + "/" + uri;
  }
  // Normalize path segments (resolve "." and ".." within allowed bounds)
  const parts = resolvedPath.split("/").filter(Boolean);
  const stack: string[] = [];
  for (const part of parts) {
    if (part === ".") continue;
    if (part === "..") {
      stack.pop();
    } else {
      stack.push(part);
    }
  }
  resolvedPath = "/" + stack.join("/");
  return `${proxyBase}/stream${resolvedPath}`;
}

function rewriteM3U8(
  content: string,
  proxyBase: string,
  currentDir: string,
): string {
  const lines = content.split("\n");
  const out: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed === "") {
      out.push(line);
      continue;
    }

    // URI="..." attributes (EXT-X-KEY, EXT-X-MAP, etc.)
    if (trimmed.startsWith("#") && trimmed.includes('URI="')) {
      const replaced = trimmed.replace(
        /URI="([^"]+)"/g,
        (_match, uri: string) => {
          return `URI="${resolveAndRewriteUri(uri, proxyBase, currentDir)}"`;
        },
      );
      out.push(replaced);
      continue;
    }

    // Other tags
    if (trimmed.startsWith("#")) {
      out.push(line);
      continue;
    }

    // Segment / playlist URL line
    out.push(resolveAndRewriteUri(trimmed, proxyBase, currentDir));
  }

  return out.join("\n");
}

// ---------- Stream from R2 (pipe-based, concurrent-safe) ----------

async function streamFromR2(
  r2Path: string,
  rangeHeader: string | null,
  userAgent: string,
): Promise<Response> {
  if (activeConnections >= MAX_ACTIVE_CONNECTIONS) {
    return new Response("Too many active streams. Try again shortly.", {
      status: 503,
      headers: { "Retry-After": "3", ...corsHeaders() },
    });
  }

  const r2Url = `${R2_BASE_URL}${r2Path}`;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const reqHeaders: Record<string, string> = {};
      if (rangeHeader) reqHeaders["Range"] = rangeHeader;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);

      let r2Resp: Response;
      try {
        r2Resp = await fetch(r2Url, {
          headers: reqHeaders,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      if (r2Resp.status === 404) {
        return new Response("Not Found", { status: 404, headers: corsHeaders() });
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

      // Cache headers based on content type
      if (r2Path.endsWith(".ts") || r2Path.endsWith(".m4s") || r2Path.endsWith(".fmp4")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      } else if (r2Path.endsWith(".mp4")) {
        respHeaders["Cache-Control"] = "public, max-age=3600";
      } else if (r2Path.endsWith(".key")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      }

      // No body (HEAD request or empty response)
      if (!r2Resp.body) {
        return new Response(null, { status: r2Resp.status, headers: respHeaders });
      }

      // *** Pipe with proper connection tracking ***
      activeConnections++;
      const reader = r2Resp.body.getReader();

      const readable = new ReadableStream({
        async pull(ctrl) {
          try {
            const { done, value } = await reader.read();
            if (done) {
              ctrl.close();
              activeConnections--;
              return;
            }
            ctrl.enqueue(value);
          } catch (_e) {
            ctrl.close();
            activeConnections--;
          }
        },
        cancel() {
          // Client disconnected — release resources
          reader.cancel().catch(() => {});
          activeConnections--;
        },
      });

      return new Response(readable, { status: r2Resp.status, headers: respHeaders });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }

  console.error(`R2 fetch failed for ${r2Path}: ${lastError?.message}`);
  return new Response("Upstream error", { status: 502, headers: corsHeaders() });
}

// ---------- M3U8 Handler ----------

async function handleM3U8(
  r2Path: string,
  proxyBase: string,
  userAgent: string,
): Promise<Response> {
  const currentDir = getDirectoryFromPath(r2Path);
  const m3u8ContentType = getContentType(r2Path, userAgent);

  // Cache hit (with LRU update)
  const cached = getCachedM3U8(r2Path);
  if (cached) {
    return new Response(rewriteM3U8(cached.raw, proxyBase, currentDir), {
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
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15_000);

      let resp: Response;
      try {
        resp = await fetch(r2Url, { signal: controller.signal });
      } finally {
        clearTimeout(timeoutId);
      }

      if (resp.status === 404) {
        return new Response("Not Found", { status: 404, headers: corsHeaders() });
      }
      if (!resp.ok) throw new Error(`R2 ${resp.status}`);

      const raw = await resp.text();
      if (raw.length > 1_048_576) {
        return new Response("Playlist too large", { status: 413, headers: corsHeaders() });
      }

      cacheM3U8(r2Path, raw);

      return new Response(rewriteM3U8(raw, proxyBase, currentDir), {
        status: 200,
        headers: {
          "Content-Type": m3u8ContentType,
          "Cache-Control": "no-cache",
          "X-Cache": "MISS",
          ...corsHeaders(),
        },
      });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }

  console.error(`M3U8 fetch failed for ${r2Path}: ${lastError?.message}`);
  return new Response("Upstream error", { status: 502, headers: corsHeaders() });
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
    return new Response("Method Not Allowed", { status: 405, headers: corsHeaders() });
  }

  // Rate limit
  const clientIP = getClientIP(req);
  if (isRateLimited(clientIP)) {
    return new Response("Rate limit exceeded", {
      status: 429,
      headers: { "Retry-After": "60", ...corsHeaders() },
    });
  }

  // Health / status
  if (path === "/" || path === "/health") {
    return new Response(
      JSON.stringify({
        status: "ok",
        active_streams: activeConnections,
        max_connections: MAX_ACTIVE_CONNECTIONS,
        m3u8_cache_entries: m3u8Cache.size,
        rate_limit_entries: rateLimitMap.size,
        timestamp: new Date().toISOString(),
      }),
      { headers: { "Content-Type": "application/json", ...corsHeaders() } },
    );
  }

  // Stream proxy — NO AUTH REQUIRED
  if (path.startsWith("/stream/")) {
    if (!validateConfig()) {
      return new Response("Server misconfigured", { status: 500, headers: corsHeaders() });
    }

    const rawR2Path = path.slice("/stream".length);
    const r2Path = sanitizePath(rawR2Path);
    if (!r2Path) {
      return new Response("Invalid path", { status: 400, headers: corsHeaders() });
    }

    if (r2Path.endsWith(".m3u8")) {
      const proxyBase = `${url.protocol}//${url.host}`;
      return handleM3U8(r2Path, proxyBase, userAgent);
    }

    return streamFromR2(r2Path, req.headers.get("Range"), userAgent);
  }

  // Built-in player
  if (path === "/player") {
    const v = url.searchParams.get("v");
    if (!v) {
      return new Response("Missing ?v= parameter", { status: 400, headers: corsHeaders() });
    }
    if (!/^[a-zA-Z0-9\/_\-\.]+$/.test(v)) {
      return new Response("Invalid video path", { status: 400, headers: corsHeaders() });
    }

    const safeV = escapeHtml(v);
    const fullM3U8Url = `${url.protocol}//${url.host}/stream/${safeV}`;

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
          + " | Streams: active";
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
