// =====================================================
// R2 M3U8 Streaming Proxy for Deno Deploy
// Memory-efficient: pipe/stream based, no full buffering
// Hardened: path traversal, XSS, rate-limit, auth, cache limits
// =====================================================

const R2_BASE_URL = Deno.env.get("R2_BASE_URL") || "";

// ---------- Security Config ----------
// APK app ကနေ ပို့မယ့် API key (env variable ထဲမှာ set ရမယ်)
const API_KEY = Deno.env.get("PROXY_API_KEY") || "";

const ALLOWED_DOMAINS = [
  "",
];

// Allowed file extensions for streaming
const ALLOWED_EXTENSIONS = new Set([
  "m3u8", "ts", "mp4", "fmp4", "m4s", "key", "vtt", "srt",
]);

// ---------- Rate Limiting ----------
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW = 60_000; // 1 minute window
const RATE_LIMIT_MAX = 300;       // max 300 requests per minute per IP
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
const M3U8_CACHE_TTL = 5 * 60 * 1000;  // 5 min
const M3U8_CACHE_MAX_SIZE = 500;        // max 500 entries

// cleanup every 3 min
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of m3u8Cache) {
    if (now - entry.cachedAt > M3U8_CACHE_TTL) {
      m3u8Cache.delete(key);
    }
  }
}, 3 * 60 * 1000);

function cacheM3U8(key: string, raw: string): void {
  // evict oldest if cache full
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
const MAX_ACTIVE_CONNECTIONS = 200; // connection cap

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
  // decode ပြီး normalize
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return null;
  }

  // double-encoded traversal ကိုလည်း စစ်
  if (decoded.includes("..") || decoded.includes("\\")) {
    return null;
  }

  // normalize: consecutive slashes ဖယ်
  const normalized = "/" + decoded.replace(/\/+/g, "/").replace(/^\/+/, "");

  // extension check
  const ext = normalized.split(".").pop()?.toLowerCase() || "";
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return null;
  }

  // null bytes စစ်
  if (normalized.includes("\0")) {
    return null;
  }

  return normalized;
}

/**
 * API Key authentication စစ်ဆေး
 * Header: X-API-Key: <key>
 * OR query param: ?key=<key>
 */
function authenticateRequest(req: Request, url: URL): boolean {
  // API_KEY မ set ထားရင် auth skip (development mode)
  if (!API_KEY) return true;

  const headerKey = req.headers.get("X-API-Key");
  if (headerKey && timingSafeCompare(headerKey, API_KEY)) return true;

  const queryKey = url.searchParams.get("key");
  if (queryKey && timingSafeCompare(queryKey, API_KEY)) return true;

  return false;
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // still do comparison to avoid length-based timing leak
    // (we compare against b padded/truncated to a's length)
    let result = a.length ^ b.length;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
    }
    return result === 0; // will always be false since lengths differ
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, Content-Type, X-API-Key",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Range, Content-Type, Accept-Ranges",
  };
}

function getContentType(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() || "";
  const types: Record<string, string> = {
    m3u8: "application/vnd.apple.mpegurl",
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

/**
 * Escape HTML special characters to prevent XSS
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function rewriteM3U8(content: string, proxyBase: string): string {
  const lines = content.split("\n");
  const out: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Absolute R2 URL → proxy URL
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      try {
        const u = new URL(trimmed);
        if (ALLOWED_DOMAINS.includes(u.hostname)) {
          out.push(`${proxyBase}/stream${u.pathname}`);
          continue;
        }
      } catch { /* keep original */ }
    }

    // URI="..." attribute (encryption keys etc.)
    if (trimmed.includes('URI="')) {
      const replaced = trimmed.replace(
        /URI="(https?:\/\/[^"]+)"/g,
        (_m, url) => {
          try {
            const u = new URL(url);
            if (ALLOWED_DOMAINS.includes(u.hostname)) {
              return `URI="${proxyBase}/stream${u.pathname}"`;
            }
          } catch { /* keep */ }
          return _m;
        },
      );
      out.push(replaced);
      continue;
    }

    out.push(line);
  }

  return out.join("\n");
}

// ---------- Streaming Fetch from R2 ----------

async function streamFromR2(
  r2Path: string,
  rangeHeader: string | null,
): Promise<Response> {
  // Connection limit check
  if (activeConnections >= MAX_ACTIVE_CONNECTIONS) {
    return new Response("Too many active streams. Try again shortly.", {
      status: 503,
      headers: {
        "Retry-After": "5",
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

      // Build response headers
      const respHeaders: Record<string, string> = {
        "Content-Type":
          r2Resp.headers.get("Content-Type") || getContentType(r2Path),
        "Accept-Ranges": "bytes",
        ...corsHeaders(),
      };

      const cl = r2Resp.headers.get("Content-Length");
      if (cl) respHeaders["Content-Length"] = cl;

      const cr = r2Resp.headers.get("Content-Range");
      if (cr) respHeaders["Content-Range"] = cr;

      // Segments → aggressive browser cache
      if (r2Path.endsWith(".ts") || r2Path.endsWith(".m4s")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      }

      // No body (HEAD request or empty)
      if (!r2Resp.body) {
        return new Response(null, {
          status: r2Resp.status,
          headers: respHeaders,
        });
      }

      // ------- Stream pipe with proper error handling -------
      const { readable, writable } = new TransformStream();

      (async () => {
        activeConnections++;
        try {
          await r2Resp.body!.pipeTo(writable);
        } catch (_e) {
          // Client disconnect or upstream error — normal during streaming
          try {
            await writable.abort(
              _e instanceof Error ? _e.message : "pipe error",
            );
          } catch {
            // writable already closed/errored — safe to ignore
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
        await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
      }
    }
  }

  // Don't leak internal error details to client
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
): Promise<Response> {
  const cacheKey = r2Path;

  // cache hit
  const cached = m3u8Cache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < M3U8_CACHE_TTL) {
    return new Response(rewriteM3U8(cached.raw, proxyBase), {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.apple.mpegurl",
        "Cache-Control": "public, max-age=5",
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

      // Sanity check: m3u8 file size limit (1MB max)
      if (raw.length > 1_048_576) {
        return new Response("Playlist too large", {
          status: 413,
          headers: corsHeaders(),
        });
      }

      // cache it (with size limit)
      cacheM3U8(cacheKey, raw);

      return new Response(rewriteM3U8(raw, proxyBase), {
        status: 200,
        headers: {
          "Content-Type": "application/vnd.apple.mpegurl",
          "Cache-Control": "public, max-age=5",
          "X-Cache": "MISS",
          ...corsHeaders(),
        },
      });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) {
        await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
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

async function handleRequest(
  req: Request,
  info: Deno.ServeHandlerInfo,
): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // CORS preflight (no auth needed)
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

  // --- Health (protected - only with API key or no key set) ---
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
        m3u8_cache_entries: m3u8Cache.size,
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
        headers: corsHeaders(),
      });
    }

    if (!validateConfig()) {
      return new Response("Server misconfigured", {
        status: 500,
        headers: corsHeaders(),
      });
    }

    const rawR2Path = path.slice("/stream".length); // keeps leading /

    // Sanitize path (prevents traversal, checks extension)
    const r2Path = sanitizePath(rawR2Path);
    if (!r2Path) {
      return new Response("Invalid path", {
        status: 400,
        headers: corsHeaders(),
      });
    }

    // m3u8 → buffer + rewrite
    if (r2Path.endsWith(".m3u8")) {
      const proxyBase = `${url.protocol}//${url.host}`;
      return handleM3U8(r2Path, proxyBase);
    }

    // everything else → stream pipe
    return streamFromR2(r2Path, req.headers.get("Range"));
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

    // Validate v parameter: only allow safe path characters
    if (!/^[a-zA-Z0-9\/_\-\.]+$/.test(v)) {
      return new Response("Invalid video path", {
        status: 400,
        headers: corsHeaders(),
      });
    }

    // Sanitize for XSS
    const safeV = escapeHtml(v);
    const m3u8Url = `${url.protocol}//${url.host}/stream/${safeV}`;

    // Build API key query param if exists
    const keyParam = url.searchParams.get("key");
    const keyQuery = keyParam
      ? `?key=${encodeURIComponent(keyParam)}`
      : "";
    const fullM3U8Url = `${m3u8Url}${keyQuery}`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Stream Player</title>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}
    video{max-width:100%;max-height:100vh}
    #stats{position:fixed;top:10px;right:10px;color:#0f0;font:12px monospace;
           background:rgba(0,0,0,.7);padding:8px;border-radius:4px;z-index:9999}
  </style>
</head>
<body>
  <video id="v" controls autoplay playsinline></video>
  <div id="stats"></div>
  <script>
    const src = ${JSON.stringify(fullM3U8Url)};
    const video = document.getElementById("v");
    const stats = document.getElementById("stats");

    if (Hls.isSupported()) {
      const hls = new Hls({
        maxBufferLength: 30,
        maxMaxBufferLength: 120,
        maxBufferSize: 120 * 1024 * 1024,
        startLevel: -1,
        testBandwidth: true,
        progressive: true,
        lowLatencyMode: false,
        xhrSetup: function(xhr, url) {
          // API key ကို segment requests တွေမှာလည်း ထည့်ပေး
          ${keyParam ? `
          const u = new URL(url);
          u.searchParams.set("key", ${JSON.stringify(keyParam)});
          xhr.open("GET", u.toString(), true);
          ` : ""}
        }
      });

      hls.loadSource(src);
      hls.attachMedia(video);

      hls.on(Hls.Events.MANIFEST_PARSED, function() {
        video.play().catch(function() {});
      });

      hls.on(Hls.Events.ERROR, function(event, data) {
        if (data.fatal) {
          if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
            console.warn("Network error, attempting recovery...");
            hls.startLoad();
          } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
            console.warn("Media error, attempting recovery...");
            hls.recoverMediaError();
          } else {
            console.error("Fatal error, destroying HLS instance");
            hls.destroy();
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
          + " | Buffer: " + bufferInfo;
      }, 1000);

    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = src;
    }
  </script>
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
