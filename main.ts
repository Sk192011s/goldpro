// ==========================================
//  R2 HLS Streaming Proxy — Improved Edition
//  Deno Deploy / Deno runtime
// ==========================================

const R2_BASE_URL = Deno.env.get("R2_BASE_URL") || "";

const ALLOWED_DOMAINS = [
  "pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
  "pub-9c8bcd6f32434fe08628852555cc2e5c.r2.dev",
];

const ALLOWED_EXTENSIONS = new Set([
  "m3u8", "ts", "mp4", "fmp4", "m4s", "key", "vtt", "srt",
]);

// ---------- Logging ----------
const LOG_LEVEL = (Deno.env.get("LOG_LEVEL") || "info").toLowerCase();

const LOG_LEVELS: Record<string, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function log(level: string, message: string, extra?: Record<string, unknown>): void {
  if ((LOG_LEVELS[level] ?? 1) < (LOG_LEVELS[LOG_LEVEL] ?? 1)) return;
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...extra,
  };
  if (level === "error") {
    console.error(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

// ---------- Rate Limiting (per-IP, sliding window) ----------
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW = 60_000;
const RATE_LIMIT_MAX = 1200;
const RATE_LIMIT_CLEANUP_INTERVAL = 2 * 60_000;

const rateLimitCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW * 2) {
      rateLimitMap.delete(key);
    }
  }
}, RATE_LIMIT_CLEANUP_INTERVAL);

function isRateLimited(ip: string): { limited: boolean; remaining: number } {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return { limited: false, remaining: RATE_LIMIT_MAX - 1 };
  }
  entry.count++;
  const remaining = Math.max(0, RATE_LIMIT_MAX - entry.count);
  return { limited: entry.count > RATE_LIMIT_MAX, remaining };
}

// ---------- M3U8 Cache (LRU via doubly-linked list) ----------
interface M3U8CacheNode {
  key: string;
  raw: string;
  rewritten: Map<string, string>; // proxyBase -> rewritten content
  cachedAt: number;
  prev: M3U8CacheNode | null;
  next: M3U8CacheNode | null;
}

class M3U8LRUCache {
  private map = new Map<string, M3U8CacheNode>();
  private head: M3U8CacheNode | null = null; // most recent
  private tail: M3U8CacheNode | null = null; // least recent
  private maxSize: number;
  private ttl: number;

  constructor(maxSize = 2000, ttl = 5 * 60 * 1000) {
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  get size(): number {
    return this.map.size;
  }

  private detach(node: M3U8CacheNode): void {
    if (node.prev) node.prev.next = node.next;
    else this.head = node.next;
    if (node.next) node.next.prev = node.prev;
    else this.tail = node.prev;
    node.prev = null;
    node.next = null;
  }

  private pushFront(node: M3U8CacheNode): void {
    node.prev = null;
    node.next = this.head;
    if (this.head) this.head.prev = node;
    this.head = node;
    if (!this.tail) this.tail = node;
  }

  get(key: string): M3U8CacheNode | null {
    const node = this.map.get(key);
    if (!node) return null;
    if (Date.now() - node.cachedAt > this.ttl) {
      this.delete(key);
      return null;
    }
    // Move to front (most recently used)
    this.detach(node);
    this.pushFront(node);
    return node;
  }

  set(key: string, raw: string): M3U8CacheNode {
    // Update existing
    const existing = this.map.get(key);
    if (existing) {
      existing.raw = raw;
      existing.rewritten.clear();
      existing.cachedAt = Date.now();
      this.detach(existing);
      this.pushFront(existing);
      return existing;
    }

    // Evict if full — O(1) via tail pointer
    while (this.map.size >= this.maxSize && this.tail) {
      this.delete(this.tail.key);
    }

    const node: M3U8CacheNode = {
      key,
      raw,
      rewritten: new Map(),
      cachedAt: Date.now(),
      prev: null,
      next: null,
    };
    this.map.set(key, node);
    this.pushFront(node);
    return node;
  }

  delete(key: string): void {
    const node = this.map.get(key);
    if (!node) return;
    this.detach(node);
    this.map.delete(key);
  }

  /** Purge expired entries (called periodically) */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    let current = this.tail;
    while (current) {
      const prev = current.prev;
      if (now - current.cachedAt > this.ttl) {
        this.delete(current.key);
        purged++;
      }
      current = prev;
    }
    return purged;
  }
}

const m3u8Cache = new M3U8LRUCache(2000, 5 * 60 * 1000);

const m3u8CacheCleanupTimer = setInterval(() => {
  const purged = m3u8Cache.purgeExpired();
  if (purged > 0) log("debug", `Purged ${purged} expired M3U8 cache entries`);
}, 3 * 60 * 1000);

// ---------- Active Connections (atomic-safe counter with guard) ----------
let activeConnections = 0;
const MAX_ACTIVE_CONNECTIONS = 500;

/** RAII-style guard to ensure activeConnections is decremented exactly once */
class ConnectionGuard {
  private released = false;

  constructor() {
    activeConnections++;
  }

  release(): void {
    if (!this.released) {
      this.released = true;
      activeConnections = Math.max(0, activeConnections - 1);
    }
  }
}

// ---------- In-Flight Dedup for M3U8 ----------
const m3u8InFlight = new Map<string, Promise<{ raw: string; status: number } | null>>();

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
  if (decoded.includes("\0")) return null;
  const normalized = "/" + decoded.replace(/\/+/g, "/").replace(/^\/+/, "");
  const ext = normalized.split(".").pop()?.toLowerCase() || "";
  if (!ALLOWED_EXTENSIONS.has(ext)) return null;
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

function getClientIP(req: Request, isBehindProxy: boolean): string {
  if (isBehindProxy) {
    // Trust proxy headers only when behind a known reverse proxy
    return (
      req.headers.get("cf-connecting-ip") ||
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip") ||
      "unknown"
    );
  }
  // Direct connection — use Deno's conn info if available, fallback to header
  return (
    req.headers.get("cf-connecting-ip") ||
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

/** Generate a simple ETag from content */
async function generateETag(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return `"${hashHex.substring(0, 16)}"`;
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
  // Normalize path segments
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

// ---------- Fetch from R2 with dedup for M3U8 ----------

async function fetchM3U8FromR2(
  r2Path: string,
): Promise<{ raw: string; status: number } | null> {
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
        return { raw: "", status: 404 };
      }
      if (!resp.ok) throw new Error(`R2 ${resp.status}`);

      const raw = await resp.text();
      if (raw.length > 1_048_576) {
        return { raw: "", status: 413 };
      }

      return { raw, status: 200 };
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }

  log("error", `M3U8 fetch failed for ${r2Path}: ${lastError?.message}`);
  return null;
}

// ---------- Stream from R2 (pipe-based, concurrent-safe) ----------

async function streamFromR2(
  r2Path: string,
  rangeHeader: string | null,
  userAgent: string,
  method: string,
): Promise<Response> {
  if (activeConnections >= MAX_ACTIVE_CONNECTIONS) {
    log("warn", "Connection limit reached", { active: activeConnections });
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
        // For HEAD requests, still use GET to R2 but we won't stream the body
        r2Resp = await fetch(r2Url, {
          method: method === "HEAD" ? "HEAD" : "GET",
          headers: reqHeaders,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      if (r2Resp.status === 404) {
        return new Response(null, { status: 404, headers: corsHeaders() });
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

      // ETag from R2 (for conditional requests)
      const etag = r2Resp.headers.get("ETag");
      if (etag) respHeaders["ETag"] = etag;
      const lastModified = r2Resp.headers.get("Last-Modified");
      if (lastModified) respHeaders["Last-Modified"] = lastModified;

      // Cache headers based on content type
      if (r2Path.endsWith(".ts") || r2Path.endsWith(".m4s") || r2Path.endsWith(".fmp4")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      } else if (r2Path.endsWith(".mp4")) {
        respHeaders["Cache-Control"] = "public, max-age=3600";
      } else if (r2Path.endsWith(".key")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      }

      // HEAD request — return headers only, no body streaming
      if (method === "HEAD") {
        return new Response(null, { status: r2Resp.status, headers: respHeaders });
      }

      // No body
      if (!r2Resp.body) {
        return new Response(null, { status: r2Resp.status, headers: respHeaders });
      }

      // Pipe with connection guard (exactly-once release)
      const guard = new ConnectionGuard();
      const reader = r2Resp.body.getReader();

      const readable = new ReadableStream({
        async pull(ctrl) {
          try {
            const { done, value } = await reader.read();
            if (done) {
              ctrl.close();
              guard.release();
              return;
            }
            ctrl.enqueue(value);
          } catch (e) {
            log("debug", `Stream read error for ${r2Path}`, {
              error: e instanceof Error ? e.message : String(e),
            });
            try { ctrl.close(); } catch { /* already closed */ }
            guard.release();
          }
        },
        cancel() {
          reader.cancel().catch(() => {});
          guard.release();
        },
      });

      return new Response(readable, { status: r2Resp.status, headers: respHeaders });
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < 2) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }

  log("error", `R2 fetch failed for ${r2Path}`, { error: lastError?.message });
  return new Response("Upstream error", { status: 502, headers: corsHeaders() });
}

// ---------- M3U8 Handler (with dedup + stale-while-revalidate) ----------

async function handleM3U8(
  r2Path: string,
  proxyBase: string,
  userAgent: string,
  ifNoneMatch: string | null,
): Promise<Response> {
  const currentDir = getDirectoryFromPath(r2Path);
  const m3u8ContentType = getContentType(r2Path, userAgent);

  // Helper to build M3U8 response
  const buildResponse = async (
    raw: string,
    cacheStatus: string,
  ): Promise<Response> => {
    // Check rewritten cache on the node
    const node = m3u8Cache.get(r2Path);
    let rewritten: string;

    if (node && node.rewritten.has(proxyBase)) {
      rewritten = node.rewritten.get(proxyBase)!;
    } else {
      rewritten = rewriteM3U8(raw, proxyBase, currentDir);
      // Store rewritten version in cache if node exists
      if (node) {
        node.rewritten.set(proxyBase, rewritten);
      }
    }

    const etag = await generateETag(rewritten);

    // Conditional request — 304 Not Modified
    if (ifNoneMatch && ifNoneMatch === etag) {
      return new Response(null, {
        status: 304,
        headers: {
          "ETag": etag,
          "Cache-Control": "no-cache",
          "X-Cache": cacheStatus,
          ...corsHeaders(),
        },
      });
    }

    return new Response(rewritten, {
      status: 200,
      headers: {
        "Content-Type": m3u8ContentType,
        "Cache-Control": "no-cache",
        "ETag": etag,
        "X-Cache": cacheStatus,
        ...corsHeaders(),
      },
    });
  };

  // Cache hit
  const cached = m3u8Cache.get(r2Path);
  if (cached) {
    // Stale-while-revalidate: if close to expiry (last 20%), refresh in background
    const age = Date.now() - cached.cachedAt;
    const ttl = 5 * 60 * 1000;
    if (age > ttl * 0.8) {
      // Background revalidation — don't await
      revalidateM3U8InBackground(r2Path);
    }
    return buildResponse(cached.raw, "HIT");
  }

  // Cache miss — fetch with dedup (multiple requests for same path share one fetch)
  let inFlight = m3u8InFlight.get(r2Path);
  if (!inFlight) {
    inFlight = fetchM3U8FromR2(r2Path).finally(() => {
      m3u8InFlight.delete(r2Path);
    });
    m3u8InFlight.set(r2Path, inFlight);
  }

  const result = await inFlight;

  if (!result) {
    return new Response("Upstream error", { status: 502, headers: corsHeaders() });
  }
  if (result.status === 404) {
    return new Response("Not Found", { status: 404, headers: corsHeaders() });
  }
  if (result.status === 413) {
    return new Response("Playlist too large", { status: 413, headers: corsHeaders() });
  }

  // Cache the raw content
  m3u8Cache.set(r2Path, result.raw);

  return buildResponse(result.raw, "MISS");
}

function revalidateM3U8InBackground(r2Path: string): void {
  // Don't duplicate in-flight revalidations
  if (m3u8InFlight.has(r2Path)) return;

  const promise = fetchM3U8FromR2(r2Path)
    .then((result) => {
      if (result && result.status === 200 && result.raw) {
        m3u8Cache.set(r2Path, result.raw);
        log("debug", `Background revalidated M3U8: ${r2Path}`);
      }
    })
    .catch((err) => {
      log("warn", `Background revalidation failed: ${r2Path}`, {
        error: err instanceof Error ? err.message : String(err),
      });
    })
    .finally(() => {
      m3u8InFlight.delete(r2Path);
    });

  m3u8InFlight.set(r2Path, promise as Promise<{ raw: string; status: number } | null>);
}

// ---------- Player Page ----------

function buildPlayerHTML(fullM3U8Url: string): string {
  return `<!DOCTYPE html>
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
           border-radius:8px;display:none;z-index:9999;max-width:90%;text-align:center}
  </style>
</head>
<body>
  <video id="v" controls autoplay playsinline></video>
  <div id="stats"></div>
  <div id="error"></div>
  <script>
    (function() {
      "use strict";
      var src = ${JSON.stringify(fullM3U8Url)};
      var video = document.getElementById("v");
      var statsEl = document.getElementById("stats");
      var errorDiv = document.getElementById("error");
      var errorTimeout = null;
      var fatalRecoveryAttempts = 0;
      var MAX_FATAL_RECOVERIES = 5;

      function showError(msg) {
        errorDiv.textContent = msg;
        errorDiv.style.display = "block";
        if (errorTimeout) clearTimeout(errorTimeout);
        errorTimeout = setTimeout(function() { errorDiv.style.display = "none"; }, 5000);
      }

      function createHlsConfig() {
        return {
          maxBufferLength: 30,
          maxMaxBufferLength: 120,
          maxBufferSize: 120 * 1024 * 1024,
          startLevel: -1,
          testBandwidth: true,
          progressive: true,
          lowLatencyMode: false,
          fragLoadingMaxRetry: 6,
          fragLoadingRetryDelay: 1000,
          fragLoadingMaxRetryTimeout: 8000,
          manifestLoadingMaxRetry: 4,
          manifestLoadingRetryDelay: 1000,
          levelLoadingMaxRetry: 4,
          levelLoadingRetryDelay: 1000,
          backBufferLength: 30,
          enableWorker: true
        };
      }

      function initHls() {
        var hls = new Hls(createHlsConfig());
        hls.loadSource(src);
        hls.attachMedia(video);

        hls.on(Hls.Events.MANIFEST_PARSED, function() {
          video.play().catch(function() {});
          fatalRecoveryAttempts = 0;
        });

        hls.on(Hls.Events.ERROR, function(event, data) {
          if (!data.fatal) return;

          fatalRecoveryAttempts++;
          if (fatalRecoveryAttempts > MAX_FATAL_RECOVERIES) {
            showError("Too many errors. Please reload the page.");
            hls.destroy();
            return;
          }

          switch(data.type) {
            case Hls.ErrorTypes.NETWORK_ERROR:
              showError("Network error - retrying... (" + fatalRecoveryAttempts + "/" + MAX_FATAL_RECOVERIES + ")");
              setTimeout(function() { hls.startLoad(); }, 1000 * fatalRecoveryAttempts);
              break;
            case Hls.ErrorTypes.MEDIA_ERROR:
              showError("Media error - recovering...");
              hls.recoverMediaError();
              break;
            default:
              showError("Reloading stream... (" + fatalRecoveryAttempts + "/" + MAX_FATAL_RECOVERIES + ")");
              hls.destroy();
              setTimeout(function() { initHls(); }, 2000 * fatalRecoveryAttempts);
              return;
          }
        });

        // Bandwidth & buffer stats
        var statsInterval = setInterval(function() {
          if (hls.media === null) {
            clearInterval(statsInterval);
            return;
          }
          var level = hls.levels && hls.levels[hls.currentLevel];
          var bufferInfo = "0.0s";
          try {
            if (video.buffered && video.buffered.length > 0) {
              bufferInfo = (video.buffered.end(video.buffered.length - 1) - video.currentTime).toFixed(1) + "s";
            }
          } catch(e) {}
          var bw = hls.bandwidthEstimate ? (hls.bandwidthEstimate / 1e6).toFixed(1) + " Mbps" : "-";
          statsEl.textContent =
            "Level: " + (level ? level.height + "p" : "-")
            + " | BW: " + bw
            + " | Buffer: " + bufferInfo;
        }, 1000);

        return hls;
      }

      if (Hls.isSupported()) {
        initHls();
      } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
        video.src = src;
        video.addEventListener("loadedmetadata", function() {
          video.play().catch(function() {});
        });
        video.addEventListener("error", function() {
          showError("Playback error: " + (video.error ? video.error.message : "unknown"));
        });
      } else {
        showError("HLS playback is not supported in this browser");
      }
    })();
  <\/script>
</body>
</html>`;
}

// ---------- Main Handler ----------

// Configuration: set to true when running behind Cloudflare / reverse proxy
const IS_BEHIND_PROXY = Deno.env.get("BEHIND_PROXY") === "true";

async function handleRequest(req: Request): Promise<Response> {
  const startTime = performance.now();
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
  const clientIP = getClientIP(req, IS_BEHIND_PROXY);
  const { limited, remaining } = isRateLimited(clientIP);

  if (limited) {
    log("warn", "Rate limited", { ip: clientIP, path });
    return new Response("Rate limit exceeded", {
      status: 429,
      headers: {
        "Retry-After": "60",
        "X-RateLimit-Remaining": "0",
        ...corsHeaders(),
      },
    });
  }

  // Health / status
  if (path === "/" || path === "/health") {
    const body = JSON.stringify({
      status: "ok",
      active_streams: activeConnections,
      max_connections: MAX_ACTIVE_CONNECTIONS,
      m3u8_cache_entries: m3u8Cache.size,
      rate_limit_entries: rateLimitMap.size,
      timestamp: new Date().toISOString(),
    });
    return new Response(body, {
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }

  // Stream proxy
  if (path.startsWith("/stream/")) {
    if (!validateConfig()) {
      log("error", "Server misconfigured — R2_BASE_URL invalid");
      return new Response("Server misconfigured", { status: 500, headers: corsHeaders() });
    }

    const rawR2Path = path.slice("/stream".length);
    const r2Path = sanitizePath(rawR2Path);
    if (!r2Path) {
      return new Response("Invalid path", { status: 400, headers: corsHeaders() });
    }

    let response: Response;

    if (r2Path.endsWith(".m3u8")) {
      const proxyBase = `${url.protocol}//${url.host}`;
      const ifNoneMatch = req.headers.get("If-None-Match");
      response = await handleM3U8(r2Path, proxyBase, userAgent, ifNoneMatch);
    } else {
      response = await streamFromR2(r2Path, req.headers.get("Range"), userAgent, req.method);
    }

    // Add common headers
    const duration = (performance.now() - startTime).toFixed(1);
    response.headers.set("X-Response-Time", `${duration}ms`);
    response.headers.set("X-RateLimit-Remaining", String(remaining));
    response.headers.set("Server", "hls-proxy");

    // Access log
    log("info", "request", {
      method: req.method,
      path: r2Path,
      status: response.status,
      ip: clientIP,
      duration_ms: parseFloat(duration),
      ua: userAgent.substring(0, 100),
    });

    return response;
  }

  // Built-in player
  if (path === "/player") {
    const v = url.searchParams.get("v");
    if (!v) {
      return new Response("Missing ?v= parameter", { status: 400, headers: corsHeaders() });
    }
    // Strict path validation — only allow safe characters
    if (!/^[a-zA-Z0-9\/_\-\.]+$/.test(v)) {
      return new Response("Invalid video path", { status: 400, headers: corsHeaders() });
    }
    // Ensure it ends with .m3u8
    if (!v.endsWith(".m3u8")) {
      return new Response("Player requires an .m3u8 path", { status: 400, headers: corsHeaders() });
    }

    const fullM3U8Url = `${url.protocol}//${url.host}/stream/${v}`;
    const html = buildPlayerHTML(fullM3U8Url);

    return new Response(html, {
      headers: {
        "Content-Type": "text/html;charset=utf-8",
        "Content-Security-Policy":
          "default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline'; media-src 'self' blob:; connect-src 'self'; img-src 'none'; font-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        ...corsHeaders(),
      },
    });
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders() });
}

// ---------- Graceful Shutdown ----------

const abortController = new AbortController();

async function gracefulShutdown(signal: string): Promise<void> {
  log("info", `Received ${signal}, starting graceful shutdown...`);

  // Stop accepting new connections
  abortController.abort();

  // Clear timers
  clearInterval(rateLimitCleanupTimer);
  clearInterval(m3u8CacheCleanupTimer);

  // Wait for active connections to drain (max 30s)
  const maxWait = 30_000;
  const start = Date.now();
  while (activeConnections > 0 && Date.now() - start < maxWait) {
    log("info", `Waiting for ${activeConnections} active connection(s) to drain...`);
    await new Promise((r) => setTimeout(r, 1000));
  }

  if (activeConnections > 0) {
    log("warn", `Force shutdown with ${activeConnections} connection(s) remaining`);
  } else {
    log("info", "All connections drained. Shutdown complete.");
  }

  Deno.exit(0);
}

// Register shutdown handlers
Deno.addSignalListener("SIGINT", () => gracefulShutdown("SIGINT"));
Deno.addSignalListener("SIGTERM", () => gracefulShutdown("SIGTERM"));

// ---------- Start ----------

const PORT = parseInt(Deno.env.get("PORT") || "8000", 10);

log("info", `HLS Proxy starting on port ${PORT}`, {
  max_connections: MAX_ACTIVE_CONNECTIONS,
  rate_limit: RATE_LIMIT_MAX,
  behind_proxy: IS_BEHIND_PROXY,
});

Deno.serve(
  {
    port: PORT,
    signal: abortController.signal,
    onListen({ hostname, port }) {
      log("info", `Server listening on ${hostname}:${port}`);
    },
  },
  handleRequest,
);
