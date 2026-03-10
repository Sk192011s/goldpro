// =====================================================
// R2 M3U8 Streaming Proxy for Deno Deploy
// Memory-efficient: pipe/stream based, no full buffering
// =====================================================

const R2_BASE_URL = Deno.env.get("R2_BASE_URL") || "";

const ALLOWED_DOMAINS = [
  "pub-cbf23f7a9f914d1a88f8f1cf741716db.r2.dev",
];

// ---------- M3U8 Cache Only ----------
// m3u8 playlist files ကသေးလို့ cache လုပ်ပေမယ့်
// segment (.ts) files တွေက stream pipe သာ သုံးမယ်
interface M3U8CacheEntry {
  raw: string;
  cachedAt: number;
}

const m3u8Cache = new Map<string, M3U8CacheEntry>();
const M3U8_CACHE_TTL = 5 * 60 * 1000; // 5 min

// cleanup every 3 min
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of m3u8Cache) {
    if (now - entry.cachedAt > M3U8_CACHE_TTL) {
      m3u8Cache.delete(key);
    }
  }
}, 3 * 60 * 1000);

// ---------- Active connection tracking ----------
let activeConnections = 0;

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

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, Content-Type",
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
  const r2Url = `${R2_BASE_URL}${r2Path}`;

  // retry with streaming
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

      // ------- KEY PART: Stream pipe -------
      // R2 response body ကို directly pipe လုပ်မယ်
      // Memory ထဲ buffer မလုပ်ဘူး
      const respHeaders: Record<string, string> = {
        "Content-Type":
          r2Resp.headers.get("Content-Type") || getContentType(r2Path),
        "Accept-Ranges": "bytes",
        ...corsHeaders(),
      };

      // pass through content-length
      const cl = r2Resp.headers.get("Content-Length");
      if (cl) respHeaders["Content-Length"] = cl;

      // pass through content-range (for seek/range requests)
      const cr = r2Resp.headers.get("Content-Range");
      if (cr) respHeaders["Content-Range"] = cr;

      // cache control: segments ကို browser cache ခိုင်းမယ်
      if (r2Path.endsWith(".ts") || r2Path.endsWith(".m4s")) {
        respHeaders["Cache-Control"] = "public, max-age=86400, immutable";
      }

      // body stream ကို pipe ---- ဒါက memory zero-copy ပုံစံ
      if (!r2Resp.body) {
        return new Response(null, {
          status: r2Resp.status,
          headers: respHeaders,
        });
      }

      // TransformStream ကနေ pipe: connection tracking + backpressure
      const { readable, writable } = new TransformStream();

      // background pipe - ဒါက memory ထဲ buffer မလုပ်ဘဲ chunk by chunk စီးသွားတာ
      (async () => {
        activeConnections++;
        try {
          await r2Resp.body!.pipeTo(writable);
        } catch (_e) {
          // client disconnect etc. - ပုံမှန်ပါ
          try { writable.close(); } catch { /* already closed */ }
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

  return new Response(`Upstream error: ${lastError?.message}`, {
    status: 502,
    headers: corsHeaders(),
  });
}

// ---------- M3U8 Handler (small file → buffer OK) ----------

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

  // fetch (m3u8 file is small, buffer OK)
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

      // cache it
      m3u8Cache.set(cacheKey, { raw, cachedAt: Date.now() });

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

  return new Response(`Upstream error: ${lastError?.message}`, {
    status: 502,
    headers: corsHeaders(),
  });
}

// ---------- Main Handler ----------

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

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

  // --- Health / Stats ---
  if (path === "/" || path === "/health") {
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
    if (!validateConfig()) {
      return new Response("Server misconfigured", {
        status: 500,
        headers: corsHeaders(),
      });
    }

    const r2Path = "/" + path.slice("/stream/".length);

    // m3u8 → buffer + rewrite (small file)
    if (r2Path.endsWith(".m3u8")) {
      const proxyBase = `${url.protocol}//${url.host}`;
      return handleM3U8(r2Path, proxyBase);
    }

    // everything else → stream pipe (zero buffer)
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
    const m3u8Url = `${url.protocol}//${url.host}/stream/${v}`;
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
    const src="${m3u8Url}",video=document.getElementById("v"),stats=document.getElementById("stats");
    if(Hls.isSupported()){
      const h=new Hls({
        maxBufferLength:30,
        maxMaxBufferLength:120,
        maxBufferSize:120*1024*1024,
        startLevel:-1,
        testBandwidth:true,
        progressive:true,
        lowLatencyMode:false
      });
      h.loadSource(src);h.attachMedia(video);
      h.on(Hls.Events.MANIFEST_PARSED,()=>video.play());
      h.on(Hls.Events.ERROR,(e,d)=>{
        if(d.fatal){
          if(d.type===Hls.ErrorTypes.NETWORK_ERROR){h.startLoad()}
          else if(d.type===Hls.ErrorTypes.MEDIA_ERROR){h.recoverMediaError()}
          else h.destroy()
        }
      });
      setInterval(()=>{
        const l=h.levels[h.currentLevel];
        stats.textContent="Level: "+(l?l.height+"p":"-")
          +" | Buffer: "+video.buffered.length
            ?(video.buffered.end(video.buffered.length-1)-video.currentTime).toFixed(1)+"s"
            :"0s";
      },1000);
    }else if(video.canPlayType("application/vnd.apple.mpegurl")){
      video.src=src
    }
  </script>
</body>
</html>`;
    return new Response(html, {
      headers: { "Content-Type": "text/html;charset=utf-8", ...corsHeaders() },
    });
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders() });
}

// ---------- Start ----------
Deno.serve({ port: 8000 }, handleRequest);
