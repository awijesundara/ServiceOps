const CACHE_NAME = "serviceops-shell-v1.113.1";
const SHELL_ASSETS = [
  "/static/platform.css?v=1.113.1",
  "/static/task-board.css?v=1.113.1",
  "/static/status-page.css?v=1.113.1",
  "/static/app.css?v=1.113.1",
  "/static/enterprise.css?v=1.113.1",
  "/static/brand.css?v=1.113.1",
  "/static/itil.css?v=1.113.1",
  "/static/platform.js?v=1.113.1",
  "/static/admin-workspace.css?v=1.113.1",
  "/static/utilities.css?v=1.113.1",
  "/static/dark.css?v=1.113.1",
  "/static/lookup.js?v=1.113.1",
  "/static/icons/serviceops-icon-192.png?v=1.113.1",
  "/static/icons/serviceops-icon-512.png?v=1.113.1"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
    ))
  );
  self.clients.claim();
});

// Shown instead of a gateway error while the server restarts (for example
// during an upgrade), so a short rollout reads as "updating", not a crash.
// It retries on its own and returns to the page the person asked for.
const UPDATING_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ServiceOps is updating</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f7;color:#1f2d33;
font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:420px;padding:32px;text-align:center}
.spinner{width:28px;height:28px;margin:0 auto 16px;border:3px solid #cdd8db;border-top-color:#00706b;
border-radius:50%;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
p{color:#52646b}</style></head><body><main><div class="spinner" aria-hidden="true"></div>
<h1>ServiceOps is updating</h1><p>This usually takes under a minute. This page reconnects by itself;
nothing you saved has been lost.</p></main><script>setTimeout(function(){location.reload()},5000)</script>
</body></html>`;

function updatingResponse() {
  return new Response(UPDATING_PAGE, {
    status: 503,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Retry-After": "5" }
  });
}

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (event.request.mode === "navigate" && url.origin === self.location.origin) {
    event.respondWith(
      fetch(event.request)
        // A 5xx without X-Request-ID came from the proxy, not ServiceOps (which
        // stamps every response), so the server itself is restarting.
        .then((response) => ([502, 503, 504].includes(response.status) && !response.headers.get("X-Request-ID")
          ? updatingResponse() : response))
        .catch(() => updatingResponse())
    );
    return;
  }
  if (url.origin !== self.location.origin || !url.pathname.startsWith("/static/")) return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok && SHELL_ASSETS.includes(`${url.pathname}${url.search}`)) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
