const CACHE_NAME = "serviceops-shell-v1.65.1";
const SHELL_ASSETS = [
  "/static/platform.css?v=1.65.1",
  "/static/app.css?v=1.65.1",
  "/static/enterprise.css?v=1.65.1",
  "/static/brand.css?v=1.65.1",
  "/static/itil.css?v=1.65.1",
  "/static/platform.js?v=1.65.1",
  "/static/admin-workspace.css?v=1.65.1",
  "/static/lookup.js?v=1.65.1"
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

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
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
