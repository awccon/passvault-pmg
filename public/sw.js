// PassVault service worker
// -------------------------
// Scope is deliberately narrow: caches only the static app shell (HTML,
// CSS, JS, icons) so the app launches fast and reliably. It NEVER caches
// anything under /api/ — the vault, auth, budget, and chat all stay
// live-network-only. This preserves the zero-knowledge design exactly
// as-is: nothing sensitive is ever written to Cache Storage, and the
// encryption key still only ever lives in page memory.
//
// Bump CACHE_NAME whenever shell assets change, so browsers already
// running the old service worker are forced onto a fresh cache instead
// of an old JS file paired with a new HTML file (a real bug this hit
// once already: renamed element ids threw "Cannot read properties of
// null" because a cached pre-rename app.js ran against post-rename
// HTML). Static assets below also use stale-while-revalidate, not pure
// cache-first, specifically so a forgotten version bump self-heals on
// the next load instead of leaving people stuck indefinitely.
const CACHE_NAME = 'passvault-shell-v2';
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/css/style.css',
  '/js/app.js',
  '/js/api.js',
  '/js/crypto.js',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never intercept API calls — vault/auth/budget/chat must always hit
  // the network live, never a cached response.
  if (url.pathname.startsWith('/api/')) return;
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;

  if (event.request.mode === 'navigate') {
    // Network-first for the page itself, so people get fresh HTML
    // whenever they're online; cached shell is just the offline fallback.
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/index.html', copy));
          return response;
        })
        .catch(() => caches.match('/index.html'))
    );
    return;
  }

  // Stale-while-revalidate for static shell assets (js/css/icons):
  // serve the cached copy immediately if there is one (fast), but
  // always also fetch fresh in the background and update the cache —
  // so the *next* load already has new assets even if CACHE_NAME
  // didn't change. Falls back to the cache if the network fetch fails
  // (e.g. offline).
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((response) => {
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, response.clone()));
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
