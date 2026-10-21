// Minimal service worker — exists only for PWA installability. The app is
// inherently online (SSH/WS/API), so nothing is cached; fetches pass through.
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));
self.addEventListener('fetch', () => {});
