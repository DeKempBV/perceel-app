// Perceel App – service worker
// Nodig om de app te kunnen installeren. Pagina's komen altijd vers van internet
// (dus updates zijn meteen zichtbaar); zonder verbinding toont hij offline.html.
const CACHE = 'perceel-v1';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['offline.html', 'icon-192.png', 'icon-512.png'])));
  self.skipWaiting();
});
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(() => caches.match('offline.html')));
  }
});
