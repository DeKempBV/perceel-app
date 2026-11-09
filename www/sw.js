// Perceel App – service worker
// Nodig om de app te kunnen installeren. Pagina's komen altijd vers van internet
// (dus updates zijn meteen zichtbaar); zonder verbinding toont hij offline.html.
const CACHE = 'perceel-v2';
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['offline.html', 'icon-192.png', 'icon-512.png'])));
  self.skipWaiting();
});
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate') {
    // altijd de nieuwste versie ophalen, niet uit het browsergeheugen
    e.respondWith(fetch(e.request.url, {cache: 'no-store', credentials: 'same-origin'}).catch(() => caches.match('offline.html')));
  }
});
