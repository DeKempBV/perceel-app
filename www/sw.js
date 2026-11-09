// Perceel App – service worker
// - De app zelf komt altijd vers van internet (updates meteen zichtbaar); zonder bereik de laatst bekende versie.
// - Kaartbibliotheken en bekeken kaarttegels worden bewaard, zodat de kaart ook zonder bereik werkt.
const CACHE = 'perceel-v3', TEGELS = 'perceel-tegels', MAX_TEGELS = 4000;
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['offline.html', 'icon-192.png', 'icon-512.png'])));
  self.skipWaiting();
});
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(k => Promise.all(k.filter(n => n !== CACHE && n !== TEGELS).map(n => caches.delete(n)))).then(() => self.clients.claim())));
const isCdn = u => /unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com/.test(u.hostname);
const isTegel = u => /arcgisonline\.com|tile\.openstreetmap\.org/.test(u.hostname);
let teller = 0;
async function tegelsOpruimen() {
  const c = await caches.open(TEGELS), k = await c.keys();
  for (let i = 0; i < k.length - MAX_TEGELS; i++) await c.delete(k[i]);
}
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return;
  const u = new URL(r.url);
  if (r.mode === 'navigate') {
    e.respondWith(fetch(r.url, {cache: 'no-store', credentials: 'same-origin'})
      .then(resp => { if (resp.ok) { const kopie = resp.clone(); caches.open(CACHE).then(c => c.put('laatste-app', kopie)); } return resp; })
      .catch(async () => (await caches.match('laatste-app')) || caches.match('offline.html')));
    return;
  }
  if (isCdn(u)) {   // eerst uit de opslag (snel), op de achtergrond verversen
    e.respondWith(caches.open(CACHE).then(async c => {
      const oud = await c.match(r);
      const vers = fetch(r).then(resp => { if (resp.ok || resp.type === 'opaque') c.put(r, resp.clone()); return resp; }).catch(() => oud);
      return oud || vers;
    }));
    return;
  }
  if (isTegel(u)) {
    e.respondWith(caches.open(TEGELS).then(async c => {
      const oud = await c.match(r); if (oud) return oud;
      try { const resp = await fetch(r); if (resp.ok || resp.type === 'opaque') { c.put(r, resp.clone()); if (++teller % 200 === 0) tegelsOpruimen(); } return resp; }
      catch { return new Response('', {status: 504}); }
    }));
    return;
  }
  if (u.origin === location.origin && !u.pathname.endsWith('version.json')) {   // eigen bestanden (config.js, iconen): eerst internet, anders de opslag
    e.respondWith(fetch(r).then(resp => { if (resp.ok) { const k = resp.clone(); caches.open(CACHE).then(c => c.put(r, k)); } return resp; }).catch(() => caches.match(r)));
  }
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type: 'window'}).then(l => l.length ? l[0].focus() : self.clients.openWindow('./')));
});
