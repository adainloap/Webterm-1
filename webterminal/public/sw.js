const CACHE_NAME = 'webterminal-cache-v1';
const urlsToCache = [
  '/',
  '/login',
  '/style.css',
  '/assets/icons/192x192.png',
  '/assets/icons/512x512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});
