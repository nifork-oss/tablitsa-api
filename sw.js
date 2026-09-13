// Простой service worker — только для того, чтобы сайт можно было
// установить как приложение. Данные (API-запросы к tablitsa-api) НЕ
// кэшируются нигде — всегда идут в сеть, чтобы отчёты были актуальными.
const CACHE_NAME = 'tablitsa-shell-v1';
const SHELL_FILES = [
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
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

  // Запросы к API (workers.dev) — всегда только из сети, никогда не кэшируем.
  if (url.hostname.includes('workers.dev')) {
    return;
  }

  // Для остального (сама страница, манифест, иконки) — сначала сеть,
  // и только если сети нет — берём из кэша (чтобы всегда видеть свежую
  // версию сайта после обновлений, но не остаться совсем без доступа
  // при плохом интернете).
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
