/* WARVEX V6 legacy PWA worker.
   The shared root worker now owns caching for both browser and PWA.
   This worker unregisters the old /pwa-only cache controller safely. */
self.addEventListener("install",event=>{
  event.waitUntil(self.skipWaiting());
});
self.addEventListener("activate",event=>{
  event.waitUntil(
    self.registration.unregister().then(()=>self.clients.claim())
  );
});
