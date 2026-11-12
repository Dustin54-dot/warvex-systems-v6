const CACHE_NAME="warvex-v6-shared-core-v8";
const APP_URL=new URL("./app/",self.registration.scope).href;
const APP_PATH=new URL(APP_URL).pathname;

self.addEventListener("install",event=>{
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache=>cache.add(new Request(APP_URL,{cache:"reload"})))
      .then(()=>self.skipWaiting())
  );
});

self.addEventListener("activate",event=>{
  event.waitUntil(
    caches.keys()
      .then(keys=>Promise.all(keys.filter(key=>key.startsWith("warvex-")&&key!==CACHE_NAME).map(key=>caches.delete(key))))
      .then(()=>self.clients.claim())
  );
});

self.addEventListener("fetch",event=>{
  const request=event.request;
  if(request.method!=="GET")return;
  const url=new URL(request.url);
  if(url.origin!==self.location.origin)return;

  if(request.mode==="navigate"){
    event.respondWith(
      fetch(request).then(response=>{
        if(response&&response.ok&&url.pathname.startsWith(APP_PATH)){
          const copy=response.clone();
          caches.open(CACHE_NAME).then(cache=>cache.put(APP_URL,copy));
        }
        return response;
      }).catch(async()=>(
        (await caches.match(APP_URL))||Response.error()
      ))
    );
    return;
  }

  event.respondWith(
    caches.match(request).then(cached=>{
      const network=fetch(request).then(response=>{
        if(response&&response.ok&&response.type==="basic"){
          const copy=response.clone();
          caches.open(CACHE_NAME).then(cache=>cache.put(request,copy));
        }
        return response;
      });
      return cached||network;
    })
  );
});
