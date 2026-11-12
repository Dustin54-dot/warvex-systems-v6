const CACHE_NAME="warvex-v6-shared-core-v13";
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


self.addEventListener("push",event=>{
  let payload={};
  try{payload=event.data?event.data.json():{};}catch(_){payload={title:"WARVEX SYSTEMS",body:event.data?event.data.text():"Neue WARVEX-Mitteilung"};}
  const title=String(payload.title||"WARVEX SYSTEMS").slice(0,80);
  const options={
    body:String(payload.body||"Du hast eine neue WARVEX-Mitteilung.").slice(0,240),
    icon:new URL("./app/icon.svg",self.registration.scope).href,
    badge:new URL("./app/icon.svg",self.registration.scope).href,
    tag:String(payload.tag||"warvex-alert").slice(0,80),
    renotify:true,
    data:{url:payload.url||APP_URL}
  };
  event.waitUntil(self.registration.showNotification(title,options));
});
self.addEventListener("notificationclick",event=>{
  event.notification.close();
  const target=new URL(event.notification.data?.url||APP_URL,self.location.origin).href;
  event.waitUntil((async()=>{
    const clientsList=await self.clients.matchAll({type:"window",includeUncontrolled:true});
    for(const client of clientsList){
      if("focus" in client){await client.focus();if("navigate" in client)await client.navigate(target);return;}
    }
    if(self.clients.openWindow)await self.clients.openWindow(target);
  })());
});
