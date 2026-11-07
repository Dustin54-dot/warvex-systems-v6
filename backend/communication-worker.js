const cors = {
  "Access-Control-Allow-Origin": "https://dustin54-dot.github.io",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Hub-Signature-256",
  "Vary": "Origin"
};
const json = (data, status=200) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type":"application/json; charset=utf-8", ...cors }
});
const enc = new TextEncoder();
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
async function signJwt(payload, secret) {
  const head = b64url(enc.encode(JSON.stringify({alg:"HS256",typ:"JWT"})));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const input = head + "." + body;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(input));
  return input + "." + b64url(new Uint8Array(sig));
}
async function verifyMeta(request, secret, raw) {
  const signature = request.headers.get("X-Hub-Signature-256") || "";
  if (!secret || !signature.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(raw));
  const expected = "sha256=" + [...new Uint8Array(mac)].map(x=>x.toString(16).padStart(2,"0")).join("");
  return signature === expected;
}
export default {
 async fetch(request, env) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null,{headers:cors});
  if (url.pathname === "/health" || url.pathname === "/api/status") {
   return json({
    service:"WARVEX Communication Gateway",
    ready:true,
    whatsapp:{configured:!!(env.WA_ACCESS_TOKEN && env.WA_PHONE_NUMBER_ID && env.WA_VERIFY_TOKEN && env.WA_APP_SECRET)},
    livekit:{configured:!!(env.LIVEKIT_URL && env.LIVEKIT_API_KEY && env.LIVEKIT_API_SECRET)},
    aiAgent:{configured:false, note:"Ein separater LiveKit-AI-Agent ist noch nicht bereitgestellt."}
   });
  }
  if (url.pathname === "/api/whatsapp/webhook" && request.method === "GET") {
   const mode=url.searchParams.get("hub.mode");
   const token=url.searchParams.get("hub.verify_token");
   const challenge=url.searchParams.get("hub.challenge");
   if (mode==="subscribe" && env.WA_VERIFY_TOKEN && token===env.WA_VERIFY_TOKEN && challenge) {
    return new Response(challenge,{headers:{"Content-Type":"text/plain",...cors}});
   }
   return new Response("Webhook verification failed",{status:403,headers:cors});
  }
  if (url.pathname === "/api/whatsapp/webhook" && request.method === "POST") {
   const raw=await request.text();
   if (!await verifyMeta(request,env.WA_APP_SECRET,raw)) return json({ok:false,error:"Ungültige Meta-Signatur oder App-Secret fehlt."},401);
   let payload;
   try { payload=JSON.parse(raw); } catch { return json({ok:false,error:"Ungültiges JSON."},400); }
   const count=(payload.entry||[]).reduce((n,e)=>n+(e.changes||[]).reduce((m,c)=>m+(((c.value||{}).messages||[]).length),0),0);
   return json({ok:true,accepted:true,messageCount:count,stored:false,autoReply:false});
  }
  if (url.pathname === "/api/whatsapp/send" && request.method === "POST") {
   if (!env.WA_ACCESS_TOKEN || !env.WA_PHONE_NUMBER_ID) return json({ok:false,error:"WhatsApp-Zugangsdaten fehlen. Meta-Verbindung zuerst einrichten."},503);
   let body; try { body=await request.json(); } catch { return json({ok:false,error:"JSON erwartet."},400); }
   const to=String(body.to||"").replace(/[^0-9]/g,"");
   const message=String(body.message||"").trim();
   if (!/^\d{8,15}$/.test(to) || !message || message.length>4096) return json({ok:false,error:"Empfänger im internationalen Format und Nachricht (max. 4096 Zeichen) erforderlich."},400);
   if (body.confirmSend !== true) return json({ok:false,needsConfirmation:true,error:"Senden muss vom Nutzer ausdrücklich bestätigt werden."},409);
   const version=env.WA_API_VERSION||"v23.0";
   const resp=await fetch("https://graph.facebook.com/"+version+"/"+env.WA_PHONE_NUMBER_ID+"/messages",{
    method:"POST",headers:{"Authorization":"Bearer "+env.WA_ACCESS_TOKEN,"Content-Type":"application/json"},
    body:JSON.stringify({messaging_product:"whatsapp",recipient_type:"individual",to,type:"text",text:{preview_url:false,body:message}})
   });
   const data=await resp.json();
   return json({ok:resp.ok,result:resp.ok?data:undefined,error:resp.ok?undefined:(data.error?.message||"Meta API Fehler.")},resp.ok?200:502);
  }
  if (url.pathname === "/api/livekit/token" && request.method === "POST") {
   if (!env.LIVEKIT_URL || !env.LIVEKIT_API_KEY || !env.LIVEKIT_API_SECRET) return json({ok:false,error:"LiveKit-Zugangsdaten fehlen."},503);
   let body; try { body=await request.json(); } catch { return json({ok:false,error:"JSON erwartet."},400); }
   const room=String(body.room||"").replace(/[^a-zA-Z0-9_-]/g,"").slice(0,64);
   const identity=String(body.identity||"").replace(/[^a-zA-Z0-9_-]/g,"").slice(0,48);
   if (!room || !identity) return json({ok:false,error:"Raum und Teilnehmerkennung erforderlich."},400);
   const now=Math.floor(Date.now()/1000);
   const token=await signJwt({iss:env.LIVEKIT_API_KEY,sub:identity,nbf:now-5,iat:now,exp:now+3600,video:{roomJoin:true,room,canPublish:true,canSubscribe:true,canPublishData:true}},env.LIVEKIT_API_SECRET);
   return json({ok:true,url:env.LIVEKIT_URL,token,room,expiresIn:3600,aiAgentPresent:false});
  }
  return json({ok:false,error:"Route nicht gefunden."},404);
 }
};