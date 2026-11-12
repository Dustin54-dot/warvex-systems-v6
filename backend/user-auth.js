const enc = new TextEncoder();
const ORIGIN = "https://dustin54-dot.github.io";
// Cloudflare Workers WebCrypto PBKDF2 limit is 100,000 iterations.
const ITERATIONS = 100000;
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const attempts = new Map();

function b64u(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64u(value) {
  const raw = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(raw + "=".repeat((4 - raw.length % 4) % 4)), c => c.charCodeAt(0));
}
function token() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return b64u(bytes);
}
async function hash(value) {
  return b64u(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Cache-Control": "no-store",
      "Vary": "Origin"
    }
  });
}
function validEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function limited(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const rows = (attempts.get(ip) || []).filter(t => now - t < 600000);
  if (rows.length >= 20) {
    attempts.set(ip, rows);
    return true;
  }
  rows.push(now);
  attempts.set(ip, rows);
  if (attempts.size > 1000) {
    for (const [key, values] of attempts) {
      if (!values.length || now - values[values.length - 1] > 600000) attempts.delete(key);
    }
  }
  return false;
}
async function passwordHash(password, salt, iterations = ITERATIONS) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64u(salt), iterations, hash: "SHA-256" }, key, 256
  );
  return b64u(bits);
}
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function bodyOf(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 10000) throw new Error("Anfrage zu groß.");
  const value = await request.json();
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Ungültige Anfrage.");
  return value;
}
async function sessionOf(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const raw = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (raw.length < 30 || raw.length > 200) return null;
  return env.DB.prepare(
    "SELECT s.token_hash,s.account_id,s.expires_at,a.email," +
    "CASE WHEN EXISTS(SELECT 1 FROM owner_accounts oa WHERE oa.email=a.email COLLATE NOCASE AND oa.role='primary_owner' AND oa.status='active') THEN 'primary_owner' ELSE a.role END AS role," +
    "a.status,a.email_verified_at,a.display_name " +
    "FROM app_user_sessions s JOIN app_accounts a ON a.id=s.account_id " +
    "WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND a.status='active'"
  ).bind(await hash(raw), Date.now()).first();
}

export async function handleUserAuth(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/auth/")) return null;
  const origin = request.headers.get("Origin") || "";
  if (origin && origin !== ORIGIN) return json({ success: false, error: "Origin nicht erlaubt." }, 403);
  if (request.method === "OPTIONS") return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });

  try {
    const path = url.pathname;
    if (path === "/api/auth/register" && request.method === "POST") {
      if (limited(request)) return json({ success: false, error: "Zu viele Versuche. Bitte später erneut probieren." }, 429);
      const body = await bodyOf(request);
      const email = String(body.email || "").trim().toLowerCase();
      const password = body.password;
      if (!validEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 128) {
        return json({ success: false, error: "Bitte gib eine gültige E-Mail-Adresse und ein Passwort mit mindestens 12 Zeichen ein." }, 400);
      }
      const existing = await env.DB.prepare("SELECT id FROM app_accounts WHERE email=? COLLATE NOCASE").bind(email).first();
      if (existing) return json({ success: false, error: "Für diese E-Mail-Adresse besteht bereits ein Konto. Bitte melde dich an." }, 409);

      const id = crypto.randomUUID();
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = b64u(saltBytes);
      const derived = await passwordHash(password, salt);
      const now = Date.now();
      const sessionToken = token();
      const batch = await env.DB.batch([
        env.DB.prepare("INSERT INTO app_accounts (id,email,status,created_at,email_verified_at,role) VALUES (?,?, 'active', ?, NULL, 'user')")
          .bind(id, email, now),
        env.DB.prepare("INSERT INTO app_account_passwords (account_id,salt,password_hash,iterations,updated_at) VALUES (?,?,?,?,?)")
          .bind(id, salt, derived, ITERATIONS, now),
        env.DB.prepare("INSERT INTO app_user_sessions (token_hash,account_id,created_at,expires_at) VALUES (?,?,?,?)")
          .bind(await hash(sessionToken), id, now, now + SESSION_MS)
      ]);
      if (!batch || batch.length !== 3 || batch.some(x => x.success === false)) {
        return json({ success: false, error: "Das Konto konnte nicht erstellt werden. Bitte versuche es erneut." }, 500);
      }
      return json({
        success: true,
        sessionToken,
        user: { id, warvexId: id, email, displayName: null, role: "user", roleLabel: "Benutzer", emailVerified: false }
      }, 201);
    }

    if (path === "/api/auth/login" && request.method === "POST") {
      if (limited(request)) return json({ success: false, error: "Zu viele Versuche. Bitte später erneut probieren." }, 429);
      const body = await bodyOf(request);
      const email = String(body.email || "").trim().toLowerCase();
      const password = body.password;
      if (!validEmail(email) || typeof password !== "string" || password.length > 128) {
        return json({ success: false, error: "E-Mail oder Passwort falsch." }, 401);
      }
      const account = await env.DB.prepare(
        "SELECT a.id,a.email,CASE WHEN EXISTS(SELECT 1 FROM owner_accounts oa WHERE oa.email=a.email COLLATE NOCASE AND oa.role='primary_owner' AND oa.status='active') THEN 'primary_owner' ELSE a.role END AS role," +
        "a.status,a.email_verified_at,a.display_name,p.salt,p.password_hash,p.iterations " +
        "FROM app_accounts a JOIN app_account_passwords p ON p.account_id=a.id " +
        "WHERE a.email=? COLLATE NOCASE AND a.status='active'"
      ).bind(email).first();
      const candidate = account ? await passwordHash(password, account.salt, account.iterations) : "";
      if (!account || !equal(candidate, account.password_hash)) {
        return json({ success: false, error: "E-Mail oder Passwort falsch." }, 401);
      }
      const sessionToken = token();
      const now = Date.now();
      await env.DB.prepare("INSERT INTO app_user_sessions (token_hash,account_id,created_at,expires_at) VALUES (?,?,?,?)")
        .bind(await hash(sessionToken), account.id, now, now + SESSION_MS).run();
      return json({
        success: true,
        sessionToken,
        user: {
          id: account.id,
          warvexId: account.id,
          email: account.email,
          displayName: account.display_name || null,
          role: account.role,
          roleLabel: account.role === "primary_owner" ? "Haupt-Owner" : account.role === "owner" ? "Owner" : account.role === "admin" ? "Admin" : account.role === "team_member" ? "Teammitglied" : "Benutzer",
          emailVerified: !!account.email_verified_at
        }
      });
    }

    if (path === "/api/auth/me" && request.method === "GET") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      return json({
        success: true,
        user: {
          id: session.account_id,
          warvexId: session.account_id,
          email: session.email,
          displayName: session.display_name || null,
          role: session.role,
          roleLabel: session.role === "primary_owner" ? "Haupt-Owner" : session.role === "owner" ? "Owner" : session.role === "admin" ? "Admin" : session.role === "team_member" ? "Teammitglied" : "Benutzer",
          emailVerified: !!session.email_verified_at
        }
      });
    }

    if (path === "/api/auth/profile" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body = await bodyOf(request);
      const displayName = String(body.displayName || "").trim().replace(/\s+/g, " ");
      if (displayName.length < 1 || displayName.length > 32 || /[\u0000-\u001f\u007f<>]/.test(displayName)) {
        return json({ success: false, error: "Der Anredename muss 1 bis 32 Zeichen lang sein und darf keine Steuerzeichen enthalten." }, 400);
      }
      await env.DB.prepare("UPDATE app_accounts SET display_name=? WHERE id=?")
        .bind(displayName, session.account_id).run();
      return json({ success: true, displayName, warvexId: session.account_id });
    }

    if (path === "/api/auth/security-report" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body = await bodyOf(request);
      const category = String(body.category || "").trim();
      const content = String(body.content || "").trim();
      const district = String(body.district || "").trim();
      if (!["suspicious_content","possible_threat","security_issue","other"].includes(category) ||
          content.length < 8 || content.length > 3000 || district.length > 80 ||
          /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content + district)) {
        return json({ success: false, error: "Bitte wähle eine Kategorie und gib eine Meldung mit 8 bis 3000 Zeichen ein. Die optionale Gegend darf höchstens 80 Zeichen haben." }, 400);
      }
      const id = crypto.randomUUID();
      const now = Date.now();
      await env.DB.prepare(
        "INSERT INTO app_security_reports (id,account_id,category,content,district,status,created_at) VALUES (?,?,?,?,?,'pending',?)"
      ).bind(id, session.account_id, category, content, district || null, now).run();
      return json({ success: true, reportId: id, message: "Deine Meldung wurde an das geschützte WARVEX-Sicherheitspostfach übermittelt. Sie ist ein ungeprüfter Hinweis." }, 201);
    }

    if (path === "/api/auth/friends" && request.method === "GET") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const incoming = await env.DB.prepare(
        "SELECT r.id,r.requester_id AS warvex_id,COALESCE(a.display_name,'WARVEX-Nutzer') AS display_name,r.created_at " +
        "FROM app_friend_requests r JOIN app_accounts a ON a.id=r.requester_id " +
        "WHERE r.recipient_id=? AND r.status='pending' ORDER BY r.created_at DESC"
      ).bind(session.account_id).all();
      const outgoing = await env.DB.prepare(
        "SELECT r.id,r.recipient_id AS warvex_id,COALESCE(a.display_name,'WARVEX-Nutzer') AS display_name,r.created_at " +
        "FROM app_friend_requests r JOIN app_accounts a ON a.id=r.recipient_id " +
        "WHERE r.requester_id=? AND r.status='pending' ORDER BY r.created_at DESC"
      ).bind(session.account_id).all();
      const friends = await env.DB.prepare(
        "SELECT r.id,r.requester_id,r.recipient_id," +
        "CASE WHEN r.requester_id=? THEN r.recipient_id ELSE r.requester_id END AS warvex_id," +
        "COALESCE(a.display_name,'WARVEX-Nutzer') AS display_name," +
        "CASE WHEN r.requester_id=? THEN COALESCE(s.enabled,0) ELSE 0 END AS share_enabled " +
        "FROM app_friend_requests r " +
        "JOIN app_accounts a ON a.id=CASE WHEN r.requester_id=? THEN r.recipient_id ELSE r.requester_id END " +
        "LEFT JOIN app_friend_shares s ON s.sender_id=r.requester_id AND s.receiver_id=r.recipient_id " +
        "WHERE (r.requester_id=? OR r.recipient_id=?) AND r.status='accepted' ORDER BY a.display_name"
      ).bind(session.account_id,session.account_id,session.account_id,session.account_id,session.account_id).all();
      return json({ success: true, incoming: incoming.results || [], outgoing: outgoing.results || [], friends: friends.results || [] });
    }

    if (path === "/api/auth/friends/request" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body = await bodyOf(request);
      const friendId = String(body.warvexId || "").trim();
      if (!friendId || friendId.length > 80 || friendId === session.account_id) {
        return json({ success: false, error: "Bitte gib eine gültige WARVEX-ID eines anderen Kontos ein." }, 400);
      }
      const friend = await env.DB.prepare("SELECT id FROM app_accounts WHERE id=? AND status='active'").bind(friendId).first();
      if (!friend) return json({ success: false, error: "Kein aktives WARVEX-Konto mit dieser ID gefunden." }, 404);
      const exists = await env.DB.prepare(
        "SELECT id,status FROM app_friend_requests WHERE (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?) LIMIT 1"
      ).bind(session.account_id,friendId,friendId,session.account_id).first();
      if (exists) return json({ success: false, error: exists.status === "accepted" ? "Ihr seid bereits verbunden." : "Für diese Konten besteht bereits eine Anfrage." }, 409);
      const id=crypto.randomUUID(), now=Date.now();
      await env.DB.prepare("INSERT INTO app_friend_requests (id,requester_id,recipient_id,status,created_at) VALUES (?,?,?,'pending',?)")
        .bind(id,session.account_id,friendId,now).run();
      return json({ success: true, requestId:id, message:"Freundschaftsanfrage wurde gesendet. Die andere Person muss sie selbst bestätigen." },201);
    }

    if (path === "/api/auth/friends/respond" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body = await bodyOf(request);
      const requestId=String(body.requestId||"");
      const accept=body.accept===true;
      const invite=await env.DB.prepare("SELECT id,requester_id,recipient_id,status FROM app_friend_requests WHERE id=? AND recipient_id=? AND status='pending'")
        .bind(requestId,session.account_id).first();
      if(!invite)return json({success:false,error:"Anfrage nicht gefunden oder bereits bearbeitet."},404);
      const now=Date.now();
      if(accept){
        await env.DB.batch([
          env.DB.prepare("UPDATE app_friend_requests SET status='accepted',responded_at=? WHERE id=? AND recipient_id=?").bind(now,requestId,session.account_id),
          env.DB.prepare("INSERT INTO app_friend_shares (sender_id,receiver_id,enabled,last_alert_at,created_at) VALUES (?,?,0,0,?)").bind(invite.requester_id,invite.recipient_id,now),
          env.DB.prepare("INSERT INTO app_notifications (id,account_id,kind,title,message,created_at,event_key) VALUES (?,?, 'friend','WARVEX-Freundschaft bestätigt','Deine Freundschaftsanfrage wurde angenommen.',?,?)")
            .bind(crypto.randomUUID(),invite.requester_id,now,"friend-accepted-"+requestId)
        ]);
      }else{
        await env.DB.prepare("UPDATE app_friend_requests SET status='rejected',responded_at=? WHERE id=? AND recipient_id=?")
          .bind(now,requestId,session.account_id).run();
      }
      return json({success:true,message:accept?"Freund hinzugefügt. Du hast die Anfrage bestätigt; der Alarmversand bleibt bis zur Freigabe durch die andere Person ausgeschaltet.":"Anfrage abgelehnt."});
    }

    if (path === "/api/auth/friends/share" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body=await bodyOf(request), friendId=String(body.friendId||""), enabled=body.enabled===true;
      const relation=await env.DB.prepare(
        "SELECT id FROM app_friend_requests WHERE requester_id=? AND recipient_id=? AND status='accepted'"
      ).bind(session.account_id,friendId).first();
      if(!relation)return json({success:false,error:"Nur bestätigte Freunde können freigegeben werden."},403);
      await env.DB.prepare("UPDATE app_friend_shares SET enabled=? WHERE sender_id=? AND receiver_id=?")
        .bind(enabled?1:0,session.account_id,friendId).run();
      return json({success:true,enabled,message:enabled?"Kritische Pulsalarme werden für diesen Freund freigegeben.":"Alarmfreigabe ausgeschaltet."});
    }

    if (path === "/api/auth/friends/remove" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body=await bodyOf(request), friendId=String(body.friendId||"");
      await env.DB.batch([
        env.DB.prepare("DELETE FROM app_friend_shares WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)").bind(session.account_id,friendId,friendId,session.account_id),
        env.DB.prepare("DELETE FROM app_friend_requests WHERE status='accepted' AND ((requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?))").bind(session.account_id,friendId,friendId,session.account_id)
      ]);
      return json({success:true,message:"Freundschaft und Alarmfreigabe entfernt."});
    }

    if (path === "/api/auth/friends/critical-alert" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body=await bodyOf(request), bpm=Number(body.bpm);
      if(!Number.isInteger(bpm)||bpm<25||bpm>250)return json({success:false,error:"Ungültiger Pulswert."},400);
      const shares=await env.DB.prepare(
        "SELECT s.receiver_id FROM app_friend_shares s JOIN app_friend_requests r ON r.requester_id=s.sender_id AND r.recipient_id=s.receiver_id AND r.status='accepted' WHERE s.sender_id=? AND s.enabled=1 AND (? - s.last_alert_at)>=60000"
      ).bind(session.account_id,Date.now()).all();
      const now=Date.now(), rows=shares.results||[];
      for(const item of rows){
        await env.DB.batch([
          env.DB.prepare("UPDATE app_friend_shares SET last_alert_at=? WHERE sender_id=? AND receiver_id=?").bind(now,session.account_id,item.receiver_id),
          env.DB.prepare("INSERT OR IGNORE INTO app_notifications (id,account_id,kind,title,message,created_at,event_key) VALUES (?,?, 'critical_pulse','KRITISCHER PULSALARM',?,?,?)")
            .bind(crypto.randomUUID(),item.receiver_id,"Eine befreundete Person hat einen kritischen Pulsalarm ausgelöst. Gemessener Puls: "+bpm+" BPM. Bitte prüfe, ob sie Unterstützung benötigt.",now,"critical-pulse-"+session.account_id+"-"+now)
        ]);
      }
      return json({success:true,notified:rows.length,delivery:"in_app"});
    }

    if (path === "/api/auth/notifications" && request.method === "GET") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const rows = await env.DB.prepare(
        "SELECT id,kind,title,message,created_at,read_at FROM app_notifications WHERE account_id=? ORDER BY created_at DESC LIMIT 30"
      ).bind(session.account_id).all();
      return json({ success: true, notifications: rows.results || [] });
    }

    if (path === "/api/auth/notifications/read" && request.method === "POST") {
      const session = await sessionOf(request, env);
      if (!session) return json({ success: false, error: "Bitte melde dich an." }, 401);
      const body = await bodyOf(request);
      const id = String(body.id || "");
      if (!id || id.length > 80) return json({ success: false, error: "Ungültige Nachricht." }, 400);
      await env.DB.prepare(
        "UPDATE app_notifications SET read_at=? WHERE id=? AND account_id=? AND read_at IS NULL"
      ).bind(Date.now(), id, session.account_id).run();
      return json({ success: true });
    }

    if (path === "/api/auth/logout" && request.method === "POST") {
      const auth = request.headers.get("Authorization") || "";
      const raw = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (raw.length >= 30 && raw.length <= 200) {
        await env.DB.prepare("UPDATE app_user_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL")
          .bind(Date.now(), await hash(raw)).run();
      }
      return json({ success: true });
    }
    return json({ success: false, error: "Nicht gefunden." }, 404);
  } catch (error) {
    console.error("WARVEX user auth:", error?.message || String(error));
    return json({ success: false, error: "Anmeldung momentan nicht möglich. Bitte später erneut versuchen." }, 500);
  }
}
