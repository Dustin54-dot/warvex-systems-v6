const enc = new TextEncoder();
const OWNER_ORIGIN = "https://dustin54-dot.github.io";
const PASSWORD_ITERATIONS = 310000;
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const REQUEST_MS = 10 * 60 * 1000;

function b64u(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64u(value) {
  const raw = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = raw + "=".repeat((4 - raw.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return b64u(data);
}
async function sha(value) {
  return b64u(await crypto.subtle.digest("SHA-256", enc.encode(value)));
}
function same(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function ownerJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": OWNER_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
      "Cache-Control": "no-store"
    }
  });
}
function validEmail(value) {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validPublicKey(key) {
  return key && key.kty === "EC" && key.crv === "P-256" &&
    typeof key.x === "string" && typeof key.y === "string" &&
    !key.d && key.x.length <= 100 && key.y.length <= 100;
}
function canonicalKey(key) {
  return JSON.stringify({ kty: "EC", crv: "P-256", x: key.x, y: key.y });
}
async function keyHash(key) {
  return sha(canonicalKey(key));
}
async function derivePassword(password, salt, iterations = PASSWORD_ITERATIONS) {
  const material = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64u(salt), iterations, hash: "SHA-256" },
    material, 256
  );
  return b64u(bits);
}
async function passwordRecord(password) {
  const salt = randomToken(16);
  return {
    salt,
    password_hash: await derivePassword(password, salt),
    iterations: PASSWORD_ITERATIONS
  };
}
async function verifyPassword(password, row) {
  if (!row || typeof password !== "string" || password.length > 128) return false;
  const candidate = await derivePassword(password, row.salt, row.iterations);
  return same(candidate, row.password_hash);
}
async function verifySignature(publicKey, challenge, signature) {
  if (!validPublicKey(publicKey) || typeof challenge !== "string" ||
      typeof signature !== "string" || signature.length > 300) return false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key,
      unb64u(signature), enc.encode(challenge)
    );
  } catch {
    return false;
  }
}
async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) throw new Error("Zu große Anfrage.");
  const value = await request.json();
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Ungültige Anfrage.");
  return value;
}
async function audit(env, ownerId, action, email, metadata = {}) {
  await env.DB.prepare(
    "INSERT INTO owner_audit_events (id,actor_owner_id,action,target_email,created_at,metadata_json) VALUES (?,?,?,?,?,?)"
  ).bind(crypto.randomUUID(), ownerId, action, email || null, Date.now(),
    JSON.stringify(metadata).slice(0, 1000)).run();
}
async function ownerSession(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (token.length < 30 || token.length > 200) return null;
  const tokenHash = await sha(token);
  return await env.DB.prepare(
    "SELECT s.token_hash,s.owner_id,s.device_id,s.expires_at,o.email,o.role,o.status,d.device_label " +
    "FROM owner_sessions s JOIN owner_accounts o ON o.id=s.owner_id " +
    "JOIN owner_devices d ON d.id=s.device_id " +
    "WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? " +
    "AND o.status='active' AND d.revoked_at IS NULL"
  ).bind(tokenHash, Date.now()).first();
}
async function newSession(env, ownerId, deviceId) {
  const token = randomToken(32);
  const expiresAt = Date.now() + SESSION_MS;
  await env.DB.prepare(
    "INSERT INTO owner_sessions (token_hash,owner_id,device_id,created_at,expires_at) VALUES (?,?,?,?,?)"
  ).bind(await sha(token), ownerId, deviceId, Date.now(), expiresAt).run();
  return { sessionToken: token, expiresAt };
}
async function consumeChallenge(env, row, purpose) {
  const result = await env.DB.prepare(
    "UPDATE owner_challenges SET consumed_at=? WHERE id=? AND purpose=? AND consumed_at IS NULL AND expires_at>?"
  ).bind(Date.now(), row.id, purpose, Date.now()).run();
  return result.meta?.changes === 1;
}
async function failedChallenge(env, row) {
  if (!row?.id) return;
  await env.DB.prepare(
    "UPDATE owner_challenges SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN failed_attempts+1>=5 THEN ? ELSE locked_until END WHERE id=? AND consumed_at IS NULL"
  ).bind(Date.now() + CHALLENGE_MS, row.id).run();
}
async function requireOwner(request, env) {
  const session = await ownerSession(request, env);
  if (!session) return { error: ownerJson({ success: false, error: "OWNER-Anmeldung erforderlich." }, 401) };
  return { session };
}

export async function handleOwnerAuth(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/owner/")) return null;

  const origin = request.headers.get("Origin") || "";
  if (origin && origin !== OWNER_ORIGIN) return ownerJson({ success: false, error: "Origin nicht erlaubt." }, 403);
  if (request.method === "OPTIONS") return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": OWNER_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });

  try {
    const path = url.pathname;
    const now = Date.now();

    if (path === "/api/owner/status" && request.method === "GET") {
      const owner = await env.DB.prepare(
        "SELECT id,email,role,status FROM owner_accounts WHERE role='primary_owner' AND status='active' LIMIT 1"
      ).first();
      return ownerJson({ success: true, initialized: !!owner });
    }

    if (path === "/api/owner/bootstrap" && request.method === "POST") {
      const body = await readBody(request);
      const email = String(body.email || "").trim().toLowerCase();
      const password = body.password;
      const bootstrapCode = body.bootstrapCode;
      const deviceLabel = String(body.deviceLabel || "WARVEX-Gerät").slice(0, 80);
      const publicKey = body.publicKey;
      if (!validEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 128 ||
          typeof bootstrapCode !== "string" || bootstrapCode.length < 30 || !validPublicKey(publicKey)) {
        return ownerJson({ success: false, error: "E-Mail, Passwort (mindestens 12 Zeichen), Einrichtungscode oder Geräteschlüssel ungültig." }, 400);
      }
      const bootstrap = await env.DB.prepare(
        "SELECT token_hash,email,expires_at,consumed_at FROM owner_bootstrap_tokens WHERE token_hash=? AND email=? COLLATE NOCASE AND consumed_at IS NULL AND expires_at>?"
      ).bind(await sha(bootstrapCode), email, now).first();
      if (!bootstrap) return ownerJson({ success: false, error: "Einrichtungscode ungültig, abgelaufen oder bereits benutzt." }, 403);
      const existing = await env.DB.prepare(
        "SELECT id FROM owner_accounts WHERE role='primary_owner' AND status='active' LIMIT 1"
      ).first();
      if (existing) return ownerJson({ success: false, error: "Der Haupt-OWNER wurde bereits eingerichtet." }, 409);

      const ownerId = crypto.randomUUID();
      const deviceId = crypto.randomUUID();
      const keyHashValue = await keyHash(publicKey);
      const pass = await passwordRecord(password);
      const publicJwk = canonicalKey(publicKey);
      const sessionToken = randomToken(32);
      const expiresAt = now + SESSION_MS;
      const batch = await env.DB.batch([
        env.DB.prepare("UPDATE owner_bootstrap_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?")
          .bind(now, bootstrap.token_hash, now),
        env.DB.prepare("INSERT INTO owner_accounts (id,email,role,status,created_at) VALUES (?,?, 'primary_owner','active',?)")
          .bind(ownerId, email, now),
        env.DB.prepare("INSERT INTO owner_passwords (owner_id,salt,password_hash,iterations,updated_at) VALUES (?,?,?,?,?)")
          .bind(ownerId, pass.salt, pass.password_hash, pass.iterations, now),
        env.DB.prepare("INSERT INTO owner_devices (id,owner_id,device_label,credential_public_key,created_at,last_seen_at,credential_id_hash) VALUES (?,?,?,?,?,?,?)")
          .bind(deviceId, ownerId, deviceLabel, publicJwk, now, now, keyHashValue),
        env.DB.prepare("INSERT INTO owner_sessions (token_hash,owner_id,device_id,created_at,expires_at) VALUES (?,?,?,?,?)")
          .bind(await sha(sessionToken), ownerId, deviceId, now, expiresAt),
        env.DB.prepare("INSERT INTO owner_audit_events (id,actor_owner_id,action,target_email,created_at,metadata_json) VALUES (?,?,?,?,?,?)")
          .bind(crypto.randomUUID(), ownerId, "primary_owner_bootstrap", email, now, JSON.stringify({ deviceLabel }))
      ]);
      if (!batch?.length || batch[0]?.meta?.changes !== 1) return ownerJson({ success: false, error: "Einrichtungscode wurde bereits verwendet oder die Einrichtung konnte nicht abgeschlossen werden." }, 409);
      return ownerJson({ success: true, email, role: "primary_owner", sessionToken, expiresAt });
    }

    if (path === "/api/owner/challenge" && request.method === "POST") {
      const body = await readBody(request);
      const email = String(body.email || "").trim().toLowerCase();
      const purpose = body.purpose;
      if (!validEmail(email) || !["login", "device_change"].includes(purpose)) {
        return ownerJson({ success: false, error: "Ungültige Anmeldedaten." }, 400);
      }
      const owner = await env.DB.prepare(
        "SELECT id FROM owner_accounts WHERE email=? COLLATE NOCASE AND status='active'"
      ).bind(email).first();
      if (!owner) return ownerJson({ success: false, error: "OWNER-Konto nicht gefunden." }, 404);
      const recent = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM owner_challenges WHERE email=? COLLATE NOCASE AND created_at>?"
      ).bind(email, now - 60000).first();
      if ((recent?.n || 0) >= 8) return ownerJson({ success: false, error: "Zu viele Versuche. Bitte später erneut versuchen." }, 429);
      const id = crypto.randomUUID();
      const challenge = randomToken(32);
      await env.DB.prepare(
        "INSERT INTO owner_challenges (id,challenge_hash,email,purpose,expires_at,created_at) VALUES (?,?,?,?,?,?)"
      ).bind(id, await sha(challenge), email, purpose, now + CHALLENGE_MS, now).run();
      return ownerJson({ success: true, challengeId: id, challenge, expiresAt: now + CHALLENGE_MS });
    }

    if (path === "/api/owner/login" && request.method === "POST") {
      const body = await readBody(request);
      const email = String(body.email || "").trim().toLowerCase();
      const challenge = await env.DB.prepare(
        "SELECT * FROM owner_challenges WHERE id=? AND email=? COLLATE NOCASE AND purpose='login' AND consumed_at IS NULL AND expires_at>?"
      ).bind(body.challengeId, email, now).first();
      if (!challenge || !same(await sha(String(body.challenge || "")), challenge.challenge_hash)) {
        return ownerJson({ success: false, error: "Anmelde-Challenge ungültig oder abgelaufen." }, 403);
      }
      if (challenge.locked_until && challenge.locked_until > now) {
        return ownerJson({ success: false, error: "Zu viele Fehlversuche. Bitte eine neue Challenge anfordern." }, 429);
      }
      const owner = await env.DB.prepare(
        "SELECT id,email,role FROM owner_accounts WHERE email=? COLLATE NOCASE AND status='active'"
      ).bind(email).first();
      const pass = owner ? await env.DB.prepare(
        "SELECT salt,password_hash,iterations FROM owner_passwords WHERE owner_id=?"
      ).bind(owner.id).first() : null;
      if (!owner || !(await verifyPassword(body.password, pass))) {
        await failedChallenge(env, challenge);
        return ownerJson({ success: false, error: "E-Mail oder Passwort falsch." }, 401);
      }
      const deviceHash = String(body.deviceKeyHash || "");
      const device = await env.DB.prepare(
        "SELECT id,credential_public_key FROM owner_devices WHERE owner_id=? AND credential_id_hash=? AND revoked_at IS NULL"
      ).bind(owner.id, deviceHash).first();
      if (!device) return ownerJson({ success: false, error: "Dieses Gerät ist noch nicht freigegeben. Bitte Gerätefreigabe anfordern." }, 403);
      const publicKey = JSON.parse(device.credential_public_key);
      if (!(await verifySignature(publicKey, String(body.challenge), body.signature))) {
        await failedChallenge(env, challenge);
        return ownerJson({ success: false, error: "Geräte-Signatur ungültig." }, 403);
      }
      if (!(await consumeChallenge(env, challenge, "login"))) return ownerJson({ success: false, error: "Challenge wurde bereits verwendet." }, 409);
      await env.DB.prepare("UPDATE owner_devices SET last_seen_at=? WHERE id=?").bind(now, device.id).run();
      const session = await newSession(env, owner.id, device.id);
      await audit(env, owner.id, "owner_login", email, { deviceId: device.id });
      return ownerJson({ success: true, email, role: owner.role, ...session });
    }

    if (path === "/api/owner/request-device" && request.method === "POST") {
      const body = await readBody(request);
      const email = String(body.email || "").trim().toLowerCase();
      const challenge = await env.DB.prepare(
        "SELECT * FROM owner_challenges WHERE id=? AND email=? COLLATE NOCASE AND purpose='device_change' AND consumed_at IS NULL AND expires_at>?"
      ).bind(body.challengeId, email, now).first();
      if (!challenge || !same(await sha(String(body.challenge || "")), challenge.challenge_hash)) {
        return ownerJson({ success: false, error: "Geräte-Challenge ungültig oder abgelaufen." }, 403);
      }
      if (challenge.locked_until && challenge.locked_until > now) {
        return ownerJson({ success: false, error: "Zu viele Fehlversuche. Bitte eine neue Challenge anfordern." }, 429);
      }
      const owner = await env.DB.prepare(
        "SELECT id FROM owner_accounts WHERE email=? COLLATE NOCASE AND status='active'"
      ).bind(email).first();
      const pass = owner ? await env.DB.prepare(
        "SELECT salt,password_hash,iterations FROM owner_passwords WHERE owner_id=?"
      ).bind(owner.id).first() : null;
      if (!owner || !(await verifyPassword(body.password, pass))) {
        await failedChallenge(env, challenge);
        return ownerJson({ success: false, error: "E-Mail oder Passwort falsch." }, 401);
      }
      if (!validPublicKey(body.publicKey) || !(await verifySignature(body.publicKey, String(body.challenge), body.signature))) {
        await failedChallenge(env, challenge);
        return ownerJson({ success: false, error: "Geräteschlüssel oder Signatur ungültig." }, 403);
      }
      const deviceHash = await keyHash(body.publicKey);
      const already = await env.DB.prepare(
        "SELECT id FROM owner_devices WHERE owner_id=? AND credential_id_hash=? AND revoked_at IS NULL"
      ).bind(owner.id, deviceHash).first();
      if (already) return ownerJson({ success: false, error: "Dieses Gerät ist bereits registriert. Bitte normal anmelden." }, 409);
      const pending = await env.DB.prepare(
        "SELECT id FROM owner_access_requests WHERE credential_id_hash=? AND status='pending' AND expires_at>?"
      ).bind(deviceHash, now).first();
      if (pending) return ownerJson({ success: false, error: "Für dieses Gerät besteht bereits eine offene Anfrage." }, 409);
      if (!(await consumeChallenge(env, challenge, "device_change"))) {
        return ownerJson({ success: false, error: "Challenge wurde bereits verwendet." }, 409);
      }
      const requestId = crypto.randomUUID();
      const requestToken = randomToken(32);
      const label = String(body.deviceLabel || "Neues WARVEX-Gerät").slice(0, 80);
      await env.DB.prepare(
        "INSERT INTO owner_access_requests (id,email,code_hash,device_summary,browser_summary,country_code,city,created_at,expires_at,status,credential_public_key,credential_id_hash) VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)"
      ).bind(requestId, email, await sha(requestToken), label,
        String(body.browserSummary || "").slice(0, 100),
        request.cf?.country || null, request.cf?.city || null,
        now, now + REQUEST_MS, canonicalKey(body.publicKey), deviceHash).run();
      await audit(env, owner.id, "owner_device_requested", email, { deviceLabel: label });
      return ownerJson({ success: true, requestId, requestToken, expiresAt: now + REQUEST_MS });
    }

    if (path === "/api/owner/request-status" && request.method === "POST") {
      const body = await readBody(request);
      const requestRow = await env.DB.prepare(
        "SELECT * FROM owner_access_requests WHERE id=? AND code_hash=?"
      ).bind(body.requestId, await sha(String(body.requestToken || ""))).first();
      if (!requestRow) return ownerJson({ success: false, error: "Geräteanfrage nicht gefunden." }, 404);
      if (requestRow.status === "denied") return ownerJson({ success: false, status: "denied", error: "Gerätefreigabe abgelehnt." }, 403);
      if (requestRow.status === "consumed") return ownerJson({ success: false, status: "consumed", error: "Diese Anfrage wurde bereits verwendet." }, 409);
      if (requestRow.expires_at <= now && requestRow.status === "pending") {
        await env.DB.prepare("UPDATE owner_access_requests SET status='expired' WHERE id=? AND status='pending'").bind(requestRow.id).run();
        return ownerJson({ success: true, status: "expired" });
      }
      if (requestRow.status !== "approved") return ownerJson({ success: true, status: requestRow.status });
      const device = await env.DB.prepare(
        "SELECT id,owner_id FROM owner_devices WHERE credential_id_hash=? AND revoked_at IS NULL"
      ).bind(requestRow.credential_id_hash).first();
      if (!device) return ownerJson({ success: false, error: "Freigegebenes Gerät nicht gefunden." }, 500);
      const sessionToken = randomToken(32);
      const expiresAt = now + SESSION_MS;
      const consumed = await env.DB.prepare(
        "UPDATE owner_access_requests SET status='consumed',consumed_at=? WHERE id=? AND status='approved' AND consumed_at IS NULL"
      ).bind(now, requestRow.id).run();
      if (consumed.meta?.changes !== 1) return ownerJson({ success: false, error: "Anfrage wurde bereits verwendet." }, 409);
      await env.DB.prepare(
        "INSERT INTO owner_sessions (token_hash,owner_id,device_id,created_at,expires_at) VALUES (?,?,?,?,?)"
      ).bind(await sha(sessionToken), device.owner_id, device.id, now, expiresAt).run();
      await audit(env, device.owner_id, "owner_device_joined", requestRow.email, { deviceId: device.id });
      return ownerJson({ success: true, status: "approved", sessionToken, expiresAt });
    }

    if (path === "/api/owner/me" && request.method === "GET") {
      const auth = await requireOwner(request, env);
      if (auth.error) return auth.error;
      const devices = await env.DB.prepare(
        "SELECT id,device_label,created_at,last_seen_at,revoked_at FROM owner_devices WHERE owner_id=? ORDER BY created_at DESC"
      ).bind(auth.session.owner_id).all();
      const events = await env.DB.prepare(
        "SELECT id,action,target_email,created_at,metadata_json FROM owner_audit_events WHERE actor_owner_id=? ORDER BY created_at DESC LIMIT 30"
      ).bind(auth.session.owner_id).all();
      return ownerJson({ success: true, owner: { email: auth.session.email, role: auth.session.role },
        currentDeviceId: auth.session.device_id, devices: devices.results || [], events: events.results || [] });
    }

    if (path === "/api/owner/requests" && request.method === "GET") {
      const auth = await requireOwner(request, env);
      if (auth.error) return auth.error;
      const requests = await env.DB.prepare(
        "SELECT id,device_summary,browser_summary,country_code,city,created_at,expires_at FROM owner_access_requests WHERE email=? COLLATE NOCASE AND status='pending' AND expires_at>? ORDER BY created_at DESC"
      ).bind(auth.session.email, now).all();
      return ownerJson({ success: true, requests: requests.results || [] });
    }

    if (path === "/api/owner/requests/decision" && request.method === "POST") {
      const auth = await requireOwner(request, env);
      if (auth.error) return auth.error;
      const body = await readBody(request);
      const requestRow = await env.DB.prepare(
        "SELECT * FROM owner_access_requests WHERE id=? AND email=? COLLATE NOCASE AND status='pending' AND expires_at>?"
      ).bind(body.requestId, auth.session.email, now).first();
      if (!requestRow) return ownerJson({ success: false, error: "Offene Geräteanfrage nicht gefunden." }, 404);
      if (body.approve === true) {
        const deviceId = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO owner_devices (id,owner_id,device_label,credential_public_key,created_at,last_seen_at,credential_id_hash) VALUES (?,?,?,?,?,?,?)")
            .bind(deviceId, auth.session.owner_id, requestRow.device_summary, requestRow.credential_public_key, now, now, requestRow.credential_id_hash),
          env.DB.prepare("UPDATE owner_access_requests SET status='approved',approved_at=?,approved_by=? WHERE id=? AND status='pending'")
            .bind(now, auth.session.owner_id, requestRow.id)
        ]);
        await audit(env, auth.session.owner_id, "owner_device_approved", auth.session.email, { deviceLabel: requestRow.device_summary });
      } else {
        await env.DB.prepare(
          "UPDATE owner_access_requests SET status='denied',approved_at=?,approved_by=? WHERE id=? AND status='pending'"
        ).bind(now, auth.session.owner_id, requestRow.id).run();
        await audit(env, auth.session.owner_id, "owner_device_denied", auth.session.email, { deviceLabel: requestRow.device_summary });
      }
      return ownerJson({ success: true });
    }

    if (path === "/api/owner/devices/revoke" && request.method === "POST") {
      const auth = await requireOwner(request, env);
      if (auth.error) return auth.error;
      const body = await readBody(request);
      if (body.deviceId === auth.session.device_id) {
        return ownerJson({ success: false, error: "Das aktuell verwendete Gerät kann hier nicht selbst widerrufen werden. Bitte von einem anderen Owner-Gerät abmelden und verwalten." }, 400);
      }
      await env.DB.batch([
        env.DB.prepare("UPDATE owner_devices SET revoked_at=? WHERE id=? AND owner_id=? AND revoked_at IS NULL")
          .bind(now, body.deviceId, auth.session.owner_id),
        env.DB.prepare("UPDATE owner_sessions SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL")
          .bind(now, body.deviceId)
      ]);
      await audit(env, auth.session.owner_id, "owner_device_revoked", auth.session.email, { deviceId: body.deviceId });
      return ownerJson({ success: true });
    }

    if (path === "/api/owner/logout" && request.method === "POST") {
      const auth = await requireOwner(request, env);
      if (auth.error) return auth.error;
      await env.DB.prepare("UPDATE owner_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL")
        .bind(now, auth.session.token_hash).run();
      return ownerJson({ success: true });
    }

    return ownerJson({ success: false, error: "OWNER-Route nicht gefunden." }, 404);
  } catch (error) {
    console.error("WARVEX OWNER API error:", error?.message || String(error));
    return ownerJson({ success: false, error: "OWNER-Dienst vorübergehend nicht verfügbar." }, 500);
  }
}
