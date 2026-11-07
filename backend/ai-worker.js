const MODEL = "@cf/zai-org/glm-4.7-flash";
const ALLOWED_ORIGIN = "https://dustin54-dot.github.io";
const hits = new Map();

function cors(origin) {
  const allowed = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) }
  });
}

function limited(ip) {
  const now = Date.now();
  const old = hits.get(ip) || [];
  const recent = old.filter(t => now - t < 60000);
  if (recent.length >= 12) {
    hits.set(ip, recent);
    return true;
  }
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 1000) {
    for (const [key, values] of hits) {
      if (!values.length || now - values[values.length - 1] > 60000) hits.delete(key);
    }
  }
  return false;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(origin) });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, service: "WARVEX AI API", model: MODEL }, 200, origin);
    }

    if (url.pathname !== "/api/ai" || request.method !== "POST") {
      return json({ success: false, error: "Not found" }, 404, origin);
    }

    if (origin && origin !== ALLOWED_ORIGIN) {
      return json({ success: false, error: "Origin not allowed" }, 403, origin);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (limited(ip)) {
      return json({ success: false, error: "Zu viele Anfragen. Bitte eine Minute warten." }, 429, origin);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, error: "Ungültiges JSON." }, 400, origin);
    }

    const prompt = typeof body?.prompt === "string" ? body.prompt.trim() : "";
    if (!prompt) {
      return json({ success: false, error: "Bitte gib eine Nachricht ein." }, 400, origin);
    }
    if (prompt.length > 6000) {
      return json({ success: false, error: "Die Nachricht ist zu lang (maximal 6000 Zeichen)." }, 413, origin);
    }

    try {
      const result = await env.AI.run(MODEL, {
        messages: [
          {
            role: "system",
            content: "Du bist WARVEX, ein hilfreicher, zuverlässiger deutschsprachiger KI-Assistent. Antworte klar, freundlich und ehrlich. Behaupte niemals, etwas ausgeführt, recherchiert oder getestet zu haben, wenn das nicht stimmt. Wenn du etwas nicht weißt, sage es offen."
          },
          { role: "user", content: prompt }
        ],
        max_tokens: 600
      });

      const answer =
        (typeof result?.response === "string" && result.response) ||
        (typeof result?.choices?.[0]?.message?.content === "string" && result.choices[0].message.content) ||
        (typeof result?.result?.response === "string" && result.result.response) ||
        (typeof result === "string" && result) ||
        "";

      if (!answer.trim()) {
        return json({ success: false, error: "Das KI-Modell hat keine Textantwort geliefert." }, 502, origin);
      }

      return json({ success: true, response: answer.trim() }, 200, origin);
    } catch (error) {
      return json({
        success: false,
        error: "Cloudflare-KI ist vorübergehend nicht verfügbar. Bitte später erneut versuchen."
      }, 502, origin);
    }
  }
};