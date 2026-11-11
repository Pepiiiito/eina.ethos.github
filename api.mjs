// Ethos Chat Studio — cuentas, pagos e IA como Netlify Function (/api/*)
//  · Registro / login con contraseña (scrypt) o con Google (OAuth 2.0 + PKCE) y sesión en cookie HttpOnly
//  · Verificación de email y recuperación de contraseña (por Resend, opcional)
//  · Pago con Stripe Checkout LIGADO a la cuenta (el plan sale de la suscripción real)
//  · IA Pro con la clave del servidor, con límite diario por cuenta
//  · Datos en Netlify Blobs (sin base de datos externa)
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
export const config = { path: '/api/*' };

// ===================== Configuración =====================
const env = (k, d = '') => process.env[k] || d;
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
export const cfg = {
  authSecret: env('AUTH_SECRET'),
  siteUrl: (env('APP_URL') || env('URL')).replace(/\/$/, ''),
  sessionDays: 30,
  stripeKey: env('STRIPE_SECRET_KEY'),
  stripeBase: env('STRIPE_API_BASE', 'https://api.stripe.com'),
  webhookSecret: env('STRIPE_WEBHOOK_SECRET'),
  pricesCreador: list(env('PRICE_IDS_CREADOR')),
  pricesPro: list(env('PRICE_IDS_PRO')),
  geminiKey: env('GEMINI_API_KEY'),
  geminiModel: env('GEMINI_MODEL', 'gemini-3-flash-preview'),
  geminiBase: env('GEMINI_API_BASE', 'https://generativelanguage.googleapis.com'),
  geminiTimeoutMs: parseInt(env('GEMINI_TIMEOUT_MS'), 10) || 9000,
  aiDailyLimit: parseInt(env('AI_DAILY_LIMIT'), 10) || 40,
  googleId: env('GOOGLE_CLIENT_ID'),
  googleSecret: env('GOOGLE_CLIENT_SECRET'),
  googleAuthUrl: env('GOOGLE_AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth'),
  googleTokenUrl: env('GOOGLE_TOKEN_URL', 'https://oauth2.googleapis.com/token'),
  resendKey: env('RESEND_API_KEY'),
  mailFrom: env('MAIL_FROM'),
  mailBase: env('MAIL_API_BASE', 'https://api.resend.com'),
  promoKeys: list(env('PROMO_KEYS')).map((e) => {
    const [key, plan, days] = e.split(':');
    return { key, plan, days: parseInt(days, 10) || 30 };
  }).filter((p) => p.key && (p.plan === 'pro' || p.plan === 'creador')),
};
const mailEnabled = () => !!(cfg.resendKey && cfg.mailFrom);
const billingEnabled = () => !!cfg.stripeKey;
const googleEnabled = () => !!(cfg.googleId && cfg.googleSecret);

// ===================== Utilidades =====================
const RANK = { free: 0, creador: 1, pro: 2 };
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
const err = (status, message) => Object.assign(new Error(message), { status });
const safeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

function secret() {
  if (cfg.authSecret.length < 32) throw err(503, 'Servidor sin configurar: falta AUTH_SECRET (32+ caracteres).');
  return cfg.authSecret;
}
const hmac = (s) => crypto.createHmac('sha256', secret()).update(s).digest('base64url');
function sign(obj) { const body = b64u(JSON.stringify(obj)); return `${body}.${hmac(body)}`; }
function unsign(tok, type) {
  if (typeof tok !== 'string' || tok.length > 2000) return null;
  const [body, sig] = tok.split('.');
  if (!body || !sig || !safeEqual(sig, hmac(body))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return p && p.t === type && p.exp > now() ? p : null;
  } catch { return null; }
}

// ---- Contraseñas (scrypt con sal propia) ----
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16), N = 16384, r = 8, p = 1;
  const h = await scrypt(pw, salt, 64, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, N, r, p, s, h] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const got = await scrypt(pw, Buffer.from(s, 'base64'), 64, { N: +N, r: +r, p: +p });
  return safeEqual(got.toString('base64'), h);
}
let dummyHash;   // para igualar tiempos cuando el email no existe
const dummyCheck = async (pw) => { dummyHash = dummyHash || await hashPassword('dummy-password'); await verifyPassword(pw, dummyHash); };

const WEAK = new Set(['12345678', '123456789', '1234567890', 'password', 'password1', 'qwertyui', 'qwerty123', 'contraseña', '11111111', 'abcdefgh', 'iloveyou']);
function checkPassword(pw, email) {
  if (typeof pw !== 'string' || pw.length < 8) throw err(400, 'La contraseña debe tener al menos 8 caracteres.');
  if (pw.length > 128) throw err(400, 'La contraseña es demasiado larga (máximo 128).');
  if (WEAK.has(pw.toLowerCase()) || (email && pw.toLowerCase() === email.toLowerCase())) throw err(400, 'Esa contraseña es demasiado fácil de adivinar. Elige otra.');
}
function normEmail(e) {
  const v = typeof e === 'string' ? e.trim().toLowerCase() : '';
  if (!v || v.length > 254 || !/^[^\s@<>()]+@[^\s@<>()]+\.[^\s@<>()]{2,}$/.test(v)) throw err(400, 'Introduce un email válido.');
  return v;
}
// Un email está "demostrado" si el usuario lo confirmó por enlace, por recuperación de contraseña o con Google.
// (Sin servicio de email las cuentas se marcan verificadas, pero eso NO demuestra que el email sea suyo.)
const isProven = (u) => u.emailProven === true || !!u.googleSub || (u.emailProven === undefined && mailEnabled() && !!u.emailVerified);
const fp = (u) => sha(u.passHash || 'sin-contraseña').slice(0, 16);
const cleanName = (n) => (typeof n === 'string' ? n.replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 60) : '');

// ===================== Almacenamiento (Netlify Blobs) =====================
let _db;
async function db() {
  if (_db) return _db;
  if (globalThis.__ETHOS_STORE__) return (_db = globalThis.__ETHOS_STORE__);
  const { getStore } = await import('@netlify/blobs');
  const s = getStore({ name: 'ethos-accounts', consistency: 'strong' });
  return (_db = { get: (k) => s.get(k, { type: 'json' }), set: (k, v) => s.setJSON(k, v), del: (k) => s.delete(k) });
}
const kUser = (email) => `u/${sha(email)}`;
async function getUserByEmail(email) { return (await db()).get(kUser(email)); }
async function getUserById(id) {
  if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) return null;
  const e = await (await db()).get(`i/${id}`);
  return e ? getUserByEmail(e.email) : null;
}
async function saveUser(u) { await (await db()).set(kUser(u.email), u); }
const publicUser = (u) => ({ email: u.email, name: u.name || '', emailVerified: !!u.emailVerified, createdAt: u.createdAt });

// ===================== Sesión (cookie HttpOnly) =====================
function cookieHeader(req, token, maxAge) {
  const https = new URL(req.url).protocol === 'https:';
  return `ethos_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${https ? '; Secure' : ''}`;
}
const sessionCookie = (req, u) => cookieHeader(req, sign({ t: 's', uid: u.id, sv: u.sv, exp: now() + cfg.sessionDays * 86400 }), cfg.sessionDays * 86400);
const clearCookie = (req) => cookieHeader(req, '', 0);
function readCookie(req, name) {
  const m = (req.headers.get('cookie') || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : '';
}
async function authenticate(req) {
  const p = unsign(readCookie(req, 'ethos_session'), 's');
  if (!p) return null;
  const u = await getUserById(p.uid);
  return u && u.sv === p.sv ? u : null;
}

// ===================== Límites anti-abuso =====================
const hits = new Map();
export const _hits = hits;
function limited(key, max, windowMs) {
  const t = Date.now(), arr = (hits.get(key) || []).filter((x) => t - x < windowMs);
  arr.push(t); hits.set(key, arr);
  return arr.length > max;
}
const MAX_FAILS = 8, LOCK_SEC = 15 * 60;

// ===================== Email (Resend) =====================
async function sendMail(to, subject, html, text) {
  const res = await fetch(`${cfg.mailBase}/emails`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${cfg.resendKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: cfg.mailFrom, to: [to], subject, html, text }),
  });
  if (!res.ok) throw err(502, 'No se pudo enviar el email. Inténtalo de nuevo en unos minutos.');
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function mailTemplate(title, intro, btn, link) {
  return `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;background:#0a0a0a;color:#eee;border-radius:16px">
<h2 style="margin:0 0 12px">${esc(title)}</h2><p style="color:#bbb;line-height:1.5">${esc(intro)}</p>
<p style="margin:24px 0"><a href="${esc(link)}" style="background:#dc2626;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:bold">${esc(btn)}</a></p>
<p style="color:#888;font-size:12px">Si el botón no funciona, copia este enlace:<br>${esc(link)}</p>
<p style="color:#666;font-size:12px">Si no has sido tú, ignora este mensaje.</p></div>`;
}
const siteOf = (req) => cfg.siteUrl || new URL(req.url).origin;
async function sendVerification(req, u) {
  const link = `${siteOf(req)}/?verify=${sign({ t: 'v', uid: u.id, exp: now() + 86400 })}`;
  await sendMail(u.email, 'Confirma tu email · Ethos', mailTemplate('Confirma tu email', 'Pulsa el botón para activar tu cuenta de Ethos Chat Studio. El enlace caduca en 24 horas.', 'Confirmar email', link), `Confirma tu email: ${link}`);
}
async function sendReset(req, u) {
  const link = `${siteOf(req)}/?reset=${sign({ t: 'r', uid: u.id, f: fp(u), exp: now() + 3600 })}`;
  await sendMail(u.email, 'Restablece tu contraseña · Ethos', mailTemplate('Restablece tu contraseña', 'Pulsa el botón para elegir una contraseña nueva. El enlace caduca en 1 hora y solo funciona una vez.', 'Elegir contraseña nueva', link), `Restablece tu contraseña: ${link}`);
}

// ===================== Stripe =====================
async function stripe(method, path, params) {
  if (!billingEnabled()) throw err(503, 'Los pagos no están configurados.');
  const url = new URL(cfg.stripeBase + path);
  const opts = { method, headers: { Authorization: `Bearer ${cfg.stripeKey}` } };
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) (Array.isArray(v) ? v : [v]).forEach((x) => usp.append(k, x));
  if (method === 'GET') url.search = usp.toString();
  else { opts.body = usp.toString(); opts.headers['Content-Type'] = 'application/x-www-form-urlencoded'; }
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw err(502, data?.error?.message || 'Error de Stripe');
  return data;
}
function planFromPrice(price) {
  if (!price) return null;
  if (cfg.pricesPro.includes(price.id)) return 'pro';
  if (cfg.pricesCreador.includes(price.id)) return 'creador';
  return null;
}
async function livePlan(cus) {
  const subs = await stripe('GET', '/v1/subscriptions', { customer: cus, status: 'all', limit: '20' });
  let best = 'free';
  for (const s of subs.data || []) {
    if (!['active', 'trialing'].includes(s.status)) continue;
    for (const it of (s.items && s.items.data) || []) {
      const pl = planFromPrice(it.price);
      if (pl && RANK[pl] > RANK[best]) best = pl;
    }
  }
  return best;
}
async function customersByEmail(email) {
  const seen = new Map();
  const add = (r) => (r.data || []).forEach((c) => seen.set(c.id, c));
  try { add(await stripe('GET', '/v1/customers', { email, limit: '10' })); } catch { /* se prueba la búsqueda */ }
  if (!seen.size) { try { add(await stripe('GET', '/v1/customers/search', { query: `email:'${email.replace(/'/g, '')}'`, limit: '10' })); } catch { /* sin resultados */ } }
  return [...seen.values()];
}
// Si el email de la cuenta está demostrado y coincide con un cliente de Stripe con suscripción activa, se vincula.
async function tryLinkStripe(u) {
  if (u.stripeCustomerId || !billingEnabled() || !isProven(u)) return false;
  u.linkCheckedAt = now();
  let best = null;
  try {
    for (const c of await customersByEmail(u.email)) {
      if (String(c.email || '').trim().toLowerCase() !== u.email) continue;   // la búsqueda de Stripe puede ser difusa
      const owner = await (await db()).get(`c/${c.id}`);
      if (owner && owner.id !== u.id) continue;                               // ya pertenece a otra cuenta
      const plan = await livePlan(c.id);
      if (plan !== 'free' && (!best || RANK[plan] > RANK[best.plan])) best = { id: c.id, plan };
    }
  } catch { await saveUser(u); return false; }
  if (!best) { await saveUser(u); return false; }
  u.stripeCustomerId = best.id;
  u.billing = { plan: best.plan, checkedAt: now() };
  await saveUser(u);
  await (await db()).set(`c/${best.id}`, { id: u.id });
  return true;
}

async function refreshBilling(u, force = false) {
  if (!u.stripeCustomerId && billingEnabled()) {
    if (isProven(u) && (force || now() - (u.linkCheckedAt || 0) > 600)) await tryLinkStripe(u);   // máx. 1 consulta cada 10 min
    if (!u.stripeCustomerId) return u;
  }
  if (!u.stripeCustomerId || !billingEnabled()) return u;
  const stale = !u.billing || now() - u.billing.checkedAt > 300;
  if (!force && !stale) return u;
  try {
    u.billing = { plan: await livePlan(u.stripeCustomerId), checkedAt: now() };
    await saveUser(u);
  } catch { /* si Stripe falla se conserva el último plan conocido */ }
  return u;
}
function effective(u) {
  let plan = (u.billing && u.billing.plan) || 'free', source = plan !== 'free' ? 'stripe' : null, until = null;
  if (u.promo && u.promo.until > now() && RANK[u.promo.plan] > RANK[plan]) { plan = u.promo.plan; source = 'promo'; until = u.promo.until; }
  return { plan, source, promoUntil: until };
}
async function ensureCustomer(u) {
  if (u.stripeCustomerId) return u.stripeCustomerId;
  const c = await stripe('POST', '/v1/customers', { email: u.email, name: u.name || u.email, 'metadata[uid]': u.id });
  u.stripeCustomerId = c.id;
  await saveUser(u);
  await (await db()).set(`c/${c.id}`, { id: u.id });
  return c.id;
}

// ===================== IA (Gemini) =====================
const AI_SYSTEM_PROMPT = `Eres un guionista experto en historias virales para YouTube Shorts (formato chat de drama, salseo, venganza).
Responde SOLO con JSON estricto y texto plano (sin HTML ni markdown) con este esquema exacto:
{
  "profileName": "Nombre con emoji (ej. Diego 💔)",
  "status": "Activo(a) hoy",
  "avatarUrl": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80",
  "messages": [
    { "type": "divider", "text": "HOY 21:40" },
    { "type": "text", "sender": "them", "text": "...", "time": "21:40", "reaction": "" },
    { "type": "audio", "sender": "them", "audioSpec": "0:14", "time": "21:41" },
    { "type": "text", "sender": "me", "text": "...", "time": "21:41", "reaction": "💀" }
  ]
}
Entre 8 y 20 mensajes. El campo "sender" es "me" o "them".`;
async function callGemini(idea) {
  const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), cfg.geminiTimeoutMs);
  try {
    const res = await fetch(`${cfg.geminiBase}/v1beta/models/${encodeURIComponent(cfg.geminiModel)}:generateContent`, {
      method: 'POST', signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': cfg.geminiKey },
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: `Crea un chat de drama viral sobre: "${idea}"` }] }],
        systemInstruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
        generationConfig: { responseMimeType: 'application/json' },
      }),
    });
    if (!res.ok) throw err(502, 'La IA no respondió correctamente.');
    const out = await res.json();
    try { return JSON.parse(out?.candidates?.[0]?.content?.parts?.[0]?.text); } catch { throw err(502, 'Respuesta de la IA no válida.'); }
  } catch (e) {
    if (e.name === 'AbortError') throw err(504, 'La IA tardó demasiado. Inténtalo de nuevo.');
    throw e;
  } finally { clearTimeout(timer); }
}

// ===================== HTTP =====================
function redirectTo(location, cookies = []) {
  const h = new Headers({ Location: location, 'Cache-Control': 'no-store' });
  cookies.forEach((c) => h.append('Set-Cookie', c));
  return new Response(null, { status: 302, headers: h });
}
function reply(status, obj, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers } });
}
async function readJson(req, limit = 32 * 1024) {
  const buf = await req.arrayBuffer();
  if (buf.byteLength > limit) throw err(413, 'Petición demasiado grande.');
  try { return JSON.parse(Buffer.from(buf).toString('utf8') || '{}'); } catch { throw err(400, 'JSON no válido.'); }
}
const features = () => ({ mail: mailEnabled(), billing: billingEnabled() && (cfg.pricesCreador.length > 0 || cfg.pricesPro.length > 0), ai: !!cfg.geminiKey, promo: cfg.promoKeys.length > 0, google: googleEnabled() });
const ipOf = (req, ctx) => (ctx && ctx.ip) || req.headers.get('x-nf-client-connection-ip') || 'unknown';

async function meBody(u) {
  await refreshBilling(u);
  const e = effective(u);
  return { user: publicUser(u), plan: e.plan, planSource: e.source, promoUntil: e.promoUntil, hasSubscription: !!(u.billing && u.billing.plan !== 'free'), hasPassword: !!u.passHash, google: !!u.googleSub, features: features() };
}

// ===================== Rutas =====================
const R = {};   // 'MÉTODO /ruta' -> { auth, fn }
const route = (k, fn, auth = false) => { R[k] = { fn, auth }; };

route('GET /api/auth/me', async ({ user }) => user ? { status: 200, body: await meBody(user), headers: {} } : { status: 200, body: { user: null, plan: 'free', features: features() } });

route('POST /api/auth/register', async ({ req, ctx, body }) => {
  if (limited('reg:' + ipOf(req, ctx), 10, 3600_000)) throw err(429, 'Demasiados registros desde esta conexión. Inténtalo más tarde.');
  const email = normEmail(body.email);
  checkPassword(body.password, email);
  if (await getUserByEmail(email)) throw err(409, 'Ya existe una cuenta con ese email. Inicia sesión.');
  const u = {
    id: crypto.randomBytes(16).toString('hex'), email, name: cleanName(body.name), passHash: await hashPassword(body.password),
    createdAt: now(), emailVerified: !mailEnabled(), emailProven: false, sv: 1, failed: { n: 0, at: 0 }, lockedUntil: 0,
    stripeCustomerId: null, billing: { plan: 'free', checkedAt: 0 }, promo: null, ai: { day: '', n: 0 },
  };
  await saveUser(u);
  await (await db()).set(`i/${u.id}`, { email });
  let mailSent = false;
  if (mailEnabled()) { try { await sendVerification(req, u); mailSent = true; } catch { /* la cuenta existe; podrá reenviar */ } }
  return { status: 201, body: { ...(await meBody(u)), mailSent }, headers: { 'Set-Cookie': sessionCookie(req, u) } };
});

route('POST /api/auth/login', async ({ req, ctx, body }) => {
  if (limited('login:' + ipOf(req, ctx), 30, 600_000)) throw err(429, 'Demasiados intentos. Espera unos minutos.');
  const email = normEmail(body.email);
  const pw = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
  const u = await getUserByEmail(email);
  if (!u) { await dummyCheck(pw); throw err(401, 'Email o contraseña incorrectos. Si te registraste con Google, usa «Continuar con Google».'); }
  if (u.lockedUntil > now()) throw err(429, `Cuenta bloqueada temporalmente por demasiados intentos. Prueba en ${Math.ceil((u.lockedUntil - now()) / 60)} min o recupera tu contraseña.`);
  if (!u.passHash || !(await verifyPassword(pw, u.passHash))) {
    const recent = now() - (u.failed?.at || 0) < LOCK_SEC;
    u.failed = { n: recent ? (u.failed.n || 0) + 1 : 1, at: now() };
    if (u.failed.n >= MAX_FAILS) { u.lockedUntil = now() + LOCK_SEC; u.failed = { n: 0, at: 0 }; }
    await saveUser(u);
    throw err(401, 'Email o contraseña incorrectos. Si te registraste con Google, usa «Continuar con Google».');
  }
  if (u.failed?.n || u.lockedUntil) { u.failed = { n: 0, at: 0 }; u.lockedUntil = 0; await saveUser(u); }
  return { status: 200, body: await meBody(u), headers: { 'Set-Cookie': sessionCookie(req, u) } };
});

route('POST /api/auth/logout', async ({ req, user, body }) => {
  if (user && body.all) { user.sv += 1; await saveUser(user); }
  return { status: 200, body: { ok: true }, headers: { 'Set-Cookie': clearCookie(req) } };
});

route('POST /api/auth/verify', async ({ req, body }) => {
  const p = unsign(body.token, 'v');
  if (!p) throw err(400, 'El enlace no es válido o ha caducado. Pide uno nuevo desde tu cuenta.');
  const u = await getUserById(p.uid);
  if (!u) throw err(400, 'El enlace no es válido.');
  if (!u.emailVerified || u.emailProven !== true) { u.emailVerified = true; u.emailProven = true; await saveUser(u); }
  return { status: 200, body: { ok: true, email: u.email }, headers: {} };
});

route('POST /api/auth/resend-verification', async ({ req, ctx, user }) => {
  if (!mailEnabled()) throw err(503, 'El envío de emails no está configurado.');
  if (user.emailVerified) return { status: 200, body: { ok: true, already: true }, headers: {} };
  if (limited('resend:' + user.id, 3, 3600_000)) throw err(429, 'Ya te hemos enviado varios emails. Revisa tu bandeja y el spam.');
  await sendVerification(req, user);
  return { status: 200, body: { ok: true }, headers: {} };
}, true);

route('POST /api/auth/forgot', async ({ req, ctx, body }) => {
  if (!mailEnabled()) throw err(503, 'La recuperación por email no está disponible. Contacta con soporte.');
  if (limited('forgot:' + ipOf(req, ctx), 5, 3600_000)) throw err(429, 'Demasiadas solicitudes. Inténtalo más tarde.');
  const email = normEmail(body.email);
  const u = await getUserByEmail(email);
  if (u && !limited('forgot-u:' + u.id, 3, 3600_000)) { try { await sendReset(req, u); } catch { /* respuesta siempre igual */ } }
  return { status: 200, body: { ok: true }, headers: {} };   // misma respuesta exista o no la cuenta
});

route('POST /api/auth/reset', async ({ req, body }) => {
  const p = unsign(body.token, 'r');
  if (!p) throw err(400, 'El enlace no es válido o ha caducado. Pide uno nuevo.');
  const u = await getUserById(p.uid);
  if (!u || fp(u) !== p.f) throw err(400, 'Este enlace ya se ha usado o no es válido. Pide uno nuevo.');
  checkPassword(body.password, u.email);
  u.passHash = await hashPassword(body.password);
  u.sv += 1; u.failed = { n: 0, at: 0 }; u.lockedUntil = 0; u.emailVerified = true; u.emailProven = true;   // llegar por email confirma la dirección
  await saveUser(u);
  return { status: 200, body: { ...(await meBody(u)), reset: true }, headers: { 'Set-Cookie': sessionCookie(req, u) } };
});

route('POST /api/auth/change-password', async ({ req, user, body }) => {
  // Las cuentas creadas con Google no tienen contraseña: pueden crear una sin la actual (ya están autenticadas)
  if (user.passHash && !(await verifyPassword(String(body.current || '').slice(0, 200), user.passHash))) throw err(403, 'La contraseña actual no es correcta.');
  checkPassword(body.password, user.email);
  user.passHash = await hashPassword(body.password);
  user.sv += 1;
  await saveUser(user);
  return { status: 200, body: { ok: true }, headers: { 'Set-Cookie': sessionCookie(req, user) } };
}, true);

route('POST /api/auth/delete', async ({ req, user, body }) => {
  if (user.passHash) {
    if (!(await verifyPassword(String(body.password || '').slice(0, 200), user.passHash))) throw err(403, 'La contraseña no es correcta.');
  } else if (String(body.confirmEmail || '').trim().toLowerCase() !== user.email) {
    throw err(403, 'Escribe tu email para confirmar.');
  }
  await refreshBilling(user, true);
  if (user.billing && user.billing.plan !== 'free') throw err(409, 'Tienes una suscripción activa. Cancélala primero desde "Gestionar suscripción".');
  const d = await db();
  await d.del(kUser(user.email)); await d.del(`i/${user.id}`);
  if (user.stripeCustomerId) await d.del(`c/${user.stripeCustomerId}`);
  return { status: 200, body: { ok: true }, headers: { 'Set-Cookie': clearCookie(req) } };
}, true);

// ---- Facturación ----
route('POST /api/billing/checkout', async ({ req, user, body }) => {
  const plan = body.plan;
  if (!['creador', 'pro'].includes(plan)) throw err(400, 'Plan no válido.');
  if (mailEnabled() && !user.emailVerified) throw err(403, 'Confirma tu email antes de pagar. Te lo hemos enviado al registrarte (puedes pedir otro desde tu cuenta).');
  const price = (plan === 'pro' ? cfg.pricesPro : cfg.pricesCreador)[0];
  if (!price) throw err(503, 'Este plan todavía no está configurado.');
  await refreshBilling(user, true);
  if (user.billing && user.billing.plan !== 'free') throw err(409, 'Ya tienes un plan activo. Cámbialo desde "Gestionar suscripción".');
  const customer = await ensureCustomer(user);
  const site = siteOf(req);
  const s = await stripe('POST', '/v1/checkout/sessions', {
    mode: 'subscription', customer, client_reference_id: user.id,
    'line_items[0][price]': price, 'line_items[0][quantity]': '1',
    allow_promotion_codes: 'true', 'subscription_data[metadata][uid]': user.id,
    success_url: `${site}/?checkout=success`, cancel_url: `${site}/?checkout=cancel`,
  });
  return { status: 200, body: { url: s.url }, headers: {} };
}, true);

route('POST /api/billing/sync', async ({ user }) => {
  await refreshBilling(user, true);
  return { status: 200, body: await meBody(user), headers: {} };
}, true);

route('POST /api/billing/recover', async ({ user }) => {
  if (!billingEnabled()) throw err(503, 'Los pagos no están configurados.');
  if (!isProven(user)) throw err(403, mailEnabled() ? 'Confirma tu email (te lo enviamos al registrarte) o entra con Google para recuperar tu compra.' : 'Para recuperar una compra entra con Google: así comprobamos que el email es tuyo.');
  const had = !!user.stripeCustomerId;
  const linked = had ? false : await tryLinkStripe(user);
  await refreshBilling(user, true);
  const body = await meBody(user);
  const found = linked || (had && body.plan !== 'free');
  if (!found && !body.hasSubscription && body.planSource !== 'promo') throw err(404, `No encontramos ninguna suscripción activa con el email ${user.email}. Si pagaste con otro email, entra con ese email (o con Google).`);
  return { status: 200, body: { ...body, recovered: found }, headers: {} };
}, true);

route('POST /api/billing/portal', async ({ req, user }) => {
  if (!user.stripeCustomerId) throw err(404, 'Todavía no tienes suscripción que gestionar.');
  const s = await stripe('POST', '/v1/billing_portal/sessions', { customer: user.stripeCustomerId, return_url: siteOf(req) });
  return { status: 200, body: { url: s.url }, headers: {} };
}, true);

route('POST /api/promo/redeem', async ({ req, ctx, user, body }) => {
  if (limited('promo:' + user.id, 8, 600_000) || limited('promo-ip:' + ipOf(req, ctx), 20, 600_000)) throw err(429, 'Demasiados intentos. Espera unos minutos.');
  const key = typeof body.key === 'string' ? body.key.trim().toUpperCase().slice(0, 100) : '';
  const found = cfg.promoKeys.find((p) => safeEqual(p.key.toUpperCase(), key));
  if (!key || !found) throw err(404, 'Código no válido.');
  user.promo = { plan: found.plan, until: now() + found.days * 86400, keyHash: sha(found.key).slice(0, 12) };
  await saveUser(user);
  return { status: 200, body: await meBody(user), headers: {} };
}, true);


// ---- Inicio de sesión con Google (OAuth 2.0, flujo de código + PKCE; el token se pide servidor a servidor) ----
const OAUTH_ERR = { denied: 'denied', state: 'state', config: 'config', unverified: 'unverified', failed: 'failed' };
const planOk = (p) => (['creador', 'pro'].includes(p) ? p : '');
const oauthCookie = (req, token, maxAge) => cookieHeader(req, token, maxAge).replace('ethos_session=', 'ethos_oauth=').replace('Path=/;', 'Path=/api/auth/google;');
const backTo = (req, query, cookies = []) => ({ redirect: `${siteOf(req)}/?${query}`, cookies });

route('GET /api/auth/google/start', async ({ req, ctx, url }) => {
  if (!googleEnabled()) return backTo(req, `google=error&reason=${OAUTH_ERR.config}`);
  if (limited('gstart:' + ipOf(req, ctx), 30, 600_000)) throw err(429, 'Demasiados intentos. Espera unos minutos.');
  const state = crypto.randomBytes(16).toString('hex'), nonce = crypto.randomBytes(16).toString('hex');
  const verifier = b64u(crypto.randomBytes(32)), challenge = b64u(crypto.createHash('sha256').update(verifier).digest());
  const plan = planOk(url.searchParams.get('plan'));
  const q = new URLSearchParams({
    client_id: cfg.googleId, redirect_uri: `${siteOf(req)}/api/auth/google/callback`, response_type: 'code', scope: 'openid email profile',
    state, nonce, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account',
  });
  const cookie = oauthCookie(req, sign({ t: 'o', state, nonce, verifier, plan, exp: now() + 600 }), 600);
  return { redirect: `${cfg.googleAuthUrl}?${q}`, cookies: [cookie] };
});

route('GET /api/auth/google/callback', async ({ req, ctx, url }) => {
  const clear = oauthCookie(req, '', 0);
  if (!googleEnabled()) return backTo(req, `google=error&reason=${OAUTH_ERR.config}`, [clear]);
  if (limited('gcb:' + ipOf(req, ctx), 30, 600_000)) throw err(429, 'Demasiados intentos. Espera unos minutos.');
  const pend = unsign(readCookie(req, 'ethos_oauth'), 'o');
  const sp = url.searchParams;
  if (sp.get('error')) return backTo(req, `google=${sp.get('error') === 'access_denied' ? 'cancel' : 'error&reason=' + OAUTH_ERR.failed}`, [clear]);
  if (!pend || !sp.get('state') || !safeEqual(sp.get('state'), pend.state) || !sp.get('code')) return backTo(req, `google=error&reason=${OAUTH_ERR.state}`, [clear]);

  let claims;
  try {
    const tr = await fetch(cfg.googleTokenUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: sp.get('code'), client_id: cfg.googleId, client_secret: cfg.googleSecret, redirect_uri: `${siteOf(req)}/api/auth/google/callback`, grant_type: 'authorization_code', code_verifier: pend.verifier }),
      signal: AbortSignal.timeout(8000),
    });
    if (!tr.ok) throw new Error('token');
    const tok = await tr.json();
    claims = JSON.parse(Buffer.from(String(tok.id_token).split('.')[1], 'base64url').toString('utf8'));   // llega directo de Google por TLS
  } catch { return backTo(req, `google=error&reason=${OAUTH_ERR.failed}`, [clear]); }

  const issOk = claims.iss === 'https://accounts.google.com' || claims.iss === 'accounts.google.com';
  if (!issOk || claims.aud !== cfg.googleId || !(claims.exp > now()) || !claims.nonce || !safeEqual(claims.nonce, pend.nonce) || !claims.sub) return backTo(req, `google=error&reason=${OAUTH_ERR.state}`, [clear]);
  if (claims.email_verified !== true || !claims.email) return backTo(req, `google=error&reason=${OAUTH_ERR.unverified}`, [clear]);

  const email = String(claims.email).trim().toLowerCase();
  let u = await getUserByEmail(email);
  if (u) {
    if (u.googleSub && u.googleSub !== claims.sub) return backTo(req, `google=error&reason=${OAUTH_ERR.failed}`, [clear]);
    if (!u.googleSub || !u.emailVerified || u.emailProven !== true) { u.googleSub = claims.sub; u.emailVerified = true; u.emailProven = true; await saveUser(u); }   // Google ya verificó el email
  } else {
    u = {
      id: crypto.randomBytes(16).toString('hex'), email, name: cleanName(claims.name || claims.given_name), passHash: null, googleSub: claims.sub,
      createdAt: now(), emailVerified: true, emailProven: true, sv: 1, failed: { n: 0, at: 0 }, lockedUntil: 0,
      stripeCustomerId: null, billing: { plan: 'free', checkedAt: 0 }, promo: null, ai: { day: '', n: 0 },
    };
    await saveUser(u);
    await (await db()).set(`i/${u.id}`, { email });
  }
  return backTo(req, `google=ok${pend.plan ? '&plan=' + pend.plan : ''}`, [sessionCookie(req, u), clear]);
});

// ---- IA ----
route('POST /api/ai', async ({ user, body }) => {
  if (!cfg.geminiKey) throw err(503, 'La IA no está configurada en el servidor.');
  await refreshBilling(user);
  if (effective(user).plan !== 'pro') throw err(403, 'La IA integrada requiere el plan Pro.');
  const idea = typeof body.prompt === 'string' ? body.prompt.replace(/[\u0000-\u001f"]/g, ' ').trim() : '';
  if (idea.length < 8 || idea.length > 600) throw err(400, 'La idea debe tener entre 8 y 600 caracteres.');
  const day = new Date().toISOString().slice(0, 10);
  if (!user.ai || user.ai.day !== day) user.ai = { day, n: 0 };
  if (user.ai.n >= cfg.aiDailyLimit) throw err(429, `Has alcanzado el límite diario de ${cfg.aiDailyLimit} generaciones.`);
  user.ai.n += 1;
  await saveUser(user);
  return { status: 200, body: { data: await callGemini(idea), remaining: cfg.aiDailyLimit - user.ai.n }, headers: {} };
}, true);

route('GET /api/config', async () => ({ status: 200, body: { features: features() }, headers: {} }));

// ---- Webhook de Stripe ----
function verifyStripeSig(raw, header) {
  if (!cfg.webhookSecret || !header) return false;
  const parts = Object.fromEntries(header.split(',').map((x) => x.split('=')));
  const t = parseInt(parts.t, 10);
  if (!t || Math.abs(now() - t) > 300) return false;
  return safeEqual(parts.v1 || '', crypto.createHmac('sha256', cfg.webhookSecret).update(`${t}.${raw}`).digest('hex'));
}
async function webhook(req) {
  const buf = await req.arrayBuffer();
  if (buf.byteLength > 512 * 1024) throw err(413, 'Demasiado grande.');
  const raw = Buffer.from(buf).toString('utf8');
  if (!verifyStripeSig(raw, req.headers.get('stripe-signature'))) return reply(400, { error: 'Firma no válida.' });
  let ev; try { ev = JSON.parse(raw); } catch { return reply(400, { error: 'JSON no válido.' }); }
  const o = ev?.data?.object || {};
  const cus = typeof o.customer === 'string' ? o.customer : null;
  let u = null;
  if (cus) { const ref = await (await db()).get(`c/${cus}`); if (ref) u = await getUserById(ref.id); }
  if (!u && ev.type === 'checkout.session.completed' && cus && o.client_reference_id) {
    u = await getUserById(o.client_reference_id);
    if (u && !u.stripeCustomerId) { u.stripeCustomerId = cus; await saveUser(u); await (await db()).set(`c/${cus}`, { id: u.id }); }
  }
  if (u) await refreshBilling(u, true);
  return reply(200, { received: true });
}

// ===================== Entrada =====================
export default async (req, ctx) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '');
    if (path === '/api/stripe/webhook' && req.method === 'POST') return await webhook(req);
    const r = R[`${req.method} ${path}`];
    if (!r) return reply(404, { error: 'No encontrado.' });

    if (req.method === 'POST') {   // protección CSRF: solo desde nuestra propia web
      const origin = req.headers.get('origin');
      const ok = [url.origin, cfg.siteUrl && new URL(cfg.siteUrl).origin].filter(Boolean);
      if (origin && !ok.includes(origin)) throw err(403, 'Origen no permitido.');
      if (req.headers.get('x-requested-with') !== 'ethos') throw err(403, 'Petición no válida.');
    }
    const user = await authenticate(req);
    if (r.auth && !user) throw err(401, 'Inicia sesión para continuar.');
    const body = req.method === 'POST' ? await readJson(req) : {};
    const out = await r.fn({ req, ctx, user, body, url });
    if (out.redirect) return redirectTo(out.redirect, out.cookies);
    return reply(out.status, out.body, out.headers);
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error('Error interno:', e.message);
    return reply(status, { error: status === 500 ? 'Error interno.' : e.message });
  }
};
