// Pruebas de cuentas, pagos e IA con Stripe, Gemini y Resend simulados.  node test-auth.mjs
import http from 'node:http';
import assert from 'node:assert';
import crypto from 'node:crypto';

const listen = (s, port) => new Promise((r) => s.listen(port, '127.0.0.1', r));
const mem = new Map();
globalThis.__ETHOS_STORE__ = { get: async (k) => (mem.has(k) ? JSON.parse(mem.get(k)) : null), set: async (k, v) => { mem.set(k, JSON.stringify(v)); }, del: async (k) => { mem.delete(k); } };

const M = { subs: {}, mails: [], sessions: [], customers: 0, geminiKey: null };
const json = (res, o, s = 200) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
const body = (req) => new Promise((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b)); });
const stripe = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x'), raw = await body(req), form = new URLSearchParams(raw);
  if (u.pathname === '/v1/customers') { M.customers++; return json(res, { id: 'cus_' + M.customers }); }
  if (u.pathname === '/v1/checkout/sessions') { M.sessions.push(Object.fromEntries(form)); return json(res, { url: 'https://checkout.stripe.test/c/' + M.sessions.length }); }
  if (u.pathname === '/v1/subscriptions') { const c = u.searchParams.get('customer'); return json(res, { data: M.subs[c] ? [{ status: M.subs[c].status, items: { data: [{ price: { id: M.subs[c].price } }] } }] : [] }); }
  if (u.pathname === '/v1/billing_portal/sessions') return json(res, { url: 'https://billing.stripe.test/p' });
  json(res, { error: { message: 'nf' } }, 404);
});
const resend = http.createServer(async (req, res) => { M.mails.push(JSON.parse(await body(req))); json(res, { id: 'm' }); });
const gemini = http.createServer((req, res) => { M.geminiKey = req.headers['x-goog-api-key']; json(res, { candidates: [{ content: { parts: [{ text: JSON.stringify({ profileName: 'T', messages: [{ type: 'text', sender: 'them', text: 'hola' }] }) }] } }] }); });
const G = { claims: null, last: null, fail: false };
const googleTok = http.createServer(async (req, res) => {
  const form = new URLSearchParams(await body(req)); G.last = Object.fromEntries(form);
  if (G.fail || form.get('client_secret') !== 'gsecret') return json(res, { error: 'invalid_grant' }, 400);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  json(res, { access_token: 'x', id_token: `${b64({ alg: 'RS256' })}.${b64(G.claims)}.sig` });
});
await listen(stripe, 3401); await listen(resend, 3402); await listen(gemini, 3403); await listen(googleTok, 3404);

Object.assign(process.env, {
  AUTH_SECRET: 'k'.repeat(40), APP_URL: 'https://mi-sitio.netlify.app', STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_API_BASE: 'http://127.0.0.1:3401',
  PRICE_IDS_PRO: 'price_pro', PRICE_IDS_CREADOR: 'price_cr', STRIPE_WEBHOOK_SECRET: 'whsec_t', GEMINI_API_KEY: 'gem_secret', GEMINI_API_BASE: 'http://127.0.0.1:3403',
  AI_DAILY_LIMIT: '2', RESEND_API_KEY: 're_x', MAIL_FROM: 'Ethos <no-reply@x.com>', MAIL_API_BASE: 'http://127.0.0.1:3402', PROMO_KEYS: 'VIP-1:pro:30',
  GOOGLE_CLIENT_ID: 'gid.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET: 'gsecret', GOOGLE_TOKEN_URL: 'http://127.0.0.1:3404/token', GOOGLE_AUTH_URL: 'https://accounts.google.com/o/oauth2/v2/auth',
});
const api = await import('./api.mjs');
const handler = api.default;

const jar = {};   // cliente -> { nombreCookie: valor }
async function call(method, path, { body, headers, client = 'a', origin = 'https://mi-sitio.netlify.app', xr = true } = {}) {
  const h = { 'Content-Type': 'application/json', ...(origin ? { Origin: origin } : {}), ...(xr ? { 'X-Requested-With': 'ethos' } : {}), ...headers };
  const ck = Object.entries(jar[client] || {}).map(([k, v]) => `${k}=${v}`).join('; ');
  if (ck) h.Cookie = ck;
  const res = await handler(new Request('https://mi-sitio.netlify.app' + path, { method, headers: h, redirect: 'manual', body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) }), { ip: '198.51.100.' + (client.charCodeAt(0) % 200) });
  const scs = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const sc of scs) {
    const nv = sc.split(';')[0], i = nv.indexOf('='), name = nv.slice(0, i), val = nv.slice(i + 1);
    jar[client] = jar[client] || {};
    if (!val || /Max-Age=0/.test(sc)) delete jar[client][name]; else jar[client][name] = val;
  }
  let j = null; try { j = await res.json(); } catch {}
  return { status: res.status, json: j, setCookie: scs.join(' | ') || null, location: res.headers.get('location') };
}
const tokenFrom = (re) => { const m = M.mails.map((x) => x.html).reverse().map((h) => h.match(re)).find(Boolean); return m && m[1]; };
const results = []; const test = async (n, f) => { try { await f(); results.push([1, n]); } catch (e) { results.push([0, n + ' → ' + e.message]); } };
const PW = 'Clave-Segura-2026';

await test('config pública', async () => assert.deepStrictEqual((await call('GET', '/api/config')).json.features, { mail: true, billing: true, ai: true, promo: true, google: true }));
await test('me sin sesión: user null', async () => { const r = await call('GET', '/api/auth/me'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.user, null); });
await test('registro: validaciones (email, contraseña corta/débil)', async () => {
  assert.strictEqual((await call('POST', '/api/auth/register', { body: { email: 'mal', password: PW } })).status, 400);
  assert.strictEqual((await call('POST', '/api/auth/register', { body: { email: 'a@b.com', password: '123' } })).status, 400);
  assert.strictEqual((await call('POST', '/api/auth/register', { body: { email: 'a@b.com', password: 'password' } })).status, 400);
});
await test('registro OK: cookie HttpOnly+Secure+SameSite, email de verificación enviado', async () => {
  const r = await call('POST', '/api/auth/register', { body: { email: 'Ana@Mail.com ', password: PW, name: 'Ana <b>' } });
  assert.strictEqual(r.status, 201); assert.strictEqual(r.json.user.email, 'ana@mail.com'); assert.strictEqual(r.json.user.emailVerified, false);
  assert.ok(/HttpOnly/.test(r.setCookie) && /SameSite=Lax/.test(r.setCookie) && /Secure/.test(r.setCookie));
  assert.strictEqual(r.json.user.name, 'Ana b'); assert.strictEqual(M.mails.length, 1); assert.ok(r.json.mailSent);
});
await test('la respuesta nunca incluye hash ni secretos', async () => { const r = await call('GET', '/api/auth/me'); const t = JSON.stringify(r.json); assert.ok(!t.includes('scrypt') && !t.includes('passHash')); assert.strictEqual(r.json.user.email, 'ana@mail.com'); });
await test('la contraseña se guarda con scrypt (no en claro)', async () => { const raw = [...mem.values()].join('|'); assert.ok(raw.includes('scrypt$') && !raw.includes(PW)); });
await test('registro duplicado → 409', async () => assert.strictEqual((await call('POST', '/api/auth/register', { body: { email: 'ana@mail.com', password: PW }, client: 'b' })).status, 409));
await test('cookie manipulada → sin sesión', async () => { const saved = jar.a.ethos_session; jar.a.ethos_session = saved.slice(0, -3) + 'xxx'; const r = await call('GET', '/api/auth/me'); jar.a.ethos_session = saved; assert.strictEqual(r.json.user, null); });
await test('pagar sin verificar email → 403', async () => assert.strictEqual((await call('POST', '/api/billing/checkout', { body: { plan: 'pro' } })).status, 403));
await test('verificar email con el enlace', async () => {
  const t = tokenFrom(/\?verify=([\w.\-]+)/); assert.ok(t);
  assert.strictEqual((await call('POST', '/api/auth/verify', { body: { token: t }, client: 'z' })).status, 200);
  assert.strictEqual((await call('GET', '/api/auth/me')).json.user.emailVerified, true);
  assert.strictEqual((await call('POST', '/api/auth/verify', { body: { token: t + 'x' } })).status, 400);
});
await test('checkout requiere sesión → 401', async () => assert.strictEqual((await call('POST', '/api/billing/checkout', { body: { plan: 'pro' }, client: 'nobody' })).status, 401));
await test('checkout ligado a la cuenta (customer + client_reference_id)', async () => {
  const r = await call('POST', '/api/billing/checkout', { body: { plan: 'pro' } });
  assert.strictEqual(r.status, 200); assert.ok(r.json.url.startsWith('https://checkout.stripe.test'));
  const s = M.sessions.at(-1);
  assert.strictEqual(s.customer, 'cus_1'); assert.ok(/^[a-f0-9]{32}$/.test(s.client_reference_id)); assert.strictEqual(s['line_items[0][price]'], 'price_pro');
  assert.strictEqual(s.success_url, 'https://mi-sitio.netlify.app/?checkout=success'); assert.strictEqual(s.mode, 'subscription');
});
await test('plan inválido → 400', async () => assert.strictEqual((await call('POST', '/api/billing/checkout', { body: { plan: 'gratis' } })).status, 400));
await test('IA con plan gratis → 403', async () => assert.strictEqual((await call('POST', '/api/ai', { body: { prompt: 'una historia de traición' } })).status, 403));
await test('webhook firmado activa el plan Pro', async () => {
  M.subs.cus_1 = { status: 'active', price: 'price_pro' };
  const payload = JSON.stringify({ type: 'customer.subscription.created', data: { object: { customer: 'cus_1' } } });
  const t = Math.floor(Date.now() / 1000), sig = crypto.createHmac('sha256', 'whsec_t').update(`${t}.${payload}`).digest('hex');
  assert.strictEqual((await call('POST', '/api/stripe/webhook', { body: payload, headers: { 'Stripe-Signature': `t=${t},v1=${sig}` }, origin: null, xr: false })).status, 200);
  const me = (await call('GET', '/api/auth/me')).json; assert.strictEqual(me.plan, 'pro'); assert.strictEqual(me.planSource, 'stripe');
});
await test('webhook con firma falsa → 400', async () => assert.strictEqual((await call('POST', '/api/stripe/webhook', { body: '{}', headers: { 'Stripe-Signature': 't=1,v1=bad' }, origin: null, xr: false })).status, 400));
await test('ya con plan activo: nuevo checkout → 409', async () => assert.strictEqual((await call('POST', '/api/billing/checkout', { body: { plan: 'creador' } })).status, 409));
await test('IA Pro OK, clave no filtrada, límite diario → 429', async () => {
  const a = await call('POST', '/api/ai', { body: { prompt: 'una historia de traición' } });
  assert.strictEqual(a.status, 200); assert.strictEqual(M.geminiKey, 'gem_secret'); assert.ok(!JSON.stringify(a.json).includes('gem_secret'));
  assert.strictEqual((await call('POST', '/api/ai', { body: { prompt: 'una historia de traición' } })).status, 200);
  assert.strictEqual((await call('POST', '/api/ai', { body: { prompt: 'una historia de traición' } })).status, 429);
});
await test('portal de cliente', async () => assert.strictEqual((await call('POST', '/api/billing/portal', { body: {} })).json.url, 'https://billing.stripe.test/p'));
await test('cancelación (sync) → vuelve a gratis y la IA se bloquea', async () => {
  M.subs.cus_1 = { status: 'canceled', price: 'price_pro' };
  assert.strictEqual((await call('POST', '/api/billing/sync', { body: {} })).json.plan, 'free');
  assert.strictEqual((await call('POST', '/api/ai', { body: { prompt: 'una historia de traición' } })).status, 403);
});
await test('CSRF: origen ajeno o sin cabecera → 403', async () => {
  assert.strictEqual((await call('POST', '/api/auth/logout', { body: {}, origin: 'https://evil.com' })).status, 403);
  assert.strictEqual((await call('POST', '/api/auth/logout', { body: {}, xr: false })).status, 403);
});
await test('promo: requiere sesión y da plan temporal', async () => {
  assert.strictEqual((await call('POST', '/api/promo/redeem', { body: { key: 'VIP-1' }, client: 'nobody' })).status, 401);
  assert.strictEqual((await call('POST', '/api/promo/redeem', { body: { key: 'nope' } })).status, 404);
  const r = await call('POST', '/api/promo/redeem', { body: { key: 'vip-1' } }); assert.strictEqual(r.json.plan, 'pro'); assert.strictEqual(r.json.planSource, 'promo');
});
await test('cambiar contraseña: exige la actual e invalida otras sesiones', async () => {
  const other = await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: PW }, client: 'c' }); assert.strictEqual(other.status, 200);
  assert.strictEqual((await call('POST', '/api/auth/change-password', { body: { current: 'mala', password: 'Otra-Clave-2027' } })).status, 403);
  assert.strictEqual((await call('POST', '/api/auth/change-password', { body: { current: PW, password: 'Otra-Clave-2027' } })).status, 200);
  assert.strictEqual((await call('GET', '/api/auth/me')).json.user.email, 'ana@mail.com');               // esta sesión sigue
  assert.strictEqual((await call('GET', '/api/auth/me', { client: 'c' })).json.user, null);               // la otra se cierra
});
await test('login: error genérico, bloqueo tras 8 fallos, contraseña correcta no entra bloqueada', async () => {
  const bad = await call('POST', '/api/auth/login', { body: { email: 'noexiste@x.com', password: 'loquesea123' }, client: 'd' });
  assert.strictEqual(bad.status, 401); assert.ok(bad.json.error.startsWith('Email o contraseña incorrectos.'));
  const w = await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'xxxxxxxx1' }, client: 'd' }); assert.strictEqual(w.json.error, bad.json.error);
  for (let i = 0; i < 7; i++) await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'xxxxxxxx1' }, client: 'e' });
  const locked = await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'Otra-Clave-2027' }, client: 'e' });
  assert.strictEqual(locked.status, 429);
});
await test('recuperar contraseña: respuesta igual exista o no, enlace de un solo uso', async () => {
  const before = M.mails.length;
  assert.strictEqual((await call('POST', '/api/auth/forgot', { body: { email: 'fantasma@x.com' }, client: 'f' })).status, 200); assert.strictEqual(M.mails.length, before);
  assert.strictEqual((await call('POST', '/api/auth/forgot', { body: { email: 'ana@mail.com' }, client: 'f' })).status, 200); assert.strictEqual(M.mails.length, before + 1);
  const t = tokenFrom(/\?reset=([\w.\-]+)/); assert.ok(t);
  assert.strictEqual((await call('POST', '/api/auth/reset', { body: { token: t, password: '123' }, client: 'f' })).status, 400);
  const ok = await call('POST', '/api/auth/reset', { body: { token: t, password: 'Tercera-Clave-2028' }, client: 'f' }); assert.strictEqual(ok.status, 200);
  assert.strictEqual((await call('POST', '/api/auth/reset', { body: { token: t, password: 'Cuarta-Clave-2029' }, client: 'g' })).status, 400);   // reutilizar
  assert.strictEqual((await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'Tercera-Clave-2028' }, client: 'h' })).status, 200);   // y desbloquea
});
await test('logout borra la cookie', async () => { const r = await call('POST', '/api/auth/logout', { body: {}, client: 'h' }); assert.ok(/Max-Age=0/.test(r.setCookie)); assert.strictEqual((await call('GET', '/api/auth/me', { client: 'h' })).json.user, null); });
await test('borrar cuenta: pide contraseña y bloquea con suscripción activa', async () => {
  await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'Tercera-Clave-2028' }, client: 'i' });
  assert.strictEqual((await call('POST', '/api/auth/delete', { body: { password: 'mala' }, client: 'i' })).status, 403);
  M.subs.cus_1 = { status: 'active', price: 'price_cr' };
  assert.strictEqual((await call('POST', '/api/auth/delete', { body: { password: 'Tercera-Clave-2028' }, client: 'i' })).status, 409);
  M.subs.cus_1 = { status: 'canceled', price: 'price_cr' };
  assert.strictEqual((await call('POST', '/api/auth/delete', { body: { password: 'Tercera-Clave-2028' }, client: 'i' })).status, 200);
  assert.strictEqual((await call('POST', '/api/auth/login', { body: { email: 'ana@mail.com', password: 'Tercera-Clave-2028' }, client: 'j' })).status, 401);
});
await test('registro sin servicio de email: cuenta verificada de entrada', async () => {
  api.cfg.resendKey = ''; 
  const r = await call('POST', '/api/auth/register', { body: { email: 'sinmail@x.com', password: PW }, client: 'k' });
  assert.strictEqual(r.json.user.emailVerified, true); api.cfg.resendKey = 're_x';
  assert.strictEqual((await call('POST', '/api/auth/forgot', { body: { email: 'sinmail@x.com' }, client: 'k' })).status, 200);
});

// ================= Google =================
const claimsFor = (nonce, extra = {}) => ({ iss: 'https://accounts.google.com', aud: 'gid.apps.googleusercontent.com', exp: Math.floor(Date.now() / 1000) + 3600, nonce, sub: 'g-sub-1', email: 'nuevo@gmail.com', email_verified: true, name: 'Nuevo Usuario', ...extra });
async function googleStart(client, plan) {
  const r = await call('GET', '/api/auth/google/start' + (plan ? '?plan=' + plan : ''), { client, origin: null, xr: false });
  const u = new URL(r.location); return { r, q: u.searchParams, url: u };
}
const goCallback = (client, state, code = 'abc') => call('GET', `/api/auth/google/callback?code=${code}&state=${state}`, { client, origin: null, xr: false });

await test('Google: /start redirige a Google con PKCE, state y nonce, y guarda cookie propia', async () => {
  const { r, q, url } = await googleStart('p', 'pro');
  assert.strictEqual(r.status, 302); assert.strictEqual(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.strictEqual(q.get('client_id'), 'gid.apps.googleusercontent.com'); assert.strictEqual(q.get('redirect_uri'), 'https://mi-sitio.netlify.app/api/auth/google/callback');
  assert.strictEqual(q.get('code_challenge_method'), 'S256'); assert.strictEqual(q.get('scope'), 'openid email profile'); assert.ok(q.get('state').length >= 32 && q.get('nonce').length >= 32);
  assert.ok(/ethos_oauth=/.test(r.setCookie) && /HttpOnly/.test(r.setCookie) && /Path=\/api\/auth\/google/.test(r.setCookie) && /SameSite=Lax/.test(r.setCookie));
});
await test('Google: usuario nuevo → cuenta verificada, sin contraseña, sesión iniciada y plan pendiente en la URL', async () => {
  const { q } = await googleStart('p', 'pro'); G.claims = claimsFor(q.get('nonce'));
  const r = await goCallback('p', q.get('state'));
  assert.strictEqual(r.status, 302); assert.strictEqual(r.location, 'https://mi-sitio.netlify.app/?google=ok&plan=pro');
  assert.strictEqual(G.last.code_verifier.length > 30, true); assert.strictEqual(G.last.grant_type, 'authorization_code');
  const me = (await call('GET', '/api/auth/me', { client: 'p' })).json;
  assert.strictEqual(me.user.email, 'nuevo@gmail.com'); assert.strictEqual(me.user.emailVerified, true); assert.strictEqual(me.hasPassword, false); assert.strictEqual(me.google, true); assert.strictEqual(me.user.name, 'Nuevo Usuario');
  assert.ok(!(jar.p.ethos_oauth), 'la cookie temporal debe borrarse');
});
await test('Google: el PKCE enviado a Google coincide con el desafío inicial', async () => {
  const { q } = await googleStart('q'); G.claims = claimsFor(q.get('nonce'), { sub: 'g-sub-1' });
  await goCallback('q', q.get('state'));
  const expected = crypto.createHash('sha256').update(G.last.code_verifier).digest('base64url');
  assert.strictEqual(expected, q.get('code_challenge'));
});
await test('Google: plan inválido en la URL se ignora', async () => {
  const { q } = await googleStart('r', 'gratis-total'); G.claims = claimsFor(q.get('nonce'));
  assert.strictEqual((await goCallback('r', q.get('state'))).location, 'https://mi-sitio.netlify.app/?google=ok');
});
await test('Google: state manipulado / sin cookie → error y sin sesión', async () => {
  const { q } = await googleStart('s'); G.claims = claimsFor(q.get('nonce'));
  const bad = await goCallback('s', 'estado-falso'); assert.ok(bad.location.includes('google=error&reason=state'));
  const noCookie = await goCallback('t', q.get('state')); assert.ok(noCookie.location.includes('reason=state'));
  assert.strictEqual((await call('GET', '/api/auth/me', { client: 's' })).json.user, null);
});
await test('Google: id_token con aud/nonce/caducidad/iss incorrectos → rechazado', async () => {
  for (const extra of [{ aud: 'otro-cliente' }, { nonce: 'otro-nonce' }, { exp: 100 }, { iss: 'https://evil.com' }]) {
    const { q } = await googleStart('u'); G.claims = claimsFor(q.get('nonce'), extra);
    const r = await goCallback('u', q.get('state')); assert.ok(r.location.includes('google=error'), JSON.stringify(extra));
    assert.strictEqual((await call('GET', '/api/auth/me', { client: 'u' })).json.user, null);
  }
});
await test('Google: email sin verificar → rechazado con motivo', async () => {
  const { q } = await googleStart('v'); G.claims = claimsFor(q.get('nonce'), { email_verified: false, email: 'x@gmail.com' });
  assert.ok((await goCallback('v', q.get('state'))).location.includes('reason=unverified'));
});
await test('Google: el usuario cancela → google=cancel; fallo del token → error', async () => {
  const { q } = await googleStart('w');
  const c = await call('GET', `/api/auth/google/callback?error=access_denied&state=${q.get('state')}`, { client: 'w', origin: null, xr: false }); assert.strictEqual(c.location, 'https://mi-sitio.netlify.app/?google=cancel');
  const s2 = await googleStart('w'); G.fail = true; G.claims = claimsFor(s2.q.get('nonce'));
  assert.ok((await goCallback('w', s2.q.get('state'))).location.includes('reason=failed')); G.fail = false;
});
await test('Google: cuenta con contraseña + mismo email → se vincula y la contraseña sigue funcionando', async () => {
  await call('POST', '/api/auth/register', { body: { email: 'mixta@gmail.com', password: PW }, client: 'x' });
  const { q } = await googleStart('y'); G.claims = claimsFor(q.get('nonce'), { sub: 'g-mixta', email: 'Mixta@Gmail.com' });
  assert.ok((await goCallback('y', q.get('state'))).location.includes('google=ok'));
  const me = (await call('GET', '/api/auth/me', { client: 'y' })).json; assert.strictEqual(me.user.email, 'mixta@gmail.com'); assert.strictEqual(me.hasPassword, true); assert.strictEqual(me.google, true); assert.strictEqual(me.user.emailVerified, true);
  assert.strictEqual((await call('POST', '/api/auth/login', { body: { email: 'mixta@gmail.com', password: PW }, client: 'z' })).status, 200);
});
await test('Google: mismo email con otra cuenta de Google distinta → rechazado', async () => {
  const { q } = await googleStart('y'); G.claims = claimsFor(q.get('nonce'), { sub: 'g-OTRA', email: 'mixta@gmail.com' });
  assert.ok((await goCallback('y', q.get('state'))).location.includes('reason=failed'));
});
await test('cuenta solo-Google: login con contraseña falla sin revelar nada y apunta a Google', async () => {
  const r = await call('POST', '/api/auth/login', { body: { email: 'nuevo@gmail.com', password: 'cualquiera123' }, client: 'aa' });
  assert.strictEqual(r.status, 401); assert.ok(r.json.error.includes('Continuar con Google'));
});
await test('cuenta solo-Google: puede crear contraseña por email (recuperar) y luego entrar con ella', async () => {
  const before = M.mails.length;
  await call('POST', '/api/auth/forgot', { body: { email: 'nuevo@gmail.com' }, client: 'bb' }); assert.strictEqual(M.mails.length, before + 1);
  const t = tokenFrom(/\?reset=([\w.\-]+)/);
  assert.strictEqual((await call('POST', '/api/auth/reset', { body: { token: t, password: 'Clave-Google-2030' }, client: 'bb' })).status, 200);
  assert.strictEqual((await call('POST', '/api/auth/login', { body: { email: 'nuevo@gmail.com', password: 'Clave-Google-2030' }, client: 'cc' })).status, 200);
  assert.strictEqual((await call('POST', '/api/auth/reset', { body: { token: t, password: 'Otra-Clave-2031' }, client: 'dd' })).status, 400);   // un solo uso
});
await test('cuenta solo-Google: crear contraseña desde la cuenta sin pedir la actual; borrar con confirmación de email', async () => {
  const { q } = await googleStart('ee'); G.claims = claimsFor(q.get('nonce'), { sub: 'g-solo', email: 'solo@gmail.com' }); await goCallback('ee', q.get('state'));
  assert.strictEqual((await call('POST', '/api/auth/change-password', { body: { password: '123' }, client: 'ee' })).status, 400);
  assert.strictEqual((await call('POST', '/api/auth/change-password', { body: { password: 'Clave-Solo-2032' }, client: 'ee' })).status, 200);
  assert.strictEqual((await call('POST', '/api/auth/login', { body: { email: 'solo@gmail.com', password: 'Clave-Solo-2032' }, client: 'ff' })).status, 200);
  const g2 = await googleStart('gg'); G.claims = claimsFor(g2.q.get('nonce'), { sub: 'g-solo2', email: 'solo2@gmail.com' }); await goCallback('gg', g2.q.get('state'));
  assert.strictEqual((await call('POST', '/api/auth/delete', { body: { confirmEmail: 'otro@x.com' }, client: 'gg' })).status, 403);
  assert.strictEqual((await call('POST', '/api/auth/delete', { body: { confirmEmail: 'SOLO2@gmail.com' }, client: 'gg' })).status, 200);
  assert.strictEqual((await call('GET', '/api/auth/me', { client: 'gg' })).json.user, null);
});
await test('Google sin configurar: /start vuelve con motivo "config"', async () => {
  const keep = api.cfg.googleId; api.cfg.googleId = '';
  const r = await call('GET', '/api/auth/google/start', { client: 'hh', origin: null, xr: false }); api.cfg.googleId = keep;
  assert.strictEqual(r.location, 'https://mi-sitio.netlify.app/?google=error&reason=config');
});

await test('cuerpo enorme → 413 y ruta desconocida → 404', async () => {
  assert.strictEqual((await call('POST', '/api/auth/login', { body: JSON.stringify({ email: 'a@b.com', password: 'a'.repeat(100000) }), client: 'l' })).status, 413);
  assert.strictEqual((await call('GET', '/api/nada')).status, 404);
});

let fail = 0; for (const [ok, n] of results) { console.log((ok ? '✓ ' : '✗ ') + n); if (!ok) fail++; }
console.log(`\n${results.length - fail}/${results.length} pruebas correctas`); process.exit(fail ? 1 : 0);
