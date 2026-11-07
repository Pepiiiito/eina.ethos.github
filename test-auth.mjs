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
await listen(stripe, 3401); await listen(resend, 3402); await listen(gemini, 3403);

Object.assign(process.env, {
  AUTH_SECRET: 'k'.repeat(40), APP_URL: 'https://mi-sitio.netlify.app', STRIPE_SECRET_KEY: 'sk_test_x', STRIPE_API_BASE: 'http://127.0.0.1:3401',
  PRICE_IDS_PRO: 'price_pro', PRICE_IDS_CREADOR: 'price_cr', STRIPE_WEBHOOK_SECRET: 'whsec_t', GEMINI_API_KEY: 'gem_secret', GEMINI_API_BASE: 'http://127.0.0.1:3403',
  AI_DAILY_LIMIT: '2', RESEND_API_KEY: 're_x', MAIL_FROM: 'Ethos <no-reply@x.com>', MAIL_API_BASE: 'http://127.0.0.1:3402', PROMO_KEYS: 'VIP-1:pro:30',
});
const api = await import('./api.mjs');
const handler = api.default;

let jar = {};   // cookies por "cliente"
async function call(method, path, { body, headers, client = 'a', origin = 'https://mi-sitio.netlify.app', xr = true } = {}) {
  const h = { 'Content-Type': 'application/json', ...(origin ? { Origin: origin } : {}), ...(xr ? { 'X-Requested-With': 'ethos' } : {}), ...headers };
  if (jar[client]) h.Cookie = jar[client];
  const res = await handler(new Request('https://mi-sitio.netlify.app' + path, { method, headers: h, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)) }), { ip: '198.51.100.' + (client.charCodeAt(0) % 200) });
  const sc = res.headers.get('set-cookie');
  if (sc) jar[client] = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
  let j = null; try { j = await res.json(); } catch {}
  return { status: res.status, json: j, setCookie: sc };
}
const tokenFrom = (re) => { const m = M.mails.map((x) => x.html).reverse().map((h) => h.match(re)).find(Boolean); return m && m[1]; };
const results = []; const test = async (n, f) => { try { await f(); results.push([1, n]); } catch (e) { results.push([0, n + ' → ' + e.message]); } };
const PW = 'Clave-Segura-2026';

await test('config pública', async () => assert.deepStrictEqual((await call('GET', '/api/config')).json.features, { mail: true, billing: true, ai: true, promo: true }));
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
await test('cookie manipulada → sin sesión', async () => { const saved = jar.a; jar.a = saved.slice(0, -3) + 'xxx'; const r = await call('GET', '/api/auth/me'); jar.a = saved; assert.strictEqual(r.json.user, null); });
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
  assert.strictEqual(bad.status, 401); assert.strictEqual(bad.json.error, 'Email o contraseña incorrectos.');
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
await test('cuerpo enorme → 413 y ruta desconocida → 404', async () => {
  assert.strictEqual((await call('POST', '/api/auth/login', { body: JSON.stringify({ email: 'a@b.com', password: 'a'.repeat(100000) }), client: 'l' })).status, 413);
  assert.strictEqual((await call('GET', '/api/nada')).status, 404);
});

let fail = 0; for (const [ok, n] of results) { console.log((ok ? '✓ ' : '✗ ') + n); if (!ok) fail++; }
console.log(`\n${results.length - fail}/${results.length} pruebas correctas`); process.exit(fail ? 1 : 0);
