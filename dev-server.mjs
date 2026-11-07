// Servidor local de pruebas: sirve index.html y /api/* con almacenamiento en memoria.
//   node dev-server.mjs            (puerto 8888; configura el .env de ejemplo o variables de entorno)
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const mem = new Map();
globalThis.__ETHOS_STORE__ = { get: async (k) => (mem.has(k) ? JSON.parse(mem.get(k)) : null), set: async (k, v) => { mem.set(k, JSON.stringify(v)); }, del: async (k) => { mem.delete(k); } };
process.env.AUTH_SECRET ||= 'dev-secret-'.padEnd(40, 'x');
const PORT = parseInt(process.env.PORT, 10) || 8888;
process.env.APP_URL ||= `http://localhost:${PORT}`;
const { default: handler } = await import('./api.mjs');

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks);
    const r = await handler(new Request(url, { method: req.method, headers: req.headers, body }), { ip: req.socket.remoteAddress });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    return res.end(Buffer.from(await r.arrayBuffer()));
  }
  const file = path.join(here, url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
  if (!file.startsWith(here) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('No encontrado'); }
  res.writeHead(200, { 'Content-Type': file.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}).listen(PORT, () => console.log(`Dev en http://localhost:${PORT}`));
