// Prepara el sitio para Netlify: crea dist/ con la web y deja la función en netlify/functions/.
// Funciona tanto si subiste los archivos sueltos como si tienes la carpeta public/.
import { mkdirSync, copyFileSync, existsSync, rmSync } from 'node:fs';

const first = (...paths) => paths.find((p) => existsSync(p));

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });
mkdirSync('netlify/functions', { recursive: true });

// 1) Página principal (acepta también el nombre original del archivo)
const index = first('index.html', 'public/index.html', 'ethos_chat_studio_saas_pro_edition.html', 'public/ethos_chat_studio_saas_pro_edition.html');
if (!index) {
  console.error('ERROR: no encuentro index.html. Sube index.html a la raíz del repositorio (o dentro de public/).');
  process.exit(1);
}
copyFileSync(index, 'dist/index.html');

// 2) Archivos opcionales
for (const f of ['_headers', 'ethos-logo.svg']) {
  const src = first(f, `public/${f}`);
  if (src) copyFileSync(src, `dist/${f}`);
}

// 3) Función del backend (licencias + IA)
if (!existsSync('netlify/functions/api.mjs')) {
  if (existsSync('api.mjs')) copyFileSync('api.mjs', 'netlify/functions/api.mjs');
  else console.warn('Aviso: no hay api.mjs; el sitio saldrá sin backend (modo gratis).');
}

console.log(`OK: dist/ listo (usado: ${index}).`);
