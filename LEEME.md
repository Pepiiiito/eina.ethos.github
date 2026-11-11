# Ethos Chat Studio — cuentas, pagos e IA en Netlify

## Qué hace esta versión
- **Cuentas reales:** registro e inicio de sesión con email y contraseña, o con **Google**. Hay que **iniciar sesión antes de pagar**.
- **El pago queda ligado a la cuenta:** el plan sale de la suscripción real de Stripe, no de enlaces ni claves.
  Puedes entrar desde cualquier dispositivo y tu plan te sigue.
- Confirmación de email, recuperar contraseña, cambiar contraseña, cerrar sesión (también en todos los
  dispositivos), eliminar cuenta, gestionar suscripción (portal de Stripe) y códigos promocionales.
- IA del plan Pro con tu clave de Gemini en el servidor, con límite diario por cuenta.
- Los datos se guardan en **Netlify Blobs** (no necesitas base de datos).

## Archivos (todos sueltos, en la raíz del repositorio)
| Archivo | Para qué |
|---|---|
| `index.html` | La app |
| `api.mjs` | Backend completo (cuentas, Stripe, IA, webhook) |
| `build.mjs`, `netlify.toml` | Preparan el despliegue |
| `package.json` | Instala `@netlify/blobs` (lo hace Netlify solo) |
| `_headers`, `ethos-logo.svg` | Cabeceras de seguridad y logo |
| `test-auth.mjs`, `dev-server.mjs` | Pruebas (43) y servidor local de pruebas |

> **El arrastrar y soltar (Netlify Drop) ya no sirve para esta versión:** necesita funciones y una dependencia.
> Despliega desde un repositorio de GitHub conectado a Netlify (o con `npx netlify-cli deploy --prod --build`).

## Variables de entorno (Netlify → Site configuration → Environment variables)
Tras cambiarlas hay que **volver a desplegar**.

| Variable | Obligatoria | Qué poner |
|---|---|---|
| `AUTH_SECRET` | **Sí** | Texto aleatorio de 32+ caracteres: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `STRIPE_SECRET_KEY` | Para cobrar | `sk_live_...` (o `sk_test_...` para probar) |
| `PRICE_IDS_PRO` | Para cobrar | ID del **precio** del plan Pro: `price_...` |
| `PRICE_IDS_CREADOR` | Para cobrar | ID del **precio** del plan Creador: `price_...` |
| `STRIPE_WEBHOOK_SECRET` | Recomendada | `whsec_...` (activa/cancela el plan al instante) |
| `RESEND_API_KEY` y `MAIL_FROM` | Recomendadas | Para emails de confirmación y recuperar contraseña. `MAIL_FROM` = `Ethos <no-reply@tu-dominio.com>` |
| `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET` | Para entrar con Google | Credenciales OAuth de Google (ver más abajo) |
| `GEMINI_API_KEY` | Para IA Pro | Tu clave de Gemini |
| `AI_DAILY_LIMIT` | No | Generaciones de IA por cuenta y día (40 por defecto) |
| `PROMO_KEYS` | No | `CODIGO:pro:30,OTRO:creador:90` (plan y días de validez) |
| `APP_URL` | No | Tu dominio propio si no usas el de Netlify |

El ID de precio está en Stripe → Catálogo de productos → el producto → el precio (empieza por `price_`).
No es el ID del producto (`prod_`) ni el del Payment Link.

## Stripe (una sola vez)
1. Ya **no usas Payment Links**: la web crea el pago con tu cuenta. Puedes desactivar los enlaces antiguos.
2. Webhook: `https://TU-SITIO/api/stripe/webhook` con los eventos `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`.
3. Activa el portal de cliente: Settings → Billing → Customer portal (lo usa "Gestionar suscripción").

## Inicio de sesión con Google (una sola vez)
1. Entra en https://console.cloud.google.com → crea un proyecto (o usa uno).
2. **APIs y servicios → Pantalla de consentimiento de OAuth**: tipo *Externo*, pon el nombre de la app y tu email de soporte.
   Los permisos que se piden son solo los básicos (`openid`, `email`, `profile`), que no requieren verificación de Google.
   Pulsa **Publicar aplicación** (en modo "Pruebas" solo podrían entrar los usuarios de prueba que añadas).
3. **Credenciales → Crear credenciales → ID de cliente de OAuth → Aplicación web.** En **URI de redireccionamiento autorizados** añade
   exactamente: `https://TU-SITIO/api/auth/google/callback` (uno por cada dirección que uses: la de Netlify y tu dominio propio si lo tienes).
4. Copia el **ID de cliente** y el **secreto** a las variables `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET` de Netlify y vuelve a desplegar.

Cómo se comporta: si alguien entra con Google con un email que ya tenía cuenta con contraseña, se vinculan (Google ya verificó ese email).
Las cuentas creadas con Google no tienen contraseña hasta que creen una desde "Cuenta" (así pueden entrar también con email).
Si no pones las variables de Google, el botón simplemente no aparece.

## Resend (emails)
Crea una cuenta en resend.com, verifica tu dominio y crea una API key. Sin Resend la app funciona, pero las cuentas
no se verifican por email y **no se puede recuperar la contraseña** (el botón avisa de que no está disponible).


## Planes y límites

| | Gratis | Creador (6,99 €) | Pro (14,99 €) |
|---|---|---|---|
| Mensajes por chat | 12 | 60 | 500 |
| Captura PNG | estándar (1x) | 2K (2x) | 4K (3x) |
| Marca de agua | Sí (diagonal, en todo el teléfono) | No | No |
| Vídeo | completo, con marca de agua | + fondo croma/negro, formato vertical 9:16, modo "últimos 3 mensajes", sonidos | igual que Creador |
| Guardar / cargar proyecto (JSON) | No | Sí | Sí |
| IA integrada | No (puede usar su propia clave de Gemini) | No | Sí, con límite diario |

Los límites están en `PLAN_LIMITS` (dentro de `index.html`, busca ese nombre) por si quieres ajustarlos.
Se aplican en el navegador, así que una persona con conocimientos técnicos podría saltárselos;
lo que protege el servidor es la cuenta, el pago y la IA.

## Grabación de vídeo con fondo transparente

En el modal de grabación eliges **Fondo del vídeo**:
- **Tal cual (como antes):** se graba con el color de fondo que hayas elegido en el editor.
- **Verde croma:** todo el fondo (también las esquinas) sale en un único verde. En tu editor: *Croma / Chroma Key* sobre el verde
  y verás el gameplay detrás; solo desaparece el fondo, el perfil y las burbujas se quedan.
- **Negro puro:** para editores donde prefieras la mezcla *Pantalla / Aclarar* en vez del croma.

El vídeo se recorta al tamaño exacto del teléfono. En **Tamaño del vídeo** puedes elegir *Vertical 9:16 · 1080×1920*:
el teléfono se centra en un lienzo vertical del color de fondo elegido, listo para poner sobre tu gameplay en Shorts/TikTok/Reels
(si tu pantalla es pequeña, el vídeo se amplía y queda algo menos nítido). Con fondo croma/negro se ocultan la barra de desplazamiento
y los bordes del teléfono para que no se cuele ninguna línea sobre el fondo. Si el vídeo sale cortado, comprueba que el teléfono se ve entero en la
ventana durante la grabación y que has elegido **"Esta pestaña"** al compartir. Funciona en Chrome/Edge de escritorio.

## Si algo falla
- **"Los pagos no están configurados" / "Este plan todavía no está configurado"**: faltan `STRIPE_SECRET_KEY` o
  `PRICE_IDS_PRO` / `PRICE_IDS_CREADOR`, o no has vuelto a desplegar después de ponerlos.
- **"Servidor sin configurar: falta AUTH_SECRET"**: pon `AUTH_SECRET` (32+ caracteres) y redespliega.
- **"No se puede conectar con el servidor"**: abre tu sitio de Netlify (no el archivo suelto). Comprueba que
  `https://TU-SITIO/api/auth/me` muestra un texto JSON; si da 404, la función no se desplegó (mira el registro del despliegue).
- **Pagaste y el plan no aparece**: vuelve a la web; se confirma solo en unos segundos. Si no, revisa el webhook en Stripe.

## Seguridad: qué está cubierto y qué no
Cubierto: inicio con Google por OAuth 2.0 (código + PKCE, `state` y `nonce` comprobados; solo emails verificados por Google), contraseñas con scrypt y sal propia (nunca en claro), sesión en cookie HttpOnly + Secure + SameSite,
protección CSRF, mensajes de login que no revelan si el email existe, bloqueo temporal tras 8 intentos fallidos,
límites de registros/recuperaciones por conexión, enlaces de email firmados y de un solo uso, cambio de contraseña
que cierra las demás sesiones, y el plan siempre comprobado en el servidor (la IA Pro solo responde con plan Pro real).

No cubierto (conviene saberlo): no hay verificación en dos pasos; los límites por conexión
se guardan en memoria de cada instancia (son aproximados; el bloqueo por cuenta sí es persistente); un atacante puede
bloquear temporalmente una cuenta ajena probando contraseñas; la marca de agua y la resolución de captura se aplican en
el navegador y las puede saltar alguien con conocimientos técnicos; el plan gratis de Netlify corta funciones a los 10 s.

## Probar en tu PC
```bash
npm install
npm test                 # 43 pruebas del backend (Stripe, Gemini, Google y email simulados)
node dev-server.mjs      # http://localhost:8888 con datos en memoria
```
