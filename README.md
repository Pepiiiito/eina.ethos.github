# Ethos Chat Studio — backend mínimo

Sin dependencias (solo Node >= 22.5, usa `node:sqlite`).

    cp .env.example .env   # rellena los valores
    npm start

## Qué hace
- **Cuentas reales**: registro/login (scrypt) y cookie de sesión HttpOnly firmada. El plan vive en SQLite, nunca en el navegador.
- **Webhook Stripe** `POST /api/stripe/webhook`: verifica la firma (tolerancia 5 min), es idempotente (`stripe_events`) y tolera eventos en cualquier orden.
- **IA Pro** `POST /api/ai/generate`: solo plan `pro`, tu clave de Gemini en el servidor (cabecera, no URL), cuota diaria y mensual por usuario (se devuelve la cuota si Gemini falla).

## Configurar Stripe
1. En cada **Payment Link**: *After payment -> Redirect* a `https://TU_DOMINIO/?status=success`.
2. Developers -> Webhooks -> endpoint `https://TU_DOMINIO/api/stripe/webhook` con los eventos:
   `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`.
3. Copia el *Signing secret* a `STRIPE_WEBHOOK_SECRET` y los IDs de precio a `STRIPE_PRICE_*`.
4. Activa el Customer Portal de Stripe para que los usuarios cancelen solos; la baja llega por webhook.

El botón de suscripción añade `client_reference_id` (id de usuario) al Payment Link, así cada pago queda ligado a su cuenta.

## Limitaciones conocidas
- **Las exportaciones (marca de agua, 2K/4K, vídeo) se generan en el navegador**: un usuario técnico puede saltarse la restricción con las DevTools. La cuenta, el plan y la IA sí están protegidos; esto es disuasión, no protección. Protegerlo de verdad exige renderizar en servidor.
- Faltan verificación de correo y "olvidé mi contraseña" (necesitan proveedor de email) y HTTPS (ponlo detrás de Caddy/Nginx).
- `app.js` y `css.css` eran una versión antigua y no se usan: toda la lógica está en `index.html`.

## Inicio de sesión y pago (v2)
- Para pagar hay que tener cuenta: "Suscribirse" abre el registro/login y, al entrar, sigue solo a Stripe con `client_reference_id`.
- `COOKIE_SECURE=auto` (por defecto): la cookie lleva `Secure` solo si la conexión es HTTPS. Detrás de Caddy/Nginx pon `TRUST_PROXY=true`.
- El vídeo se exporta siempre en 9:16 (1080x1920) para YouTube Shorts.
- Abre la app en `http://localhost:3000` (no el HTML con doble clic).

## Publicarlo en internet (sin depender de tu ordenador)
Una web estática (GitHub Pages, Netlify sin funciones, etc.) NO sirve: no puede ejecutar el login. Necesitas un hosting que ejecute Node 22.13+ de forma continua y con disco persistente:
1. Sube esta carpeta a un repositorio de GitHub (sin `.env` ni `ethos.db`).
2. En Render (Web Service) o Railway: Build command vacío, Start command `npm start`.
3. Variables de entorno: las de `.env.example` (SESSION_SECRET, STRIPE_*, GEMINI_API_KEY, TRUST_PROXY=true).
4. Añade un disco persistente montado en `/data` y pon `DB_PATH=/data/ethos.db`. Sin disco, SQLite se borra en cada reinicio.
5. Webhook de Stripe: `https://TU_DOMINIO/api/stripe/webhook`.

## Correo: verificar cuenta y recuperar contraseña
- Usa Resend (resend.com, plan gratis): crea cuenta, añade y verifica tu dominio (te da registros DNS) y crea una API key.
- Variables en Render: `RESEND_API_KEY`, `MAIL_FROM` (ej. `Ethos <no-reply@ethosfakechats.com>`) y `APP_URL` (ej. `https://ethosfakechats.com`).
- Sin esas variables la app funciona igual, pero no envía correos: los enlaces salen en los Logs del servidor.
- Al cambiar la contraseña se cierran todas las sesiones anteriores.
