# React + Vite

The browser authenticates through the backend login page and an HttpOnly API
session cookie. Do not add bearer tokens, passwords, or component credentials
to `VITE_*` environment variables; those values are visible to every browser.
For API origins other than the default `http://localhost:8000`, set only
`VITE_API_BASE_URL` and configure that frontend origin in the backend's
`CORS_ALLOWED_ORIGINS` setting. Cookie sessions require a same-site deployment
for the default `SameSite=Lax` policy. For local setup, configure a password-hash
user in the backend's `MVP_USER_CREDENTIALS`, start the API with
`AUTH_COOKIE_SECURE=false` over local HTTP, then run `npm install` and
`npm run dev` in this directory. Do not use a Vite environment variable for a
permanent bearer token or password.

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
