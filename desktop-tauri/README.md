# AEGIS Desktop (Tauri)

Starter wrapper to run the existing Next.js UI inside a Tauri shell for local testing.

## Local dev

1. `cd frontend && npm install`
2. `cd ../desktop-tauri && npm install`
3. `npm run dev`

The Tauri config points to the Next dev server at `http://localhost:3000` and will auto-run `npm run dev` from `../frontend`.

## Packaging (not wired yet)

`tauri build` expects static assets in `frontend/out`. We will define the production build strategy (static export vs bundled local server) once the desktop scope is finalized.
