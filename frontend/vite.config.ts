import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Port plan:
//   8080 — backend (FastAPI / uvicorn)
//   80   — frontend (this Vite dev server, or nginx in production)
// Override via SECHUB_BACKEND_PORT / SECHUB_FRONTEND_PORT if you need to.

const BACKEND_PORT = process.env.SECHUB_BACKEND_PORT || '8080'
const FRONTEND_PORT = Number(process.env.SECHUB_FRONTEND_PORT || 80)
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',          // bind all interfaces so the host firewall sees it
    port: FRONTEND_PORT,
    strictPort: true,
    proxy: {
      '/api': { target: BACKEND_URL, changeOrigin: true, ws: true },
      '/m':   { target: BACKEND_URL, changeOrigin: true },
    },
  },
})
