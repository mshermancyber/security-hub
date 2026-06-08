import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { maybeRedirectToMobile } from './lib/useDeviceType'

// Pre-React UA check. If the visitor is on a phone or tablet and hasn't
// opted into the desktop view, redirect to /m before paying the cost of
// loading the SPA bundle + React tree. The server middleware
// (backend/app/mobile_redirect.py) does the same check as a fallback for
// no-JS clients, but doing it client-side too means a cached HTML shell
// still redirects correctly without a backend round-trip.
if (!maybeRedirectToMobile()) {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}
