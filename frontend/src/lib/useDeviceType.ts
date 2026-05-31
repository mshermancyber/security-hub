/**
 * Device-type detection — UA-based with iPadOS-as-Mac disambiguation.
 *
 * Used in two places:
 *   1. `main.tsx` before React mounts: if mobile and no `?desktop=1` /
 *      `sechub_view=desktop` cookie override, hard-redirect to /m so phones
 *      never download the 240 KB SPA bundle.
 *   2. Inside the SPA via `useDeviceType()` for telemetry / conditional UI.
 *
 * Operator decisions baked in (see CLAUDE.md mobile spec):
 *   - Tablets (iPad, Android tablet) → 'ios' / 'android' (route to /m).
 *     The terminal UI is too dense for portrait tablet use.
 *   - iPadOS 13+ reports the user-agent as Macintosh; we disambiguate via
 *     `navigator.maxTouchPoints > 1` which is the only reliable signal.
 */
import { useEffect, useState } from 'react'

export type DeviceType = 'desktop' | 'android' | 'ios'

const VIEW_OVERRIDE_COOKIE = 'sechub_view'
const DESKTOP_OPT_OUT = 'desktop'

/** UA + touch-points → device type. Pure function (testable, callable
 *  before React mounts).  `touchPoints` defaults to navigator's value but
 *  is overridable for unit tests. */
export function detectDevice(
  ua: string = typeof navigator !== 'undefined' ? navigator.userAgent : '',
  touchPoints: number = typeof navigator !== 'undefined' ? navigator.maxTouchPoints : 0,
): DeviceType {
  if (!ua) return 'desktop'
  if (/iPhone|iPod|iPad/i.test(ua)) return 'ios'
  // iPadOS 13+ identifies as Macintosh on Safari. Only multi-touch Macs are
  // iPads in disguise — a real Mac trackpad reports maxTouchPoints === 0.
  if (/Macintosh/i.test(ua) && touchPoints > 1) return 'ios'
  if (/Android/i.test(ua)) return 'android'
  if (/webOS|BlackBerry|Opera Mini|IEMobile/i.test(ua)) return 'android'
  return 'desktop'
}

export function isMobile(device: DeviceType): boolean {
  return device !== 'desktop'
}

/** Did the user explicitly opt into the desktop view from a mobile device?
 *  Set by clicking "Open desktop view" on /m, persists for 30 days. */
export function hasDesktopOverride(
  search: string = typeof location !== 'undefined' ? location.search : '',
  cookie: string = typeof document !== 'undefined' ? document.cookie : '',
): boolean {
  // Query-string wins (lets you share a "force-desktop" link).
  const params = new URLSearchParams(search)
  if (params.get('desktop') === '1') return true
  // Cookie persists across navigations.
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${VIEW_OVERRIDE_COOKIE}=([^;]+)`))
  return m?.[1] === DESKTOP_OPT_OUT
}

/** React hook — returns the current device type. Stable across renders;
 *  recomputed on window resize so DevTools toggling phones works in dev. */
export function useDeviceType(): DeviceType {
  const [device, setDevice] = useState<DeviceType>(() => detectDevice())
  useEffect(() => {
    const onResize = () => setDevice(detectDevice())
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return device
}

/** Pre-mount redirect. Called from main.tsx before React renders.
 *  Returns true if the page is being navigated away (caller should bail). */
export function maybeRedirectToMobile(): boolean {
  if (typeof location === 'undefined') return false
  // Never redirect if we're already on /m or any sub-path of it.
  if (location.pathname === '/m' || location.pathname.startsWith('/m/')) return false
  if (hasDesktopOverride()) return false
  const device = detectDevice()
  if (device === 'desktop') return false
  // location.replace (not assign) so back-button doesn't bounce between views.
  location.replace('/m' + location.search + location.hash)
  return true
}
