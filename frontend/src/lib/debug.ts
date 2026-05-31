/**
 * High-verbosity debug logger. Enabled by default; silence via
 * `localStorage.setItem('sechub.debug', '0')` and reload.
 *
 * Categories let you grep in DevTools:
 *   [SecHub:API]    HTTP requests + responses
 *   [SecHub:Panel]  active panel changes + mount/unmount
 *   [SecHub:Lazy]   lazy-import lifecycle (start / loaded / error)
 *   [SecHub:WS]     websocket events
 */
function enabled(): boolean {
  try {
    const v = localStorage.getItem('sechub.debug')
    return v === null ? true : v !== '0'
  } catch {
    return true
  }
}

const COLORS: Record<string, string> = {
  API:   'color:#6db; font-weight:600',
  Panel: 'color:#fa3; font-weight:600',
  Lazy:  'color:#a9f; font-weight:600',
  WS:    'color:#9c8; font-weight:600',
  ERR:   'color:#f55; font-weight:700',
}

export function dlog(cat: keyof typeof COLORS | string, ...args: any[]): void {
  if (!enabled()) return
  // eslint-disable-next-line no-console
  console.log(`%c[SecHub:${cat}]`, COLORS[cat] || 'color:#888', ...args)
}

export function dwarn(cat: string, ...args: any[]): void {
  if (!enabled()) return
  // eslint-disable-next-line no-console
  console.warn(`%c[SecHub:${cat}]`, COLORS.ERR, ...args)
}

export function derror(cat: string, ...args: any[]): void {
  // Errors always log even when disabled
  // eslint-disable-next-line no-console
  console.error(`%c[SecHub:${cat}]`, COLORS.ERR, ...args)
}

/** Wrap a lazy import so we log start / loaded ms / load error. */
export function debugLazy<T>(name: string, loader: () => Promise<T>): () => Promise<T> {
  return () => {
    const t0 = performance.now()
    dlog('Lazy', `chunk start: ${name}`)
    return loader()
      .then(mod => {
        const dt = (performance.now() - t0).toFixed(0)
        dlog('Lazy', `chunk loaded: ${name} (${dt}ms)`)
        return mod
      })
      .catch(err => {
        derror('Lazy', `chunk FAILED: ${name}`, err)
        throw err
      })
  }
}

/** Drop into a panel component to get uniform mount/unmount lifecycle logs.
 * Caller pattern:  `useEffect(() => trackPanelLifecycle('NewsPanel'), [])`
 * Returns the cleanup fn that logs the unmount line with mounted duration. */
export function trackPanelLifecycle(name: string): () => void {
  const t0 = performance.now()
  dlog('Panel', `mount   ${name}`)
  return () => {
    const dt = (performance.now() - t0).toFixed(0)
    dlog('Panel', `unmount ${name} (was mounted ${dt}ms)`)
  }
}

if (typeof window !== 'undefined') {
  ;(window as any).__sechubDebug = {
    enable: () => { localStorage.setItem('sechub.debug', '1'); location.reload() },
    disable: () => { localStorage.setItem('sechub.debug', '0'); location.reload() },
    status: () => enabled(),
  }
  if (enabled()) {
    // eslint-disable-next-line no-console
    console.log(
      '%c[SecHub] debug logging ON. Disable: __sechubDebug.disable()',
      'color:#fa3; font-weight:600',
    )
  }
}
