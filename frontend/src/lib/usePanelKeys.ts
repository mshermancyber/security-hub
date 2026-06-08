import { useEffect, useState } from 'react'

/**
 * Keyboard-driven row navigation inside a panel.
 *
 *   j / ↓  → next row
 *   k / ↑  → previous row
 *   Enter  → onActivate(index)
 *   s      → onStar(index)
 *   a      → onAck(index)   — analyst dismiss / acknowledge
 *   n      → onNote(index)
 *
 * Returns the current selection index. The host renders a highlight on
 * the row that matches it. Keys are ignored when an input/textarea is
 * focused so typing in the filter doesn't move the cursor.
 */
export function usePanelKeys(
  count: number,
  opts: {
    onActivate?: (i: number) => void
    onStar?: (i: number) => void
    onAck?: (i: number) => void
    onNote?: (i: number) => void
    enabled?: boolean
  } = {},
) {
  const enabled = opts.enabled ?? true
  const [sel, setSel] = useState(0)

  useEffect(() => {
    if (sel >= count) setSel(Math.max(0, count - 1))
  }, [count, sel])

  useEffect(() => {
    if (!enabled) return
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase()
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return
      // Don't steal cmd/ctrl combos
      if (e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault(); setSel(s => Math.min(count - 1, s + 1)); return
      }
      if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault(); setSel(s => Math.max(0, s - 1)); return
      }
      if (e.key === 'Enter') {
        e.preventDefault(); opts.onActivate?.(sel); return
      }
      if (e.key === 's' && opts.onStar) {
        e.preventDefault(); opts.onStar(sel); return
      }
      if (e.key === 'a' && opts.onAck) {
        e.preventDefault(); opts.onAck(sel); return
      }
      if (e.key === 'n' && opts.onNote) {
        e.preventDefault(); opts.onNote(sel); return
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [count, sel, enabled, opts])

  return { sel, setSel }
}
