import { useEffect, useRef, useState } from 'react'
import { wsBus } from '../api/ws'
import type { WSEvent } from '../api/ws'

export function useWSConnected(): boolean {
  const [c, setC] = useState(wsBus.connected)
  useEffect(() => wsBus.onConnectedChange(setC), [])
  return c
}

/** Subscribe to a single event type. Stable subscription — inline `handler`
 * functions don't churn the WS bus subscribers list every render. The latest
 * handler ref is invoked at dispatch time. */
export function useWSEvent<T extends WSEvent['type']>(
  type: T,
  handler: (e: Extract<WSEvent, { type: T }>) => void,
): void {
  const handlerRef = useRef(handler)
  useEffect(() => { handlerRef.current = handler }, [handler])
  useEffect(() => {
    return wsBus.subscribe((e) => {
      if (e.type === type) handlerRef.current(e as Extract<WSEvent, { type: T }>)
    })
  }, [type])
}

/** Count events of a given type since mount. Used for "N new" badges. */
export function useWSCounter(type: WSEvent['type']): { count: number; reset: () => void } {
  const [count, setCount] = useState(0)
  useEffect(() => wsBus.subscribe((e) => { if (e.type === type) setCount(n => n + 1) }), [type])
  return { count, reset: () => setCount(0) }
}
