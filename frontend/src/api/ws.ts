/**
 * WebSocket bus — singleton connection to /api/ws with exponential backoff,
 * a pub/sub interface for components, and a small ring of recent events for
 * panels that mount after the message has arrived.
 */
import { dlog } from '../lib/debug'

export type WSEvent =
  | { type: 'hello'; at: string; server?: string; clients?: number }
  | { type: 'heartbeat'; at: string }
  | { type: 'pong'; at?: string }
  | { type: 'news.batch'; at: string; count: number; top: SlimNews[] }
  | { type: 'news.item';  at: string; item: SlimNews }
  | { type: 'kev.batch';  at: string; count: number; top: SlimCVE[] }
  | { type: 'nvd.batch';  at: string; count: number; top: SlimCVE[] }
  | { type: 'org.alert';  at: string; org: string; org_name: string; reason: string; item: SlimNews }
  | { type: 'status';     at: string; counts: Record<string, number>; feeds_ok: number }
  | { type: 'feed.stale'; at: string; feed: string; name?: string; hours_stale?: number; last_success?: string | null; last_error?: string | null }
  | { type: 'feed.recovered'; at: string; feed: string }

export type SlimNews = {
  id: string; title: string; url: string; source_name: string
  priority: number; severity: number
  tags: string[]; cves: string[]
  published_at: string
  entities?: { vendors?: string[]; orgs?: string[]; threat_actors?: string[] }
}

export type SlimCVE = {
  cve_id: string; description?: string
  cvss_score?: number | null; is_kev?: number
  kev_added?: string | null; kev_ransomware?: string | null
  priority?: number
}

type Listener = (e: WSEvent) => void

class WSBus {
  private ws: WebSocket | null = null
  private listeners = new Set<Listener>()
  private connectedListeners = new Set<(connected: boolean) => void>()
  private backoff = 500
  private maxBackoff = 15000
  private reconnectTimer: number | null = null
  private pingTimer: number | null = null
  private _connected = false
  recent: WSEvent[] = []  // last ~50 events for late-mounting panels

  constructor() {
    if (typeof window !== 'undefined') this.connect()
  }

  private url(): string {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}/api/ws`
  }

  private setConnected(b: boolean) {
    if (this._connected !== b) {
      this._connected = b
      this.connectedListeners.forEach(l => { try { l(b) } catch {} })
    }
  }

  get connected(): boolean { return this._connected }

  connect() {
    if (this.ws && this.ws.readyState <= 1) return
    if (this.reconnectTimer != null) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null }
    let ws: WebSocket
    try {
      ws = new WebSocket(this.url())
    } catch {
      this.scheduleReconnect()
      return
    }
    this.ws = ws
    dlog('WS', `connect → ${this.url()}`)
    ws.onopen = () => {
      this.backoff = 500
      this.setConnected(true)
      this.startPing()
      dlog('WS', 'open')
    }
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data) as WSEvent
        this.recent.push(data)
        if (this.recent.length > 50) this.recent.shift()
        dlog('WS', `event ${data.type}`, data)
        this.listeners.forEach(l => { try { l(data) } catch {} })
      } catch (err) {
        dlog('WS', 'parse error', err, ev.data)
      }
    }
    ws.onclose = (ev) => {
      this.setConnected(false)
      this.stopPing()
      dlog('WS', `close code=${ev.code} reason="${ev.reason}" — reconnect in ${this.backoff}ms`)
      this.scheduleReconnect()
    }
    ws.onerror = (e) => { dlog('WS', 'error', e) /* close will fire */ }
  }

  private scheduleReconnect() {
    this.backoff = Math.min(this.maxBackoff, Math.max(500, this.backoff * 2))
    this.reconnectTimer = window.setTimeout(() => this.connect(), this.backoff)
  }

  private startPing() {
    this.stopPing()
    this.pingTimer = window.setInterval(() => {
      try { this.ws?.send(JSON.stringify({ type: 'ping' })) } catch {}
    }, 30000)
  }

  private stopPing() {
    if (this.pingTimer != null) { clearInterval(this.pingTimer); this.pingTimer = null }
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => { this.listeners.delete(listener) }
  }

  onConnectedChange(listener: (connected: boolean) => void): () => void {
    this.connectedListeners.add(listener)
    listener(this._connected)
    return () => { this.connectedListeners.delete(listener) }
  }
}

export const wsBus = new WSBus()
