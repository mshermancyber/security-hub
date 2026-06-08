export function relTime(iso?: string | null): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = (Date.now() - t) / 1000
  if (diff < 60) return `${Math.max(0, Math.round(diff))}s`
  if (diff < 3600) return `${Math.round(diff / 60)}m`
  if (diff < 86400) return `${Math.round(diff / 3600)}h`
  if (diff < 86400 * 7) return `${Math.round(diff / 86400)}d`
  return `${Math.round(diff / 86400 / 7)}w`
}

export function fmtDate(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toISOString().slice(0, 16).replace('T', ' ') + 'Z'
}

export function priorityClass(p: number): string {
  if (p >= 85) return 'chip-red'
  if (p >= 70) return 'chip-amber'
  if (p >= 45) return 'chip-yellow'
  if (p >= 20) return 'chip-blue'
  return 'chip'
}

export function severityLabel(p: number): string {
  if (p >= 85) return 'CRIT'
  if (p >= 70) return 'HIGH'
  if (p >= 45) return 'ELEV'
  if (p >= 20) return 'GRD'
  return 'LOW'
}

export function tagClass(tag: string): string {
  switch (tag) {
    case 'zero-day':
    case 'active-exploitation':
    case 'breach': return 'chip-red'
    case 'ransomware':
    case 'supply-chain': return 'chip-amber'
    case 'nation-state':
    case 'phishing': return 'chip-purple'
    case 'vulnerability':
    case 'malware': return 'chip-yellow'
    case 'ai-incident': return 'chip-blue'
    case 'patch':
    case 'funding':
    case 'acquisition': return 'chip-green'
    default: return 'chip'
  }
}
