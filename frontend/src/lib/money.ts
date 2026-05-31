export function fmtUSD(n?: number | null): string {
  if (n == null || !isFinite(n)) return '—'
  const abs = Math.abs(n)
  if (abs >= 1e12) return `$${(n / 1e12).toFixed(1)}T`
  if (abs >= 1e9)  return `$${(n / 1e9).toFixed(1)}B`
  if (abs >= 1e6)  return `$${(n / 1e6).toFixed(1)}M`
  if (abs >= 1e3)  return `$${(n / 1e3).toFixed(0)}K`
  return `$${n.toFixed(0)}`
}

export function fmtCount(n?: number | null): string {
  if (n == null) return '—'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toLocaleString()
}
