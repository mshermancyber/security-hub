type Props = {
  values: number[]
  width?: number
  height?: number
  color?: string
  fill?: string
  label?: string
}

export function Sparkline({ values, width = 160, height = 28, color = '#ff9f1c', fill = 'rgba(255,159,28,0.18)', label }: Props) {
  if (!values || values.length === 0) {
    return <span className="text-mute text-[10px]">—</span>
  }
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? width / (values.length - 1) : 0
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * (height - 2) - 1).toFixed(1)}`).join(' ')
  const area = `0,${height} ${points} ${width},${height}`
  return (
    <svg width={width} height={height} role="img" aria-label={label}>
      <polyline points={area} fill={fill} stroke="none" />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  )
}

export function BarSeries({ values, width = 200, height = 36, color = '#ff9f1c', label }: Props) {
  if (!values || values.length === 0) return <span className="text-mute text-[10px]">—</span>
  const max = Math.max(1, ...values)
  const bw = width / values.length
  return (
    <svg width={width} height={height} role="img" aria-label={label}>
      {values.map((v, i) => {
        const h = (v / max) * (height - 2)
        return <rect key={i} x={i * bw + 0.5} y={height - h - 1} width={Math.max(1, bw - 1)} height={h} fill={color} />
      })}
    </svg>
  )
}
