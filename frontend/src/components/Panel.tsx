import type { ReactNode } from 'react'

type Props = {
  code: string                  // e.g. "NEWS", "VULN", "KEV"
  title: string
  right?: ReactNode
  children: ReactNode
  hotkey?: string
  className?: string
}

export function Panel({ code, title, right, children, hotkey, className = '' }: Props) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-header">
        <span className="text-amber font-semibold">{code}</span>
        <span className="text-mute/70">›</span>
        <span className="text-mute">{title}</span>
        <div className="ml-auto flex items-center gap-2 normal-case tracking-normal">
          {right}
          {hotkey && <span className="kbd">{hotkey}</span>}
        </div>
      </header>
      <div className="panel-body">{children}</div>
    </section>
  )
}
