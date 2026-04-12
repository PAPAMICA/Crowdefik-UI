import { AlertTriangle } from 'lucide-react'
import { Link } from 'react-router-dom'

function scenarioColor(s: string): string {
  let hash = 0
  for (let i = 0; i < s.length; i++) hash = ((hash * 31) + s.charCodeAt(i)) >>> 0
  const colors = [
    'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    'border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300',
    'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300',
    'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    'border-pink-500/30 bg-pink-500/10 text-pink-700 dark:text-pink-300',
    'border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300',
    'border-teal-500/30 bg-teal-500/10 text-teal-700 dark:text-teal-300',
  ]
  return colors[hash % colors.length]
}

/** Derive a short human-readable label for WAF anomaly score strings */
function wafShortLabel(s: string): string {
  const lower = s.toLowerCase()
  const types: string[] = []
  const map: Record<string, string> = {
    xss: 'XSS',
    sql_injection: 'SQLi',
    lfi: 'LFI',
    rce: 'RCE',
    php_injection: 'PHP',
    http_violation: 'HTTP',
  }
  for (const [key, label] of Object.entries(map)) {
    if (new RegExp(`${key}:\\s*\\d+`).test(lower)) types.push(label)
  }
  return types.length ? `WAF · ${types.join('+')}` : 'WAF Block'
}

function scenarioLabel(s: string): string {
  if (s.toLowerCase().includes('anomaly score')) return wafShortLabel(s)
  return s.replace(/^crowdsecurity\//, '').replace(/^ltsich\//, '').replace(/^firehol\//, '').replace(/-/g, ' ')
}

type Props = {
  scenario: string
  /** Show the AlertTriangle icon (default: true) */
  icon?: boolean
  /** Extra className for the badge span */
  className?: string
}

/**
 * Displays a scenario as a colored badge that links to /scenarios/:scenario.
 * Stops click propagation so it works inside clickable table rows.
 */
export function ScenarioBadge({ scenario, icon = true, className = '' }: Props) {
  if (!scenario) return <span className="text-xs text-slate-400">—</span>
  const label = scenarioLabel(scenario)
  const color = scenarioColor(scenario)
  return (
    <Link
      to={`/scenarios/${encodeURIComponent(scenario)}`}
      onClick={(e) => e.stopPropagation()}
      title={scenario}
      className={`inline-flex max-w-[220px] items-center gap-1.5 truncate rounded-full border px-2.5 py-0.5 text-xs font-medium transition-opacity hover:opacity-80 ${color} ${className}`}
    >
      {icon && <AlertTriangle className="h-3 w-3 flex-shrink-0" />}
      <span className="truncate">{label || '—'}</span>
    </Link>
  )
}
