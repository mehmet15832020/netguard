import { cn } from '@/lib/utils'
import type { Severity } from '@/types/models'

const styles: Record<Severity, string> = {
  critical: [
    'bg-red-500/10 border border-red-500/30 text-red-400',
    'shadow-[0_0_10px_rgba(239,68,68,0.12),inset_0_1px_0_rgba(255,255,255,0.05)]',
    'backdrop-blur-sm',
  ].join(' '),
  high: [
    'bg-orange-500/10 border border-orange-500/30 text-orange-400',
    'shadow-[0_0_10px_rgba(249,115,22,0.12),inset_0_1px_0_rgba(255,255,255,0.05)]',
    'backdrop-blur-sm',
  ].join(' '),
  warning: [
    'bg-yellow-500/10 border border-yellow-500/25 text-yellow-400',
    'shadow-[0_0_8px_rgba(234,179,8,0.1),inset_0_1px_0_rgba(255,255,255,0.04)]',
    'backdrop-blur-sm',
  ].join(' '),
  info: [
    'bg-blue-500/10 border border-blue-500/25 text-blue-400',
    'shadow-[0_0_8px_rgba(59,130,246,0.1),inset_0_1px_0_rgba(255,255,255,0.04)]',
    'backdrop-blur-sm',
  ].join(' '),
}

const dots: Record<Severity, string> = {
  critical: 'bg-red-400 shadow-[0_0_4px_rgba(239,68,68,0.8)]',
  high:     'bg-orange-400 shadow-[0_0_4px_rgba(249,115,22,0.7)]',
  warning:  'bg-yellow-400',
  info:     'bg-blue-400',
}

const labels: Record<Severity, string> = {
  info:     'Bilgi',
  warning:  'Uyarı',
  high:     'Yüksek',
  critical: 'Kritik',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium',
      styles[severity],
    )}>
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', dots[severity])} />
      {labels[severity]}
    </span>
  )
}
