import { cn } from '@/lib/utils'
import type { Severity } from '@/types/models'

const styles: Record<Severity, string> = {
  info:     'bg-blue-900/40 text-blue-300 border border-blue-800',
  warning:  'bg-yellow-900/40 text-yellow-300 border border-yellow-800',
  high:     'bg-orange-900/40 text-orange-300 border border-orange-800',
  critical: 'bg-red-900/40 text-red-300 border border-red-800',
}

const labels: Record<Severity, string> = {
  info:     'Bilgi',
  warning:  'Uyarı',
  high:     'Yüksek',
  critical: 'Kritik',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', styles[severity])}>
      {labels[severity]}
    </span>
  )
}
