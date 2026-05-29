import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'

interface MetricCardProps {
  title: string
  value: string | number
  unit?: string
  subtitle?: string
  icon: LucideIcon
  trend?: 'up' | 'down' | 'neutral'
  status?: 'ok' | 'warning' | 'critical'
}

const statusBorder: Record<string, string> = {
  ok:       'border-sky-900/20',
  warning:  'border-yellow-500/40',
  critical: 'border-red-500/40',
}

const iconBg: Record<string, string> = {
  ok:       'bg-sky-500/10 text-sky-400',
  warning:  'bg-yellow-500/10 text-yellow-400',
  critical: 'bg-red-500/10 text-red-400',
}

export function MetricCard({
  title,
  value,
  unit,
  subtitle,
  icon: Icon,
  status = 'ok',
}: MetricCardProps) {
  return (
    <div className={cn('bg-[#0a1120] border rounded-xl p-5', statusBorder[status])}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs text-slate-500 uppercase tracking-wider">{title}</p>
          <div className="flex items-baseline gap-1">
            <span className="text-2xl font-bold text-slate-100">{value}</span>
            {unit && <span className="text-sm text-slate-400">{unit}</span>}
          </div>
          {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
        </div>
        <div className={cn('p-2.5 rounded-lg', iconBg[status])}>
          <Icon size={18} />
        </div>
      </div>
    </div>
  )
}
