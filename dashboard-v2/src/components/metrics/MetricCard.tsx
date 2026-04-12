import { cn } from '@/lib/utils'
import { Card, CardContent } from '@/components/ui/card'
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

const statusRing: Record<string, string> = {
  ok:       'border-zinc-800',
  warning:  'border-yellow-700',
  critical: 'border-red-700',
}

const iconBg: Record<string, string> = {
  ok:       'bg-indigo-600/20 text-indigo-400',
  warning:  'bg-yellow-600/20 text-yellow-400',
  critical: 'bg-red-600/20 text-red-400',
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
    <Card className={cn('bg-zinc-900 border', statusRing[status])}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs text-zinc-500 uppercase tracking-wider">{title}</p>
            <div className="flex items-baseline gap-1">
              <span className="text-2xl font-bold text-zinc-100">{value}</span>
              {unit && <span className="text-sm text-zinc-400">{unit}</span>}
            </div>
            {subtitle && <p className="text-xs text-zinc-500">{subtitle}</p>}
          </div>
          <div className={cn('p-2.5 rounded-lg', iconBg[status])}>
            <Icon size={18} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
