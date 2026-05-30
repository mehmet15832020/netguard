'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, RefreshCw, ShieldAlert, AlertTriangle, Bell, Info } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { AlertVolumeChart } from '@/components/charts/AlertVolumeChart'
import { SkeletonChart } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

export default function AlertVolumePage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['alert-volume', hours],
    queryFn:  () => analyticsApi.alertVolume(hours),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  })

  const { totalAlerts, criticalCount, highCount, warningCount, infoCount } = useMemo(() => {
    if (!data) return { totalAlerts: 0, criticalCount: 0, highCount: 0, warningCount: 0, infoCount: 0 }
    const sum = (arr: { v: number }[]) => arr.reduce((s, p) => s + p.v, 0)
    return {
      totalAlerts:   sum(data.series.critical) + sum(data.series.high) + sum(data.series.warning) + sum(data.series.info),
      criticalCount: sum(data.series.critical),
      highCount:     sum(data.series.high),
      warningCount:  sum(data.series.warning),
      infoCount:     sum(data.series.info),
    }
  }, [data])

  const isEmpty = !data || totalAlerts === 0

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">Alert Hacmi</h1>
          {isFetching && (
            <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />
          )}
        </div>

        <div className="flex items-center gap-3">
          <div className="flex gap-1">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={cn(
                  'px-2 py-0.5 text-xs rounded-lg border',
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-sky-950/30 border border-sky-900/20 transition-colors"
            title="Yenile"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button
            onClick={() => refetch()}
            className="text-xs underline hover:text-red-300"
          >
            Tekrar dene
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className={cn(
          'rounded-xl border p-4',
          criticalCount > 0 ? 'bg-red-950/20 border-red-800/60' : 'bg-[#0a1120] border-sky-900/20'
        )}>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className={cn('w-4 h-4 flex-shrink-0', criticalCount > 0 ? 'text-red-400' : 'text-slate-500')} />
            <p className="text-xs text-slate-500">Critical</p>
          </div>
          <p className={cn('text-2xl font-bold tabular-nums', criticalCount > 0 ? 'text-red-400' : 'text-slate-100')}>
            {isLoading ? '—' : criticalCount.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">acil müdahale gerektirir</p>
        </div>
        <div className={cn(
          'rounded-xl border p-4',
          highCount > 0 ? 'bg-orange-950/20 border-orange-800/60' : 'bg-[#0a1120] border-sky-900/20'
        )}>
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className={cn('w-4 h-4 flex-shrink-0', highCount > 0 ? 'text-orange-400' : 'text-slate-500')} />
            <p className="text-xs text-slate-500">High</p>
          </div>
          <p className={cn('text-2xl font-bold tabular-nums', highCount > 0 ? 'text-orange-400' : 'text-slate-100')}>
            {isLoading ? '—' : highCount.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">öncelikli inceleme</p>
        </div>
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-1">
            <Bell className="w-4 h-4 text-yellow-400 flex-shrink-0" />
            <p className="text-xs text-slate-500">Warning</p>
          </div>
          <p className="text-2xl font-bold text-yellow-400 tabular-nums">
            {isLoading ? '—' : warningCount.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">izleme gerektirir</p>
        </div>
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-1">
            <Info className="w-4 h-4 text-blue-400 flex-shrink-0" />
            <p className="text-xs text-slate-500">Info</p>
          </div>
          <p className="text-2xl font-bold text-blue-400 tabular-nums">
            {isLoading ? '—' : infoCount.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">bilgi amaçlı</p>
        </div>
      </div>

      {/* Chart */}
      {isLoading ? (
        <SkeletonChart height={256} className="rounded-xl" />
      ) : isEmpty ? (
        <div className="ui-panel p-4">
          <EmptyState />
        </div>
      ) : (
        <div className="ui-panel p-4">
          <AlertVolumeChart series={data!.series} hours={hours} bucketMinutes={data!.bucket_minutes} height={320} />
        </div>
      )}

      {/* Summary */}
      {data && (
        <p className="text-xs text-slate-600 text-right">
          Son {hours} saatte {totalAlerts.toLocaleString('tr-TR')} alert
        </p>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-slate-600">
      <Activity className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">Alert Hacmi</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
