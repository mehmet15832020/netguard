'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { TrendingUp, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { TrafficVolumeChart } from '@/components/charts/TrafficVolumeChart'
import { SkeletonChart } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

export default function TrafficVolumePage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['traffic-volume', hours],
    queryFn:  () => analyticsApi.trafficVolume(hours),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  })

  const isEmpty =
    !data ||
    (data.series.east_west.every((p) => p.v === 0) &&
      data.series.ns_egress.every((p) => p.v === 0) &&
      data.series.ns_ingress.every((p) => p.v === 0))

  const { totalEastWest, totalNsEgress, totalNsIngress } = useMemo(() => {
    if (!data) return { totalEastWest: 0, totalNsEgress: 0, totalNsIngress: 0 }
    return {
      totalEastWest:  data.series.east_west.reduce((sum, p) => sum + p.v, 0),
      totalNsEgress:  data.series.ns_egress.reduce((sum, p) => sum + p.v, 0),
      totalNsIngress: data.series.ns_ingress.reduce((sum, p) => sum + p.v, 0),
    }
  }, [data])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <TrendingUp className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">Trafik Hacmi</h1>
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
                  'px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-lg border border-sky-900/20 text-slate-400 hover:text-slate-100 hover:bg-sky-950/30 transition-colors"
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
      <div className="grid grid-cols-3 gap-4">
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-500 flex-shrink-0" />
            <p className="text-xs text-slate-500">İç ↔ İç (East-West)</p>
          </div>
          <p className="text-3xl font-bold leading-none text-slate-100">
            {isLoading ? '—' : totalEastWest.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">lateral hareket riski</p>
        </div>
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500 flex-shrink-0" />
            <p className="text-xs text-slate-500">İç → Dış (Egress)</p>
          </div>
          <p className="text-3xl font-bold leading-none text-orange-400">
            {isLoading ? '—' : totalNsEgress.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">veri sızdırma riski</p>
        </div>
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 flex-shrink-0" />
            <p className="text-xs text-slate-500">Dış → İç (Ingress)</p>
          </div>
          <p className="text-3xl font-bold leading-none text-red-400">
            {isLoading ? '—' : totalNsIngress.toLocaleString('tr-TR')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">dış kaynaklı trafik</p>
        </div>
      </div>

      {/* Chart */}
      {isLoading ? (
        <SkeletonChart height={320} className="rounded-xl" />
      ) : isEmpty ? (
        <div className="ui-panel p-4">
          <EmptyState />
        </div>
      ) : (
        <div className="ui-panel p-4">
          <TrafficVolumeChart series={data!.series} hours={hours} height={320} />
        </div>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-slate-600">
      <TrendingUp className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">Trafik Hacmi</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
