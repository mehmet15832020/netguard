'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { AlertVolumeChart } from '@/components/charts/AlertVolumeChart'
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

  const totalAlerts = useMemo(() => {
    if (!data) return 0
    return [...data.series.critical, ...data.series.high, ...data.series.warning, ...data.series.info]
      .reduce((sum, p) => sum + p.v, 0)
  }, [data])

  const isEmpty = !data || totalAlerts === 0

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Alert Hacmi</h1>
          {isFetching && (
            <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />
          )}
        </div>

        <div className="flex items-center gap-3">
          <div className="flex rounded-md overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={cn(
                  'px-3 py-1 text-xs',
                  hours === opt.value
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => refetch()}
            className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
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

      {/* Chart */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-64 animate-pulse" />
      ) : isEmpty ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <EmptyState />
        </div>
      ) : (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <AlertVolumeChart series={data!.series} hours={hours} bucketMinutes={data!.bucket_minutes} height={320} />
        </div>
      )}

      {/* Summary */}
      {data && (
        <p className="text-xs text-zinc-600 text-right">
          Son {hours} saatte {totalAlerts.toLocaleString('tr-TR')} alert
        </p>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-zinc-600">
      <Activity className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">Alert Hacmi</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
