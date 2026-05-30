'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Grid2X2, ArrowRight } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { EastWestHeatmapChart } from '@/components/charts/EastWestHeatmapChart'
import { Skeleton, SkeletonChart, SkeletonStatGrid } from '@/components/ui/skeleton'
import { CHART_COLORS } from '@/lib/echarts-theme'

const HOUR_OPTIONS = [
  { label: '6s',  value: 6   },
  { label: '24s', value: 24  },
  { label: '48s', value: 48  },
  { label: '7g',  value: 168 },
]

export default function EastWestMatrixPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['analytics', 'east-west-matrix', hours],
    queryFn:  () => analyticsApi.eastWestMatrix(hours),
    staleTime: 60_000,
  })

  const topPairs = useMemo(() =>
    [...(data?.rows ?? [])].sort((a, b) => b.count - a.count).slice(0, 10),
  [data])

  const maxPairCount = topPairs[0]?.count ?? 1

  const uniqueSources = useMemo(() =>
    new Set((data?.rows ?? []).map(r => r.src)).size,
  [data])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Grid2X2 className="h-5 w-5 text-sky-400" />
          <div>
            <h1 className="text-xl font-semibold text-slate-100">East-West Matrix</h1>
            <p className="text-sm text-slate-400">İç ağ bağlantı yoğunluk haritası (RFC1918→RFC1918)</p>
          </div>
        </div>
        <div className="flex gap-1">
          {HOUR_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setHours(o.value)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                hours === o.value
                  ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                  : 'bg-sky-950/20 text-slate-400 border border-sky-900/20 hover:border-sky-700/40 hover:text-slate-300'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* KPI Cards */}
      {isLoading ? (
        <SkeletonStatGrid cols={3} height={80} />
      ) : (
        <div className="grid grid-cols-3 gap-4">
          <div className="panel-cyber p-4">
            <p className="text-xs text-slate-500 mb-1">Benzersiz Çift</p>
            <p className="text-2xl font-bold text-slate-100">{(data?.unique_pairs ?? 0).toLocaleString()}</p>
            <p className="text-xs text-slate-600 mt-0.5">src→dst kombinasyonu</p>
          </div>
          <div className="panel-cyber p-4">
            <p className="text-xs text-slate-500 mb-1">Maks Bağlantı</p>
            <p className="text-2xl font-bold text-sky-400">{(data?.max_count ?? 0).toLocaleString()}</p>
            <p className="text-xs text-slate-600 mt-0.5">tek çiftte en yüksek</p>
          </div>
          <div className="panel-cyber p-4">
            <p className="text-xs text-slate-500 mb-1">Aktif Kaynak</p>
            <p className="text-2xl font-bold text-slate-100">{uniqueSources.toLocaleString()}</p>
            <p className="text-xs text-slate-600 mt-0.5">iç ağ bağlantısı başlatan IP</p>
          </div>
        </div>
      )}

      {/* Heatmap */}
      <div className="panel-cyber p-4">
        {isLoading && <SkeletonChart height={400} />}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">Veri yüklenemedi</div>
        )}
        {data && data.rows.length === 0 && (
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-slate-500">
            <Grid2X2 className="h-8 w-8 text-slate-700" />
            <p className="text-sm">Bu zaman aralığında iç ağ bağlantısı bulunamadı</p>
          </div>
        )}
        {data && data.rows.length > 0 && (
          <EastWestHeatmapChart rows={data.rows} max_count={data.max_count} height={400} />
        )}
      </div>

      {/* Top Pairs Table */}
      {isLoading && <Skeleton className="h-72 w-full" />}
      {!isLoading && topPairs.length > 0 && (
        <div className="panel-cyber overflow-hidden">
          <div className="ui-panel-header">
            <h2 className="text-sm font-semibold text-slate-200">En Yoğun Bağlantı Çiftleri (İlk 10)</h2>
          </div>
          <div className="divide-y divide-sky-900/15">
            {topPairs.map((row, i) => (
              <div key={`${row.src}-${row.dst}`} className="px-4 py-2.5 hover:bg-sky-950/20 transition-colors">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-xs text-slate-600 w-5 text-right flex-shrink-0">{i + 1}</span>
                    <span className="font-mono text-xs text-slate-300">{row.src}</span>
                    <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" />
                    <span className="font-mono text-xs text-slate-300">{row.dst}</span>
                  </div>
                  <span className="text-xs font-mono text-sky-400 ml-2 flex-shrink-0">
                    {row.count.toLocaleString()}
                  </span>
                </div>
                <div className="ml-7 h-1 bg-sky-950/40 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(row.count / maxPairCount) * 100}%`,
                      background: CHART_COLORS.cyber,
                      opacity: 0.5,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <p className="text-xs text-slate-600">
        Yalnızca RFC1918 kaynak → RFC1918 hedef trafiği. Top {data?.unique_pairs ?? 20} çift heatmap'te gösterilir.
      </p>
    </div>
  )
}
