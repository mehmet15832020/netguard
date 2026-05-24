'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Grid2X2 } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { EastWestHeatmapChart } from '@/components/charts/EastWestHeatmapChart'

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Grid2X2 className="h-6 w-6 text-indigo-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">East-West Matrix</h1>
            <p className="text-sm text-zinc-400">İç ağ bağlantı yoğunluk haritası</p>
          </div>
        </div>
        <div className="flex gap-1">
          {HOUR_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setHours(o.value)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                hours === o.value
                  ? 'bg-indigo-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* Summary */}
      {data && (
        <div className="flex gap-6 text-sm text-zinc-400">
          <span><span className="text-zinc-200 font-medium">{data.unique_pairs}</span> benzersiz çift</span>
          <span>Maks: <span className="text-zinc-200 font-medium">{data.max_count.toLocaleString('tr-TR')}</span> bağlantı</span>
          <span>Son <span className="text-zinc-200 font-medium">{hours}s</span></span>
        </div>
      )}

      {/* Chart card */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        {isLoading && (
          <div className="h-96 animate-pulse bg-zinc-800 rounded" />
        )}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">
            Veri yüklenemedi
          </div>
        )}
        {data && data.rows.length === 0 && (
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-zinc-500">
            <Grid2X2 className="h-8 w-8 text-zinc-700" />
            <p className="text-sm">Bu zaman aralığında iç ağ bağlantısı bulunamadı</p>
          </div>
        )}
        {data && data.rows.length > 0 && (
          <EastWestHeatmapChart
            rows={data.rows}
            max_count={data.max_count}
            height={400}
          />
        )}
      </div>

      {/* Info */}
      <p className="text-xs text-zinc-600">
        Yalnızca RFC1918 kaynak → RFC1918 hedef trafiği gösterilir. Top {data?.unique_pairs ?? 20} çift.
      </p>
    </div>
  )
}
