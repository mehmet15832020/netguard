'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { PieChart, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { ProtocolDonutChart } from '@/components/charts/ProtocolDonutChart'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

const COLOR_PALETTE = [
  '#6366f1', '#0ea5e9', '#10b981', '#f97316',
  '#eab308', '#ef4444', '#8b5cf6', '#ec4899',
]

export default function ProtocolDistributionPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['protocol-distribution', hours],
    queryFn:  () => analyticsApi.protocolDistribution(hours),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  })

  const isEmpty = !data || data.protocols.length === 0
  const topRows = data ? data.protocols.slice(0, 10) : []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <PieChart className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Protokol Dağılımı</h1>
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

      {/* Chart card */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-80 animate-pulse" />
      ) : isEmpty ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <EmptyState />
        </div>
      ) : (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <ProtocolDonutChart
            protocols={data!.protocols}
            total={data!.total}
            height={320}
          />
        </div>
      )}

      {/* Protocol table */}
      {!isLoading && !isEmpty && (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                <th className="text-left px-4 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                  Protokol
                </th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                  Sayı
                </th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                  Oran
                </th>
              </tr>
            </thead>
            <tbody>
              {topRows.map((item, i) => (
                <tr
                  key={item.protocol}
                  className="border-b border-zinc-800/50 hover:bg-zinc-800/50 transition-colors"
                >
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                        style={{ backgroundColor: COLOR_PALETTE[i % COLOR_PALETTE.length] }}
                      />
                      <span className="font-mono text-zinc-300 text-xs">
                        {item.protocol.toUpperCase()}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-right text-zinc-400 tabular-nums">
                    {item.count.toLocaleString('tr-TR')}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-16 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${item.pct}%`,
                            backgroundColor: COLOR_PALETTE[i % COLOR_PALETTE.length],
                          }}
                        />
                      </div>
                      <span className="text-zinc-400 tabular-nums w-12 text-right">
                        {item.pct.toFixed(1)}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Summary */}
      {data && (
        <p className="text-xs text-zinc-600 text-right">
          Son {hours} saatte {data.total.toLocaleString('tr-TR')} kayıt
        </p>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-zinc-600">
      <PieChart className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">Protokol Dağılımı</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
