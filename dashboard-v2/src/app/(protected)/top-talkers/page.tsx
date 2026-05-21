'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BarChart2, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { TopTalkersChart } from '@/components/charts/TopTalkersChart'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

const LIMIT_OPTIONS = [10, 20]

export default function TopTalkersPage() {
  const [hours, setHours]   = useState(24)
  const [limit, setLimit]   = useState(10)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['top-talkers', hours, limit],
    queryFn:  () => analyticsApi.topTalkers(hours, limit),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const sources = (data?.top_sources      ?? []).map((d) => ({ label: d.ip,           count: d.count }))
  const dests   = (data?.top_destinations ?? []).map((d) => ({ label: d.ip,           count: d.count }))
  const ports   = (data?.top_dst_ports    ?? []).map((d) => ({ label: String(d.port), count: d.count }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <BarChart2 className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Top Talkers</h1>
          {isFetching && (
            <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />
          )}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* Limit */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-zinc-500">Limit</span>
            <div className="flex rounded-md overflow-hidden border border-zinc-700">
              {LIMIT_OPTIONS.map((l) => (
                <button
                  key={l}
                  onClick={() => setLimit(l)}
                  className={cn(
                    'px-3 py-1 text-xs',
                    limit === l
                      ? 'bg-indigo-600 text-white'
                      : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700',
                  )}
                >
                  {l}
                </button>
              ))}
            </div>
          </div>

          {/* Time range */}
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

      {/* Charts grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 h-64 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            {sources.length > 0 ? (
              <TopTalkersChart
                title="Top Kaynak IP"
                items={sources}
                color="#6366f1"
                height={limit * 28 + 40}
              />
            ) : (
              <EmptyState label="Top Kaynak IP" />
            )}
          </div>

          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            {dests.length > 0 ? (
              <TopTalkersChart
                title="Top Hedef IP"
                items={dests}
                color="#0ea5e9"
                height={limit * 28 + 40}
              />
            ) : (
              <EmptyState label="Top Hedef IP" />
            )}
          </div>

          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            {ports.length > 0 ? (
              <TopTalkersChart
                title="Top Hedef Port"
                items={ports}
                color="#10b981"
                height={limit * 28 + 40}
              />
            ) : (
              <EmptyState label="Top Hedef Port" />
            )}
          </div>
        </div>
      )}

      {/* Summary row */}
      {data && (
        <p className="text-xs text-zinc-600 text-right">
          Son {hours} saatte {data.top_sources.length} kaynak · {data.top_destinations.length} hedef · {data.top_dst_ports.length} port
        </p>
      )}
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-zinc-600">
      <BarChart2 className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">{label}</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
