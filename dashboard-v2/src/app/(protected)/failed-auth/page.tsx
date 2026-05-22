'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Lock, RefreshCw } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function fmtHour(iso: string): string {
  const d = new Date(iso)
  const hh = String(d.getUTCHours()).padStart(2, '0')
  return `${hh}:00`
}

export default function FailedAuthPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['failed-auth', hours],
    queryFn:  () => analyticsApi.failedAuth(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const chartOption = data && data.hourly.length > 0
    ? {
        backgroundColor: 'transparent',
        grid: { top: 16, right: 16, bottom: 32, left: 8, containLabel: true },
        xAxis: {
          type: 'category',
          data: data.hourly.map((p) => fmtHour(p.t)),
          axisLabel: { color: '#71717a', fontSize: 10 },
          axisLine: { lineStyle: { color: '#3f3f46' } },
          splitLine: { show: false },
        },
        yAxis: {
          type: 'value',
          minInterval: 1,
          axisLabel: { color: '#71717a', fontSize: 10 },
          axisLine: { show: false },
          splitLine: { lineStyle: { color: '#27272a' } },
        },
        tooltip: {
          trigger: 'axis',
          backgroundColor: '#18181b',
          borderColor: '#3f3f46',
          textStyle: { color: '#f4f4f5', fontSize: 12 },
        },
        series: [
          {
            name: 'Başarısız Giriş',
            type: 'line',
            smooth: true,
            areaStyle: { opacity: 0.3 },
            lineStyle: { width: 2 },
            color: '#ef4444',
            itemStyle: { color: '#ef4444' },
            data: data.hourly.map((p) => p.v),
          },
        ],
      }
    : null

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Lock className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Başarısız Kimlik Doğrulama</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
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

      {/* Error */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button onClick={() => refetch()} className="text-xs underline hover:text-red-300">
            Tekrar dene
          </button>
        </div>
      )}

      {/* Özet */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-16 animate-pulse" />
      ) : data ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
          <Lock className="w-6 h-6 text-red-400 flex-shrink-0" />
          <p className="text-sm text-zinc-300">
            Son{' '}
            <span className="font-semibold text-zinc-100">{hours}</span>{' '}
            saatte{' '}
            <span className="font-bold text-red-400 text-base">
              {data.total.toLocaleString('tr-TR')}
            </span>{' '}
            başarısız giriş denemesi
          </p>
        </div>
      ) : null}

      {/* Trend chart */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Saatlik Trend</h2>
        </div>
        {isLoading ? (
          <div className="h-52 animate-pulse bg-zinc-800/40 m-4 rounded" />
        ) : chartOption ? (
          <div className="p-4">
            <ReactECharts option={chartOption} style={{ height: 200 }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <Lock className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>

      {/* Top kaynak IP'ler */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Top Kaynak IP'ler</h2>
        </div>
        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : !data || data.top_sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <p className="text-sm">Veri yok</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">#</th>
                  <th className="text-left px-4 py-2.5 font-medium">IP Adresi</th>
                  <th className="text-left px-4 py-2.5 font-medium">Deneme Sayısı</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.top_sources.map((src, idx) => (
                  <tr key={src.ip} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="px-4 py-2.5 text-zinc-600 text-xs">{idx + 1}</td>
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{src.ip}</td>
                    <td className="px-4 py-2.5 text-red-400 font-semibold">
                      {src.count.toLocaleString('tr-TR')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
