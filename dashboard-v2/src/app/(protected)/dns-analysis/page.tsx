'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe, RefreshCw } from 'lucide-react'
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

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`
}

export default function DnsAnalysisPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['dns-analysis', hours],
    queryFn:  () => analyticsApi.dnsAnalysis(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const volumeChartOption = data && data.hourly_volume.length > 0
    ? {
        backgroundColor: 'transparent',
        grid: { top: 16, right: 16, bottom: 32, left: 8, containLabel: true },
        xAxis: {
          type: 'category',
          data: data.hourly_volume.map((p) => fmtHour(p.t)),
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
            name: 'DNS Sorgu',
            type: 'line',
            smooth: true,
            areaStyle: { opacity: 0.3 },
            lineStyle: { width: 2 },
            color: '#6366f1',
            itemStyle: { color: '#6366f1' },
            data: data.hourly_volume.map((p) => p.v),
          },
        ],
      }
    : null

  const top10 = data?.top_domains.slice(0, 10) ?? []
  const barChartOption = top10.length > 0
    ? {
        backgroundColor: 'transparent',
        grid: { top: 8, right: 80, bottom: 8, left: 8, containLabel: true },
        xAxis: {
          type: 'value',
          axisLabel: { color: '#71717a', fontSize: 10 },
          axisLine: { show: false },
          splitLine: { lineStyle: { color: '#27272a' } },
        },
        yAxis: {
          type: 'category',
          data: top10.map((d) => d.ip).reverse(),
          axisLabel: {
            color: '#a1a1aa',
            fontSize: 10,
            width: 140,
            overflow: 'truncate',
          },
          axisLine: { show: false },
          splitLine: { show: false },
        },
        tooltip: {
          trigger: 'axis',
          backgroundColor: '#18181b',
          borderColor: '#3f3f46',
          textStyle: { color: '#f4f4f5', fontSize: 12 },
        },
        series: [
          {
            name: 'Sorgu Sayısı',
            type: 'bar',
            barMaxWidth: 20,
            color: '#6366f1',
            data: top10.map((d) => d.count).reverse(),
            label: {
              show: true,
              position: 'right',
              color: '#a1a1aa',
              fontSize: 10,
            },
          },
        ],
      }
    : null

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">DNS Analiz</h1>
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

      {/* Stat kartlar */}
      {isLoading ? (
        <div className="grid grid-cols-3 gap-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
          ))}
        </div>
      ) : data ? (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-xs text-zinc-500 mb-1">Benzersiz Domain</p>
            <p className="text-2xl font-bold text-zinc-100">
              {data.unique_domains.toLocaleString('tr-TR')}
            </p>
          </div>
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-xs text-zinc-500 mb-1">NXDOMAIN Sayısı</p>
            <p className="text-2xl font-bold text-orange-400">
              {data.nxdomain_count.toLocaleString('tr-TR')}
            </p>
          </div>
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-xs text-zinc-500 mb-1">NXDOMAIN Oranı</p>
            <p className="text-2xl font-bold text-red-400">
              {pct(data.nxdomain_rate)}
            </p>
          </div>
        </div>
      ) : null}

      {/* Saatlik hacim */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Saatlik DNS Sorgu Hacmi</h2>
        </div>
        {isLoading ? (
          <div className="h-52 animate-pulse bg-zinc-800/40 m-4 rounded" />
        ) : volumeChartOption ? (
          <div className="p-4">
            <ReactECharts option={volumeChartOption} style={{ height: 200 }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <Globe className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>

      {/* Top DNS server / domain */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Top Hedef DNS / Domain (İlk 10)</h2>
        </div>
        {isLoading ? (
          <div className="h-52 animate-pulse bg-zinc-800/40 m-4 rounded" />
        ) : barChartOption ? (
          <div className="p-4">
            <ReactECharts option={barChartOption} style={{ height: Math.max(160, top10.length * 28) }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>
    </div>
  )
}
