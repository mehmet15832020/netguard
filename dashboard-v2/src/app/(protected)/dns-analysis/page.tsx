'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe, RefreshCw, AlertTriangle, Activity, Search, Zap, Shield } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi, type DnsEvent } from '@/lib/api'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function fmtHour(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
}

function StatCard({
  label, value, sub, icon: Icon, colorClass,
}: {
  label: string
  value: number | string
  sub?: string
  icon: React.ElementType
  colorClass: string
}) {
  return (
    <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-start gap-3">
      <div className={`p-2 rounded-lg mt-0.5 ${colorClass}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-xs text-zinc-500">{label}</p>
        <p className="text-2xl font-bold text-zinc-100 leading-tight">{value}</p>
        {sub && <p className="text-xs text-zinc-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export default function DnsAnalysisPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['dns-analysis', hours],
    queryFn:  () => analyticsApi.dnsAnalysis(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  // ─── Saatlik hacim grafiği ─────────────────────────────────────────────────
  const volumeOption = data && data.hourly_volume.length > 0 ? {
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
      formatter: (p: { name: string; value: number }[]) =>
        `${p[0].name}<br/><b>${p[0].value}</b> DNS sorgusu`,
    },
    series: [{
      name: 'DNS Sorgu',
      type: 'line',
      smooth: true,
      areaStyle: { color: '#6366f1', opacity: 0.15 },
      lineStyle: { color: '#6366f1', width: 2 },
      itemStyle: { color: '#6366f1' },
      symbol: 'none',
      data: data.hourly_volume.map((p) => p.v),
    }],
  } : null

  // ─── Top hedefler bar grafiği ──────────────────────────────────────────────
  const top10 = data?.top_queried_destinations.slice(0, 10) ?? []
  const barOption = top10.length > 0 ? {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 64, bottom: 8, left: 8, containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#71717a', fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    yAxis: {
      type: 'category',
      data: [...top10].reverse().map((d) => d.ip),
      axisLabel: {
        color: '#a1a1aa', fontSize: 10,
        width: 130, overflow: 'truncate',
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
    series: [{
      name: 'Sorgu',
      type: 'bar',
      barMaxWidth: 18,
      color: '#6366f1',
      data: [...top10].reverse().map((d) => d.count),
      label: {
        show: true,
        position: 'right',
        color: '#a1a1aa',
        fontSize: 10,
      },
    }],
  } : null

  const isEmpty = !isLoading && !data?.hourly_volume.some((p) => p.v > 0)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">DNS Analiz</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-md overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={`px-3 py-1 text-xs font-medium transition-colors ${
                  hours === opt.value
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-900 text-zinc-400 hover:text-zinc-100'
                }`}
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

      {/* ─ Stat kartlar: 3 + 3 ── */}
      {isLoading ? (
        <div className="grid grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
          ))}
        </div>
      ) : data ? (
        <>
          {/* Satır 1: genel metrikler */}
          <div className="grid grid-cols-3 gap-4">
            <StatCard
              label="Benzersiz Hedef"
              value={data.unique_destinations.toLocaleString('tr-TR')}
              icon={Globe}
              colorClass="bg-indigo-500/15 text-indigo-400"
            />
            <StatCard
              label="NXDOMAIN Sayısı"
              value={data.nxdomain_count.toLocaleString('tr-TR')}
              sub={`Toplam sorgularının %${data.nxdomain_rate.toFixed(1)}'i`}
              icon={AlertTriangle}
              colorClass="bg-orange-500/15 text-orange-400"
            />
            <StatCard
              label="NXDOMAIN Oranı"
              value={`%${data.nxdomain_rate.toFixed(1)}`}
              icon={Activity}
              colorClass={data.nxdomain_rate > 20 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400'}
            />
          </div>

          {/* Satır 2: tehdit göstergeleri */}
          <div className="grid grid-cols-3 gap-4">
            <StatCard
              label="Yüksek Entropi Sorgu"
              value={data.high_entropy_count.toLocaleString('tr-TR')}
              sub="DNS tünel adayı"
              icon={Search}
              colorClass={data.high_entropy_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400'}
            />
            <StatCard
              label="Uzun Subdomain Sorgu"
              value={data.long_query_count.toLocaleString('tr-TR')}
              sub="Olası veri sızdırma"
              icon={Zap}
              colorClass={data.long_query_count > 0 ? 'bg-amber-500/15 text-amber-400' : 'bg-zinc-700/40 text-zinc-400'}
            />
            <StatCard
              label="DNS Flood Tespiti"
              value={data.anomaly_count.toLocaleString('tr-TR')}
              sub="dns_query_burst olayları"
              icon={AlertTriangle}
              colorClass={data.anomaly_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400'}
            />
          </div>
        </>
      ) : null}

      {/* ─ Saatlik hacim ── */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Saatlik DNS Sorgu Hacmi</h2>
        </div>
        {isLoading ? (
          <div className="h-52 m-4 rounded animate-pulse bg-zinc-800/40" />
        ) : volumeOption ? (
          <div className="p-4">
            <ReactECharts option={volumeOption} style={{ height: 200 }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <Globe className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Seçilen dönemde DNS sorgusu yok</p>
          </div>
        )}
      </div>

      {/* ─ Top hedefler ── */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-200">En Çok Sorgulanan Hedefler (İlk 10)</h2>
          {data && <span className="text-xs text-zinc-500">{data.unique_destinations} benzersiz hedef</span>}
        </div>
        {isLoading ? (
          <div className="h-52 m-4 rounded animate-pulse bg-zinc-800/40" />
        ) : barOption ? (
          <div className="p-4">
            <ReactECharts
              option={barOption}
              style={{ height: Math.max(160, top10.length * 28) }}
              notMerge
            />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-zinc-600">
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>

      {/* ─ Drill-down: şüpheli DNS olayları ── */}
      {data && (data.high_entropy_domains.length > 0 || data.long_query_domains.length > 0 || data.nxdomain_top_sources.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Yüksek entropi domainler */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-red-400" />
              <h2 className="text-sm font-semibold text-zinc-200">Yüksek Entropi Domain</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
                {data.high_entropy_count}
              </span>
            </div>
            {data.high_entropy_domains.length === 0 ? (
              <p className="text-xs text-zinc-600 text-center py-6">Tespit yok</p>
            ) : (
              <div className="divide-y divide-zinc-800">
                {data.high_entropy_domains.map((ev, i) => (
                  <DnsEventRow key={i} ev={ev} accent="text-red-300" />
                ))}
              </div>
            )}
          </div>

          {/* Uzun subdomain sorguları */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <h2 className="text-sm font-semibold text-zinc-200">Uzun Subdomain Sorgusu</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400">
                {data.long_query_count}
              </span>
            </div>
            {data.long_query_domains.length === 0 ? (
              <p className="text-xs text-zinc-600 text-center py-6">Tespit yok</p>
            ) : (
              <div className="divide-y divide-zinc-800">
                {data.long_query_domains.map((ev, i) => (
                  <DnsEventRow key={i} ev={ev} accent="text-amber-300" />
                ))}
              </div>
            )}
          </div>

          {/* NXDOMAIN üreten IP'ler */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 text-orange-400" />
              <h2 className="text-sm font-semibold text-zinc-200">NXDOMAIN Kaynakları</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400">
                {data.nxdomain_count}
              </span>
            </div>
            {data.nxdomain_top_sources.length === 0 ? (
              <p className="text-xs text-zinc-600 text-center py-6">Tespit yok</p>
            ) : (() => {
              const max = Math.max(...data.nxdomain_top_sources.map(s => s.count), 1)
              return (
                <div className="divide-y divide-zinc-800">
                  {data.nxdomain_top_sources.map((src, i) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono text-zinc-300">{src.ip}</span>
                        <span className="text-xs font-mono text-orange-400">{src.count}</span>
                      </div>
                      <div className="h-1 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-orange-500/60 rounded-full"
                          style={{ width: `${(src.count / max) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )
            })()}
          </div>
        </div>
      )}
    </div>
  )
}

function DnsEventRow({ ev, accent }: { ev: DnsEvent; accent: string }) {
  const ts = ev.timestamp
    ? new Date(ev.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'
  return (
    <div className="px-4 py-2.5 hover:bg-zinc-800/40 transition-colors">
      <p className={`text-xs font-mono truncate ${accent}`} title={ev.message}>{ev.message}</p>
      <div className="flex items-center justify-between mt-0.5">
        <span className="text-[10px] text-zinc-600 font-mono">{ev.source_ip ?? '—'}</span>
        <span className="text-[10px] text-zinc-700 font-mono">{ts}</span>
      </div>
    </div>
  )
}
