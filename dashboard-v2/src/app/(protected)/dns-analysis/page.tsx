'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe, RefreshCw, AlertTriangle, Activity, Search, Zap, Shield } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi, type DnsEvent } from '@/lib/api'
import { TOOLTIP_BASE, CHART_COLORS } from '@/lib/echarts-theme'
import { SkeletonStatGrid, SkeletonChart } from '@/components/ui/skeleton'

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
    <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-start gap-3">
      <div className={`p-2 rounded-lg mt-0.5 ${colorClass}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <p className="text-3xl font-bold leading-none text-slate-100">{value}</p>
        {sub && <p className="text-xs text-slate-500 mt-0.5">{sub}</p>}
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
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
      formatter: (p: { name: string; value: number }[]) =>
        `${p[0].name}<br/><b>${p[0].value}</b> DNS sorgusu`,
    },
    series: [{
      name: 'DNS Sorgu',
      type: 'line',
      smooth: true,
      areaStyle: { color: CHART_COLORS.cyber, opacity: 0.15 },
      lineStyle: { color: CHART_COLORS.cyber, width: 2 },
      itemStyle: { color: CHART_COLORS.cyber },
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
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category',
      data: [...top10].reverse().map((d) => d.ip),
      axisLabel: {
        color: '#64748b', fontSize: 10,
        width: 130, overflow: 'truncate',
      },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
    },
    series: [{
      name: 'Sorgu',
      type: 'bar',
      barMaxWidth: 18,
      color: CHART_COLORS.cyber,
      data: [...top10].reverse().map((d) => d.count),
      label: {
        show: true,
        position: 'right',
        color: '#64748b',
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
          <Globe className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">DNS Analiz</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={`px-2 py-0.5 text-xs font-medium transition-colors rounded-lg border ${
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300'
                }`}
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
        <SkeletonStatGrid cols={3} rows={2} height={80} />
      ) : data ? (
        <>
          {/* Satır 1: genel metrikler */}
          <div className="grid grid-cols-3 gap-4">
            <StatCard
              label="Benzersiz Hedef"
              value={data.unique_destinations.toLocaleString('tr-TR')}
              icon={Globe}
              colorClass="bg-sky-500/15 text-sky-400"
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
              colorClass={data.nxdomain_rate > 20 ? 'bg-red-500/15 text-red-400' : 'bg-sky-950/20 text-slate-400'}
            />
          </div>

          {/* Satır 2: tehdit göstergeleri */}
          <div className="grid grid-cols-3 gap-4">
            <StatCard
              label="Yüksek Entropi Sorgu"
              value={data.high_entropy_count.toLocaleString('tr-TR')}
              sub="DNS tünel adayı"
              icon={Search}
              colorClass={data.high_entropy_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-sky-950/20 text-slate-400'}
            />
            <StatCard
              label="Uzun Subdomain Sorgu"
              value={data.long_query_count.toLocaleString('tr-TR')}
              sub="Olası veri sızdırma"
              icon={Zap}
              colorClass={data.long_query_count > 0 ? 'bg-amber-500/15 text-amber-400' : 'bg-sky-950/20 text-slate-400'}
            />
            <StatCard
              label="DNS Flood Tespiti"
              value={data.anomaly_count.toLocaleString('tr-TR')}
              sub="dns_query_burst olayları"
              icon={AlertTriangle}
              colorClass={data.anomaly_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-sky-950/20 text-slate-400'}
            />
          </div>
        </>
      ) : null}

      {/* ─ Saatlik hacim ── */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <h2 className="text-sm font-semibold text-slate-200">Saatlik DNS Sorgu Hacmi</h2>
        </div>
        {isLoading ? (
          <SkeletonChart height={208} className="m-4" />
        ) : volumeOption ? (
          <div className="p-4">
            <ReactECharts option={volumeOption} style={{ height: 200 }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600">
            <Globe className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Seçilen dönemde DNS sorgusu yok</p>
          </div>
        )}
      </div>

      {/* ─ Top hedefler ── */}
      <div className="ui-panel">
        <div className="ui-panel-header justify-between">
          <h2 className="text-sm font-semibold text-slate-200">En Çok Sorgulanan Hedefler (İlk 10)</h2>
          {data && <span className="text-xs text-slate-500">{data.unique_destinations} benzersiz hedef</span>}
        </div>
        {isLoading ? (
          <SkeletonChart height={208} className="m-4" />
        ) : barOption ? (
          <div className="p-4">
            <ReactECharts
              option={barOption}
              style={{ height: Math.max(160, top10.length * 28) }}
              notMerge
            />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600">
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>

      {/* ─ Drill-down: şüpheli DNS olayları ── */}
      {data && (data.high_entropy_domains.length > 0 || data.long_query_domains.length > 0 || data.nxdomain_top_sources.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Yüksek entropi domainler */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="ui-panel-header">
              <Search className="w-3.5 h-3.5 text-red-400" />
              <h2 className="text-sm font-semibold text-slate-200">Yüksek Entropi Domain</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
                {data.high_entropy_count}
              </span>
            </div>
            {data.high_entropy_domains.length === 0 ? (
              <p className="text-xs text-slate-600 text-center py-6">Tespit yok</p>
            ) : (
              <div className="divide-y divide-sky-900/20">
                {data.high_entropy_domains.map((ev, i) => (
                  <DnsEventRow key={i} ev={ev} accent="text-red-300" />
                ))}
              </div>
            )}
          </div>

          {/* Uzun subdomain sorguları */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="ui-panel-header">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <h2 className="text-sm font-semibold text-slate-200">Uzun Subdomain Sorgusu</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400">
                {data.long_query_count}
              </span>
            </div>
            {data.long_query_domains.length === 0 ? (
              <p className="text-xs text-slate-600 text-center py-6">Tespit yok</p>
            ) : (
              <div className="divide-y divide-sky-900/20">
                {data.long_query_domains.map((ev, i) => (
                  <DnsEventRow key={i} ev={ev} accent="text-amber-300" />
                ))}
              </div>
            )}
          </div>

          {/* NXDOMAIN üreten IP'ler */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 lg:col-span-1">
            <div className="ui-panel-header">
              <Shield className="w-3.5 h-3.5 text-orange-400" />
              <h2 className="text-sm font-semibold text-slate-200">NXDOMAIN Kaynakları</h2>
              <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400">
                {data.nxdomain_count}
              </span>
            </div>
            {data.nxdomain_top_sources.length === 0 ? (
              <p className="text-xs text-slate-600 text-center py-6">Tespit yok</p>
            ) : (() => {
              const max = Math.max(...data.nxdomain_top_sources.map(s => s.count), 1)
              return (
                <div className="divide-y divide-sky-900/20">
                  {data.nxdomain_top_sources.map((src, i) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono text-slate-300">{src.ip}</span>
                        <span className="text-xs font-mono text-orange-400">{src.count}</span>
                      </div>
                      <div className="h-1 bg-sky-950/30 rounded-full overflow-hidden">
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
    <div className="px-4 py-2.5 hover:bg-sky-950/20 transition-colors">
      <p className={`text-xs font-mono truncate ${accent}`} title={ev.message}>{ev.message}</p>
      <div className="flex items-center justify-between mt-0.5">
        <span className="text-[10px] text-slate-600 font-mono">{ev.source_ip ?? '—'}</span>
        <span className="text-[10px] text-slate-700 font-mono">{ts}</span>
      </div>
    </div>
  )
}
