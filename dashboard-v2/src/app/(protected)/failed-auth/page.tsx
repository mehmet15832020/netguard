'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Lock, RefreshCw, TrendingUp, TrendingDown, Minus, Clock, Globe, Users, ShieldAlert } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import { SkeletonStatGrid, SkeletonChart, SkeletonTable } from '@/components/ui/skeleton'
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

  // KPI hesapları
  const kpis = useMemo(() => {
    if (!data || data.hourly.length === 0) return null
    const avgPerHour = data.total / Math.max(1, data.hourly.length)
    const byHour = Array(24).fill(0)
    data.hourly.forEach(p => { byHour[new Date(p.t).getHours()] += p.v })
    const peakHour = byHour.indexOf(Math.max(...byHour))
    const mid = Math.floor(data.hourly.length / 2)
    const firstAvg = data.hourly.slice(0, mid).reduce((s, p) => s + p.v, 0) / Math.max(1, mid)
    const secondAvg = data.hourly.slice(mid).reduce((s, p) => s + p.v, 0) / Math.max(1, data.hourly.length - mid)
    const trend = secondAvg > firstAvg * 1.15 ? 'up' : secondAvg < firstAvg * 0.85 ? 'down' : 'stable'
    return { avgPerHour, peakHour, trend, byHour }
  }, [data])

  // Saldırı sınıflandırması (MITRE T1110 alt-teknikler)
  const attackType = useMemo(() => {
    if (!data || data.total === 0) return null
    const unique = data.unique_source_count
    const ext = data.external_source_count
    const avgHr = data.total / Math.max(1, hours)
    if (unique >= 5 && avgHr < 20)
      return { label: 'Password Spraying', desc: 'Çok IP, düşük hız — T1110.003', color: 'text-orange-400', border: 'border-orange-800/60', bg: 'bg-orange-950/20' }
    if (ext >= 3)
      return { label: 'Credential Stuffing', desc: 'Dış kaynaklı, çok IP — T1110.004', color: 'text-red-400', border: 'border-red-800/60', bg: 'bg-red-950/20' }
    if (avgHr >= 10)
      return { label: 'Brute Force', desc: 'Yüksek hız, tek kaynak — T1110.001', color: 'text-red-400', border: 'border-red-800/60', bg: 'bg-red-950/20' }
    return { label: 'Düşük Yoğunluk', desc: 'Normal seviye — izle', color: 'text-slate-400', border: 'border-sky-900/20', bg: 'bg-[#0a1120]' }
  }, [data, hours])

  // NIST eşik durumu
  const nistStatus = useMemo(() => {
    if (!data) return null
    const maxHourly = Math.max(0, ...data.hourly.map(p => p.v))
    if (maxHourly >= 50) return { level: 'critical', label: '≥50/saat — Kritik (NIST SP 800-63B)', color: 'text-red-400' }
    if (maxHourly >= 10) return { level: 'warning', label: '≥10/saat — Uyarı (NIST SP 800-63B)', color: 'text-yellow-400' }
    return { level: 'ok', label: 'Normal seviye', color: 'text-emerald-400' }
  }, [data])

  // Saat dağılımı grafiği
  const hourlyDistOption = kpis ? {
    backgroundColor: 'transparent',
    grid: { top: 12, right: 8, bottom: 28, left: 36, containLabel: false },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}:00 — ${params[0].value} deneme`,
    },
    xAxis: {
      type: 'category',
      data: Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0')),
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: [{
      type: 'bar',
      data: kpis.byHour.map((v, i) => ({
        value: v,
        itemStyle: { color: i === kpis.peakHour ? '#ef4444' : i >= 22 || i <= 5 ? '#f97316' : '#6366f1' },
      })),
      barMaxWidth: 20,
    }],
  } : null

  const chartOption = data && data.hourly.length > 0
    ? {
        backgroundColor: 'transparent',
        grid: { top: 16, right: 16, bottom: 32, left: 8, containLabel: true },
        xAxis: {
          type: 'category',
          data: data.hourly.map((p) => fmtHour(p.t)),
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
          <Lock className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">Başarısız Kimlik Doğrulama</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-1">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={cn(
                  'px-2 py-0.5 text-xs rounded-lg border',
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
                )}
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

      {/* Saldırı sınıflandırma banner */}
      {attackType && data && data.total > 0 && (
        <div className={cn('rounded-lg border px-4 py-3 flex items-center gap-3', attackType.border, attackType.bg)}>
          <ShieldAlert size={16} className={cn('flex-shrink-0', attackType.color)} />
          <div>
            <span className={cn('text-sm font-semibold', attackType.color)}>{attackType.label}</span>
            <span className="text-xs text-slate-500 ml-2">{attackType.desc}</span>
          </div>
          {nistStatus && (
            <span className={cn('ml-auto text-xs font-mono', nistStatus.color)}>{nistStatus.label}</span>
          )}
        </div>
      )}

      {/* KPI kartları */}
      {isLoading ? (
        <SkeletonStatGrid cols={5} height={80} />
      ) : data && kpis ? (
        <div className="grid grid-cols-3 lg:grid-cols-5 gap-4">
          {/* Toplam */}
          <div className="ui-panel p-4">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-slate-500 uppercase tracking-wide">Toplam Deneme</span>
              {kpis.trend === 'up'     && <TrendingUp  size={14} className="text-red-400" />}
              {kpis.trend === 'down'   && <TrendingDown size={14} className="text-emerald-400" />}
              {kpis.trend === 'stable' && <Minus        size={14} className="text-slate-500" />}
            </div>
            <p className="text-3xl font-bold leading-none text-red-400">{data.total.toLocaleString('tr-TR')}</p>
            <p className="text-[11px] text-slate-600 mt-0.5">Son {hours} saat</p>
          </div>
          {/* Benzersiz kaynak */}
          <div className="ui-panel p-4">
            <div className="flex items-center gap-1.5 mb-1">
              <Users size={11} className="text-slate-500" />
              <span className="text-xs text-slate-500 uppercase tracking-wide">Benzersiz Kaynak</span>
            </div>
            <p className={cn('text-3xl font-bold leading-none', (data.unique_source_count ?? 0) >= 5 ? 'text-orange-400' : 'text-slate-100')}>
              {(data.unique_source_count ?? 0).toLocaleString('tr-TR')}
            </p>
            <p className="text-[11px] text-slate-600 mt-0.5">farklı kaynak IP</p>
          </div>
          {/* Dış IP */}
          <div className="ui-panel p-4">
            <div className="flex items-center gap-1.5 mb-1">
              <Globe size={11} className="text-slate-500" />
              <span className="text-xs text-slate-500 uppercase tracking-wide">Dış Kaynak</span>
            </div>
            <p className={cn('text-3xl font-bold leading-none', (data.external_source_count ?? 0) > 0 ? 'text-red-400' : 'text-slate-100')}>
              {(data.external_source_count ?? 0).toLocaleString('tr-TR')}
            </p>
            <p className="text-[11px] text-slate-600 mt-0.5">RFC1918 dışı IP</p>
          </div>
          {/* Saatlik ort */}
          <div className="ui-panel p-4">
            <span className="text-xs text-slate-500 uppercase tracking-wide block mb-1">Saatlik Ort.</span>
            <p className={cn('text-3xl font-bold leading-none', kpis.avgPerHour >= 50 ? 'text-red-400' : kpis.avgPerHour >= 10 ? 'text-yellow-400' : 'text-orange-400')}>
              {kpis.avgPerHour.toFixed(1)}
            </p>
            <p className="text-[11px] text-slate-600 mt-0.5">deneme / saat</p>
          </div>
          {/* Zirve saat */}
          <div className="ui-panel p-4">
            <div className="flex items-center gap-1.5 mb-1">
              <Clock size={11} className="text-slate-500" />
              <span className="text-xs text-slate-500 uppercase tracking-wide">Zirve Saat</span>
            </div>
            <p className="text-3xl font-bold leading-none text-slate-100">
              {String(kpis.peakHour).padStart(2, '0')}:00
            </p>
            <p className="text-[11px] text-slate-600 mt-0.5">
              {kpis.peakHour >= 22 || kpis.peakHour <= 5 ? 'Gece saati saldırısı' : 'Mesai saati'}
            </p>
          </div>
        </div>
      ) : null}

      {/* Trend chart */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <h2 className="text-sm font-semibold text-slate-200">Saatlik Trend</h2>
        </div>
        {isLoading ? (
          <SkeletonChart height={208} className="m-4" />
        ) : chartOption ? (
          <div className="p-4">
            <ReactECharts option={chartOption} style={{ height: 200 }} notMerge />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600">
            <Lock className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
          </div>
        )}
      </div>

      {/* Günlük saat dağılımı */}
      {hourlyDistOption && (
        <div className="ui-panel">
          <div className="ui-panel-header justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Saat Dağılımı (Gün Boyu)</h2>
            <span className="text-[11px] text-slate-500">Kırmızı: zirve · Turuncu: gece 22-05</span>
          </div>
          <div className="p-4">
            <ReactECharts option={hourlyDistOption} style={{ height: 140 }} notMerge />
          </div>
        </div>
      )}

      {/* Top kaynak IP'ler */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <h2 className="text-sm font-semibold text-slate-200">Top Kaynak IP'ler</h2>
        </div>
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={3} height={36} />
          </div>
        ) : !data || data.top_sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600">
            <p className="text-sm">Veri yok</p>
          </div>
        ) : (
          <div className="p-4 space-y-3">
            {(() => {
              const max = Math.max(1, ...data.top_sources.map(s => s.count))
              return data.top_sources.map((src, idx) => (
                <div key={src.ip} className="flex items-center gap-3">
                  <span className="text-xs text-slate-600 w-4 flex-shrink-0">{idx + 1}</span>
                  <span className="font-mono text-xs text-slate-300 w-32 flex-shrink-0 truncate" title={src.ip}>{src.ip}</span>
                  <div className="flex-1 h-2 bg-sky-950/30 rounded-full overflow-hidden">
                    <div
                      className={cn('h-full rounded-full', idx === 0 ? 'bg-red-500' : 'bg-orange-500/70')}
                      style={{ width: `${(src.count / max) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono font-semibold text-red-400 w-16 text-right flex-shrink-0">
                    {src.count.toLocaleString('tr-TR')}
                  </span>
                </div>
              ))
            })()}
          </div>
        )}
      </div>
    </div>
  )
}
