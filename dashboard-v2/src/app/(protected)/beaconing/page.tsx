'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Radio, RefreshCw } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import type { BeaconingDetection } from '@/lib/api'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function beaconRisk(jitter: number | null): 'HIGH' | 'MEDIUM' | 'LOW' | null {
  if (jitter === null) return null
  if (jitter < 0.1)   return 'HIGH'
  if (jitter < 0.2)   return 'MEDIUM'
  return 'LOW'
}

function c2Signature(iat: number | null): string | null {
  if (iat === null) return null
  if (Math.abs(iat - 60)  < 5)  return 'Cobalt Strike'
  if (Math.abs(iat - 30)  < 5)  return 'Sliver'
  if (Math.abs(iat - 300) < 30) return 'Metasploit'
  if (iat < 10)                  return 'Empire'
  return null
}

function RiskBadge({ level }: { level: 'HIGH' | 'MEDIUM' | 'LOW' | null }) {
  if (!level) return null
  const cls = {
    HIGH:   'bg-red-900/60 text-red-400 border-red-800',
    MEDIUM: 'bg-amber-900/50 text-amber-400 border-amber-800',
    LOW:    'bg-zinc-700/60 text-zinc-400 border-zinc-600',
  }[level]
  return <span className={cn('px-2 py-0.5 rounded text-xs font-semibold border', cls)}>{level}</span>
}

// IAT bins: [label, min, max, c2_signature]
const IAT_BINS: [string, number, number, string | null][] = [
  ['<10s',   0,    10,  'Empire'],
  ['10-25s', 10,   25,  null],
  ['25-35s', 25,   35,  'Sliver'],
  ['35-55s', 35,   55,  null],
  ['55-65s', 55,   65,  'Cobalt Strike'],
  ['65-120s',65,   120, null],
  ['120-280s',120, 280, null],
  ['280-320s',280, 320, 'Metasploit'],
  ['>320s',  320,  Infinity, null],
]

function IATHistogram({ detections }: { detections: BeaconingDetection[] }) {
  const counts = useMemo(() => {
    return IAT_BINS.map(([, min, max]) =>
      detections.filter(d => d.mean_iat !== null && d.mean_iat >= min && d.mean_iat < max).length
    )
  }, [detections])

  const colors = IAT_BINS.map(([,,,sig]) =>
    sig === 'Cobalt Strike' ? '#ef4444' :
    sig === 'Sliver'        ? '#f97316' :
    sig === 'Metasploit'    ? '#eab308' :
    sig === 'Empire'        ? '#a855f7' :
    '#6b7280'
  )

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
      formatter: (params: { name: string; value: number; dataIndex: number }[]) => {
        const p = params[0]
        const sig = IAT_BINS[p.dataIndex]?.[3]
        return `${p.name}: ${p.value} tespit${sig ? `<br/><b style="color:#f97316">${sig} imzası</b>` : ''}`
      },
    },
    grid: { left: 40, right: 20, top: 20, bottom: 40 },
    xAxis: {
      type: 'category',
      data: IAT_BINS.map(b => b[0]),
      axisLabel: { color: '#475569', fontSize: 11, rotate: 30 },
      axisLine: { show: false }, axisTick: { show: false },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 11 },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: [{
      type: 'bar',
      data: counts.map((v, i) => ({ value: v, itemStyle: { color: colors[i] } })),
      barMaxWidth: 40,
    }],
  }

  return <ReactECharts option={option} style={{ height: 200 }} notMerge />
}

function JitterScatter({ detections }: { detections: BeaconingDetection[] }) {
  const data = useMemo(() =>
    detections
      .filter(d => d.mean_iat !== null && d.jitter !== null)
      .map(d => {
        const risk = beaconRisk(d.jitter)
        const color = risk === 'HIGH' ? '#ef4444' : risk === 'MEDIUM' ? '#f97316' : '#6b7280'
        const conn = d.conn_count ?? 0
        return {
          value: [d.mean_iat, (d.jitter! * 100).toFixed(1), d.source_ip ?? '?', d.destination_ip ?? '?', conn],
          symbolSize: Math.max(8, Math.min(20, conn / 2)),
          itemStyle: { color },
        }
      }),
  [detections])

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'item',
      formatter: (p: { value: (string | number)[] }) => {
        const [iat, jitter, src, dst, conn] = p.value
        const sig = c2Signature(Number(iat))
        return [
          `<b>${src} → ${dst}</b>`,
          `IAT: ${Number(iat).toFixed(1)}s | Jitter: ${jitter}%`,
          `Bağlantı: ${conn}`,
          sig ? `<span style="color:#f97316">İmza: ${sig}</span>` : '',
        ].filter(Boolean).join('<br/>')
      },
    },
    grid: { left: 50, right: 20, top: 20, bottom: 40 },
    xAxis: {
      type: 'value',
      name: 'IAT (sn)',
      nameTextStyle: { color: '#475569', fontSize: 11 },
      axisLabel: { color: '#475569', fontSize: 11, formatter: (v: number) => `${v}s` },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'value',
      name: 'Jitter %',
      nameTextStyle: { color: '#475569', fontSize: 11 },
      axisLabel: { color: '#475569', fontSize: 11, formatter: (v: number) => `${v}%` },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: [{
      type: 'scatter',
      data,
      emphasis: { itemStyle: { borderWidth: 2, borderColor: '#fff' } },
    }],
  }

  if (data.length === 0) return (
    <div className="h-48 flex items-center justify-center text-zinc-500 text-sm">Scatter için yetersiz veri</div>
  )

  return <ReactECharts option={option} style={{ height: 200 }} notMerge />
}

function C2SignatureSummary({ detections }: { detections: BeaconingDetection[] }) {
  const groups = useMemo(() => {
    const map: Record<string, number> = {}
    detections.forEach(d => {
      const sig = c2Signature(d.mean_iat) ?? 'Bilinmeyen'
      map[sig] = (map[sig] ?? 0) + 1
    })
    return Object.entries(map).sort((a, b) => b[1] - a[1])
  }, [detections])

  const sigColors: Record<string, string> = {
    'Cobalt Strike': 'text-red-400 bg-red-950/40 border-red-900',
    'Sliver':        'text-orange-400 bg-orange-950/40 border-orange-900',
    'Metasploit':    'text-yellow-400 bg-yellow-950/40 border-yellow-900',
    'Empire':        'text-purple-400 bg-purple-950/40 border-purple-900',
    'Bilinmeyen':    'text-zinc-400 bg-zinc-800 border-zinc-700',
  }

  if (groups.length === 0) return null

  return (
    <div className="flex flex-wrap gap-2">
      {groups.map(([sig, count]) => (
        <span key={sig} className={cn('px-3 py-1 rounded-full text-xs font-medium border', sigColors[sig] ?? sigColors['Bilinmeyen'])}>
          {sig}: {count}
        </span>
      ))}
    </div>
  )
}

export default function BeaconingPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['beaconing-summary', hours],
    queryFn:  () => analyticsApi.beaconingSummary(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const detections = data?.detections ?? []

  const avgIat = useMemo(() => {
    const valid = detections.filter(d => d.mean_iat !== null)
    return valid.length ? valid.reduce((s, d) => s + d.mean_iat!, 0) / valid.length : null
  }, [detections])

  const avgJitter = useMemo(() => {
    const valid = detections.filter(d => d.jitter !== null)
    return valid.length ? valid.reduce((s, d) => s + d.jitter!, 0) / valid.length : null
  }, [detections])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Radio className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Beaconing Tespiti</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-md overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map(opt => (
              <button key={opt.value} onClick={() => setHours(opt.value)}
                className={cn('px-3 py-1 text-xs', hours === opt.value
                  ? 'bg-indigo-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700')}>
                {opt.label}
              </button>
            ))}
          </div>
          <button onClick={() => refetch()} className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
          Veri yüklenemedi. <button onClick={() => refetch()} className="underline">Tekrar dene</button>
        </div>
      )}

      {/* KPI Kartlar */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', (data?.total ?? 0) > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400')}>
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-zinc-500">Tespit Sayısı</p>
            <div className="flex items-center gap-2">
              <p className={cn('text-2xl font-bold', (data?.total ?? 0) > 0 ? 'text-red-400' : 'text-zinc-100')}>
                {isLoading ? '—' : (data?.total ?? 0)}
              </p>
              {(data?.total ?? 0) > 0 && (
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/50 text-red-400 border border-red-800">UYARI</span>
              )}
            </div>
            <p className="text-xs text-zinc-500 mt-0.5">Son {hours} saat</p>
          </div>
        </div>

        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <p className="text-xs text-zinc-500 mb-1">Ortalama IAT</p>
          <p className="text-2xl font-bold text-zinc-100">
            {avgIat !== null ? `${avgIat.toFixed(1)}s` : '—'}
          </p>
          {avgIat !== null && (
            <p className="text-xs text-zinc-500 mt-0.5">{c2Signature(avgIat) ?? 'Bilinen imza yok'}</p>
          )}
        </div>

        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <p className="text-xs text-zinc-500 mb-1">Ortalama Jitter (CV)</p>
          <div className="flex items-center gap-2">
            <p className="text-2xl font-bold text-zinc-100">
              {avgJitter !== null ? `${(avgJitter * 100).toFixed(1)}%` : '—'}
            </p>
            <RiskBadge level={beaconRisk(avgJitter)} />
          </div>
          <p className="text-xs text-zinc-500 mt-0.5">CV &lt; 10% → C2 otomasyonu</p>
        </div>
      </div>

      {/* C2 İmza Özeti */}
      {detections.length > 0 && (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <p className="text-xs text-zinc-500 mb-2 uppercase tracking-wide">Tespit Edilen C2 İmzaları</p>
          <C2SignatureSummary detections={detections} />
          <p className="text-xs text-zinc-600 mt-2">
            Cobalt Strike: IAT ≈60s ±5s · Sliver: ≈30s ±5s · Metasploit: ≈300s ±30s · Empire: &lt;10s
          </p>
        </div>
      )}

      {/* Grafikler */}
      {detections.length > 0 && (
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-sm font-medium text-zinc-300 mb-3">IAT Dağılım Histogramı</p>
            <IATHistogram detections={detections} />
            <p className="text-xs text-zinc-600 mt-2">
              Renkli barlar: kırmızı=Cobalt Strike, turuncu=Sliver, sarı=Metasploit, mor=Empire
            </p>
          </div>
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-sm font-medium text-zinc-300 mb-3">IAT vs Jitter Scatter</p>
            <JitterScatter detections={detections} />
            <p className="text-xs text-zinc-600 mt-2">
              Düşük IAT + düşük jitter (sol-alt) = yüksek C2 riski. Nokta büyüklüğü = bağlantı sayısı.
            </p>
          </div>
        </div>
      )}

      {/* Detay Tablosu */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Tespit Edilen Beacon'lar</h2>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map(i => <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />)}
          </div>
        ) : !detections.length ? (
          <div className="flex flex-col items-center justify-center py-16 rounded-b-xl bg-emerald-950/20 border-t border-emerald-900/40">
            <Radio className="w-8 h-8 mb-2 text-emerald-500 opacity-60" />
            <p className="text-sm text-emerald-400 font-medium">Bu zaman aralığında beaconing tespiti yapılmadı</p>
            <p className="text-xs text-emerald-600 mt-1">Ağda C2 beacon aktivitesi gözlemlenmedi</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                    <th className="text-left px-4 py-2.5">Kaynak IP</th>
                    <th className="text-left px-4 py-2.5">Hedef IP</th>
                    <th className="text-left px-4 py-2.5">Port</th>
                    <th className="text-left px-4 py-2.5">Mean IAT</th>
                    <th className="text-left px-4 py-2.5">Jitter</th>
                    <th className="text-left px-4 py-2.5">Bağ.</th>
                    <th className="text-left px-4 py-2.5">C2 İmzası</th>
                    <th className="text-left px-4 py-2.5">Risk</th>
                    <th className="text-left px-4 py-2.5">Zaman</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {detections.map((det, idx) => {
                    const risk = beaconRisk(det.jitter)
                    const sig  = c2Signature(det.mean_iat)
                    return (
                      <tr key={`${det.source_ip}-${det.destination_ip}-${idx}`}
                        className="hover:bg-zinc-800/30 transition-colors">
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.source_ip}</td>
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.destination_ip}</td>
                        <td className="px-4 py-2.5 text-zinc-400 text-xs">
                          {det.destination_port != null ? `${det.destination_port}/${(det.network_protocol ?? 'TCP').toUpperCase()}` : '—'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">
                          {det.mean_iat !== null ? `${det.mean_iat.toFixed(1)}s` : '—'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          {det.jitter !== null ? (
                            <span className={det.jitter < 0.1 ? 'text-red-400' : det.jitter < 0.2 ? 'text-amber-400' : 'text-emerald-400'}>
                              {(det.jitter * 100).toFixed(1)}%
                            </span>
                          ) : '—'}
                        </td>
                        <td className="px-4 py-2.5 text-zinc-400 text-xs">{det.conn_count ?? '—'}</td>
                        <td className="px-4 py-2.5">
                          {sig && (
                            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-900/50 text-orange-400 border border-orange-800">
                              {sig}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5"><RiskBadge level={risk} /></td>
                        <td className="px-4 py-2.5 text-zinc-500 text-xs whitespace-nowrap">
                          {new Date(det.detected_at).toLocaleString('tr-TR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <p className="px-4 py-3 text-xs text-zinc-600 border-t border-zinc-800/50">
              Jitter (CV) &lt; 0.1: yüksek olasılıkla C2 otomasyonu. Cobalt Strike varsayılan CV ≈ 0.02. Kaynak: MITRE ATT&CK T1071, Mandiant APT analizi.
            </p>
          </>
        )}
      </div>
    </div>
  )
}
