'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Radio, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('tr-TR', { timeZone: 'UTC' })
}

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
  if (iat < 10)                  return 'Empire (agresif)'
  return null
}

function RiskBadge({ level }: { level: 'HIGH' | 'MEDIUM' | 'LOW' | null }) {
  if (!level) return null
  const cls = {
    HIGH:   'bg-red-900/60 text-red-400 border-red-800',
    MEDIUM: 'bg-amber-900/50 text-amber-400 border-amber-800',
    LOW:    'bg-zinc-700/60 text-zinc-400 border-zinc-600',
  }[level]
  return (
    <span className={cn('px-2 py-0.5 rounded text-xs font-semibold border', cls)}>
      {level}
    </span>
  )
}

function JitterCell({ jitter }: { jitter: number | null }) {
  if (jitter === null) return <span className="text-zinc-600">-</span>
  const pct = (jitter * 100).toFixed(1)
  const cls =
    jitter < 0.1  ? 'text-red-400' :
    jitter < 0.2  ? 'text-amber-400' :
    'text-emerald-400'
  return <span className={cn('font-mono text-xs', cls)}>{pct}%</span>
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

  const avgIat: number | null = detections.length > 0
    ? detections.reduce((s, d) => s + (d.mean_iat ?? 0), 0) / detections.filter((d) => d.mean_iat !== null).length || null
    : null

  const avgJitter: number | null = detections.length > 0
    ? (() => {
        const valid = detections.filter((d) => d.jitter !== null)
        if (valid.length === 0) return null
        return valid.reduce((s, d) => s + (d.jitter ?? 0), 0) / valid.length
      })()
    : null

  const avgJitterRisk = beaconRisk(avgJitter)

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

      {/* KPI Kartlar */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-24 animate-pulse" />
          ))}
        </div>
      ) : data ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Tespit Sayisi */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className={cn(
              'p-2 rounded-lg',
              data.total > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400',
            )}>
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Tespit Sayisi</p>
              <div className="flex items-center gap-2">
                <p className={cn('text-2xl font-bold', data.total > 0 ? 'text-red-400' : 'text-zinc-100')}>
                  {data.total.toLocaleString('tr-TR')}
                </p>
                {data.total > 0 && (
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/50 text-red-400 border border-red-800">
                    UYARI
                  </span>
                )}
              </div>
              <p className="text-xs text-zinc-500 mt-0.5">Son {hours} saat</p>
            </div>
          </div>

          {/* Ortalama IAT */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-zinc-700/40 text-zinc-400">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Ortalama IAT</p>
              <p className="text-2xl font-bold text-zinc-100">
                {avgIat !== null && !isNaN(avgIat) ? `${avgIat.toFixed(1)}s` : '-'}
              </p>
              <p className="text-xs text-zinc-500 mt-0.5">Inter-arrival time</p>
            </div>
          </div>

          {/* Ortalama Jitter (CV) */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-zinc-700/40 text-zinc-400">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Ortalama Jitter (CV)</p>
              <div className="flex items-center gap-2">
                <p className="text-2xl font-bold text-zinc-100">
                  {avgJitter !== null ? `${(avgJitter * 100).toFixed(1)}%` : '-'}
                </p>
                {avgJitterRisk === 'HIGH' && (
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/50 text-red-400 border border-red-800">
                    Yüksek Risk
                  </span>
                )}
              </div>
              <p className="text-xs text-zinc-500 mt-0.5">Coefficient of variation</p>
            </div>
          </div>
        </div>
      ) : null}

      {/* Detay Tablosu */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Tespit Edilen Beacon&apos;lar</h2>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : !data || data.detections.length === 0 ? (
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
                    <th className="text-left px-4 py-2.5 font-medium">Kaynak IP</th>
                    <th className="text-left px-4 py-2.5 font-medium">Hedef IP</th>
                    <th className="text-left px-4 py-2.5 font-medium">Port</th>
                    <th className="text-left px-4 py-2.5 font-medium">Mean IAT</th>
                    <th className="text-left px-4 py-2.5 font-medium">Jitter (CV)</th>
                    <th className="text-left px-4 py-2.5 font-medium">C2 İmzası</th>
                    <th className="text-left px-4 py-2.5 font-medium">Risk</th>
                    <th className="text-left px-4 py-2.5 font-medium">Zaman</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {data.detections.map((det, idx) => {
                    const risk = beaconRisk(det.jitter)
                    const sig  = c2Signature(det.mean_iat)
                    return (
                      <tr
                        key={`${det.source_ip}-${det.destination_ip}-${idx}`}
                        className="hover:bg-zinc-800/30 transition-colors"
                      >
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.source_ip}</td>
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.destination_ip}</td>
                        <td className="px-4 py-2.5 text-zinc-400 text-xs whitespace-nowrap">
                          {det.destination_port !== null
                            ? `${det.destination_port}/${(det.network_protocol ?? 'TCP').toUpperCase()}`
                            : '-'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">
                          {det.mean_iat !== null ? `${det.mean_iat.toFixed(1)}s` : '-'}
                        </td>
                        <td className="px-4 py-2.5">
                          <JitterCell jitter={det.jitter} />
                        </td>
                        <td className="px-4 py-2.5">
                          {sig ? (
                            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-900/50 text-orange-400 border border-orange-800">
                              {sig}
                            </span>
                          ) : null}
                        </td>
                        <td className="px-4 py-2.5">
                          <RiskBadge level={risk} />
                        </td>
                        <td className="px-4 py-2.5 text-zinc-500 text-xs whitespace-nowrap">
                          {fmtDate(det.detected_at)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <p className="px-4 py-3 text-xs text-zinc-600 border-t border-zinc-800/50">
              Jitter (CV) &lt; 0.1: yüksek olasılıkla C2 otomasyonu. Cobalt Strike varsayılan CV ≈ 0.02 (60s ±~1s). Kaynak: MITRE ATT&amp;CK T1071, Mandiant APT jitter analizi.
            </p>
          </>
        )}
      </div>
    </div>
  )
}
