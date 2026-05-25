'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Fingerprint,
  RefreshCw,
  Shield,
  AlertTriangle,
  ShieldAlert,
} from 'lucide-react'
import { analyticsApi, TlsVersionItem } from '@/lib/api'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function truncateFingerprint(hash: string, maxLen = 32): string {
  if (hash.length <= maxLen) return hash
  return `${hash.slice(0, maxLen)}…`
}

function tlsVersionColor(version: string): { bar: string; warning: boolean } {
  const v = version.toLowerCase()
  if (v.includes('1.0') || v.includes('1.1')) return { bar: 'bg-red-500',    warning: true  }
  if (v.includes('1.2'))                       return { bar: 'bg-amber-400',  warning: false }
  if (v.includes('1.3'))                       return { bar: 'bg-emerald-500', warning: false }
  return { bar: 'bg-zinc-500', warning: false }
}

function TlsVersionBar({ item, total }: { item: TlsVersionItem; total: number }) {
  const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
  const { bar, warning } = tlsVersionColor(item.version)
  return (
    <div className="flex items-center gap-3">
      <div className="w-28 shrink-0 flex items-center gap-1.5">
        {warning && <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />}
        <span className={cn('text-xs font-mono', warning ? 'text-red-300' : 'text-zinc-300')}>
          {item.version}
        </span>
      </div>
      <div className="flex-1 bg-zinc-700 rounded-full h-2">
        <div
          className={cn('h-2 rounded-full transition-all', bar)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-14 text-right text-xs text-zinc-400 shrink-0">
        {item.count.toLocaleString('tr-TR')} <span className="text-zinc-600">({pct}%)</span>
      </span>
    </div>
  )
}

export default function TlsFingerprintsPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['tls-fingerprints', hours],
    queryFn:  () => analyticsApi.tlsFingerprints(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const hasMalicious = data?.top_fingerprints.some((fp) => fp.is_malicious) ?? false
  const versionTotal = data?.tls_version_dist.reduce((s, v) => s + v.count, 0) ?? 0

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Fingerprint className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">TLS / JA4 Fingerprint</h1>
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
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-24 animate-pulse" />
          ))}
        </div>
      ) : data ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Toplam Baglanti */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/15 text-indigo-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Toplam Baglanti</p>
              <p className="text-2xl font-bold text-zinc-100">
                {data.total_connections.toLocaleString('tr-TR')}
              </p>
            </div>
          </div>

          {/* Benzersiz Fingerprint */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-zinc-700/40 text-zinc-400">
              <Fingerprint className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Benzersiz Fingerprint</p>
              <p className="text-2xl font-bold text-zinc-100">
                {data.unique_count.toLocaleString('tr-TR')}
              </p>
            </div>
          </div>

          {/* Suphelı/Zararlı */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className={cn(
              'p-2 rounded-lg',
              data.suspicious_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400',
            )}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Suphelı / Zararlı</p>
              <p className={cn(
                'text-2xl font-bold',
                data.suspicious_count > 0 ? 'text-red-400' : 'text-zinc-100',
              )}>
                {data.suspicious_count.toLocaleString('tr-TR')}
              </p>
            </div>
          </div>

          {/* Self-Signed Sertifika */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-3">
            <div className={cn(
              'p-2 rounded-lg',
              data.self_signed_count > 0 ? 'bg-amber-500/15 text-amber-400' : 'bg-zinc-700/40 text-zinc-400',
            )}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">Self-Signed Sertifika</p>
              <p className={cn(
                'text-2xl font-bold',
                data.self_signed_count > 0 ? 'text-amber-400' : 'text-zinc-100',
              )}>
                {data.self_signed_count.toLocaleString('tr-TR')}
              </p>
            </div>
          </div>
        </div>
      ) : null}

      {/* Versiyon + SNI kolonlari */}
      {isLoading ? (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-48 animate-pulse" />
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-48 animate-pulse" />
        </div>
      ) : data ? (
        <div className="grid md:grid-cols-2 gap-4">
          {/* TLS Versiyon Dagilimi */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800">
            <div className="px-4 py-3 border-b border-zinc-800">
              <h2 className="text-sm font-semibold text-zinc-200">TLS Versiyon Dagilimi</h2>
            </div>
            <div className="p-4 space-y-3">
              {data.tls_version_dist.length === 0 ? (
                <p className="text-sm text-zinc-600 py-4 text-center">Versiyon verisi mevcut degil</p>
              ) : (
                data.tls_version_dist.map((item) => (
                  <TlsVersionBar key={item.version} item={item} total={versionTotal} />
                ))
              )}
              {data.tls_version_dist.some((v) => tlsVersionColor(v.version).warning) && (
                <p className="text-xs text-red-400 mt-2 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  TLS 1.0/1.1 güvensizdir — NIST SP 800-52r2 uyarınca devre dışı bırakılmalıdır.
                </p>
              )}
            </div>
          </div>

          {/* Top Domainler / SNI */}
          <div className="bg-zinc-900 rounded-xl border border-zinc-800">
            <div className="px-4 py-3 border-b border-zinc-800">
              <h2 className="text-sm font-semibold text-zinc-200">Baglanilan Top Domainler (SNI)</h2>
            </div>
            {data.top_sni.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-zinc-600">
                <p className="text-sm">SNI verisi mevcut degil</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                      <th className="text-left px-4 py-2.5 font-medium">Domain</th>
                      <th className="text-right px-4 py-2.5 font-medium">Baglanti</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    {data.top_sni.map((item) => (
                      <tr key={item.sni} className="hover:bg-zinc-800/30 transition-colors">
                        <td className="px-4 py-2.5 font-mono text-xs text-zinc-300 max-w-xs truncate" title={item.sni}>
                          {item.sni}
                        </td>
                        <td className="px-4 py-2.5 text-right text-zinc-300 font-semibold text-xs">
                          {item.count.toLocaleString('tr-TR')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}

      {/* Fingerprint Tablosu */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-200">Top Fingerprint&apos;ler</h2>
        </div>

        {hasMalicious && (
          <div className="mx-4 mt-3 rounded-lg border border-red-800 bg-red-950/30 px-3 py-2 text-xs text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            Tabloda zararlı olarak isaretlenmis fingerprint bulunuyor. Acilen incelenmesi gerekiyor.
          </div>
        )}

        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : !data || data.top_fingerprints.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <Fingerprint className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Bu zaman aralığında TLS bağlantısı tespit edilmedi</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">#</th>
                  <th className="text-left px-4 py-2.5 font-medium">Parmak İzi</th>
                  <th className="text-left px-4 py-2.5 font-medium">Baglanti Sayisi</th>
                  <th className="text-left px-4 py-2.5 font-medium">Durum</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.top_fingerprints.map((fp, idx) => (
                  <tr
                    key={fp.fingerprint}
                    className={cn(
                      'transition-colors',
                      fp.is_malicious ? 'bg-red-950/20 hover:bg-red-950/30' : 'hover:bg-zinc-800/30',
                    )}
                  >
                    <td className="px-4 py-2.5 text-zinc-600 text-xs">{idx + 1}</td>
                    <td className="px-4 py-2.5">
                      <span
                        title={fp.fingerprint}
                        className="font-mono text-xs text-indigo-300 cursor-default"
                      >
                        {truncateFingerprint(fp.fingerprint)}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-zinc-300 font-semibold text-sm">
                      {fp.count.toLocaleString('tr-TR')}
                    </td>
                    <td className="px-4 py-2.5">
                      {fp.is_malicious ? (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/60 text-red-400 border border-red-800">
                          ZARARLI
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-900/40 text-emerald-400 border border-emerald-800">
                          Temiz
                        </span>
                      )}
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
