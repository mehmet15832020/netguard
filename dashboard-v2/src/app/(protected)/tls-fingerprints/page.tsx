'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Fingerprint, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
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

export default function TlsFingerprintsPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['tls-fingerprints', hours],
    queryFn:  () => analyticsApi.tlsFingerprints(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

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

      {/* Stat kart */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
      ) : data ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 inline-flex items-center gap-4">
          <Fingerprint className="w-6 h-6 text-indigo-400 flex-shrink-0" />
          <div>
            <p className="text-xs text-zinc-500">Benzersiz Fingerprint</p>
            <p className="text-2xl font-bold text-zinc-100">
              {data.unique_count.toLocaleString('tr-TR')}
            </p>
          </div>
        </div>
      ) : null}

      {/* Tablo */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Top Fingerprint'ler</h2>
        </div>

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
                  <th className="text-left px-4 py-2.5 font-medium">Görülme Sayısı</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.top_fingerprints.map((fp, idx) => (
                  <tr key={fp.fingerprint} className="hover:bg-zinc-800/30 transition-colors">
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
