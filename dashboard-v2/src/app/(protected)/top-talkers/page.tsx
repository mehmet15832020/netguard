'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BarChart2, RefreshCw, Radio, Target, Zap } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { TopTalkersChart } from '@/components/charts/TopTalkersChart'
import { SkeletonChart } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const WELL_KNOWN_PORTS: Record<number, string> = {
  20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
  53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
  445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 636: 'LDAPS',
  993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
  3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 9200: 'Elasticsearch',
  27017: 'MongoDB',
}

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

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['top-talkers', hours, limit],
    queryFn:  () => analyticsApi.topTalkers(hours, limit),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  })

  const sources = (data?.top_sources      ?? []).map((d) => ({ label: d.ip,           count: d.count }))
  const dests   = (data?.top_destinations ?? []).map((d) => ({ label: d.ip,           count: d.count }))
  const ports   = (data?.top_dst_ports    ?? []).map((d) => ({ label: String(d.port), count: d.count }))

  const topSource = useMemo(() => data?.top_sources[0]      ?? null, [data])
  const topDest   = useMemo(() => data?.top_destinations[0] ?? null, [data])
  const topPort   = useMemo(() => data?.top_dst_ports[0]    ?? null, [data])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <BarChart2 className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">Top Talkers</h1>
          {isFetching && (
            <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />
          )}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* Limit */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-500">Limit</span>
            <div className="flex gap-1">
              {LIMIT_OPTIONS.map((l) => (
                <button
                  key={l}
                  onClick={() => setLimit(l)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
                    limit === l
                      ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                      : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40',
                  )}
                >
                  {l}
                </button>
              ))}
            </div>
          </div>

          {/* Time range */}
          <div className="flex gap-1">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={cn(
                  'px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-lg border border-sky-900/20 text-slate-400 hover:text-slate-100 hover:bg-sky-950/30 transition-colors"
            title="Yenile"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button
            onClick={() => refetch()}
            className="text-xs underline hover:text-red-300"
          >
            Tekrar dene
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-4 h-4 text-sky-400 flex-shrink-0" />
            <p className="text-xs text-slate-500">En Aktif Kaynak</p>
          </div>
          <p className="text-xl font-bold text-slate-100 font-mono truncate">
            {isLoading ? '—' : (topSource?.ip ?? '—')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">
            {topSource ? `${topSource.count.toLocaleString('tr-TR')} bağlantı · tarama/sızdırma riski` : 'veri yok'}
          </p>
        </div>
        <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
          <div className="flex items-center gap-2 mb-1">
            <Target className="w-4 h-4 text-sky-400 flex-shrink-0" />
            <p className="text-xs text-slate-500">En Meşgul Hedef</p>
          </div>
          <p className="text-xl font-bold text-slate-100 font-mono truncate">
            {isLoading ? '—' : (topDest?.ip ?? '—')}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">
            {topDest ? `${topDest.count.toLocaleString('tr-TR')} bağlantı · C2/exfil hedefi olabilir` : 'veri yok'}
          </p>
        </div>
        <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
          <div className="flex items-center gap-2 mb-1">
            <Zap className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <p className="text-xs text-slate-500">En Yaygın Port</p>
          </div>
          <p className="text-xl font-bold text-slate-100 font-mono">
            {isLoading ? '—' : topPort
              ? `${topPort.port}${WELL_KNOWN_PORTS[topPort.port] ? ` · ${WELL_KNOWN_PORTS[topPort.port]}` : ''}`
              : '—'}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">
            {topPort ? `${topPort.count.toLocaleString('tr-TR')} bağlantı` : 'veri yok'}
          </p>
        </div>
      </div>

      {/* Charts grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[...Array(3)].map((_, i) => (
            <SkeletonChart key={i} height={256} className="rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
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

          <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
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

          <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4">
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

      {data && (
        <p className="text-xs text-slate-600">
          Son {hours} saatte en aktif {data.top_sources.length} kaynak IP, {data.top_destinations.length} hedef IP ve {data.top_dst_ports.length} hedef port · Yüksek hacimli kaynaklar tarama veya veri sızdırma belirtisi olabilir
        </p>
      )}
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-slate-600">
      <BarChart2 className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">{label}</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
