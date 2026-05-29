'use client'

import { useState, useEffect } from 'react'
import { Radar, Play, RefreshCw, Circle, CheckCircle2, Loader2 } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { discoveryApi } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { Device } from '@/types/models'

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function ScanProgress({ running, found, total, cidr }: {
  running: boolean; found: number; total: number; cidr: string | null
}) {
  if (!cidr) return null
  const pct = total > 0 ? Math.min(100, Math.round((found / total) * 100)) : 0

  return (
    <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
      <div className="flex items-center gap-3 mb-3">
        {running
          ? <Loader2 size={15} className="text-sky-400 animate-spin flex-shrink-0" />
          : <CheckCircle2 size={15} className="text-emerald-400 flex-shrink-0" />
        }
        <span className="text-sm text-slate-200 font-medium">
          {running ? `Taranıyor: ${cidr}` : `Tamamlandı: ${cidr}`}
        </span>
        <span className="ml-auto text-xs font-mono px-2 py-0.5 rounded bg-sky-950/30 border border-sky-900/20 text-slate-400">
          {found} cihaz bulundu
        </span>
      </div>

      <div className="w-full h-1.5 bg-sky-950/30 rounded-full overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all duration-500', running ? 'bg-sky-500' : 'bg-emerald-500')}
          style={{ width: running ? `${pct}%` : '100%' }}
        />
      </div>
      {running && (
        <p className="text-xs text-slate-600 mt-1.5">
          {found} / {total} host tarandı ({pct}%)
        </p>
      )}
    </div>
  )
}

const INP = 'bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors disabled:opacity-50'

export default function DiscoveryPage() {
  const queryClient = useQueryClient()
  const [cidr,      setCidr]      = useState('192.168.1.0/24')
  const [community, setCommunity] = useState('public')

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['discovery-status'],
    queryFn:  () => discoveryApi.status(),
    refetchInterval: (query) => query.state.data?.running ? 2000 : 10_000,
  })

  const { data: resultsData, isLoading: resultsLoading, refetch: refetchResults } = useQuery({
    queryKey: ['discovery-results'],
    queryFn:  () => discoveryApi.results(200),
    refetchInterval: 10_000,
  })

  const scanMutation = useMutation({
    mutationFn: () => discoveryApi.startScan(cidr, community),
    onSuccess: () => {
      refetchStatus()
      setTimeout(() => refetchResults(), 3000)
    },
  })

  useEffect(() => {
    if (status && !status.running && status.finished_at) {
      refetchResults()
    }
  }, [status?.running])

  const devices: Device[] = resultsData?.devices ?? []
  const isRunning = status?.running ?? false

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <Radar size={15} className="text-sky-400" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-slate-100 leading-tight">Ağ Keşfi</h1>
          <p className="text-xs text-slate-600">Subnet tarama ile ağdaki cihazları otomatik keşfet</p>
        </div>
      </div>

      {/* Scan form */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Yeni Tarama</p>
        <div className="flex flex-wrap gap-4 items-end">
          <div className="space-y-1">
            <span className="text-xs text-slate-500">Subnet (CIDR)</span>
            <input
              value={cidr}
              onChange={e => setCidr(e.target.value)}
              placeholder="192.168.1.0/24"
              className={cn(INP, 'w-48')}
              disabled={isRunning}
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs text-slate-500">SNMP Community</span>
            <input
              value={community}
              onChange={e => setCommunity(e.target.value)}
              placeholder="public"
              className={cn(INP, 'w-32')}
              disabled={isRunning}
            />
          </div>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={isRunning || scanMutation.isPending || !cidr.trim()}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-sm text-white bg-sky-600 hover:bg-sky-500 transition-colors shadow-[0_0_12px_rgba(56,189,248,0.15)] disabled:opacity-60 disabled:shadow-none"
          >
            {isRunning ? (
              <><Loader2 size={13} className="animate-spin" /><span>Taranıyor...</span></>
            ) : (
              <><Play size={13} /><span>Tara</span></>
            )}
          </button>
        </div>
        {scanMutation.isError && (
          <p className="text-xs text-red-400 mt-2">{(scanMutation.error as Error).message}</p>
        )}
      </div>

      {/* Progress */}
      {status?.cidr && (
        <ScanProgress
          running={isRunning}
          found={status.found}
          total={status.total_probed}
          cidr={status.cidr}
        />
      )}

      {/* Results header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-300">Keşfedilen Cihazlar</span>
          <span className="text-xs text-slate-600">({resultsData?.count ?? 0})</span>
        </div>
        <button
          onClick={() => refetchResults()}
          className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs text-slate-400 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors"
        >
          <RefreshCw size={11} /> Yenile
        </button>
      </div>

      {/* Results table */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
        {resultsLoading ? (
          <div className="p-4">
            <SkeletonTable rows={6} height={40} />
          </div>
        ) : devices.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-700">
            <Radar size={32} className="opacity-20" />
            <p className="text-sm">Henüz keşfedilmiş cihaz yok</p>
            <p className="text-xs">Subnet taraması başlatın</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sky-900/15 text-xs text-slate-600 uppercase tracking-wide">
                <th className="px-4 py-3 w-6" />
                <th className="px-4 py-3 text-left w-36">IP</th>
                <th className="px-4 py-3 text-left">Hostname / Adı</th>
                <th className="px-4 py-3 text-left w-36">Vendor</th>
                <th className="px-4 py-3 text-left">OS / Bilgi</th>
                <th className="px-4 py-3 text-left w-40">İlk Görülme</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {devices.map((d) => (
                <tr key={d.device_id} className="hover:bg-sky-950/20 transition-colors">
                  <td className="px-4 py-3">
                    <Circle
                      size={8}
                      className={d.status === 'up'
                        ? 'text-emerald-400 fill-emerald-400'
                        : 'text-slate-700 fill-slate-700'
                      }
                    />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{d.ip}</td>
                  <td className="px-4 py-3 text-sm text-slate-200">
                    {d.name !== d.ip ? d.name : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">{d.vendor || '—'}</td>
                  <td className="px-4 py-3 text-xs text-slate-500 max-w-[200px] truncate">
                    {d.os_info || d.notes || '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600 whitespace-nowrap">
                    {formatDate(d.first_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
