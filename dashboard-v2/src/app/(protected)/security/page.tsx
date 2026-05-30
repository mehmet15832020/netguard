'use client'

import { useState } from 'react'
import { Shield, RefreshCw, ScanLine, X } from 'lucide-react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { securityApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { ThreatBadge } from '@/components/ui/threat-badge'
import { SkeletonTable, SkeletonStatGrid } from '@/components/ui/skeleton'
import type { SecurityEvent, Severity } from '@/types/models'
import { cn } from '@/lib/utils'

const EVENT_TYPE_LABELS: Record<string, string> = {
  brute_force:      'Brute Force',
  ssh_failure:      'SSH Başarısız',
  ssh_success:      'SSH Başarılı',
  sudo_usage:       'Sudo Kullanımı',
  port_opened:      'Port Açıldı',
  port_closed:      'Port Kapandı',
  checksum_changed: 'Dosya Değişti',
}

const EVENT_TYPE_COLORS: Record<string, string> = {
  brute_force:      'text-red-400 bg-red-500/10 border-red-500/25',
  ssh_failure:      'text-orange-400 bg-orange-500/10 border-orange-500/25',
  ssh_success:      'text-emerald-400 bg-emerald-500/10 border-emerald-500/25',
  sudo_usage:       'text-yellow-400 bg-yellow-500/10 border-yellow-500/25',
  port_opened:      'text-sky-400 bg-sky-500/10 border-sky-500/25',
  port_closed:      'text-slate-400 bg-slate-500/10 border-slate-500/25',
  checksum_changed: 'text-violet-400 bg-violet-500/10 border-violet-500/25',
}

function EventTypeBadge({ type }: { type: string }) {
  const cls = EVENT_TYPE_COLORS[type] ?? 'text-slate-400 bg-sky-950/20 border-sky-900/20'
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border backdrop-blur-sm', cls)}>
      {EVENT_TYPE_LABELS[type] ?? type}
    </span>
  )
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function SummaryCard({
  type, count, active, onClick,
}: { type: string; count: number; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'text-left p-4 rounded-xl border transition-colors',
        active
          ? 'bg-sky-500/10 border-sky-500/30 shadow-[0_0_12px_rgba(56,189,248,0.08)]'
          : 'bg-[#0a1120] border-sky-900/20 hover:border-sky-700/30',
      )}
    >
      <p className="text-[11px] text-slate-500 mb-1 truncate">{EVENT_TYPE_LABELS[type] ?? type}</p>
      <p className={cn('text-3xl font-bold leading-none', active ? 'text-sky-400' : 'text-slate-100')}>{count}</p>
    </button>
  )
}

export default function SecurityPage() {
  const queryClient = useQueryClient()
  const [eventTypeFilter, setEventTypeFilter] = useState('all')
  const [ipFilter, setIpFilter] = useState('')

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['security-events', eventTypeFilter, ipFilter],
    queryFn: () =>
      securityApi.listEvents({
        event_action: eventTypeFilter !== 'all' ? eventTypeFilter : undefined,
        source_ip:    ipFilter || undefined,
        limit:        200,
      }),
    refetchInterval: 30_000,
  })

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['security-summary'],
    queryFn:  () => securityApi.summary(),
    refetchInterval: 60_000,
  })

  const scanMutation = useMutation({
    mutationFn: () => securityApi.triggerScan(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-events'] })
      queryClient.invalidateQueries({ queryKey: ['security-summary'] })
    },
  })

  const events = data?.events ?? []
  const summaryEntries = Object.entries(summary?.summary ?? {}).filter(([, v]) => v > 0)
  const hasFilters = eventTypeFilter !== 'all' || ipFilter !== ''

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Shield size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Güvenlik Olayları</h1>
            <p className="text-xs text-slate-600">
              {isLoading ? '—' : `${data?.count ?? 0} olay · auth log + port monitor + checksum`}
            </p>
          </div>
          {isFetching && <RefreshCw size={13} className="text-slate-500 animate-spin ml-1" />}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['security-events'] })}
            disabled={isFetching}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
            Yenile
          </button>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            className="ui-btn ui-btn-primary shadow-[0_0_12px_rgba(56,189,248,0.15)]"
          >
            <ScanLine size={13} />
            {scanMutation.isPending ? 'Taranıyor...' : 'Manuel Tara'}
          </button>
        </div>
      </div>

      {/* Summary cards */}
      {summaryLoading ? (
        <SkeletonStatGrid cols={4} height={72} />
      ) : summaryEntries.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-3">
          {summaryEntries.slice(0, 7).map(([type, count]) => (
            <SummaryCard
              key={type}
              type={type}
              count={count}
              active={eventTypeFilter === type}
              onClick={() => setEventTypeFilter(eventTypeFilter === type ? 'all' : type)}
            />
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={eventTypeFilter}
          onChange={e => setEventTypeFilter(e.target.value)}
          className="ui-select"
        >
          <option value="all">Tüm Tipler</option>
          {Object.entries(EVENT_TYPE_LABELS).map(([val, label]) => (
            <option key={val} value={val}>{label}</option>
          ))}
        </select>
        <div className="relative">
          <input
            placeholder="IP filtrele..."
            value={ipFilter}
            onChange={e => setIpFilter(e.target.value)}
            className="ui-input w-36 pr-6"
          />
          {ipFilter && (
            <button onClick={() => setIpFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400">
              <X size={11} />
            </button>
          )}
        </div>
        {hasFilters && (
          <button
            onClick={() => { setEventTypeFilter('all'); setIpFilter('') }}
            className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
          >
            Temizle
          </button>
        )}
        <span className="text-xs text-slate-600 ml-auto">{events.length} sonuç</span>
      </div>

      {/* Table */}
      <div className="ui-panel">
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={8} height={40} />
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Shield size={28} className="opacity-20" />
            <p className="text-sm">
              {hasFilters ? 'Filtre kriterlerine uyan olay bulunamadı' : 'Güvenlik olayı bulunamadı'}
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr >
                <th className="ui-th w-24">Seviye</th>
                <th className="ui-th w-36">Tip</th>
                <th className="ui-th">Mesaj</th>
                <th className="ui-th w-40">Kaynak IP</th>
                <th className="ui-th w-28">Hostname</th>
                <th className="ui-th w-24">Kullanıcı</th>
                <th className="ui-th w-36">Zaman</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {events.map((ev: SecurityEvent) => (
                <tr key={ev.event_id} className="hover:bg-sky-950/20 transition-colors">
                  <td className="ui-td">
                    <SeverityBadge severity={ev.severity as Severity} />
                  </td>
                  <td className="ui-td">
                    <EventTypeBadge type={ev.event_action} />
                  </td>
                  <td className="ui-td text-slate-200 max-w-xs truncate text-xs" title={ev.message}>
                    {ev.message}
                  </td>
                  <td className="ui-td text-xs text-slate-400 font-mono">
                    {ev.source_ip ? (
                      <div className="flex items-center gap-1.5">
                        <span>{ev.source_ip}</span>
                        <ThreatBadge ip={ev.source_ip} />
                      </div>
                    ) : (
                      <span className="text-slate-700">—</span>
                    )}
                  </td>
                  <td className="ui-td text-xs text-slate-500 font-mono">{ev.hostname ?? '—'}</td>
                  <td className="ui-td text-xs text-slate-500">{ev.username ?? '—'}</td>
                  <td className="ui-td text-xs text-slate-700 whitespace-nowrap">
                    {formatDate(ev.occurred_at)}
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
