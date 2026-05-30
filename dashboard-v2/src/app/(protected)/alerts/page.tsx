'use client'

import { useState } from 'react'
import { Bell, RefreshCw, CheckCheck, Activity, Monitor } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi, analyticsApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { AlertVolumeChart } from '@/components/charts/AlertVolumeChart'
import { SkeletonTable, SkeletonChart } from '@/components/ui/skeleton'
import type { Alert, Severity } from '@/types/models'
import { cn } from '@/lib/utils'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function StatusBadge({ status }: { status: Alert['status'] }) {
  return status === 'active'
    ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-400 backdrop-blur-sm">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400 shadow-[0_0_4px_rgba(239,68,68,0.8)]" />
        Aktif
      </span>
    : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-sky-950/20 border border-sky-900/20 text-slate-500">
        Çözüldü
      </span>
}

const SEV_SLA: Record<string, number> = { critical: 60, high: 120, warning: 240, info: 480 }

function AlertAge({ triggeredAt, severity, status }: { triggeredAt: string; severity: string; status: string }) {
  const mins = Math.floor((Date.now() - new Date(triggeredAt).getTime()) / 60000)
  const sla  = SEV_SLA[severity] ?? 240
  const text = mins < 60 ? `${mins}dk` : mins < 1440 ? `${Math.floor(mins / 60)}s` : `${Math.floor(mins / 1440)}g`
  const color = status !== 'active'  ? 'text-slate-700'
    : mins > sla        ? 'text-red-400'
    : mins > sla * 0.5  ? 'text-yellow-400'
    : 'text-slate-600'
  return <span className={cn('text-xs font-mono', color)}>{text}</span>
}

const SEV_LABELS: Record<string, string> = { critical: 'Kritik', high: 'Yüksek', warning: 'Uyarı', info: 'Bilgi' }

const SEV_ACTIVE_CLS: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/30',
  high:     'bg-orange-500/10 border-orange-500/30',
  warning:  'bg-yellow-500/10 border-yellow-500/25',
  info:     'bg-blue-500/10 border-blue-500/25',
}

export default function AlertsPage() {
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter]     = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')

  const liveAlerts = useAlertStore((s) => s.liveAlerts)
  const markAllRead = useAlertStore((s) => s.markAllRead)

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['alerts', 'all'],
    queryFn:  () => alertsApi.list({ limit: 200 }),
    refetchInterval: 20_000,
  })

  const apiAlerts = data?.alerts ?? []
  const liveIds   = new Set(liveAlerts.map((a) => a.alert_id))
  const all       = [...liveAlerts, ...apiAlerts.filter((a) => !liveIds.has(a.alert_id))]

  const filtered = all.filter((a) => {
    if (statusFilter   !== 'all' && a.status   !== statusFilter)   return false
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false
    return true
  })

  const activeCount   = all.filter((a) => a.status === 'active').length
  const criticalCount = all.filter((a) => a.severity === 'critical' && a.status === 'active').length

  const { data: volumeData } = useQuery({
    queryKey: ['alert-volume-alerts-page'],
    queryFn:  () => analyticsApi.alertVolume(24),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const topSources = Object.entries(
    all
      .filter(a => a.status === 'active')
      .reduce((acc: Record<string, number>, a) => {
        const key = a.hostname || 'unknown'
        acc[key] = (acc[key] || 0) + 1
        return acc
      }, {}),
  ).sort((a, b) => b[1] - a[1]).slice(0, 6)
  const maxSourceCount = topSources[0]?.[1] ?? 1

  const resolveAllMutation = useMutation({
    mutationFn: () => alertsApi.resolveAll(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['security-status'] })
    },
  })

  const handleRefresh = () => {
    markAllRead()
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Bell size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Alertler</h1>
            <p className="text-xs text-slate-600">
              {activeCount} aktif · {criticalCount} kritik
              {isFetching && <RefreshCw size={10} className="inline ml-1.5 animate-spin" />}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => resolveAllMutation.mutate()}
            disabled={resolveAllMutation.isPending || activeCount === 0}
            className="ui-btn ui-btn-secondary"
          >
            <CheckCheck size={13} />
            Tümünü Çözüldü Yap
          </button>
          <button
            onClick={handleRefresh}
            disabled={isFetching}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
            Yenile
          </button>
        </div>
      </div>

      {/* Severity cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {(['critical', 'high', 'warning', 'info'] as Severity[]).map((sev) => {
          const count = all.filter((a) => a.severity === sev && a.status === 'active').length
          const total = all.filter((a) => a.severity === sev).length
          const isActive = severityFilter === sev
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev === severityFilter ? 'all' : sev)}
              className={cn(
                'text-left p-4 rounded-xl border transition-colors',
                isActive
                  ? cn('shadow-[0_0_12px_rgba(56,189,248,0.06)]', SEV_ACTIVE_CLS[sev])
                  : 'bg-[#0a1120] border-sky-900/20 hover:border-sky-700/30',
              )}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-500">{SEV_LABELS[sev]}</span>
                <SeverityBadge severity={sev} />
              </div>
              <span className="text-2xl font-bold text-slate-100">{count}</span>
              <span className="text-xs text-slate-700 ml-1.5">/ {total} toplam</span>
            </button>
          )
        })}
      </div>

      {/* Alert Trend + Top Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Volume chart */}
        <div className="lg:col-span-2 ui-panel">
          <div className="ui-panel-header">
            <Activity size={13} className="text-slate-600" />
            <span className="ui-section-label">Alert Trendi — 24 Saat</span>
            <span className="text-[11px] text-slate-700 ml-auto">Severity bazında dağılım</span>
          </div>
          {volumeData ? (
            <div className="px-2 py-2">
              <AlertVolumeChart
                series={volumeData.series}
                hours={volumeData.hours}
                bucketMinutes={volumeData.bucket_minutes}
                height={180}
              />
            </div>
          ) : (
            <SkeletonChart height={180} className="m-3" />
          )}
        </div>

        {/* Top sources */}
        <div className="ui-panel">
          <div className="ui-panel-header">
            <Monitor size={13} className="text-slate-600" />
            <span className="ui-section-label">En Aktif Kaynaklar</span>
            <span className="text-[11px] text-slate-700 ml-auto">Aktif alertler</span>
          </div>
          {topSources.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-slate-700 text-sm">Aktif alert yok</div>
          ) : (
            <div className="p-4 space-y-3">
              {topSources.map(([host, count]) => (
                <div key={host} className="flex items-center gap-2">
                  <span className="text-xs text-slate-500 w-28 truncate flex-shrink-0 font-mono" title={host}>{host}</span>
                  <div className="flex-1 h-1.5 bg-sky-950/20 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-sky-500 rounded-full"
                      style={{ width: `${(count / maxSourceCount) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-slate-600 w-5 text-right flex-shrink-0">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Alert list */}
      <div className="ui-panel">
        {/* Filters */}
        <div className="ui-panel-header flex-wrap gap-3">
          <span className="text-xs text-slate-500 font-medium flex-shrink-0">Alert Listesi</span>
          <span className="text-xs text-slate-700">{filtered.length} kayıt</span>
          <div className="ml-auto flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="ui-select"
            >
              <option value="all">Tüm durumlar</option>
              <option value="active">Aktif</option>
              <option value="resolved">Çözüldü</option>
            </select>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="ui-select"
            >
              <option value="all">Tüm seviyeler</option>
              <option value="critical">Kritik</option>
              <option value="high">Yüksek</option>
              <option value="warning">Uyarı</option>
              <option value="info">Bilgi</option>
            </select>
          </div>
        </div>

        {/* Table */}
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={8} height={40} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Bell size={28} className="opacity-20" />
            <p className="text-sm">Alert bulunamadı</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr >
                <th className="ui-th w-24">Seviye</th>
                <th className="ui-th w-24">Durum</th>
                <th className="ui-th">Mesaj</th>
                <th className="ui-th w-32">Host</th>
                <th className="ui-th w-24">Metrik</th>
                <th className="ui-th w-28">Değer / Eşik</th>
                <th className="ui-th w-40">Zaman</th>
                <th className="ui-th w-14">Süre</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {filtered.map((alert) => (
                <tr
                  key={alert.alert_id}
                  className={cn(
                    'transition-colors hover:bg-sky-950/20',
                    alert.status === 'active' && alert.severity === 'critical' && 'bg-red-950/5',
                  )}
                >
                  <td className="ui-td"><SeverityBadge severity={alert.severity} /></td>
                  <td className="ui-td"><StatusBadge status={alert.status} /></td>
                  <td className="ui-td text-slate-200 max-w-xs truncate text-xs" title={alert.message}>{alert.message}</td>
                  <td className="ui-td text-xs text-slate-500 font-mono">{alert.hostname}</td>
                  <td className="ui-td text-xs text-slate-500">{alert.metric}</td>
                  <td className="ui-td text-xs text-slate-400 font-mono">
                    {alert.value.toFixed(1)} / {alert.threshold.toFixed(1)}
                  </td>
                  <td className="ui-td text-xs text-slate-700 whitespace-nowrap">{formatDate(alert.triggered_at)}</td>
                  <td className="ui-td">
                    <AlertAge triggeredAt={alert.triggered_at} severity={alert.severity} status={alert.status} />
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
