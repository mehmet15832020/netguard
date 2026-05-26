'use client'

import { useState } from 'react'
import { Bell, RefreshCw, CheckCheck, Activity, Monitor } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi, analyticsApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { AlertVolumeChart } from '@/components/charts/AlertVolumeChart'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
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
    ? <Badge className="bg-red-900/40 text-red-300 border border-red-800 text-xs">Aktif</Badge>
    : <Badge className="bg-zinc-800 text-zinc-400 border border-zinc-700 text-xs">Çözüldü</Badge>
}

// SLA sınırları: kritik=60dk, high=120dk, warning=240dk
const SEV_SLA: Record<string, number> = { critical: 60, high: 120, warning: 240, info: 480 }

function AlertAge({ triggeredAt, severity, status }: { triggeredAt: string; severity: string; status: string }) {
  const mins = Math.floor((Date.now() - new Date(triggeredAt).getTime()) / 60000)
  const sla = SEV_SLA[severity] ?? 240
  const text = mins < 60 ? `${mins}dk` : mins < 1440 ? `${Math.floor(mins / 60)}s` : `${Math.floor(mins / 1440)}g`
  const color = status !== 'active' ? 'text-zinc-700'
    : mins > sla       ? 'text-red-400'
    : mins > sla * 0.5 ? 'text-yellow-400'
    : 'text-zinc-500'
  return <span className={cn('text-xs font-mono', color)}>{text}</span>
}

export default function AlertsPage() {
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')

  const liveAlerts = useAlertStore((s) => s.liveAlerts)
  const markAllRead = useAlertStore((s) => s.markAllRead)

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['alerts', 'all'],
    queryFn: () => alertsApi.list({ limit: 200 }),
    refetchInterval: 20_000,
  })

  const apiAlerts = data?.alerts ?? []
  const liveIds = new Set(liveAlerts.map((a) => a.alert_id))
  const all = [
    ...liveAlerts,
    ...apiAlerts.filter((a) => !liveIds.has(a.alert_id)),
  ]

  const filtered = all.filter((a) => {
    if (statusFilter !== 'all' && a.status !== statusFilter) return false
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false
    return true
  })

  const activeCount   = all.filter((a) => a.status === 'active').length
  const criticalCount = all.filter((a) => a.severity === 'critical' && a.status === 'active').length

  // Alert volume trend
  const { data: volumeData } = useQuery({
    queryKey: ['alert-volume-alerts-page'],
    queryFn:  () => analyticsApi.alertVolume(24),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  // Top sources (client-side computed from loaded alerts)
  const topSources = Object.entries(
    all
      .filter(a => a.status === 'active')
      .reduce((acc: Record<string, number>, a) => {
        const key = a.hostname || 'unknown'
        acc[key] = (acc[key] || 0) + 1
        return acc
      }, {})
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Bell size={18} /> Alertler
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {activeCount} aktif · {criticalCount} kritik
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => resolveAllMutation.mutate()}
            disabled={resolveAllMutation.isPending || activeCount === 0}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <CheckCheck size={14} />
            <span className="ml-1.5">Tümünü Çözüldü Yap</span>
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={handleRefresh}
            disabled={isFetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            <span className="ml-1.5">Yenile</span>
          </Button>
        </div>
      </div>

      {/* 4 Severity Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {(['critical', 'high', 'warning', 'info'] as Severity[]).map((sev) => {
          const count = all.filter((a) => a.severity === sev && a.status === 'active').length
          const total = all.filter((a) => a.severity === sev).length
          const labels: Record<string, string> = { critical: 'Kritik', high: 'Yüksek', warning: 'Uyarı', info: 'Bilgi' }
          const active = severityFilter === sev
          return (
            <Card
              key={sev}
              className={cn(
                'cursor-pointer transition-colors',
                active ? 'bg-zinc-800 border-zinc-600' : 'bg-zinc-900 border-zinc-800 hover:border-zinc-600',
              )}
              onClick={() => setSeverityFilter(sev === severityFilter ? 'all' : sev)}
            >
              <CardContent className="p-4 flex items-center justify-between">
                <span className="text-sm text-zinc-400">{labels[sev]}</span>
                <SeverityBadge severity={sev} />
              </CardContent>
              <div className="px-4 pb-4">
                <span className="text-2xl font-bold text-zinc-100">{count}</span>
                <span className="text-xs text-zinc-600 ml-1.5">/ {total} toplam</span>
              </div>
            </Card>
          )
        })}
      </div>

      {/* Alert Trend + Top Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Alert Volume Trend */}
        <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
            <Activity size={13} className="text-zinc-500" />
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Alert Trendi — 24 Saat</span>
            <span className="text-[11px] text-zinc-600 ml-auto">Severity bazında dağılım</span>
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
            <div className="flex items-center justify-center py-12 text-zinc-600 text-sm">Yükleniyor...</div>
          )}
        </div>

        {/* Top Alert Sources */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
            <Monitor size={13} className="text-zinc-500" />
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">En Aktif Kaynaklar</span>
            <span className="text-[11px] text-zinc-600 ml-auto">Aktif alertler</span>
          </div>
          {topSources.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-zinc-600 text-sm">Aktif alert yok</div>
          ) : (
            <div className="p-4 space-y-3">
              {topSources.map(([host, count]) => (
                <div key={host} className="flex items-center gap-2">
                  <span className="text-xs text-zinc-400 w-28 truncate flex-shrink-0" title={host}>{host}</span>
                  <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-indigo-500 rounded-full"
                      style={{ width: `${(count / maxSourceCount) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-zinc-500 w-6 text-right flex-shrink-0">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <CardTitle className="text-sm text-zinc-300 flex-1">Alert Listesi</CardTitle>
            <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v ?? 'all')}>
              <SelectTrigger className="w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="all" className="text-zinc-300">Tüm durumlar</SelectItem>
                <SelectItem value="active" className="text-zinc-300">Aktif</SelectItem>
                <SelectItem value="resolved" className="text-zinc-300">Çözüldü</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v ?? 'all')}>
              <SelectTrigger className="w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="all" className="text-zinc-300">Tüm seviyeler</SelectItem>
                <SelectItem value="critical" className="text-zinc-300">Kritik</SelectItem>
                <SelectItem value="high" className="text-zinc-300">Yüksek</SelectItem>
                <SelectItem value="warning" className="text-zinc-300">Uyarı</SelectItem>
                <SelectItem value="info" className="text-zinc-300">Bilgi</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : filtered.length === 0 ? (
            <p className="text-zinc-600 text-sm text-center py-10">Alert bulunamadı</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-24">Durum</TableHead>
                  <TableHead className="text-zinc-500 text-xs">Mesaj</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-32">Host</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-24">Metrik</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-28">Değer / Eşik</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-40">Zaman</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-16">Süre</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((alert) => (
                  <TableRow key={alert.alert_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell><SeverityBadge severity={alert.severity} /></TableCell>
                    <TableCell><StatusBadge status={alert.status} /></TableCell>
                    <TableCell className="text-sm text-zinc-200 max-w-xs truncate">{alert.message}</TableCell>
                    <TableCell className="text-xs text-zinc-400">{alert.hostname}</TableCell>
                    <TableCell className="text-xs text-zinc-400">{alert.metric}</TableCell>
                    <TableCell className="text-xs text-zinc-400">
                      {alert.value.toFixed(1)} / {alert.threshold.toFixed(1)}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{formatDate(alert.triggered_at)}</TableCell>
                    <TableCell>
                      <AlertAge triggeredAt={alert.triggered_at} severity={alert.severity} status={alert.status} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
