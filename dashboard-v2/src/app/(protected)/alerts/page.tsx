'use client'

import { useState } from 'react'
import { Bell, RefreshCw } from 'lucide-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'
import { SeverityBadge } from '@/components/ui/severity-badge'
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

  const handleRefresh = () => {
    markAllRead()
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Bell size={18} /> Alertler
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {activeCount} aktif · {criticalCount} kritik
          </p>
        </div>
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

      <div className="grid grid-cols-3 gap-3">
        {(['critical', 'warning', 'info'] as Severity[]).map((sev) => {
          const count = all.filter((a) => a.severity === sev && a.status === 'active').length
          const labels: Record<string, string> = { critical: 'Kritik', warning: 'Uyarı', high: 'Yüksek', info: 'Bilgi' }
          return (
            <Card
              key={sev}
              className="bg-zinc-900 border-zinc-800 cursor-pointer hover:border-zinc-600 transition-colors"
              onClick={() => setSeverityFilter(sev === severityFilter ? 'all' : sev)}
            >
              <CardContent className="p-4 flex items-center justify-between">
                <span className="text-sm text-zinc-400">{labels[sev]}</span>
                <SeverityBadge severity={sev} />
              </CardContent>
              <div className="px-4 pb-4">
                <span className="text-2xl font-bold text-zinc-100">{count}</span>
              </div>
            </Card>
          )
        })}
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
