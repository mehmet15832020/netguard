'use client'

import { useState } from 'react'
import { Shield, RefreshCw, ScanLine } from 'lucide-react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { securityApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { Severity } from '@/types/models'
import { ThreatBadge } from '@/components/ui/threat-badge'

const EVENT_TYPE_LABELS: Record<string, string> = {
  brute_force:     'Brute Force',
  ssh_failure:     'SSH Başarısız',
  ssh_success:     'SSH Başarılı',
  sudo_usage:      'Sudo Kullanımı',
  port_opened:     'Port Açıldı',
  port_closed:     'Port Kapandı',
  checksum_changed:'Dosya Değişti',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export default function SecurityPage() {
  const queryClient = useQueryClient()
  const [eventTypeFilter, setEventTypeFilter] = useState('all')
  const [ipFilter, setIpFilter] = useState('')

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['security-events', eventTypeFilter, ipFilter],
    queryFn: () =>
      securityApi.listEvents({
        event_type: eventTypeFilter !== 'all' ? eventTypeFilter : undefined,
        source_ip: ipFilter || undefined,
        limit: 200,
      }),
    refetchInterval: 30_000,
  })

  const { data: summary } = useQuery({
    queryKey: ['security-summary'],
    queryFn: () => securityApi.summary(),
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

  return (
    <div className="space-y-5">
      {/* Başlık */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Shield size={18} /> Güvenlik Olayları
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">{data?.count ?? 0} olay</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ['security-events'] })}
            disabled={isFetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            <span className="ml-1.5">Yenile</span>
          </Button>
          <Button
            size="sm"
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending}
            className="bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            <ScanLine size={14} />
            <span className="ml-1.5">
              {scanMutation.isPending ? 'Taranıyor...' : 'Manuel Tara'}
            </span>
          </Button>
        </div>
      </div>

      {/* Özet satırı — tıklayınca filtreler */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
          {Object.entries(summary.summary)
            .filter(([, v]) => v > 0)
            .slice(0, 8)
            .map(([type, count]) => (
              <Card
                key={type}
                onClick={() => setEventTypeFilter(eventTypeFilter === type ? 'all' : type)}
                className={`bg-zinc-900 border-zinc-800 cursor-pointer transition-colors hover:border-indigo-600 ${eventTypeFilter === type ? 'border-indigo-500 bg-indigo-950/30' : ''}`}
              >
                <CardContent className="p-4">
                  <p className="text-xs text-zinc-500">{EVENT_TYPE_LABELS[type] ?? type}</p>
                  <p className="text-2xl font-bold text-zinc-100 mt-1">{count}</p>
                </CardContent>
              </Card>
            ))}
        </div>
      )}

      {/* Filtreler + tablo */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <CardTitle className="text-sm text-zinc-300 flex-1">Olay Listesi</CardTitle>
            <Input
              placeholder="IP filtrele..."
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              className="w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600"
            />
            <Select value={eventTypeFilter} onValueChange={(v) => setEventTypeFilter(v ?? 'all')}>
              <SelectTrigger className="w-40 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="all" className="text-zinc-300">Tüm tipler</SelectItem>
                {Object.entries(EVENT_TYPE_LABELS).map(([val, label]) => (
                  <SelectItem key={val} value={val} className="text-zinc-300">{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : events.length === 0 ? (
            <p className="text-zinc-600 text-sm text-center py-10">Olay bulunamadı</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">Tip</TableHead>
                  <TableHead className="text-zinc-500 text-xs">Mesaj</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-32">Kaynak IP</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-28">Kullanıcı</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((ev) => (
                  <TableRow key={ev.event_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell><SeverityBadge severity={ev.severity as Severity} /></TableCell>
                    <TableCell className="text-xs text-zinc-300">
                      {EVENT_TYPE_LABELS[ev.event_type] ?? ev.event_type}
                    </TableCell>
                    <TableCell className="text-sm text-zinc-200 max-w-xs truncate">{ev.message}</TableCell>
                    <TableCell className="text-xs text-zinc-400 font-mono">
                      {ev.source_ip ?? '—'}
                      {ev.source_ip && <ThreatBadge ip={ev.source_ip} />}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">{ev.username ?? '—'}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{formatDate(ev.occurred_at)}</TableCell>
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
