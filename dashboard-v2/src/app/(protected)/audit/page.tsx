'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ClipboardList, RefreshCw, Search } from 'lucide-react'
import { maintenanceApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

const ACTION_LABELS: Record<string, string> = {
  'api_key.create':    'API Key Oluşturuldu',
  'api_key.delete':    'API Key Silindi',
  'retention.cleanup': 'Temizlik Çalıştırıldı',
  'auth.logout':       'Oturum Kapatıldı',
}

const ACTION_COLORS: Record<string, string> = {
  'api_key.create':    'text-emerald-400',
  'api_key.delete':    'text-red-400',
  'retention.cleanup': 'text-blue-400',
  'auth.logout':       'text-zinc-400',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const LIMITS = [50, 100, 250, 500]

export default function AuditPage() {
  const [actorFilter, setActorFilter] = useState('')
  const [limit, setLimit]             = useState(100)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['audit-log', actorFilter, limit],
    queryFn:  () => maintenanceApi.auditLog({ limit, actor: actorFilter || undefined }),
    refetchInterval: 60_000,
  })

  const events = data?.events ?? []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <ClipboardList size={18} /> Denetim Günlüğü
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">{events.length} kayıt</p>
        </div>
        <Button
          variant="outline" size="sm"
          onClick={() => refetch()}
          disabled={isFetching}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
        >
          <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
          <span className="ml-1.5">Yenile</span>
        </Button>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <CardTitle className="text-sm text-zinc-300 flex-1">Admin Eylem Geçmişi</CardTitle>
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
              <Input
                placeholder="Kullanıcı filtrele..."
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                className="pl-8 w-40 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600"
              />
            </div>
            <Select value={String(limit)} onValueChange={(v) => setLimit(Number(v))}>
              <SelectTrigger className="w-28 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                {LIMITS.map((l) => (
                  <SelectItem key={l} value={String(l)} className="text-zinc-300">
                    Son {l}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : events.length === 0 ? (
            <p className="text-zinc-600 text-sm text-center py-10">Kayıt bulunamadı</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-24">Kullanıcı</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-44">İşlem</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-40">Kaynak</TableHead>
                  <TableHead className="text-zinc-500 text-xs">Detay</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-32">IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((ev) => (
                  <TableRow key={ev.event_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell className="text-xs text-zinc-500 font-mono">
                      {formatDate(ev.timestamp)}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-200 font-medium">
                      {ev.actor}
                    </TableCell>
                    <TableCell className={`text-xs font-medium ${ACTION_COLORS[ev.action] ?? 'text-zinc-300'}`}>
                      {ACTION_LABELS[ev.action] ?? ev.action}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400 font-mono truncate max-w-[10rem]">
                      {ev.resource}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500 max-w-xs truncate">
                      {ev.detail ?? '—'}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500 font-mono">
                      {ev.ip_address ?? '—'}
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
