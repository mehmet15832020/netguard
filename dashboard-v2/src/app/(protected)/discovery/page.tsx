'use client'

import { useState, useEffect } from 'react'
import { Radar, Play, RefreshCw, Circle, CheckCircle2, Loader2 } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { discoveryApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import type { Device } from '@/types/models'

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function ScanProgress({ running, found, total, cidr }: {
  running: boolean
  found: number
  total: number
  cidr: string | null
}) {
  const pct = total > 0 ? Math.min(100, Math.round((found / total) * 100)) : 0
  if (!cidr) return null

  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardContent className="p-4">
        <div className="flex items-center gap-3 mb-3">
          {running
            ? <Loader2 size={16} className="text-indigo-400 animate-spin" />
            : <CheckCircle2 size={16} className="text-emerald-400" />
          }
          <span className="text-sm text-zinc-200 font-medium">
            {running ? `Taranıyor: ${cidr}` : `Tamamlandı: ${cidr}`}
          </span>
          <Badge className="ml-auto bg-zinc-800 text-zinc-300 border-zinc-700">
            {found} cihaz bulundu
          </Badge>
        </div>

        <div className="w-full h-1.5 bg-zinc-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${running ? 'bg-indigo-500' : 'bg-emerald-500'}`}
            style={{ width: running ? `${pct}%` : '100%' }}
          />
        </div>
        {running && (
          <p className="text-xs text-zinc-500 mt-1.5">
            {found} / {total} host tarandı ({pct}%)
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export default function DiscoveryPage() {
  const queryClient = useQueryClient()
  const [cidr, setCidr] = useState('192.168.1.0/24')
  const [community, setCommunity] = useState('public')

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['discovery-status'],
    queryFn: () => discoveryApi.status(),
    refetchInterval: (query) => query.state.data?.running ? 2000 : 10_000,
  })

  const { data: resultsData, isLoading: resultsLoading, refetch: refetchResults } = useQuery({
    queryKey: ['discovery-results'],
    queryFn: () => discoveryApi.results(200),
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
    <div className="space-y-5">
      {/* Başlık */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
          <Radar size={18} /> Ağ Keşfi
        </h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Subnet tarama ile ağdaki cihazları otomatik keşfet
        </p>
      </div>

      {/* Tarama formu */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm text-zinc-300">Yeni Tarama</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 items-end">
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">Subnet (CIDR)</Label>
              <Input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="192.168.1.0/24"
                className="h-8 text-sm bg-zinc-800 border-zinc-700 text-zinc-200 w-48"
                disabled={isRunning}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-zinc-400">SNMP Community</Label>
              <Input
                value={community}
                onChange={(e) => setCommunity(e.target.value)}
                placeholder="public"
                className="h-8 text-sm bg-zinc-800 border-zinc-700 text-zinc-200 w-32"
                disabled={isRunning}
              />
            </div>
            <Button
              size="sm"
              onClick={() => scanMutation.mutate()}
              disabled={isRunning || scanMutation.isPending || !cidr.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 text-white h-8"
            >
              {isRunning ? (
                <><Loader2 size={14} className="animate-spin" /><span className="ml-1.5">Taranıyor...</span></>
              ) : (
                <><Play size={14} /><span className="ml-1.5">Tara</span></>
              )}
            </Button>
          </div>
          {scanMutation.isError && (
            <p className="text-xs text-red-400 mt-2">
              {(scanMutation.error as Error).message}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Tarama durumu */}
      {status?.cidr && (
        <ScanProgress
          running={isRunning}
          found={status.found}
          total={status.total_probed}
          cidr={status.cidr}
        />
      )}

      {/* Sonuçlar */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-zinc-300">
          Keşfedilen Cihazlar
          <span className="ml-2 text-zinc-500 font-normal">({resultsData?.count ?? 0})</span>
        </h2>
        <Button
          variant="outline" size="sm"
          onClick={() => refetchResults()}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 h-7 text-xs"
        >
          <RefreshCw size={12} className="mr-1" /> Yenile
        </Button>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          {resultsLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : devices.length === 0 ? (
            <div className="text-center py-12">
              <Radar size={32} className="text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500 text-sm">Henüz keşfedilmiş cihaz yok</p>
              <p className="text-zinc-600 text-xs mt-1">Subnet taraması başlatın</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-6"></TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">IP</TableHead>
                  <TableHead className="text-zinc-500 text-xs">Hostname / Adı</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">Vendor</TableHead>
                  <TableHead className="text-zinc-500 text-xs">OS / Bilgi</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">İlk Görülme</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((d) => (
                  <TableRow key={d.device_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell>
                      <Circle
                        size={8}
                        className={
                          d.status === 'up'
                            ? 'text-emerald-400 fill-emerald-400'
                            : 'text-zinc-600 fill-zinc-600'
                        }
                      />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-300">{d.ip}</TableCell>
                    <TableCell className="text-sm text-zinc-200">
                      {d.name !== d.ip ? d.name : <span className="text-zinc-500">—</span>}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">{d.vendor || '—'}</TableCell>
                    <TableCell className="text-xs text-zinc-500 max-w-[200px] truncate">
                      {d.os_info || d.notes || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {formatDate(d.first_seen)}
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
