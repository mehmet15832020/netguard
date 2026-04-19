'use client'

import { useState } from 'react'
import { Monitor, RefreshCw, Circle, Search } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { devicesApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import type { Device, DeviceType } from '@/types/models'

const TYPE_LABELS: Record<DeviceType, string> = {
  agent:      'Agent',
  snmp:       'SNMP',
  discovered: 'Keşfedilen',
  hybrid:     'Hibrit',
}

const TYPE_COLORS: Record<DeviceType, string> = {
  agent:      'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
  snmp:       'bg-blue-500/20 text-blue-300 border-blue-500/30',
  discovered: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  hybrid:     'bg-purple-500/20 text-purple-300 border-purple-500/30',
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === 'up'      ? 'text-emerald-400 fill-emerald-400' :
    status === 'down'    ? 'text-red-400 fill-red-400' :
                           'text-zinc-600 fill-zinc-600'
  return <Circle size={8} className={`shrink-0 ${color}`} />
}

function DeviceTypeBadge({ type }: { type: DeviceType }) {
  return (
    <Badge className={`text-xs border ${TYPE_COLORS[type] ?? 'bg-zinc-700 text-zinc-300'}`}>
      {TYPE_LABELS[type] ?? type}
    </Badge>
  )
}

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

const FILTER_TYPES: { value: string; label: string }[] = [
  { value: '',           label: 'Tümü' },
  { value: 'agent',      label: 'Agent' },
  { value: 'snmp',       label: 'SNMP' },
  { value: 'discovered', label: 'Keşfedilen' },
]

export default function DevicesPage() {
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch] = useState('')

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['devices', typeFilter],
    queryFn: () => devicesApi.list(typeFilter || undefined),
    refetchInterval: 30_000,
  })

  const devices: Device[] = data?.devices ?? []

  const filtered = devices.filter((d) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      d.name.toLowerCase().includes(q) ||
      d.ip.toLowerCase().includes(q) ||
      d.vendor.toLowerCase().includes(q) ||
      d.os_info.toLowerCase().includes(q)
    )
  })

  const counts = {
    up:      devices.filter(d => d.status === 'up').length,
    down:    devices.filter(d => d.status === 'down').length,
    unknown: devices.filter(d => d.status === 'unknown').length,
  }

  return (
    <div className="space-y-5">
      {/* Başlık */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Monitor size={18} /> Cihazlar
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {data?.count ?? 0} cihaz · {counts.up} up · {counts.down} down
          </p>
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

      {/* Durum kartları */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Erişilebilir', value: counts.up,      color: 'text-emerald-400' },
          { label: 'Erişilemiyor', value: counts.down,    color: 'text-red-400' },
          { label: 'Bilinmiyor',   value: counts.unknown, color: 'text-zinc-400' },
        ].map(({ label, value, color }) => (
          <Card key={label} className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-4">
              <p className="text-xs text-zinc-500">{label}</p>
              <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filtreler */}
      <div className="flex flex-wrap gap-3">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <Input
            placeholder="IP, isim, vendor..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-sm bg-zinc-900 border-zinc-700 text-zinc-200 w-56"
          />
        </div>
        <div className="flex gap-1">
          {FILTER_TYPES.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setTypeFilter(value)}
              className={`px-3 py-1 rounded text-xs transition-colors ${
                typeFilter === value
                  ? 'bg-indigo-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tablo */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : filtered.length === 0 ? (
            <p className="text-zinc-600 text-sm text-center py-10">
              {search ? 'Arama sonucu bulunamadı' : 'Kayıtlı cihaz yok'}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-6"></TableHead>
                  <TableHead className="text-zinc-500 text-xs">Cihaz</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-32">IP</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-28">Tür</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-32">Vendor</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-40">OS</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">Son Görülme</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((device) => (
                  <TableRow key={device.device_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell>
                      <StatusDot status={device.status} />
                    </TableCell>
                    <TableCell>
                      <p className="text-sm text-zinc-200 font-medium">{device.name}</p>
                      {device.mac && (
                        <p className="text-xs text-zinc-500 font-mono">{device.mac}</p>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-300">
                      {device.ip || '—'}
                    </TableCell>
                    <TableCell>
                      <DeviceTypeBadge type={device.type} />
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">
                      {device.vendor || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400 max-w-[160px] truncate">
                      {device.os_info || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {formatDate(device.last_seen)}
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
