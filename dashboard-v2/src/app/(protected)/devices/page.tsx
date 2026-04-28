'use client'

import { useState } from 'react'
import { Monitor, RefreshCw, Circle, Search, Settings2, X, ChevronDown, ChevronUp } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
    status === 'up'   ? 'text-emerald-400 fill-emerald-400' :
    status === 'down' ? 'text-red-400 fill-red-400' :
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

const FILTER_TYPES = [
  { value: '',           label: 'Tümü' },
  { value: 'agent',      label: 'Agent' },
  { value: 'snmp',       label: 'SNMP' },
  { value: 'discovered', label: 'Keşfedilen' },
]

// ------------------------------------------------------------------ //
//  SNMP Ayarla Modal
// ------------------------------------------------------------------ //

function SNMPModal({
  device,
  onClose,
}: {
  device: Device
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [community, setCommunity] = useState((device as any).snmp_community || 'public')
  const [version, setVersion]     = useState<'v2c' | 'v3'>((device as any).snmp_version || 'v2c')
  const [showV3, setShowV3]       = useState(version === 'v3')
  const [v3User, setV3User]       = useState((device as any).snmp_v3_username || '')
  const [v3AuthProto, setV3AuthProto] = useState<'MD5' | 'SHA'>((device as any).snmp_v3_auth_protocol || 'SHA')
  const [v3AuthKey, setV3AuthKey] = useState('')
  const [v3PrivProto, setV3PrivProto] = useState<'DES' | 'AES'>((device as any).snmp_v3_priv_protocol || 'AES')
  const [v3PrivKey, setV3PrivKey] = useState('')
  const [saved, setSaved]         = useState(false)

  const { mutate, isPending, isError } = useMutation({
    mutationFn: () => devicesApi.updateSnmp(device.device_id, {
      community,
      snmp_version: version,
      v3_username:      version === 'v3' ? v3User      : undefined,
      v3_auth_protocol: version === 'v3' ? v3AuthProto : undefined,
      v3_auth_key:      version === 'v3' ? v3AuthKey   : undefined,
      v3_priv_protocol: version === 'v3' ? v3PrivProto : undefined,
      v3_priv_key:      version === 'v3' ? v3PrivKey   : undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      setSaved(true)
      setTimeout(onClose, 800)
    },
  })

  const inp = 'bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-600'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-zinc-900 border border-zinc-700 rounded-lg w-full max-w-md mx-4 shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">SNMP Ayarları</h2>
            <p className="text-xs text-zinc-500 mt-0.5">{device.name} · {device.ip}</p>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-4">
          {/* Version + Community */}
          <div className="flex gap-3">
            <div className="space-y-1">
              <Label className="text-xs text-zinc-400">Versiyon</Label>
              <select
                value={version}
                onChange={e => { const v = e.target.value as 'v2c'|'v3'; setVersion(v); setShowV3(v === 'v3') }}
                className="h-9 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3"
              >
                <option value="v2c">SNMPv2c</option>
                <option value="v3">SNMPv3</option>
              </select>
            </div>
            {version === 'v2c' && (
              <div className="flex-1 space-y-1">
                <Label className="text-xs text-zinc-400">Community</Label>
                <Input value={community} onChange={e => setCommunity(e.target.value)}
                  placeholder="public" className={inp} />
              </div>
            )}
          </div>

          {/* SNMPv3 fields */}
          {version === 'v3' && (
            <div className="border border-zinc-700 rounded-lg p-3 space-y-3">
              <button
                type="button"
                onClick={() => setShowV3(!showV3)}
                className="flex items-center gap-2 text-xs text-zinc-400 hover:text-zinc-200"
              >
                {showV3 ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                SNMPv3 Kimlik Bilgileri
              </button>
              {showV3 && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="col-span-2 space-y-1">
                    <Label className="text-xs text-zinc-400">Kullanıcı Adı</Label>
                    <Input value={v3User} onChange={e => setV3User(e.target.value)}
                      placeholder="netguard" className={inp} />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-zinc-400">Auth Protokol</Label>
                    <select value={v3AuthProto} onChange={e => setV3AuthProto(e.target.value as 'MD5'|'SHA')}
                      className="w-full h-9 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3">
                      <option value="SHA">SHA</option>
                      <option value="MD5">MD5</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-zinc-400">Auth Key</Label>
                    <Input type="password" value={v3AuthKey} onChange={e => setV3AuthKey(e.target.value)}
                      placeholder="••••••••" className={inp} />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-zinc-400">Priv Protokol</Label>
                    <select value={v3PrivProto} onChange={e => setV3PrivProto(e.target.value as 'DES'|'AES')}
                      className="w-full h-9 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3">
                      <option value="AES">AES</option>
                      <option value="DES">DES</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs text-zinc-400">Priv Key</Label>
                    <Input type="password" value={v3PrivKey} onChange={e => setV3PrivKey(e.target.value)}
                      placeholder="••••••••" className={inp} />
                  </div>
                </div>
              )}
            </div>
          )}

          {isError && (
            <p className="text-xs text-red-400">Kaydedilemedi, tekrar deneyin.</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-zinc-800">
          <Button variant="outline" size="sm" onClick={onClose}
            className="border-zinc-700 text-zinc-400 hover:bg-zinc-800">
            İptal
          </Button>
          <Button size="sm" onClick={() => mutate()} disabled={isPending || saved}
            className="bg-indigo-600 hover:bg-indigo-500 text-white">
            {saved ? 'Kaydedildi ✓' : isPending ? 'Kaydediliyor...' : 'Kaydet'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Ana sayfa
// ------------------------------------------------------------------ //

export default function DevicesPage() {
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch]         = useState('')
  const [snmpDevice, setSnmpDevice] = useState<Device | null>(null)

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
      {snmpDevice && (
        <SNMPModal device={snmpDevice} onClose={() => setSnmpDevice(null)} />
      )}

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
                  <TableHead className="text-zinc-500 text-xs w-20">SNMP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((device) => {
                  const hasCommunity = !!(device as any).snmp_community
                  return (
                    <TableRow
                      key={device.device_id}
                      className="border-zinc-800 hover:bg-zinc-800/50 cursor-pointer"
                      onClick={() => window.location.href = `/devices/${device.device_id}`}
                    >
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
                      <TableCell>
                        <button
                          onClick={() => setSnmpDevice(device)}
                          title="SNMP ayarla"
                          className={`flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors ${
                            hasCommunity
                              ? 'text-blue-400 bg-blue-500/10 hover:bg-blue-500/20'
                              : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-700'
                          }`}
                        >
                          <Settings2 size={12} />
                          {hasCommunity ? (device as any).snmp_community : 'Ayarla'}
                        </button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
