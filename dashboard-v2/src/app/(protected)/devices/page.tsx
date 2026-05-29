'use client'

import { useState } from 'react'
import { Monitor, RefreshCw, Circle, Search, Settings2, X, ChevronDown, ChevronUp } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { devicesApi } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { Device, DeviceType } from '@/types/models'

const TYPE_LABELS: Record<DeviceType, string> = {
  agent:      'Agent',
  snmp:       'SNMP',
  discovered: 'Keşfedilen',
  hybrid:     'Hibrit',
}

const TYPE_COLORS: Record<DeviceType, string> = {
  agent:      'bg-sky-500/10 text-sky-300 border-sky-500/25',
  snmp:       'bg-blue-500/10 text-blue-300 border-blue-500/25',
  discovered: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  hybrid:     'bg-violet-500/10 text-violet-300 border-violet-500/25',
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === 'up'   ? 'text-emerald-400 fill-emerald-400' :
    status === 'down' ? 'text-red-400 fill-red-400' :
                        'text-slate-700 fill-slate-700'
  return <Circle size={8} className={cn('shrink-0', cls)} />
}

function DeviceTypeBadge({ type }: { type: DeviceType }) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border backdrop-blur-sm',
      TYPE_COLORS[type] ?? 'bg-sky-950/20 text-slate-500 border-sky-900/20',
    )}>
      {TYPE_LABELS[type] ?? type}
    </span>
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

const INP = 'w-full bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors'
const SEL = 'h-9 bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 text-sm text-slate-200 focus:outline-none focus:border-sky-500/50 transition-colors'

function SNMPModal({ device, onClose }: { device: Device; onClose: () => void }) {
  const qc = useQueryClient()
  const [community,   setCommunity]   = useState((device as any).snmp_community || 'public')
  const [version,     setVersion]     = useState<'v2c' | 'v3'>((device as any).snmp_version || 'v2c')
  const [showV3,      setShowV3]      = useState(version === 'v3')
  const [v3User,      setV3User]      = useState((device as any).snmp_v3_username || '')
  const [v3AuthProto, setV3AuthProto] = useState<'MD5' | 'SHA'>((device as any).snmp_v3_auth_protocol || 'SHA')
  const [v3AuthKey,   setV3AuthKey]   = useState('')
  const [v3PrivProto, setV3PrivProto] = useState<'DES' | 'AES'>((device as any).snmp_v3_priv_protocol || 'AES')
  const [v3PrivKey,   setV3PrivKey]   = useState('')
  const [saved,       setSaved]       = useState(false)

  const { mutate, isPending, isError } = useMutation({
    mutationFn: () => devicesApi.updateSnmp(device.device_id, {
      community,
      snmp_version:     version,
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#040911]/80 backdrop-blur-sm">
      <div className="bg-[#0a1120] border border-sky-900/30 rounded-xl w-full max-w-md mx-4 shadow-[0_24px_64px_rgba(0,0,0,0.8)]">
        <div className="flex items-center justify-between px-5 py-4 border-b border-sky-900/20">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">SNMP Ayarları</h2>
            <p className="text-xs text-slate-600 mt-0.5">{device.name} · {device.ip}</p>
          </div>
          <button onClick={onClose} className="text-slate-600 hover:text-slate-300 transition-colors">
            <X size={15} />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="flex gap-3">
            <div className="space-y-1">
              <span className="text-xs text-slate-500">Versiyon</span>
              <select
                value={version}
                onChange={e => { const v = e.target.value as 'v2c' | 'v3'; setVersion(v); setShowV3(v === 'v3') }}
                className={SEL}
              >
                <option value="v2c">SNMPv2c</option>
                <option value="v3">SNMPv3</option>
              </select>
            </div>
            {version === 'v2c' && (
              <div className="flex-1 space-y-1">
                <span className="text-xs text-slate-500">Community</span>
                <input value={community} onChange={e => setCommunity(e.target.value)}
                  placeholder="public" className={INP} />
              </div>
            )}
          </div>

          {version === 'v3' && (
            <div className="border border-sky-900/25 rounded-lg p-3 space-y-3">
              <button
                type="button"
                onClick={() => setShowV3(!showV3)}
                className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors"
              >
                {showV3 ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                SNMPv3 Kimlik Bilgileri
              </button>
              {showV3 && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="col-span-2 space-y-1">
                    <span className="text-xs text-slate-500">Kullanıcı Adı</span>
                    <input value={v3User} onChange={e => setV3User(e.target.value)}
                      placeholder="netguard" className={INP} />
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Auth Protokol</span>
                    <select value={v3AuthProto} onChange={e => setV3AuthProto(e.target.value as 'MD5' | 'SHA')}
                      className={cn(SEL, 'w-full')}>
                      <option value="SHA">SHA</option>
                      <option value="MD5">MD5</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Auth Key</span>
                    <input type="password" value={v3AuthKey} onChange={e => setV3AuthKey(e.target.value)}
                      placeholder="••••••••" className={INP} />
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Priv Protokol</span>
                    <select value={v3PrivProto} onChange={e => setV3PrivProto(e.target.value as 'DES' | 'AES')}
                      className={cn(SEL, 'w-full')}>
                      <option value="AES">AES</option>
                      <option value="DES">DES</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Priv Key</span>
                    <input type="password" value={v3PrivKey} onChange={e => setV3PrivKey(e.target.value)}
                      placeholder="••••••••" className={INP} />
                  </div>
                </div>
              )}
            </div>
          )}

          {isError && <p className="text-xs text-red-400">Kaydedilemedi, tekrar deneyin.</p>}
        </div>

        <div className="flex justify-end gap-2 px-5 py-3 border-t border-sky-900/20">
          <button onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs text-slate-400 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors">
            İptal
          </button>
          <button onClick={() => mutate()} disabled={isPending || saved}
            className="px-3 py-1.5 rounded-lg text-xs text-white bg-sky-600 hover:bg-sky-500 transition-colors disabled:opacity-60 shadow-[0_0_12px_rgba(56,189,248,0.15)]">
            {saved ? 'Kaydedildi ✓' : isPending ? 'Kaydediliyor...' : 'Kaydet'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function DevicesPage() {
  const [typeFilter, setTypeFilter] = useState('')
  const [search,     setSearch]     = useState('')
  const [snmpDevice, setSnmpDevice] = useState<Device | null>(null)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['devices', typeFilter],
    queryFn:  () => devicesApi.list(typeFilter || undefined),
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
    <div className="p-6 space-y-5">
      {snmpDevice && <SNMPModal device={snmpDevice} onClose={() => setSnmpDevice(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Monitor size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Cihazlar</h1>
            <p className="text-xs text-slate-600">
              {data?.count ?? 0} cihaz · {counts.up} up · {counts.down} down
              {isFetching && <RefreshCw size={10} className="inline ml-1.5 animate-spin" />}
            </p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
          Yenile
        </button>
      </div>

      {/* Status cards */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Erişilebilir', value: counts.up,      color: 'text-emerald-400' },
          { label: 'Erişilemiyor', value: counts.down,    color: 'text-red-400' },
          { label: 'Bilinmiyor',   value: counts.unknown, color: 'text-slate-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
            <p className="text-xs text-slate-500">{label}</p>
            <p className={cn('text-2xl font-bold mt-1', color)}>{value}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
          <input
            placeholder="IP, isim, vendor..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-xs bg-sky-950/20 border border-sky-900/25 rounded-lg text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors w-52"
          />
        </div>
        <div className="flex gap-1">
          {FILTER_TYPES.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setTypeFilter(value)}
              className={cn(
                'px-3 py-1 rounded-lg text-xs transition-colors border',
                typeFilter === value
                  ? 'bg-sky-500/15 text-sky-400 border-sky-500/30'
                  : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={7} height={40} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Monitor size={28} className="opacity-20" />
            <p className="text-sm">{search ? 'Arama sonucu bulunamadı' : 'Kayıtlı cihaz yok'}</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sky-900/15 text-xs text-slate-600 uppercase tracking-wide">
                <th className="px-4 py-3 w-6" />
                <th className="px-4 py-3 text-left">Cihaz</th>
                <th className="px-4 py-3 text-left w-32">IP</th>
                <th className="px-4 py-3 text-left w-28">Tür</th>
                <th className="px-4 py-3 text-left w-32">Vendor</th>
                <th className="px-4 py-3 text-left w-40">OS</th>
                <th className="px-4 py-3 text-left w-36">Son Görülme</th>
                <th className="px-4 py-3 text-left w-24">SNMP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {filtered.map((device) => {
                const hasCommunity = !!(device as any).snmp_community
                return (
                  <tr
                    key={device.device_id}
                    className="hover:bg-sky-950/20 cursor-pointer transition-colors"
                    onClick={() => window.location.href = `/devices/${device.device_id}`}
                  >
                    <td className="px-4 py-3">
                      <StatusDot status={device.status} />
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-slate-200 font-medium">{device.name}</p>
                      {device.mac && <p className="text-xs text-slate-600 font-mono">{device.mac}</p>}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">{device.ip || '—'}</td>
                    <td className="px-4 py-3"><DeviceTypeBadge type={device.type} /></td>
                    <td className="px-4 py-3 text-xs text-slate-500">{device.vendor || '—'}</td>
                    <td className="px-4 py-3 text-xs text-slate-500 max-w-[160px] truncate">{device.os_info || '—'}</td>
                    <td className="px-4 py-3 text-xs text-slate-600 whitespace-nowrap">{formatDate(device.last_seen)}</td>
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => setSnmpDevice(device)}
                        title="SNMP ayarla"
                        className={cn(
                          'flex items-center gap-1 text-xs px-2 py-1 rounded-lg transition-colors border',
                          hasCommunity
                            ? 'text-sky-400 bg-sky-500/10 border-sky-500/20 hover:bg-sky-500/20'
                            : 'text-slate-600 bg-sky-950/20 border-sky-900/15 hover:text-slate-400',
                        )}
                      >
                        <Settings2 size={11} />
                        {hasCommunity ? (device as any).snmp_community : 'Ayarla'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
