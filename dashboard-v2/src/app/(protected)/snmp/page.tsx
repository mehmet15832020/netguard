'use client'

import { useState } from 'react'
import { Network, Search, CheckCircle, XCircle, Clock, ArrowDownUp, ChevronDown, ChevronUp, Activity } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { snmpApi, type SNMPDeviceInfo, type SNMPInterface } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

function formatUptime(ticks: number): string {
  if (!ticks) return '—'
  const totalSeconds = Math.floor(ticks / 100)
  const days    = Math.floor(totalSeconds / 86400)
  const hours   = Math.floor((totalSeconds % 86400) / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  if (days > 0) return `${days}g ${hours}s ${minutes}d`
  if (hours > 0) return `${hours}s ${minutes}d`
  return `${minutes}d`
}

function formatBytes(bytes: number): string {
  if (!bytes) return '—'
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`
  return `${bytes} B`
}

function ifOperStatusLabel(status: number): { label: string; color: string } {
  switch (status) {
    case 1: return { label: 'up',      color: 'text-emerald-400' }
    case 2: return { label: 'down',    color: 'text-red-400' }
    case 3: return { label: 'testing', color: 'text-yellow-400' }
    default: return { label: '—',      color: 'text-zinc-500' }
  }
}

function formatBps(bps: number): string {
  if (!bps) return '—'
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`
  return `${bps.toFixed(0)} bps`
}

function InterfaceRow({ iface }: { iface: SNMPInterface }) {
  const status = ifOperStatusLabel(iface.oper_status)
  return (
    <div className="border border-zinc-800 rounded-md p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-zinc-200">{iface.name}</span>
        <span className={`text-xs font-medium ${status.color}`}>{status.label}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        <Row label="Toplam Gelen"  value={formatBytes(iface.hc_in_octets)}  icon={<ArrowDownUp size={10} className="text-zinc-500" />} />
        <Row label="Toplam Giden"  value={formatBytes(iface.hc_out_octets)} />
        <Row label="Anlık Gelen"   value={formatBps(iface.bandwidth_in_bps)} />
        <Row label="Anlık Giden"   value={formatBps(iface.bandwidth_out_bps)} />
        {iface.in_errors > 0 && <Row label="Hata (gelen)" value={String(iface.in_errors)} valueClass="text-red-400" />}
        {iface.out_errors > 0 && <Row label="Hata (giden)" value={String(iface.out_errors)} valueClass="text-red-400" />}
      </div>
    </div>
  )
}

function ResultCard({ info }: { info: SNMPDeviceInfo }) {
  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader className="pb-2 pt-4 px-4">
        <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
          {info.reachable
            ? <CheckCircle size={14} className="text-emerald-400" />
            : <XCircle    size={14} className="text-red-400" />
          }
          {info.reachable ? 'Cihaz erişilebilir' : 'Cihaza ulaşılamadı'}
          <span className="text-zinc-500 font-normal ml-1">— {info.host}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!info.reachable ? (
          <p className="text-sm text-red-400">
            {info.error || 'Cihaz yanıt vermedi veya SNMP devre dışı.'}
          </p>
        ) : (
          <>
            {/* Sistem bilgileri */}
            <div className="space-y-2">
              <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Sistem</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                <Row label="Hostname"  value={info.sys_name  || '—'} />
                <Row label="Community" value={info.community} />
                <Row label="Uptime"    value={formatUptime(info.uptime_ticks)} icon={<Clock size={12} className="text-zinc-500" />} />
                <Row label="Açıklama"  value={info.sys_descr ? info.sys_descr.slice(0, 60) + (info.sys_descr.length > 60 ? '…' : '') : '—'} />
              </div>
            </div>

            {/* Arayüzler */}
            {info.interfaces.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider flex items-center gap-1">
                  <Activity size={11} /> Arayüzler ({info.interfaces.length})
                  {info.interfaces.some(i => i.bandwidth_in_bps === 0) && (
                    <span className="text-zinc-600 font-normal normal-case ml-1">· Anlık hız için tekrar sorgula</span>
                  )}
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {info.interfaces.map(iface => (
                    <InterfaceRow key={iface.index} iface={iface} />
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function Row({
  label, value, icon, valueClass = 'text-zinc-200',
}: {
  label: string
  value: string
  icon?: React.ReactNode
  valueClass?: string
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs text-zinc-500 shrink-0">{label}</span>
      <span className={`text-sm text-right break-all ${valueClass} flex items-center gap-1`}>
        {icon}{value}
      </span>
    </div>
  )
}

export default function SNMPPage() {
  const [host, setHost]           = useState('')
  const [community, setCommunity] = useState('public')
  const [version, setVersion]     = useState<'v2c' | 'v3'>('v2c')
  const [showV3, setShowV3]       = useState(false)
  const [v3User, setV3User]       = useState('')
  const [v3AuthProto, setV3AuthProto] = useState<'MD5' | 'SHA'>('SHA')
  const [v3AuthKey, setV3AuthKey] = useState('')
  const [v3PrivProto, setV3PrivProto] = useState<'DES' | 'AES'>('AES')
  const [v3PrivKey, setV3PrivKey] = useState('')
  const [lastResult, setLastResult] = useState<SNMPDeviceInfo | null>(null)

  const { mutate, isPending, isError, error } = useMutation({
    mutationFn: () => snmpApi.poll({
      host: host.trim(),
      community: community.trim() || 'public',
      snmp_version: version,
      v3_username:       version === 'v3' ? v3User     : undefined,
      v3_auth_protocol:  version === 'v3' ? v3AuthProto: undefined,
      v3_auth_key:       version === 'v3' ? v3AuthKey  : undefined,
      v3_priv_protocol:  version === 'v3' ? v3PrivProto: undefined,
      v3_priv_key:       version === 'v3' ? v3PrivKey  : undefined,
    }),
    onSuccess: (data) => setLastResult(data),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!host.trim()) return
    mutate()
  }

  const inputCls = "bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-600"

  return (
    <div className="space-y-6">
      {/* Başlık */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">SNMP Sorgulama</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Router, switch veya SNMP destekli cihazları sorgula (v2c / v3)
        </p>
      </div>

      {/* Sorgu formu */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3 pt-4 px-4">
          <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
            <Network size={14} /> Cihaz Sorgusu
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Satır 1: host + community + version */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="flex-1 space-y-1">
                <Label htmlFor="host" className="text-xs text-zinc-400">IP Adresi veya Hostname</Label>
                <Input
                  id="host"
                  value={host}
                  onChange={e => setHost(e.target.value)}
                  placeholder="192.168.1.1"
                  required
                  className={inputCls}
                />
              </div>
              <div className="w-full sm:w-36 space-y-1">
                <Label htmlFor="version" className="text-xs text-zinc-400">Versiyon</Label>
                <select
                  id="version"
                  value={version}
                  onChange={e => {
                    const v = e.target.value as 'v2c' | 'v3'
                    setVersion(v)
                    setShowV3(v === 'v3')
                  }}
                  className="w-full h-10 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3"
                >
                  <option value="v2c">SNMPv2c</option>
                  <option value="v3">SNMPv3</option>
                </select>
              </div>
              {version === 'v2c' && (
                <div className="w-full sm:w-36 space-y-1">
                  <Label htmlFor="community" className="text-xs text-zinc-400">Community</Label>
                  <Input
                    id="community"
                    value={community}
                    onChange={e => setCommunity(e.target.value)}
                    placeholder="public"
                    className={inputCls}
                  />
                </div>
              )}
              <div className="flex items-end">
                <Button
                  type="submit"
                  disabled={isPending || !host.trim()}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white w-full sm:w-auto"
                >
                  {isPending
                    ? <><span className="animate-spin mr-2">⟳</span>Sorgulanıyor...</>
                    : <><Search size={14} className="mr-2" />Sorgula</>
                  }
                </Button>
              </div>
            </div>

            {/* SNMPv3 alanları */}
            {version === 'v3' && (
              <div className="border border-zinc-700 rounded-lg p-4 space-y-3">
                <button
                  type="button"
                  onClick={() => setShowV3(!showV3)}
                  className="flex items-center gap-2 text-xs text-zinc-400 hover:text-zinc-200"
                >
                  {showV3 ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  SNMPv3 Kimlik Bilgileri
                </button>
                {showV3 && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <Label className="text-xs text-zinc-400">Kullanıcı Adı</Label>
                      <Input value={v3User} onChange={e => setV3User(e.target.value)}
                        placeholder="netguard" className={inputCls} />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-zinc-400">Auth Protokol</Label>
                      <select value={v3AuthProto} onChange={e => setV3AuthProto(e.target.value as 'MD5' | 'SHA')}
                        className="w-full h-10 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3">
                        <option value="SHA">SHA</option>
                        <option value="MD5">MD5</option>
                      </select>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-zinc-400">Auth Key</Label>
                      <Input type="password" value={v3AuthKey} onChange={e => setV3AuthKey(e.target.value)}
                        placeholder="auth şifresi" className={inputCls} />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs text-zinc-400">Priv Protokol</Label>
                      <select value={v3PrivProto} onChange={e => setV3PrivProto(e.target.value as 'DES' | 'AES')}
                        className="w-full h-10 rounded-md border border-zinc-700 bg-zinc-800 text-zinc-100 text-sm px-3">
                        <option value="AES">AES</option>
                        <option value="DES">DES</option>
                      </select>
                    </div>
                    <div className="space-y-1 sm:col-span-2">
                      <Label className="text-xs text-zinc-400">Priv Key</Label>
                      <Input type="password" value={v3PrivKey} onChange={e => setV3PrivKey(e.target.value)}
                        placeholder="priv şifresi" className={inputCls} />
                    </div>
                  </div>
                )}
              </div>
            )}
          </form>

          {isError && (
            <p className="mt-3 text-sm text-red-400 bg-red-900/20 border border-red-800 rounded px-3 py-2">
              {error instanceof Error ? error.message : 'Sorgu başarısız'}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Sonuç */}
      {lastResult && <ResultCard info={lastResult} />}

      {/* Bilgi kutusu */}
      {!lastResult && (
        <Card className="bg-zinc-900/50 border-zinc-800/50">
          <CardContent className="py-8 text-center">
            <Network className="mx-auto mb-3 text-zinc-700" size={32} />
            <p className="text-zinc-500 text-sm">
              SNMP destekli bir cihazın IP'sini girerek sorgulayabilirsin.
            </p>
            <p className="text-zinc-600 text-xs mt-1">
              Varsayılan community: <span className="font-mono">public</span> — port 161 UDP
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
