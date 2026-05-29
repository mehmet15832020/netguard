'use client'

import { useState } from 'react'
import { Network, Search, CheckCircle, XCircle, Clock, ArrowDownUp, ChevronDown, ChevronUp, Activity } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { snmpApi, type SNMPDeviceInfo, type SNMPInterface } from '@/lib/api'
import { cn } from '@/lib/utils'

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
    case 1:  return { label: 'up',      color: 'text-emerald-400' }
    case 2:  return { label: 'down',    color: 'text-red-400' }
    case 3:  return { label: 'testing', color: 'text-yellow-400' }
    default: return { label: '—',       color: 'text-slate-600' }
  }
}

function formatBps(bps: number): string {
  if (!bps) return '—'
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`
  return `${bps.toFixed(0)} bps`
}

function Row({
  label, value, icon, valueClass = 'text-slate-200',
}: {
  label: string; value: string; icon?: React.ReactNode; valueClass?: string
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs text-slate-600 shrink-0">{label}</span>
      <span className={cn('text-xs text-right break-all flex items-center gap-1 font-mono', valueClass)}>
        {icon}{value}
      </span>
    </div>
  )
}

function InterfaceRow({ iface }: { iface: SNMPInterface }) {
  const status = ifOperStatusLabel(iface.oper_status)
  return (
    <div className="border border-sky-900/20 bg-sky-950/10 rounded-lg p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-slate-200">{iface.name}</span>
        <span className={cn('text-xs font-medium', status.color)}>{status.label}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        <Row label="Toplam Gelen"  value={formatBytes(iface.hc_in_octets)}   icon={<ArrowDownUp size={10} className="text-slate-600" />} />
        <Row label="Toplam Giden"  value={formatBytes(iface.hc_out_octets)} />
        <Row label="Anlık Gelen"   value={formatBps(iface.bandwidth_in_bps)} />
        <Row label="Anlık Giden"   value={formatBps(iface.bandwidth_out_bps)} />
        {iface.in_errors  > 0 && <Row label="Hata (gelen)" value={String(iface.in_errors)}  valueClass="text-red-400" />}
        {iface.out_errors > 0 && <Row label="Hata (giden)" value={String(iface.out_errors)} valueClass="text-red-400" />}
      </div>
    </div>
  )
}

function ResultCard({ info }: { info: SNMPDeviceInfo }) {
  return (
    <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
        {info.reachable
          ? <CheckCircle size={14} className="text-emerald-400" />
          : <XCircle    size={14} className="text-red-400" />
        }
        <span className="text-sm font-medium text-slate-200">
          {info.reachable ? 'Cihaz erişilebilir' : 'Cihaza ulaşılamadı'}
        </span>
        <span className="text-slate-600 text-xs ml-1">— {info.host}</span>
      </div>

      <div className="p-4 space-y-5">
        {!info.reachable ? (
          <p className="text-sm text-red-400">
            {info.error || 'Cihaz yanıt vermedi veya SNMP devre dışı.'}
          </p>
        ) : (
          <>
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Sistem</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
                <Row label="Hostname"  value={info.sys_name  || '—'} />
                <Row label="Community" value={info.community} />
                <Row label="Uptime"    value={formatUptime(info.uptime_ticks)} icon={<Clock size={11} className="text-slate-600" />} />
                <Row label="Açıklama"  value={info.sys_descr ? info.sys_descr.slice(0, 60) + (info.sys_descr.length > 60 ? '…' : '') : '—'} />
              </div>
            </div>

            {info.interfaces.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-600 uppercase tracking-wide flex items-center gap-1.5">
                  <Activity size={11} /> Arayüzler ({info.interfaces.length})
                  {info.interfaces.some(i => i.bandwidth_in_bps === 0) && (
                    <span className="text-slate-700 font-normal normal-case">· Anlık hız için tekrar sorgula</span>
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
      </div>
    </div>
  )
}

const INP = 'w-full bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors'
const SEL = 'w-full h-9 bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 text-sm text-slate-200 focus:outline-none focus:border-sky-500/50 transition-colors'

export default function SNMPPage() {
  const [host,        setHost]        = useState('')
  const [community,   setCommunity]   = useState('public')
  const [version,     setVersion]     = useState<'v2c' | 'v3'>('v2c')
  const [showV3,      setShowV3]      = useState(false)
  const [v3User,      setV3User]      = useState('')
  const [v3AuthProto, setV3AuthProto] = useState<'MD5' | 'SHA'>('SHA')
  const [v3AuthKey,   setV3AuthKey]   = useState('')
  const [v3PrivProto, setV3PrivProto] = useState<'DES' | 'AES'>('AES')
  const [v3PrivKey,   setV3PrivKey]   = useState('')
  const [lastResult,  setLastResult]  = useState<SNMPDeviceInfo | null>(null)

  const { mutate, isPending, isError, error } = useMutation({
    mutationFn: () => snmpApi.poll({
      host:             host.trim(),
      community:        community.trim() || 'public',
      snmp_version:     version,
      v3_username:      version === 'v3' ? v3User      : undefined,
      v3_auth_protocol: version === 'v3' ? v3AuthProto : undefined,
      v3_auth_key:      version === 'v3' ? v3AuthKey   : undefined,
      v3_priv_protocol: version === 'v3' ? v3PrivProto : undefined,
      v3_priv_key:      version === 'v3' ? v3PrivKey   : undefined,
    }),
    onSuccess: (data) => setLastResult(data),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!host.trim()) return
    mutate()
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <Network size={15} className="text-sky-400" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-slate-100 leading-tight">SNMP Sorgulama</h1>
          <p className="text-xs text-slate-600">Router, switch veya SNMP destekli cihazları sorgula (v2c / v3)</p>
        </div>
      </div>

      {/* Query form */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Network size={13} className="text-slate-600" />
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Cihaz Sorgusu</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-end">
            <div className="flex-1 space-y-1">
              <label htmlFor="host" className="text-xs text-slate-500">IP Adresi veya Hostname</label>
              <input
                id="host"
                value={host}
                onChange={e => setHost(e.target.value)}
                placeholder="192.168.1.1"
                required
                className={INP}
              />
            </div>
            <div className="w-full sm:w-36 space-y-1">
              <label htmlFor="version" className="text-xs text-slate-500">Versiyon</label>
              <select
                id="version"
                value={version}
                onChange={e => {
                  const v = e.target.value as 'v2c' | 'v3'
                  setVersion(v)
                  setShowV3(v === 'v3')
                }}
                className={SEL}
              >
                <option value="v2c">SNMPv2c</option>
                <option value="v3">SNMPv3</option>
              </select>
            </div>
            {version === 'v2c' && (
              <div className="w-full sm:w-36 space-y-1">
                <label htmlFor="community" className="text-xs text-slate-500">Community</label>
                <input
                  id="community"
                  value={community}
                  onChange={e => setCommunity(e.target.value)}
                  placeholder="public"
                  className={INP}
                />
              </div>
            )}
            <button
              type="submit"
              disabled={isPending || !host.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-sm text-white bg-sky-600 hover:bg-sky-500 transition-colors shadow-[0_0_12px_rgba(56,189,248,0.15)] disabled:opacity-60 disabled:shadow-none whitespace-nowrap"
            >
              <Search size={13} />
              {isPending ? 'Sorgulanıyor...' : 'Sorgula'}
            </button>
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
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Kullanıcı Adı</span>
                    <input value={v3User} onChange={e => setV3User(e.target.value)}
                      placeholder="netguard" className={INP} />
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Auth Protokol</span>
                    <select value={v3AuthProto} onChange={e => setV3AuthProto(e.target.value as 'MD5' | 'SHA')}
                      className={SEL}>
                      <option value="SHA">SHA</option>
                      <option value="MD5">MD5</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Auth Key</span>
                    <input type="password" value={v3AuthKey} onChange={e => setV3AuthKey(e.target.value)}
                      placeholder="auth şifresi" className={INP} />
                  </div>
                  <div className="space-y-1">
                    <span className="text-xs text-slate-500">Priv Protokol</span>
                    <select value={v3PrivProto} onChange={e => setV3PrivProto(e.target.value as 'DES' | 'AES')}
                      className={SEL}>
                      <option value="AES">AES</option>
                      <option value="DES">DES</option>
                    </select>
                  </div>
                  <div className="space-y-1 sm:col-span-2">
                    <span className="text-xs text-slate-500">Priv Key</span>
                    <input type="password" value={v3PrivKey} onChange={e => setV3PrivKey(e.target.value)}
                      placeholder="priv şifresi" className={INP} />
                  </div>
                </div>
              )}
            </div>
          )}
        </form>

        {isError && (
          <p className="mt-3 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            {error instanceof Error ? error.message : 'Sorgu başarısız'}
          </p>
        )}
      </div>

      {/* Result */}
      {lastResult && <ResultCard info={lastResult} />}

      {/* Empty state */}
      {!lastResult && (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-700 bg-[#0a1120]/50 border border-sky-900/15 rounded-xl">
          <Network size={32} className="opacity-20" />
          <p className="text-sm">SNMP destekli bir cihazın IP'sini girerek sorgulayabilirsin.</p>
          <p className="text-xs">
            Varsayılan community: <span className="font-mono">public</span> — port 161 UDP
          </p>
        </div>
      )}
    </div>
  )
}
