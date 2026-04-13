'use client'

import { useState } from 'react'
import { Network, Search, CheckCircle, XCircle, Clock, ArrowDownUp } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { snmpApi, type SNMPDeviceInfo } from '@/lib/api'
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

function ResultCard({ info }: { info: SNMPDeviceInfo }) {
  const ifStatus = ifOperStatusLabel(info.if_oper_status)

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
      <CardContent>
        {!info.reachable ? (
          <p className="text-sm text-red-400">
            {info.error || 'Cihaz yanıt vermedi veya SNMP devre dışı.'}
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Sistem bilgileri */}
            <div className="space-y-3">
              <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Sistem</h3>
              <Row label="Hostname"   value={info.sys_name  || '—'} />
              <Row label="Açıklama"   value={info.sys_descr || '—'} />
              <Row
                label="Uptime"
                value={formatUptime(info.uptime_ticks)}
                icon={<Clock size={12} className="text-zinc-500" />}
              />
              <Row label="Community"  value={info.community} />
            </div>

            {/* Arayüz istatistikleri */}
            <div className="space-y-3">
              <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Arayüz (IF 1)</h3>
              <Row
                label="Durum"
                value={ifStatus.label}
                valueClass={ifStatus.color}
              />
              <Row
                label="Gelen"
                value={formatBytes(info.if_in_octets)}
                icon={<ArrowDownUp size={12} className="text-zinc-500" />}
              />
              <Row
                label="Giden"
                value={formatBytes(info.if_out_octets)}
              />
            </div>
          </div>
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
  const [lastResult, setLastResult] = useState<SNMPDeviceInfo | null>(null)

  const { mutate, isPending, isError, error } = useMutation({
    mutationFn: () => snmpApi.poll(host.trim(), community.trim() || 'public'),
    onSuccess: (data) => setLastResult(data),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!host.trim()) return
    mutate()
  }

  return (
    <div className="space-y-6">
      {/* Başlık */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">SNMP Sorgulama</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Router, switch veya SNMP destekli cihazları sorgula
        </p>
      </div>

      {/* Sorgu formu */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3 pt-4 px-4">
          <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
            <Network size={14} /> Cihaz Sorgusu
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1 space-y-1">
              <Label htmlFor="host" className="text-xs text-zinc-400">IP Adresi veya Hostname</Label>
              <Input
                id="host"
                value={host}
                onChange={e => setHost(e.target.value)}
                placeholder="192.168.1.1"
                required
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-600"
              />
            </div>
            <div className="w-full sm:w-40 space-y-1">
              <Label htmlFor="community" className="text-xs text-zinc-400">Community</Label>
              <Input
                id="community"
                value={community}
                onChange={e => setCommunity(e.target.value)}
                placeholder="public"
                className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-600"
              />
            </div>
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
