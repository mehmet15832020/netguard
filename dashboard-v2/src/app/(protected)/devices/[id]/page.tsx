'use client'

import { use } from 'react'
import Link from 'next/link'
import {
  ArrowLeft, Circle, Cpu, Server, AlertTriangle,
  FileText, Wifi, Shield,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { TimeSeriesChart } from '@/components/charts/TimeSeriesChart'
import { useInfluxMetrics, useLatestSnapshot } from '@/hooks/useMetrics'
import { devicesApi, logsApi } from '@/lib/api'
import type { Severity } from '@/types/models'

const TYPE_LABELS: Record<string, string> = {
  agent: 'Agent', snmp: 'SNMP', discovered: 'Keşfedilen', hybrid: 'Hibrit',
}
const TYPE_COLORS: Record<string, string> = {
  agent:      'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
  snmp:       'bg-blue-500/20 text-blue-300 border-blue-500/30',
  discovered: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  hybrid:     'bg-purple-500/20 text-purple-300 border-purple-500/30',
}
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500',
  warning:  'bg-yellow-500', info: 'bg-blue-500',
}

function InfoRow({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="flex items-start justify-between py-2.5 border-b border-zinc-800/60 last:border-0">
      <span className="text-xs text-zinc-500">{label}</span>
      <span className="text-xs text-zinc-300 text-right max-w-[60%] break-all font-mono">
        {value || '—'}
      </span>
    </div>
  )
}

function Panel({ title, icon: Icon, children }: {
  title: string; icon: React.ElementType; children: React.ReactNode
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
        <Icon size={13} className="text-zinc-500" />
        <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">{title}</span>
      </div>
      {children}
    </div>
  )
}

function AgentMetrics({ deviceId }: { deviceId: string }) {
  const { snapshot } = useLatestSnapshot(deviceId)
  const { data: influx } = useInfluxMetrics(deviceId, '1h')

  const cpuData = influx?.available ? (influx.cpu ?? []) : []
  const memPct  = snapshot?.memory.usage_percent ?? null
  const cpuPct  = snapshot?.cpu.usage_percent ?? null

  return (
    <Panel title="Canlı Metrikler (1 saat)" icon={Cpu}>
      <div className="p-4 space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-zinc-800/50 rounded-lg p-3">
            <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-1">CPU</p>
            <p className={`text-2xl font-bold tabular-nums ${
              cpuPct !== null && cpuPct >= 90 ? 'text-red-400' :
              cpuPct !== null && cpuPct >= 70 ? 'text-yellow-400' : 'text-zinc-200'
            }`}>
              {cpuPct !== null ? `${cpuPct.toFixed(1)}%` : '—'}
            </p>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3">
            <p className="text-[10px] text-zinc-500 uppercase tracking-wide mb-1">Bellek</p>
            <p className={`text-2xl font-bold tabular-nums ${
              memPct !== null && memPct >= 90 ? 'text-red-400' :
              memPct !== null && memPct >= 70 ? 'text-yellow-400' : 'text-zinc-200'
            }`}>
              {memPct !== null ? `${memPct.toFixed(1)}%` : '—'}
            </p>
          </div>
        </div>
        {cpuData.length > 1 ? (
          <TimeSeriesChart data={cpuData} label="CPU" color="#6366f1" unit="%" height={140} />
        ) : (
          <p className="text-zinc-600 text-xs text-center py-6">
            InfluxDB verisi bekleniyor...
          </p>
        )}
        <Link
          href={`/agents/${deviceId}`}
          className="block text-center text-xs text-indigo-400 hover:text-indigo-300 transition-colors"
        >
          Tüm metrikler → Agent detay sayfası
        </Link>
      </div>
    </Panel>
  )
}

export default function DeviceDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)

  const { data: device, isLoading } = useQuery({
    queryKey: ['device', id],
    queryFn: () => devicesApi.get(id),
  })

  const { data: alertsData } = useQuery({
    queryKey: ['device-alerts', id],
    queryFn: () => devicesApi.alerts(id, 10),
    enabled: !!device,
    refetchInterval: 30_000,
  })

  const { data: logsData } = useQuery({
    queryKey: ['device-logs', device?.ip],
    queryFn: () => logsApi.listNormalized({ src_ip: device!.ip, limit: 10 }),
    enabled: !!device?.ip,
    refetchInterval: 60_000,
  })

  if (isLoading) {
    return <p className="text-zinc-500 text-sm p-6">Yükleniyor...</p>
  }

  if (!device) {
    return (
      <div className="space-y-4 p-6">
        <Link href="/devices" className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} /> Geri
        </Link>
        <p className="text-zinc-500 text-sm">Cihaz bulunamadı.</p>
      </div>
    )
  }

  const isUp = device.status === 'up'
  const isAgent = device.type === 'agent' || device.type === 'hybrid'
  const hasSNMP = !!device.snmp_community
  const riskColor =
    device.risk_score >= 70 ? 'text-red-400' :
    device.risk_score >= 40 ? 'text-yellow-400' : 'text-emerald-400'

  const alerts = alertsData?.alerts ?? []
  const logs   = logsData?.logs ?? []

  return (
    <div className="space-y-5 p-1">
      {/* Başlık */}
      <div>
        <Link
          href="/devices"
          className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-100 mb-4 transition-colors"
        >
          <ArrowLeft size={14} /> Cihazlar
        </Link>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <Circle
              size={10}
              className={isUp ? 'text-emerald-400 fill-emerald-400' : 'text-zinc-600 fill-zinc-600'}
            />
            <h1 className="text-xl font-semibold text-zinc-100">{device.name}</h1>
            <span className="font-mono text-sm text-zinc-500">{device.ip}</span>
            <Badge className={`text-xs border ${TYPE_COLORS[device.type] ?? 'bg-zinc-700 text-zinc-300'}`}>
              {TYPE_LABELS[device.type] ?? device.type}
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <Shield size={14} className={riskColor} />
            <span className={`text-sm font-bold tabular-nums ${riskColor}`}>
              Risk {device.risk_score}
            </span>
          </div>
        </div>
      </div>

      {/* İki sütun: bilgi + metrikler/SNMP */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Sol: cihaz bilgileri */}
        <Panel title="Cihaz Bilgileri" icon={Server}>
          <div className="px-4">
            <InfoRow label="Durum"     value={isUp ? 'Erişilebilir' : 'Erişilemiyor'} />
            <InfoRow label="IP"        value={device.ip} />
            <InfoRow label="MAC"       value={device.mac} />
            <InfoRow label="Vendor"    value={device.vendor} />
            <InfoRow label="OS"        value={device.os_info} />
            <InfoRow label="Segment"   value={device.segment} />
            <InfoRow label="Son Görülme" value={
              device.last_seen
                ? new Date(device.last_seen).toLocaleString('tr-TR')
                : '—'
            } />
            <InfoRow label="İlk Görülme" value={
              new Date(device.first_seen).toLocaleString('tr-TR')
            } />
            {hasSNMP && (
              <>
                <InfoRow label="SNMP Community" value={device.snmp_community} />
                <InfoRow label="SNMP Versiyon"  value={device.snmp_version} />
              </>
            )}
            {device.notes && <InfoRow label="Notlar" value={device.notes} />}
          </div>
        </Panel>

        {/* Sağ: agent metrikleri veya SNMP özeti */}
        <div className="lg:col-span-2">
          {isAgent ? (
            <AgentMetrics deviceId={id} />
          ) : (
            <Panel title="SNMP Durumu" icon={Wifi}>
              <div className="px-4 py-6 text-center">
                {hasSNMP ? (
                  <div className="space-y-2">
                    <p className="text-zinc-400 text-sm">
                      SNMP {device.snmp_version} · community: <span className="font-mono text-indigo-400">{device.snmp_community}</span>
                    </p>
                    <p className="text-zinc-600 text-xs">
                      InfluxDB'deki arayüz metrikleri A3 aşamasında eklenecek
                    </p>
                  </div>
                ) : (
                  <p className="text-zinc-600 text-sm">SNMP yapılandırılmamış</p>
                )}
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* Alertler + Son Loglar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        <Panel title={`Son Alertler (${alerts.length})`} icon={AlertTriangle}>
          {alerts.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">
              Alert yok
            </div>
          ) : (
            <div className="divide-y divide-zinc-800/60">
              {alerts.map((a) => (
                <div key={a.alert_id} className="flex items-start gap-3 px-4 py-2.5">
                  <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${SEV_DOT[a.severity] ?? 'bg-zinc-600'}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-zinc-300 font-medium">{a.message}</p>
                    <p className="text-[11px] text-zinc-600 mt-0.5">
                      {new Date(a.triggered_at).toLocaleString('tr-TR')}
                      {' · '}
                      <span className="font-mono">{a.metric}</span>
                      {' = '}
                      <span className="font-mono">{a.value.toFixed(1)}</span>
                    </p>
                  </div>
                  <SeverityBadge severity={a.severity as Severity} />
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title={`Son Loglar (${logs.length})`} icon={FileText}>
          {logs.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">
              Bu cihaza ait log yok
            </div>
          ) : (
            <div className="divide-y divide-zinc-800/60">
              {logs.map((l) => (
                <div key={l.log_id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[11px] text-zinc-500 font-mono">{l.event_type}</span>
                    <span className="text-[11px] text-zinc-600">
                      {new Date(l.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400 truncate">{l.message}</p>
                </div>
              ))}
            </div>
          )}
        </Panel>

      </div>
    </div>
  )
}
