'use client'

import { use, useState } from 'react'
import Link from 'next/link'
import {
  ArrowLeft, Circle, Cpu, Server, AlertTriangle,
  FileText, Wifi, Shield, Activity,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { TimeSeriesChart } from '@/components/charts/TimeSeriesChart'
import { useInfluxMetrics, useLatestSnapshot } from '@/hooks/useMetrics'
import { devicesApi, logsApi, snmpApi, type SNMPIfaceHistory } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { Severity } from '@/types/models'

const TYPE_LABELS: Record<string, string> = {
  agent: 'Agent', snmp: 'SNMP', discovered: 'Keşfedilen', hybrid: 'Hibrit',
}
const TYPE_COLORS: Record<string, string> = {
  agent:      'bg-sky-500/10 text-sky-300 border-sky-500/25',
  snmp:       'bg-blue-500/10 text-blue-300 border-blue-500/25',
  discovered: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  hybrid:     'bg-violet-500/10 text-violet-300 border-violet-500/25',
}
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500',
  warning:  'bg-yellow-500', info: 'bg-blue-500',
}

function InfoRow({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="flex items-start justify-between py-2.5 border-b border-sky-900/10 last:border-0">
      <span className="text-xs text-slate-600">{label}</span>
      <span className="text-xs text-slate-300 text-right max-w-[60%] break-all font-mono">
        {value || '—'}
      </span>
    </div>
  )
}

function Panel({ title, icon: Icon, children }: {
  title: string; icon: React.ElementType; children: React.ReactNode
}) {
  return (
    <div className="ui-panel">
      <div className="ui-panel-header">
        <Icon size={13} className="text-slate-600" />
        <span className="ui-section-label">{title}</span>
      </div>
      {children}
    </div>
  )
}

const RANGE_OPTIONS = ['1h', '6h', '24h', '7d'] as const
type Range = typeof RANGE_OPTIONS[number]

function IfaceStatusDot({ points }: { points: { t: string; v: number }[] }) {
  const last = points.at(-1)?.v
  if (last === undefined) return <span className="text-slate-600">—</span>
  return (
    <span className={cn(
      'inline-flex items-center gap-1 text-xs font-medium',
      last === 1 ? 'text-emerald-400' : 'text-red-400',
    )}>
      <span className={cn('w-1.5 h-1.5 rounded-full', last === 1 ? 'bg-emerald-400' : 'bg-red-500')} />
      {last === 1 ? 'UP' : 'DOWN'}
    </span>
  )
}

function SNMPMetrics({ host }: { host: string }) {
  const [range, setRange] = useState<Range>('6h')
  const [selected, setSelected] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['snmp-iface-history', host, range],
    queryFn: () => snmpApi.interfaceHistory(host, range),
    refetchInterval: 60_000,
  })

  if (isLoading) return (
    <Panel title="SNMP Arayüzler" icon={Wifi}>
      <div className="p-6 text-center text-slate-700 text-xs">Yükleniyor...</div>
    </Panel>
  )

  if (data?.influx_disabled) return (
    <Panel title="SNMP Arayüzler" icon={Wifi}>
      <div className="p-6 text-center text-slate-700 text-xs">
        InfluxDB yapılandırılmamış — INFLUXDB_TOKEN env var tanımlı değil
      </div>
    </Panel>
  )

  const ifaces = data?.interfaces ?? []
  const activeIface = ifaces.find(i => i.if_name === selected) ?? ifaces[0] ?? null

  return (
    <Panel title="SNMP Arayüzler" icon={Wifi}>
      <div className="p-4 space-y-4">
        {/* Range selector */}
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-slate-600 uppercase tracking-wide">Zaman Aralığı</span>
          <div className="flex gap-1">
            {RANGE_OPTIONS.map(r => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={cn(
                  'px-2 py-0.5 text-[10px] rounded border transition-colors',
                  range === r
                    ? 'bg-sky-500/20 border-sky-500/40 text-sky-300'
                    : 'border-sky-900/20 text-slate-600 hover:text-slate-400',
                )}
              >{r}</button>
            ))}
          </div>
        </div>

        {ifaces.length === 0 ? (
          <p className="text-slate-700 text-xs text-center py-4">Arayüz verisi yok</p>
        ) : (
          <>
            {/* Interface list */}
            <div className="space-y-1">
              {ifaces.map((iface: SNMPIfaceHistory) => (
                <button
                  key={iface.if_name}
                  onClick={() => setSelected(iface.if_name)}
                  className={cn(
                    'w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs transition-colors border',
                    iface.if_name === (activeIface?.if_name)
                      ? 'bg-sky-500/10 border-sky-500/30 text-slate-200'
                      : 'border-sky-900/10 text-slate-500 hover:bg-sky-950/20',
                  )}
                >
                  <span className="font-mono">{iface.if_name}</span>
                  <IfaceStatusDot points={iface.oper_status} />
                </button>
              ))}
            </div>

            {/* Bandwidth chart for selected interface */}
            {activeIface && (activeIface.bw_in.length > 1 || activeIface.bw_out.length > 1) && (
              <div className="space-y-2">
                <p className="text-[10px] text-slate-600 uppercase tracking-wide">
                  {activeIface.if_name} — Bant Genişliği (bps)
                </p>
                {activeIface.bw_in.length > 1 && (
                  <TimeSeriesChart
                    data={activeIface.bw_in}
                    label="In"
                    color="#22d3ee"
                    unit=" bps"
                    height={100}
                  />
                )}
                {activeIface.bw_out.length > 1 && (
                  <TimeSeriesChart
                    data={activeIface.bw_out}
                    label="Out"
                    color="#818cf8"
                    unit=" bps"
                    height={100}
                  />
                )}
              </div>
            )}
            {activeIface && activeIface.bw_in.length <= 1 && activeIface.bw_out.length <= 1 && (
              <p className="text-[10px] text-slate-700 text-center">
                Bant genişliği verisi yok — SNMP_COLLECT_INTERFACE_STATS=true yapılınca etkinleşir
              </p>
            )}
          </>
        )}
      </div>
    </Panel>
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
          <div className="bg-sky-950/20 border border-sky-900/15 rounded-lg p-3">
            <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">CPU</p>
            <p className={cn('text-3xl font-bold leading-none tabular-nums',
              cpuPct !== null && cpuPct >= 90 ? 'text-red-400' :
              cpuPct !== null && cpuPct >= 70 ? 'text-yellow-400' : 'text-slate-200',
            )}>
              {cpuPct !== null ? `${cpuPct.toFixed(1)}%` : '—'}
            </p>
          </div>
          <div className="bg-sky-950/20 border border-sky-900/15 rounded-lg p-3">
            <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">Bellek</p>
            <p className={cn('text-3xl font-bold leading-none tabular-nums',
              memPct !== null && memPct >= 90 ? 'text-red-400' :
              memPct !== null && memPct >= 70 ? 'text-yellow-400' : 'text-slate-200',
            )}>
              {memPct !== null ? `${memPct.toFixed(1)}%` : '—'}
            </p>
          </div>
        </div>
        {cpuData.length > 1 ? (
          <TimeSeriesChart data={cpuData} label="CPU" color="#6366f1" unit="%" height={140} />
        ) : (
          <p className="text-slate-700 text-xs text-center py-6">InfluxDB verisi bekleniyor...</p>
        )}
        <Link
          href={`/agents/${deviceId}`}
          className="block text-center text-xs text-sky-400 hover:text-sky-300 transition-colors"
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
    queryFn:  () => devicesApi.get(id),
  })

  const { data: alertsData } = useQuery({
    queryKey: ['device-alerts', id],
    queryFn:  () => devicesApi.alerts(id, 10),
    enabled:  !!device,
    refetchInterval: 30_000,
  })

  const { data: logsData } = useQuery({
    queryKey: ['device-logs', device?.ip],
    queryFn:  () => logsApi.listNormalized({ source_ip: device!.ip, limit: 10 }),
    enabled:  !!device?.ip,
    refetchInterval: 60_000,
  })

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <div className="h-3 w-20 bg-sky-950/40 rounded animate-shimmer" />
        <div className="h-6 w-48 bg-sky-950/40 rounded animate-shimmer" />
      </div>
    )
  }

  if (!device) {
    return (
      <div className="space-y-4 p-6">
        <Link href="/devices" className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors">
          <ArrowLeft size={13} /> Geri
        </Link>
        <p className="text-slate-600 text-sm">Cihaz bulunamadı.</p>
      </div>
    )
  }

  const isUp    = device.status === 'up'
  const isAgent = device.type === 'agent' || device.type === 'hybrid'
  const hasSNMP = !!device.snmp_community
  const riskColor =
    device.risk_score >= 70 ? 'text-red-400' :
    device.risk_score >= 40 ? 'text-yellow-400' : 'text-emerald-400'

  const alerts = alertsData?.alerts ?? []
  const logs   = logsData?.logs ?? []

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <Link
          href="/devices"
          className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 mb-4 transition-colors"
        >
          <ArrowLeft size={13} /> Cihazlar
        </Link>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2.5">
            <Circle
              size={9}
              className={isUp ? 'text-emerald-400 fill-emerald-400' : 'text-slate-700 fill-slate-700'}
            />
            <h1 className="text-base font-semibold text-slate-100">{device.name}</h1>
            <span className="font-mono text-xs text-slate-500">{device.ip}</span>
            <span className={cn(
              'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border backdrop-blur-sm',
              TYPE_COLORS[device.type] ?? 'bg-sky-950/20 text-slate-500 border-sky-900/20',
            )}>
              {TYPE_LABELS[device.type] ?? device.type}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <Shield size={13} className={riskColor} />
            <span className={cn('text-sm font-bold tabular-nums', riskColor)}>
              Risk {device.risk_score}
            </span>
          </div>
        </div>
      </div>

      {/* Info + metrics grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="Cihaz Bilgileri" icon={Server}>
          <div className="px-4">
            <InfoRow label="Durum"       value={isUp ? 'Erişilebilir' : 'Erişilemiyor'} />
            <InfoRow label="IP"          value={device.ip} />
            <InfoRow label="MAC"         value={device.mac} />
            <InfoRow label="Vendor"      value={device.vendor} />
            <InfoRow label="OS"          value={device.os_info} />
            <InfoRow label="Segment"     value={device.segment} />
            <InfoRow label="Son Görülme" value={device.last_seen ? new Date(device.last_seen).toLocaleString('tr-TR') : '—'} />
            <InfoRow label="İlk Görülme" value={new Date(device.first_seen).toLocaleString('tr-TR')} />
            {hasSNMP && (
              <>
                <InfoRow label="SNMP Community" value={device.snmp_community} />
                <InfoRow label="SNMP Versiyon"  value={device.snmp_version} />
              </>
            )}
            {device.notes && <InfoRow label="Notlar" value={device.notes} />}
          </div>
        </Panel>

        <div className="lg:col-span-2">
          {isAgent ? (
            <AgentMetrics deviceId={id} />
          ) : hasSNMP ? (
            <SNMPMetrics host={id} />
          ) : (
            <Panel title="SNMP Durumu" icon={Wifi}>
              <div className="px-4 py-6 text-center">
                <p className="text-slate-700 text-sm">SNMP yapılandırılmamış</p>
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* Alerts + Recent logs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel title={`Son Alertler (${alerts.length})`} icon={AlertTriangle}>
          {alerts.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-slate-700 text-sm">Alert yok</div>
          ) : (
            <div className="divide-y divide-sky-900/10">
              {alerts.map((a) => (
                <div key={a.alert_id} className="flex items-start gap-3 px-4 py-2.5">
                  <span className={cn('w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0', SEV_DOT[a.severity] ?? 'bg-slate-600')} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-300 font-medium">{a.message}</p>
                    <p className="text-[11px] text-slate-700 mt-0.5">
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
            <div className="flex items-center justify-center py-8 text-slate-700 text-sm">
              Bu cihaza ait log yok
            </div>
          ) : (
            <div className="divide-y divide-sky-900/10">
              {logs.map((l) => (
                <div key={l.log_id} className="px-4 py-2.5 hover:bg-sky-950/20 transition-colors">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[11px] text-slate-500 font-mono">{l.event_action}</span>
                    <span className="text-[11px] text-slate-700">
                      {new Date(l.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 truncate">{l.message}</p>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}
