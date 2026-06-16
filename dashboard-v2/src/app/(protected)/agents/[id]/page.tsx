'use client'

import { use, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowLeft, Cpu, MemoryStick, HardDrive, Circle, Wifi, AlertTriangle } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { MetricCard } from '@/components/metrics/MetricCard'
import { CPUChart } from '@/components/charts/CPUChart'
import { MemoryGauge } from '@/components/charts/MemoryGauge'
import { TimeSeriesChart } from '@/components/charts/TimeSeriesChart'
import { useLatestSnapshot, useSnapshotHistory, useAgents, useInfluxMetrics } from '@/hooks/useMetrics'
import { agentsApi } from '@/lib/api'
import type { MetricRange } from '@/lib/api'
import type { Severity } from '@/types/models'
import { cn } from '@/lib/utils'

const RANGES: { label: string; value: MetricRange }[] = [
  { label: '1s', value: '1h' },
  { label: '6s', value: '6h' },
  { label: '24s', value: '24h' },
]

export default function AgentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const router = useRouter()
  const [range, setRange] = useState<MetricRange>('1h')

  const { data: agentsData } = useAgents()
  const { snapshot, isLoading } = useLatestSnapshot(id)
  const history = useSnapshotHistory(id)
  const { data: influx } = useInfluxMetrics(id, range)
  const { data: traffic } = useQuery({
    queryKey: ['traffic', id],
    queryFn:  () => agentsApi.trafficSummary(id),
    refetchInterval: 60_000,
  })

  const agentMeta = agentsData?.agents.find(a => a.agent_id === id)
  const isOnline  = agentMeta
    ? Date.now() - new Date(agentMeta.last_seen).getTime() < 60_000
    : false

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="h-4 w-32 bg-sky-950/40 rounded animate-shimmer mb-6" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-5 h-24 animate-shimmer" />
          ))}
        </div>
      </div>
    )
  }

  if (!snapshot) {
    return (
      <div className="p-6 space-y-4">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-100 transition-colors"
        >
          <ArrowLeft size={14} /> Geri
        </button>
        <p className="text-slate-600 text-sm">Agent bulunamadı veya henüz veri yok.</p>
      </div>
    )
  }

  const cpuStatus: Severity =
    snapshot.cpu.usage_percent >= 90 ? 'critical' :
    snapshot.cpu.usage_percent >= 70 ? 'warning' : 'info'

  const memPct    = snapshot.memory.usage_percent
  const memStatus: Severity = memPct >= 90 ? 'critical' : memPct >= 70 ? 'warning' : 'info'
  const usedGB    = snapshot.memory.used_bytes  / 1e9
  const totalGB   = snapshot.memory.total_bytes / 1e9

  const diskMax   = snapshot.disks.reduce((m, d) => d.usage_percent > m ? d.usage_percent : m, 0)
  const diskStatus: Severity = diskMax >= 90 ? 'critical' : diskMax >= 70 ? 'warning' : 'info'

  const influxLoaded   = influx !== undefined
  const influxAvailable = influx?.available === true
  const cpuData    = influxAvailable ? (influx!.cpu    ?? []) : []
  const memData    = influxAvailable ? (influx!.memory ?? []) : []
  const netInData  = influxAvailable ? (influx!.net_in  ?? []) : []
  const netOutData = influxAvailable ? (influx!.net_out ?? []) : []

  const rangeLabel = RANGES.find(r => r.value === range)?.label ?? range

  const noDataMsg = !influxLoaded
    ? 'Yükleniyor...'
    : !influxAvailable
      ? 'InfluxDB yapılandırılmamış'
      : `Son ${rangeLabel}'de veri yok`

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 mb-4 transition-colors"
        >
          <ArrowLeft size={13} /> Agents
        </button>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Circle
              size={9}
              className={isOnline ? 'text-emerald-400 fill-emerald-400' : 'text-slate-700 fill-slate-700'}
            />
            <h1 className="text-base font-semibold text-slate-100">{snapshot.hostname}</h1>
            <span className="text-xs text-slate-500">{agentMeta?.os}</span>
          </div>

          <div className="flex gap-1">
            {RANGES.map((r) => (
              <button
                key={r.value}
                onClick={() => setRange(r.value)}
                className={cn(
                  'px-3 py-1 text-xs rounded-lg transition-colors',
                  range === r.value
                    ? 'bg-sky-500/15 text-sky-400 border border-x border-sky-500/30'
                    : 'bg-sky-950/20 border border-sky-900/20 text-slate-500 hover:text-slate-300',
                )}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-3 mt-1 ml-[22px]">
          <p className="text-xs text-slate-700">
            Son veri: {new Date(snapshot.collected_at).toLocaleString('tr-TR')}
          </p>
          {!isOnline && (
            <span className="flex items-center gap-1 text-xs text-amber-500/80">
              <AlertTriangle size={11} />
              Agent çevrimdışı — grafikler son anlık görüntüyü gösteriyor
            </span>
          )}
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricCard
          title="CPU"
          value={snapshot.cpu.usage_percent.toFixed(1)}
          unit="%"
          subtitle={`${snapshot.cpu.core_count} çekirdek`}
          icon={Cpu}
          status={cpuStatus === 'info' ? 'ok' : cpuStatus}
        />
        <MetricCard
          title="Bellek"
          value={memPct.toFixed(1)}
          unit="%"
          subtitle={`${usedGB.toFixed(1)} / ${totalGB.toFixed(1)} GB`}
          icon={MemoryStick}
          status={memStatus === 'info' ? 'ok' : memStatus}
        />
        <MetricCard
          title="Disk (maks)"
          value={diskMax.toFixed(1)}
          unit="%"
          subtitle={`${snapshot.disks.length} bölüm`}
          icon={HardDrive}
          status={diskStatus === 'info' ? 'ok' : diskStatus}
        />
        <MetricCard
          title="Yük Ortalaması"
          value={snapshot.cpu.load_avg_1m.toFixed(2)}
          subtitle="son 1 dakika"
          icon={Cpu}
          status="ok"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="ui-panel">
          <div className="ui-panel-header">
            <span className="ui-section-label">CPU Kullanımı</span>
          </div>
          <div className="px-2 py-3">
            {influxAvailable && cpuData.length > 1 ? (
              <TimeSeriesChart data={cpuData} label="CPU" color="#6366f1" unit="%" />
            ) : history.length > 1 ? (
              <CPUChart snapshots={history} />
            ) : (
              <p className="text-slate-700 text-xs text-center py-12">{noDataMsg}</p>
            )}
          </div>
        </div>

        <div className="ui-panel">
          <div className="ui-panel-header">
            <span className="ui-section-label">Bellek Kullanımı</span>
          </div>
          <div className="px-2 py-3">
            {influxAvailable && memData.length > 1 ? (
              <TimeSeriesChart data={memData} label="Bellek" color="#10b981" unit="%" />
            ) : (
              <MemoryGauge usagePercent={memPct} usedGB={usedGB} totalGB={totalGB} />
            )}
          </div>
        </div>

        <div className="ui-panel">
          <div className="ui-panel-header">
            <span className="ui-section-label">Ağ — Gelen (bytes/s)</span>
          </div>
          <div className="px-2 py-3">
            {influxAvailable && netInData.length > 1 ? (
              <TimeSeriesChart data={netInData} label="Gelen" color="#f59e0b" unit=" B/s" />
            ) : (
              <p className="text-slate-700 text-xs text-center py-12">{noDataMsg}</p>
            )}
          </div>
        </div>

        <div className="ui-panel">
          <div className="ui-panel-header">
            <span className="ui-section-label">Ağ — Giden (bytes/s)</span>
          </div>
          <div className="px-2 py-3">
            {influxAvailable && netOutData.length > 1 ? (
              <TimeSeriesChart data={netOutData} label="Giden" color="#ec4899" unit=" B/s" />
            ) : (
              <p className="text-slate-700 text-xs text-center py-12">{noDataMsg}</p>
            )}
          </div>
        </div>
      </div>

      {/* Traffic summary */}
      {traffic && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="ui-panel">
            <div className="ui-panel-header">
              <Wifi size={13} className="text-slate-600" />
              <span className="ui-section-label">Trafik Özeti</span>
              {traffic.suspicious_packet_count >= 5 && (
                <span className="flex items-center gap-1 text-xs text-red-400 ml-2">
                  <AlertTriangle size={11} />
                  {traffic.suspicious_packet_count} şüpheli bağlantı
                </span>
              )}
            </div>
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-3 gap-2 text-center">
                {[
                  { label: 'Bağlantı/Akış', value: traffic.total_packets.toLocaleString() },
                  { label: 'Boyut', value: traffic.total_bytes > 1e6 ? `${(traffic.total_bytes / 1e6).toFixed(1)} MB` : `${(traffic.total_bytes / 1e3).toFixed(0)} KB` },
                  { label: 'Veri Kaynağı', value: traffic.interface },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-sky-950/20 rounded-lg p-2 border border-sky-900/15">
                    <p className="text-[10px] text-slate-600">{label}</p>
                    <p className="text-sm font-mono font-medium text-slate-200 truncate">{value}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-1.5">
                {traffic.protocols.slice(0, 5).map((p) => (
                  <div key={p.protocol} className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-500 w-20 flex-shrink-0 font-mono">{p.protocol}</span>
                    <div className="flex-1 bg-sky-950/20 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="h-full bg-sky-500 rounded-full"
                        style={{ width: `${Math.min(100, p.percentage)}%` }}
                      />
                    </div>
                    <span className="text-[11px] text-slate-500 w-10 text-right tabular-nums">{p.percentage.toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="ui-panel">
            <div className="ui-panel-header">
              <span className="ui-section-label">En Aktif IP'ler</span>
            </div>
            {traffic.top_src_ips.length === 0 && traffic.top_dst_ips.length === 0 ? (
              <p className="text-slate-700 text-xs text-center py-6">Veri yok</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th className="ui-th">Kaynak IP</th>
                    <th className="ui-th">Hedef IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sky-900/10">
                  {Array.from({ length: Math.max(traffic.top_src_ips.length, traffic.top_dst_ips.length) }, (_, i) => (
                    <tr key={i} className="hover:bg-sky-950/20 transition-colors">
                      <td className="ui-td font-mono text-slate-300">{traffic.top_src_ips[i] ?? '—'}</td>
                      <td className="ui-td font-mono text-slate-300">{traffic.top_dst_ips[i] ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Disk partitions */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <HardDrive size={13} className="text-slate-600" />
          <span className="ui-section-label">Disk Bölümleri</span>
        </div>
        <table className="w-full">
          <thead>
            <tr>
              <th className="ui-th">Bağlama Noktası</th>
              <th className="ui-th text-right">Toplam</th>
              <th className="ui-th text-right">Kullanılan</th>
              <th className="ui-th text-right">Boş</th>
              <th className="ui-th text-right">Kullanım</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sky-900/10">
            {snapshot.disks.map((disk) => {
              const color = disk.usage_percent >= 90 ? 'text-red-400' : disk.usage_percent >= 70 ? 'text-yellow-400' : 'text-slate-300'
              return (
                <tr key={disk.mount_point} className="hover:bg-sky-950/20 transition-colors text-sm">
                  <td className="ui-td text-slate-200 font-mono">{disk.mount_point}</td>
                  <td className="ui-td text-right text-slate-500">{(disk.total_bytes / 1e9).toFixed(1)} GB</td>
                  <td className="ui-td text-right text-slate-500">{(disk.used_bytes  / 1e9).toFixed(1)} GB</td>
                  <td className="ui-td text-right text-slate-500">{(disk.free_bytes  / 1e9).toFixed(1)} GB</td>
                  <td className={`ui-td text-right font-mono font-medium ${color}`}>
                    {disk.usage_percent.toFixed(1)}%
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
