'use client'

import { use, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowLeft, Cpu, MemoryStick, HardDrive, Circle, Wifi, AlertTriangle } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { MetricCard } from '@/components/metrics/MetricCard'
import { CPUChart } from '@/components/charts/CPUChart'
import { MemoryGauge } from '@/components/charts/MemoryGauge'
import { TimeSeriesChart } from '@/components/charts/TimeSeriesChart'
import { useLatestSnapshot, useSnapshotHistory, useAgents, useInfluxMetrics } from '@/hooks/useMetrics'
import { agentsApi } from '@/lib/api'
import type { MetricRange } from '@/lib/api'
import type { Severity, TrafficSummary } from '@/types/models'

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
    return <p className="text-zinc-500 text-sm">Yükleniyor...</p>
  }

  if (!snapshot) {
    return (
      <div className="space-y-4">
        <button onClick={() => router.back()} className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} /> Geri
        </button>
        <p className="text-zinc-500 text-sm">Agent bulunamadı veya henüz veri yok.</p>
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

  const influxAvailable = influx?.available === true
  const cpuData    = influxAvailable ? (influx!.cpu    ?? []) : []
  const memData    = influxAvailable ? (influx!.memory ?? []) : []
  const netInData  = influxAvailable ? (influx!.net_in  ?? []) : []
  const netOutData = influxAvailable ? (influx!.net_out ?? []) : []

  return (
    <div className="space-y-6">
      {/* Başlık */}
      <div>
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-100 mb-4 transition-colors"
        >
          <ArrowLeft size={14} /> Agents
        </button>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Circle
              size={10}
              className={isOnline ? 'text-emerald-400 fill-emerald-400' : 'text-zinc-600 fill-zinc-600'}
            />
            <h1 className="text-xl font-semibold text-zinc-100">{snapshot.hostname}</h1>
            <span className="text-sm text-zinc-500">{agentMeta?.os}</span>
          </div>

          {/* Zaman aralığı seçici */}
          <div className="flex gap-1">
            {RANGES.map((r) => (
              <button
                key={r.value}
                onClick={() => setRange(r.value)}
                className={`px-3 py-1 text-xs rounded transition-colors ${
                  range === r.value
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:text-zinc-100'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
        <p className="text-xs text-zinc-600 mt-1 ml-[22px]">
          Son veri: {new Date(snapshot.collected_at).toLocaleString('tr-TR')}
        </p>
      </div>

      {/* Metrik kartları */}
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

      {/* Grafikler — InfluxDB varsa geçmiş, yoksa WebSocket verisi */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">CPU Kullanımı</CardTitle>
          </CardHeader>
          <CardContent className="px-2 pb-3">
            {influxAvailable && cpuData.length > 1 ? (
              <TimeSeriesChart data={cpuData} label="CPU" color="#6366f1" unit="%" />
            ) : history.length > 1 ? (
              <CPUChart snapshots={history} />
            ) : (
              <p className="text-zinc-600 text-xs text-center py-12">Grafik için veri bekleniyor...</p>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">Bellek Kullanımı</CardTitle>
          </CardHeader>
          <CardContent className="px-2 pb-3">
            {influxAvailable && memData.length > 1 ? (
              <TimeSeriesChart data={memData} label="Bellek" color="#10b981" unit="%" />
            ) : (
              <MemoryGauge usagePercent={memPct} usedGB={usedGB} totalGB={totalGB} />
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">Ağ — Gelen (bytes/s)</CardTitle>
          </CardHeader>
          <CardContent className="px-2 pb-3">
            {influxAvailable && netInData.length > 1 ? (
              <TimeSeriesChart data={netInData} label="Gelen" color="#f59e0b" unit=" B/s" />
            ) : (
              <p className="text-zinc-600 text-xs text-center py-12">InfluxDB bağlantısı bekleniyor...</p>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">Ağ — Giden (bytes/s)</CardTitle>
          </CardHeader>
          <CardContent className="px-2 pb-3">
            {influxAvailable && netOutData.length > 1 ? (
              <TimeSeriesChart data={netOutData} label="Giden" color="#ec4899" unit=" B/s" />
            ) : (
              <p className="text-zinc-600 text-xs text-center py-12">InfluxDB bağlantısı bekleniyor...</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Trafik Özeti */}
      {traffic && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
                <Wifi size={14} />
                Trafik Özeti
                {traffic.suspicious_packet_count >= 5 && (
                  <span className="flex items-center gap-1 text-xs text-red-400 font-normal">
                    <AlertTriangle size={11} />
                    {traffic.suspicious_packet_count} şüpheli paket
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3 space-y-2">
              <div className="grid grid-cols-3 gap-2 text-center">
                {[
                  { label: 'Paket', value: traffic.total_packets.toLocaleString() },
                  { label: 'Boyut', value: traffic.total_bytes > 1e6 ? `${(traffic.total_bytes / 1e6).toFixed(1)} MB` : `${(traffic.total_bytes / 1e3).toFixed(0)} KB` },
                  { label: 'Arayüz', value: traffic.interface },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-zinc-800/50 rounded p-2">
                    <p className="text-[10px] text-zinc-500">{label}</p>
                    <p className="text-sm font-mono font-medium text-zinc-200 truncate">{value}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-1.5">
                {traffic.protocols.slice(0, 5).map((p) => (
                  <div key={p.protocol} className="flex items-center gap-2">
                    <span className="text-[11px] text-zinc-500 w-20 flex-shrink-0 font-mono">{p.protocol}</span>
                    <div className="flex-1 bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="h-full bg-indigo-500 rounded-full"
                        style={{ width: `${Math.min(100, p.percentage)}%` }}
                      />
                    </div>
                    <span className="text-[11px] text-zinc-400 w-10 text-right tabular-nums">{p.percentage.toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm text-zinc-300">En Aktif IP'ler</CardTitle>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              {traffic.top_src_ips.length === 0 && traffic.top_dst_ips.length === 0 ? (
                <p className="text-zinc-600 text-xs text-center py-6">Veri yok</p>
              ) : (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      <th className="px-4 py-2 text-left text-zinc-500 font-medium">Kaynak IP</th>
                      <th className="px-4 py-2 text-left text-zinc-500 font-medium">Hedef IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Array.from({ length: Math.max(traffic.top_src_ips.length, traffic.top_dst_ips.length) }, (_, i) => (
                      <tr key={i} className="border-b border-zinc-800/40 last:border-0">
                        <td className="px-4 py-1.5 font-mono text-zinc-300">{traffic.top_src_ips[i] ?? '—'}</td>
                        <td className="px-4 py-1.5 font-mono text-zinc-300">{traffic.top_dst_ips[i] ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Disk detayı */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-2 pt-4 px-4">
          <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
            <HardDrive size={14} /> Disk Bölümleri
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                <th className="px-4 py-2.5 text-left font-medium">Bağlama Noktası</th>
                <th className="px-4 py-2.5 text-right font-medium">Toplam</th>
                <th className="px-4 py-2.5 text-right font-medium">Kullanılan</th>
                <th className="px-4 py-2.5 text-right font-medium">Boş</th>
                <th className="px-4 py-2.5 text-right font-medium">Kullanım</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.disks.map((disk) => {
                const color = disk.usage_percent >= 90 ? 'text-red-400' : disk.usage_percent >= 70 ? 'text-yellow-400' : 'text-zinc-300'
                return (
                  <tr key={disk.mount_point} className="border-b border-zinc-800/50 text-sm">
                    <td className="px-4 py-3 text-zinc-200 font-mono">{disk.mount_point}</td>
                    <td className="px-4 py-3 text-right text-zinc-400">{(disk.total_bytes / 1e9).toFixed(1)} GB</td>
                    <td className="px-4 py-3 text-right text-zinc-400">{(disk.used_bytes  / 1e9).toFixed(1)} GB</td>
                    <td className="px-4 py-3 text-right text-zinc-400">{(disk.free_bytes  / 1e9).toFixed(1)} GB</td>
                    <td className={`px-4 py-3 text-right font-mono font-medium ${color}`}>
                      {disk.usage_percent.toFixed(1)}%
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  )
}
