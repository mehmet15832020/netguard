'use client'

import { Cpu, MemoryStick, Bell, Server, Shield, GitMerge } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { MetricCard } from '@/components/metrics/MetricCard'
import { CPUChart } from '@/components/charts/CPUChart'
import { MemoryGauge } from '@/components/charts/MemoryGauge'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAgents, useLatestSnapshot, useSnapshotHistory } from '@/hooks/useMetrics'
import { useAlerts } from '@/hooks/useAlerts'
import { securityApi, correlationApi } from '@/lib/api'
import type { Severity } from '@/types/models'

// Tek agent'ın metrik kartları + grafikleri
function AgentMetrics({ agentId }: { agentId: string }) {
  const { snapshot, isLoading } = useLatestSnapshot(agentId)
  const history = useSnapshotHistory(agentId)

  if (isLoading) return <div className="text-zinc-500 text-sm">Yükleniyor...</div>
  if (!snapshot) return <div className="text-zinc-500 text-sm">Veri yok</div>

  const cpuStatus: Severity =
    snapshot.cpu.usage_percent >= 90 ? 'critical' :
    snapshot.cpu.usage_percent >= 70 ? 'warning' : 'info'

  const memPct = snapshot.memory.usage_percent
  const memStatus: Severity =
    memPct >= 90 ? 'critical' : memPct >= 70 ? 'warning' : 'info'

  const usedGB  = snapshot.memory.used_bytes / 1e9
  const totalGB = snapshot.memory.total_bytes / 1e9

  const diskMax = snapshot.disks.reduce(
    (m, d) => (d.usage_percent > m ? d.usage_percent : m), 0
  )
  const diskStatus: Severity =
    diskMax >= 90 ? 'critical' : diskMax >= 70 ? 'warning' : 'info'

  return (
    <div className="space-y-4">
      <p className="text-sm font-medium text-zinc-400">
        {snapshot.hostname}
        <span className="ml-2 text-xs text-zinc-600">
          {new Date(snapshot.collected_at).toLocaleTimeString('tr-TR')}
        </span>
      </p>

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
          icon={Server}
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

      {/* Grafikler */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2 bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">CPU Kullanımı</CardTitle>
          </CardHeader>
          <CardContent className="px-2 pb-3">
            {history.length > 1
              ? <CPUChart snapshots={history} />
              : <p className="text-zinc-600 text-xs text-center py-12">Grafik için veri bekleniyor...</p>
            }
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300">Bellek Kullanımı</CardTitle>
          </CardHeader>
          <CardContent className="pb-3">
            <MemoryGauge
              usagePercent={memPct}
              usedGB={usedGB}
              totalGB={totalGB}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Overview sayfası
// ------------------------------------------------------------------ //

export default function OverviewPage() {
  const { data: agentsData, isLoading: agentsLoading } = useAgents()
  const { alerts } = useAlerts('active', 5)

  const { data: securitySummary } = useQuery({
    queryKey: ['security-summary'],
    queryFn: () => securityApi.summary(),
    refetchInterval: 60_000,
  })

  const { data: corrData } = useQuery({
    queryKey: ['correlated-events', 'overview'],
    queryFn: () => correlationApi.listEvents({ limit: 5 }),
    refetchInterval: 30_000,
  })

  const agents = agentsData?.agents ?? []
  const totalSecurityEvents = securitySummary
    ? Object.values(securitySummary.summary).reduce((a, b) => a + b, 0)
    : 0

  return (
    <div className="space-y-6">
      {/* Başlık */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Genel Bakış</h1>
        <p className="text-sm text-zinc-500 mt-0.5">Sistemin anlık durumu</p>
      </div>

      {/* Özet kartlar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricCard
          title="Aktif Alertler"
          value={alerts.length}
          icon={Bell}
          status={alerts.some(a => a.severity === 'critical') ? 'critical' : alerts.length > 0 ? 'warning' : 'ok'}
        />
        <MetricCard
          title="Online Agent"
          value={agents.length}
          icon={Server}
          status="ok"
        />
        <MetricCard
          title="Güvenlik Olayı"
          value={totalSecurityEvents}
          icon={Shield}
          status={totalSecurityEvents > 50 ? 'warning' : 'ok'}
        />
        <MetricCard
          title="Korelasyon"
          value={corrData?.count ?? 0}
          icon={GitMerge}
          status={(corrData?.count ?? 0) > 0 ? 'warning' : 'ok'}
        />
      </div>

      {/* Agent metrikleri */}
      {agentsLoading && (
        <p className="text-zinc-500 text-sm">Agent'lar yükleniyor...</p>
      )}
      {agents.map((agent) => (
        <AgentMetrics key={agent.agent_id} agentId={agent.agent_id} />
      ))}
      {!agentsLoading && agents.length === 0 && (
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="py-12 text-center">
            <Server className="mx-auto mb-3 text-zinc-600" size={32} />
            <p className="text-zinc-500 text-sm">Henüz bağlı agent yok.</p>
          </CardContent>
        </Card>
      )}

      {/* Alt satır: Son alertler + Son korelasyon */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Son alertler */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <Bell size={14} />Son Alertler
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {alerts.length === 0 ? (
              <p className="text-zinc-600 text-sm text-center py-6">Alert yok</p>
            ) : (
              <ul className="divide-y divide-zinc-800">
                {alerts.slice(0, 5).map((alert) => (
                  <li key={alert.alert_id} className="flex items-start gap-3 px-4 py-3">
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0">
                      <p className="text-sm text-zinc-200 truncate">{alert.message}</p>
                      <p className="text-xs text-zinc-500">{alert.hostname}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Son korelasyon olayları */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <GitMerge size={14} />Son Korelasyon Olayları
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {(corrData?.events ?? []).length === 0 ? (
              <p className="text-zinc-600 text-sm text-center py-6">Olay yok</p>
            ) : (
              <ul className="divide-y divide-zinc-800">
                {(corrData?.events ?? []).slice(0, 5).map((ev) => (
                  <li key={ev.corr_id} className="flex items-start gap-3 px-4 py-3">
                    <SeverityBadge severity={ev.severity as Severity} />
                    <div className="min-w-0">
                      <p className="text-sm text-zinc-200 truncate">{ev.rule_name}</p>
                      <p className="text-xs text-zinc-500">
                        {ev.group_value} — {ev.matched_count} olay
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
