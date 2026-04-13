'use client'

import Link from 'next/link'
import { Bell, Server, Shield, GitMerge, Circle, ChevronRight } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { MetricCard } from '@/components/metrics/MetricCard'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAgents, useLatestSnapshot } from '@/hooks/useMetrics'
import { useAlerts } from '@/hooks/useAlerts'
import { securityApi, correlationApi } from '@/lib/api'
import type { Severity } from '@/types/models'

// Kompakt agent satırı — Overview'daki özet liste için
function AgentRow({ agent }: {
  agent: { agent_id: string; hostname: string; os: string; last_seen: string }
}) {
  const { snapshot } = useLatestSnapshot(agent.agent_id)
  const isOnline = Date.now() - new Date(agent.last_seen).getTime() < 60_000

  const cpu  = snapshot?.cpu.usage_percent ?? null
  const mem  = snapshot?.memory.usage_percent ?? null

  const pct = (val: number | null) => {
    if (val === null) return <span className="text-zinc-600">—</span>
    const color = val >= 90 ? 'text-red-400' : val >= 70 ? 'text-yellow-400' : 'text-zinc-300'
    return <span className={`font-mono ${color}`}>{val.toFixed(0)}%</span>
  }

  return (
    <Link
      href={`/agents/${agent.agent_id}`}
      className="flex items-center gap-3 px-4 py-3 border-b border-zinc-800/50 hover:bg-zinc-800/40 transition-colors"
    >
      <Circle
        size={8}
        className={isOnline ? 'text-emerald-400 fill-emerald-400 shrink-0' : 'text-zinc-600 fill-zinc-600 shrink-0'}
      />
      <span className="text-sm text-zinc-200 flex-1 truncate">{agent.hostname}</span>
      <div className="flex items-center gap-4 text-sm">
        <span className="text-zinc-500 text-xs hidden sm:inline">CPU {pct(cpu)}</span>
        <span className="text-zinc-500 text-xs hidden sm:inline">RAM {pct(mem)}</span>
      </div>
      <ChevronRight size={14} className="text-zinc-600 shrink-0" />
    </Link>
  )
}

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

      {/* Özet sayaçlar */}
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

      {/* Ana içerik: agent listesi + alertler */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Agent özet listesi */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <Server size={14} /> Agents
            </CardTitle>
            <Link href="/agents" className="text-xs text-indigo-400 hover:text-indigo-300">
              Tümünü gör →
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            {agentsLoading ? (
              <p className="text-zinc-600 text-sm text-center py-6">Yükleniyor...</p>
            ) : agents.length === 0 ? (
              <p className="text-zinc-600 text-sm text-center py-6">Henüz bağlı agent yok</p>
            ) : (
              agents.slice(0, 8).map(agent => (
                <AgentRow key={agent.agent_id} agent={agent} />
              ))
            )}
          </CardContent>
        </Card>

        {/* Son alertler */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <Bell size={14} /> Son Alertler
            </CardTitle>
            <Link href="/alerts" className="text-xs text-indigo-400 hover:text-indigo-300">
              Tümünü gör →
            </Link>
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
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <GitMerge size={14} /> Son Korelasyon Olayları
            </CardTitle>
            <Link href="/correlation" className="text-xs text-indigo-400 hover:text-indigo-300">
              Tümünü gör →
            </Link>
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
                      <p className="text-xs text-zinc-500">{ev.group_value} — {ev.matched_count} olay</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Güvenlik özeti */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <Shield size={14} /> Güvenlik Özeti
            </CardTitle>
            <Link href="/security" className="text-xs text-indigo-400 hover:text-indigo-300">
              Tümünü gör →
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            {!securitySummary || Object.keys(securitySummary.summary).length === 0 ? (
              <p className="text-zinc-600 text-sm text-center py-6">Güvenlik olayı yok</p>
            ) : (
              <ul className="divide-y divide-zinc-800">
                {Object.entries(securitySummary.summary).slice(0, 5).map(([type, count]) => (
                  <li key={type} className="flex items-center justify-between px-4 py-3">
                    <span className="text-sm text-zinc-300">{type}</span>
                    <span className="text-sm font-mono text-zinc-400">{count}</span>
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
