'use client'

import Link from 'next/link'
import { Bell, Server, Shield, GitMerge, Circle, ChevronRight, Share2, TrendingUp, AlertTriangle, Activity, Swords } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { useAgents, useLatestSnapshot } from '@/hooks/useMetrics'
import { useAlerts } from '@/hooks/useAlerts'
import { securityApi, correlationApi, complianceApi } from '@/lib/api'
import { MiniTopology } from '@/components/topology/MiniTopology'
import type { Severity } from '@/types/models'

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  warning:  'bg-yellow-500',
  info:     'bg-blue-500',
}

function StatCard({
  label, value, sub, accent, icon: Icon, href,
}: {
  label: string; value: string | number; sub?: string
  accent: string; icon: React.ElementType; href?: string
}) {
  const inner = (
    <div className={`relative bg-[#13161e] border border-white/[0.06] rounded-lg p-4 hover:border-white/10 transition-colors group`}>
      <div className="flex items-start justify-between mb-3">
        <div className={`w-8 h-8 rounded-md flex items-center justify-center ${accent}`}>
          <Icon size={15} />
        </div>
        {href && <ChevronRight size={13} className="text-zinc-700 group-hover:text-zinc-500 transition-colors mt-0.5" />}
      </div>
      <p className="text-2xl font-bold text-zinc-100 tabular-nums">{value}</p>
      <p className="text-xs text-zinc-500 mt-0.5 font-medium">{label}</p>
      {sub && <p className="text-[11px] text-zinc-600 mt-1">{sub}</p>}
    </div>
  )
  return href ? <Link href={href}>{inner}</Link> : inner
}

function AgentRow({ agent }: {
  agent: { agent_id: string; hostname: string; os: string; last_seen: string }
}) {
  const { snapshot } = useLatestSnapshot(agent.agent_id)
  const isOnline = Date.now() - new Date(agent.last_seen).getTime() < 60_000
  const cpu = snapshot?.cpu.usage_percent ?? null
  const mem = snapshot?.memory.usage_percent ?? null
  const pct = (val: number | null, warn = 70, crit = 90) => {
    if (val === null) return <span className="text-zinc-700">—</span>
    const c = val >= crit ? 'text-red-400' : val >= warn ? 'text-yellow-400' : 'text-zinc-400'
    return <span className={`font-mono text-xs ${c}`}>{val.toFixed(0)}%</span>
  }
  return (
    <Link href={`/agents/${agent.agent_id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] transition-colors border-b border-white/[0.04] last:border-0">
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isOnline ? 'bg-emerald-500' : 'bg-zinc-700'}`} />
      <span className="text-sm text-zinc-300 flex-1 truncate font-medium">{agent.hostname}</span>
      <div className="flex items-center gap-4">
        <div className="text-right">
          <p className="text-[10px] text-zinc-600 mb-0.5">CPU</p>
          {pct(cpu)}
        </div>
        <div className="text-right">
          <p className="text-[10px] text-zinc-600 mb-0.5">RAM</p>
          {pct(mem)}
        </div>
      </div>
      <ChevronRight size={13} className="text-zinc-700 flex-shrink-0" />
    </Link>
  )
}

function Panel({ title, icon: Icon, href, children }: {
  title: string; icon: React.ElementType; href?: string; children: React.ReactNode
}) {
  return (
    <div className="bg-[#13161e] border border-white/[0.06] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
        <div className="flex items-center gap-2">
          <Icon size={13} className="text-zinc-500" />
          <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">{title}</span>
        </div>
        {href && (
          <Link href={href} className="text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors">
            Tümü →
          </Link>
        )}
      </div>
      {children}
    </div>
  )
}

export default function OverviewPage() {
  const { data: agentsData, isLoading: agentsLoading } = useAgents()
  const { alerts } = useAlerts('active', 10)

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

  const { data: complianceSummary } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: () => complianceApi.summary(),
    refetchInterval: 300_000,
  })

  const agents = agentsData?.agents ?? []
  const totalSecurity = securitySummary
    ? Object.values(securitySummary.summary).reduce((a, b) => a + b, 0)
    : 0
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length
  const pciScore = complianceSummary?.pci_dss.score ?? null

  return (
    <div className="p-5 space-y-5 max-w-[1600px]">

      {/* Üst stat kartları */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <StatCard
          label="Aktif Alert"
          value={alerts.length}
          sub={criticalAlerts > 0 ? `${criticalAlerts} kritik` : 'Kritik yok'}
          accent={criticalAlerts > 0 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}
          icon={Bell}
          href="/alerts"
        />
        <StatCard
          label="Bağlı Agent"
          value={agents.filter(a => Date.now() - new Date(a.last_seen).getTime() < 60_000).length + '/' + agents.length}
          sub="Online / Toplam"
          accent="bg-blue-500/20 text-blue-400"
          icon={Server}
          href="/agents"
        />
        <StatCard
          label="Güvenlik Olayı"
          value={totalSecurity}
          sub="Toplam kayıtlı"
          accent={totalSecurity > 100 ? 'bg-orange-500/20 text-orange-400' : 'bg-purple-500/20 text-purple-400'}
          icon={Shield}
          href="/security"
        />
        <StatCard
          label="PCI DSS Uyum"
          value={pciScore !== null ? `%${pciScore}` : '—'}
          sub={complianceSummary ? `ISO 27001: %${complianceSummary.iso_27001.score}` : 'Hesaplanıyor'}
          accent="bg-emerald-500/20 text-emerald-400"
          icon={TrendingUp}
          href="/compliance"
        />
      </div>

      {/* Orta satır: Topoloji + Son Olaylar */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">

        {/* Topoloji — geniş */}
        <div className="xl:col-span-2">
          <Panel title="Ağ Topolojisi" icon={Share2} href="/topology">
            <div className="h-56">
              <MiniTopology />
            </div>
          </Panel>
        </div>

        {/* Korelasyon */}
        <Panel title="Saldırı Zinciri" icon={Swords} href="/timeline">
          {(corrData?.events ?? []).length === 0 ? (
            <div className="flex items-center justify-center h-56 text-zinc-600 text-sm">
              Aktif saldırı zinciri yok
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {(corrData?.events ?? []).slice(0, 6).map((ev) => (
                <div key={ev.corr_id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[ev.severity] ?? 'bg-zinc-600'}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-zinc-300 truncate font-medium">{ev.rule_name}</p>
                    <p className="text-[11px] text-zinc-600 font-mono">{ev.group_value}</p>
                  </div>
                  <SeverityBadge severity={ev.severity as Severity} />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Alt satır: 3 panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">

        {/* Agents */}
        <Panel title="Agents" icon={Server} href="/agents">
          {agentsLoading ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">Yükleniyor...</div>
          ) : agents.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">Agent bağlı değil</div>
          ) : (
            <div>
              {agents.slice(0, 6).map(a => <AgentRow key={a.agent_id} agent={a} />)}
            </div>
          )}
        </Panel>

        {/* Son Alertler */}
        <Panel title="Son Alertler" icon={AlertTriangle} href="/alerts">
          {alerts.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">Alert yok</div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {alerts.slice(0, 6).map((alert) => (
                <div key={alert.alert_id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[alert.severity] ?? 'bg-zinc-600'}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-zinc-300 truncate font-medium">{alert.message}</p>
                    <p className="text-[11px] text-zinc-600">{alert.hostname}</p>
                  </div>
                  <SeverityBadge severity={alert.severity} />
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Güvenlik Özeti */}
        <Panel title="Güvenlik Özeti" icon={Activity} href="/security">
          {!securitySummary || Object.keys(securitySummary.summary).length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">Olay yok</div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {Object.entries(securitySummary.summary).slice(0, 6).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between px-4 py-2.5">
                  <span className="text-xs text-zinc-400 font-medium truncate">{type.replace(/_/g, ' ')}</span>
                  <span className="text-xs font-mono font-bold text-zinc-300 ml-2">{count}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

      </div>
    </div>
  )
}
