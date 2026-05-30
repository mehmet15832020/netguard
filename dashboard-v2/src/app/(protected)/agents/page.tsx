'use client'

import { useState, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import { Server, Search, Circle, ChevronRight, Wifi, WifiOff, Activity } from 'lucide-react'
import { useAgents, useLatestSnapshot } from '@/hooks/useMetrics'
import { SkeletonTable } from '@/components/ui/skeleton'

const PAGE_SIZE = 20

function AgentRow({ agent, onClick }: {
  agent: { agent_id: string; hostname: string; os: string; last_seen: string }
  onClick: () => void
}) {
  const { snapshot } = useLatestSnapshot(agent.agent_id)

  const isOnline = Date.now() - new Date(agent.last_seen).getTime() < 60_000

  const cpu  = snapshot?.cpu.usage_percent ?? null
  const mem  = snapshot?.memory.usage_percent ?? null
  const disk = snapshot?.disks.reduce((m, d) => d.usage_percent > m ? d.usage_percent : m, 0) ?? null

  const pctCell = (val: number | null) => {
    if (val === null) return <span className="text-slate-700">—</span>
    const color = val >= 90 ? 'text-red-400' : val >= 70 ? 'text-yellow-400' : 'text-slate-300'
    return <span className={color}>{val.toFixed(1)}%</span>
  }

  return (
    <tr
      onClick={onClick}
      className="border-b border-sky-900/10 hover:bg-sky-950/20 cursor-pointer transition-colors"
    >
      <td className="ui-td">
        <div className="flex items-center gap-2">
          <Circle
            size={8}
            className={isOnline ? 'text-emerald-400 fill-emerald-400' : 'text-slate-700 fill-slate-700'}
          />
          <span className="text-sm text-slate-100">{agent.hostname}</span>
        </div>
      </td>
      <td className="ui-td text-sm text-slate-500 hidden md:table-cell">{agent.os}</td>
      <td className="ui-td text-sm text-right font-mono">{pctCell(cpu)}</td>
      <td className="ui-td text-sm text-right font-mono">{pctCell(mem)}</td>
      <td className="ui-td text-sm text-right font-mono hidden sm:table-cell">{pctCell(disk)}</td>
      <td className="ui-td text-sm text-slate-600 hidden lg:table-cell">
        {new Date(agent.last_seen).toLocaleTimeString('tr-TR')}
      </td>
      <td className="ui-td text-right">
        <ChevronRight size={14} className="text-slate-600 inline" />
      </td>
    </tr>
  )
}

export default function AgentsPage() {
  const router = useRouter()
  const { data, isLoading } = useAgents()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  const agents = data?.agents ?? []

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return agents
    return agents.filter(a =>
      a.hostname.toLowerCase().includes(q) || a.os.toLowerCase().includes(q)
    )
  }, [agents, search])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paginated  = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const handleSearch = (v: string) => {
    setSearch(v)
    setPage(1)
  }

  const onlineCount  = agents.filter(a => Date.now() - new Date(a.last_seen).getTime() < 60_000).length
  const offlineCount = agents.length - onlineCount

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <Server size={15} className="text-sky-400" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-slate-100 leading-tight">Agents</h1>
          <p className="text-xs text-slate-600">{agents.length} agent kayıtlı</p>
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="ui-panel p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10">
            <Wifi size={16} className="text-emerald-400" />
          </div>
          <div>
            <p className="text-xs text-slate-500">Online</p>
            <p className="text-2xl font-bold text-emerald-400">{onlineCount}</p>
          </div>
        </div>
        <div className="ui-panel p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-sky-950/40">
            <WifiOff size={16} className="text-slate-500" />
          </div>
          <div>
            <p className="text-xs text-slate-500">Offline</p>
            <p className="text-2xl font-bold text-slate-400">{offlineCount}</p>
          </div>
        </div>
        <div className="ui-panel p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-sky-500/10">
            <Activity size={16} className="text-sky-400" />
          </div>
          <div>
            <p className="text-xs text-slate-500">Toplam</p>
            <p className="text-2xl font-bold text-slate-100">{agents.length}</p>
          </div>
        </div>
      </div>

      {/* Table panel */}
      <div className="ui-panel">
        {/* Search */}
        <div className="ui-panel-header">
          <div className="relative w-full">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
            <input
              type="text"
              value={search}
              onChange={e => handleSearch(e.target.value)}
              placeholder="Hostname veya OS ara..."
              className="ui-input pl-8"
            />
          </div>
        </div>

        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={6} height={40} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Server size={28} className="opacity-20" />
            <p className="text-sm">
              {search ? 'Eşleşen agent bulunamadı.' : 'Henüz bağlı agent yok.'}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="ui-th">Hostname</th>
                    <th className="ui-th hidden md:table-cell">OS</th>
                    <th className="ui-th text-right">CPU</th>
                    <th className="ui-th text-right">RAM</th>
                    <th className="ui-th text-right hidden sm:table-cell">Disk</th>
                    <th className="ui-th hidden lg:table-cell">Son Görülme</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {paginated.map(agent => (
                    <AgentRow
                      key={agent.agent_id}
                      agent={agent}
                      onClick={() => router.push(`/agents/${agent.agent_id}`)}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="ui-panel-footer flex items-center justify-between">
                <span className="text-xs text-slate-600">
                  {filtered.length} sonuç — sayfa {page} / {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="ui-btn ui-btn-secondary"
                  >
                    Önceki
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="ui-btn ui-btn-secondary"
                  >
                    Sonraki
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
