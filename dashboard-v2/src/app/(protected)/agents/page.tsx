'use client'

import { useState, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import { Server, Search, Circle, ChevronRight } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAgents, useLatestSnapshot } from '@/hooks/useMetrics'

const PAGE_SIZE = 20

// Tek satır — snapshot verisi için ayrı hook çağrısı
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
    if (val === null) return <span className="text-zinc-600">—</span>
    const color = val >= 90 ? 'text-red-400' : val >= 70 ? 'text-yellow-400' : 'text-zinc-300'
    return <span className={color}>{val.toFixed(1)}%</span>
  }

  return (
    <tr
      onClick={onClick}
      className="border-b border-zinc-800 hover:bg-zinc-800/50 cursor-pointer transition-colors"
    >
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <Circle
            size={8}
            className={isOnline ? 'text-emerald-400 fill-emerald-400' : 'text-zinc-600 fill-zinc-600'}
          />
          <span className="text-sm text-zinc-100">{agent.hostname}</span>
        </div>
      </td>
      <td className="px-4 py-3 text-sm text-zinc-400 hidden md:table-cell">{agent.os}</td>
      <td className="px-4 py-3 text-sm text-right font-mono">{pctCell(cpu)}</td>
      <td className="px-4 py-3 text-sm text-right font-mono">{pctCell(mem)}</td>
      <td className="px-4 py-3 text-sm text-right font-mono hidden sm:table-cell">{pctCell(disk)}</td>
      <td className="px-4 py-3 text-sm text-zinc-500 hidden lg:table-cell">
        {new Date(agent.last_seen).toLocaleTimeString('tr-TR')}
      </td>
      <td className="px-4 py-3 text-right">
        <ChevronRight size={14} className="text-zinc-500 inline" />
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

  return (
    <div className="space-y-6">
      {/* Başlık */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Agents</h1>
        <p className="text-sm text-zinc-500 mt-0.5">{agents.length} agent kayıtlı</p>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          {/* Arama */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={search}
              onChange={e => handleSearch(e.target.value)}
              placeholder="Hostname veya OS ara..."
              className="w-full bg-zinc-800 border border-zinc-700 rounded-md pl-8 pr-4 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-12">Yükleniyor...</p>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12">
              <Server className="mx-auto mb-3 text-zinc-600" size={28} />
              <p className="text-zinc-500 text-sm">
                {search ? 'Eşleşen agent bulunamadı.' : 'Henüz bağlı agent yok.'}
              </p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                      <th className="px-4 py-2.5 text-left font-medium">Hostname</th>
                      <th className="px-4 py-2.5 text-left font-medium hidden md:table-cell">OS</th>
                      <th className="px-4 py-2.5 text-right font-medium">CPU</th>
                      <th className="px-4 py-2.5 text-right font-medium">RAM</th>
                      <th className="px-4 py-2.5 text-right font-medium hidden sm:table-cell">Disk</th>
                      <th className="px-4 py-2.5 text-left font-medium hidden lg:table-cell">Son Görülme</th>
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

              {/* Sayfalama */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-zinc-800">
                  <span className="text-xs text-zinc-500">
                    {filtered.length} sonuç — sayfa {page} / {totalPages}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setPage(p => Math.max(1, p - 1))}
                      disabled={page === 1}
                      className="px-3 py-1 text-xs rounded bg-zinc-800 text-zinc-300 disabled:opacity-40 hover:bg-zinc-700 transition-colors"
                    >
                      Önceki
                    </button>
                    <button
                      onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                      disabled={page === totalPages}
                      className="px-3 py-1 text-xs rounded bg-zinc-800 text-zinc-300 disabled:opacity-40 hover:bg-zinc-700 transition-colors"
                    >
                      Sonraki
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
