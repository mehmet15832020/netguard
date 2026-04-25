'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Swords, RefreshCw, ChevronRight } from 'lucide-react'
import { correlationApi } from '@/lib/api'
import type { CorrelatedEvent } from '@/types/models'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400 border-red-500/40 bg-red-500/10',
  warning:  'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  high:     'text-orange-400 border-orange-500/40 bg-orange-500/10',
  info:     'text-blue-400 border-blue-500/40 bg-blue-500/10',
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  warning:  'bg-yellow-500',
  high:     'bg-orange-500',
  info:     'bg-blue-500',
}

const TACTIC_LABEL: Record<string, string> = {
  reconnaissance:       'Reconnaissance',
  initial_access:       'Initial Access',
  credential_access:    'Credential Access',
  lateral_movement:     'Lateral Movement',
  execution:            'Execution',
  persistence:          'Persistence',
  privilege_escalation: 'Privilege Escalation',
  defense_evasion:      'Defense Evasion',
  discovery:            'Discovery',
  command_and_control:  'C2',
  exfiltration:         'Exfiltration',
  impact:               'Impact',
}

function MitreBadge({ tech }: { tech: string }) {
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
      {tech}
    </span>
  )
}

function TacticBadge({ tactic }: { tactic: string }) {
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
      {TACTIC_LABEL[tactic] ?? tactic}
    </span>
  )
}

function ChainGroup({ ip, events }: { ip: string; events: CorrelatedEvent[] }) {
  const [expanded, setExpanded] = useState(false)
  const sorted = [...events].sort((a, b) => a.created_at.localeCompare(b.created_at))
  const highest: string = events.some(e => e.severity === 'critical') ? 'critical'
    : events.some(e => e.severity === 'warning' || e.severity === 'high') ? 'warning' : 'info'

  const allTechniques = [...new Set(events.flatMap(e => e.mitre_techniques ?? []))]
  const allTactics    = [...new Set(events.flatMap(e => e.mitre_tactics ?? []))]

  return (
    <Card className="bg-zinc-900 border-zinc-800 mb-3">
      <CardHeader
        className="py-3 px-4 cursor-pointer select-none"
        onClick={() => setExpanded(v => !v)}
      >
        <div className="flex items-center gap-3">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[highest] ?? 'bg-zinc-500'}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm text-zinc-100">{ip}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded border ${SEV_COLOR[highest] ?? ''}`}>
                {highest.toUpperCase()}
              </span>
              <span className="text-xs text-zinc-500">{events.length} olay</span>
            </div>
            <div className="flex gap-1 flex-wrap mt-1">
              {allTactics.map(t => <TacticBadge key={t} tactic={t} />)}
              {allTechniques.map(t => <MitreBadge key={t} tech={t} />)}
            </div>
          </div>
          <ChevronRight
            size={14}
            className={`text-zinc-500 transition-transform flex-shrink-0 ${expanded ? 'rotate-90' : ''}`}
          />
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="px-4 pb-4 pt-0">
          <div className="border-t border-zinc-800 pt-3 space-y-0">
            {sorted.map((ev, i) => (
              <div key={ev.corr_id} className="flex gap-3 relative pb-3">
                <div className="flex flex-col items-center">
                  <span className={`mt-1 w-2.5 h-2.5 rounded-full flex-shrink-0 ${SEV_DOT[ev.severity] ?? 'bg-zinc-500'}`} />
                  {i < sorted.length - 1 && <div className="w-px flex-1 bg-zinc-700 mt-1" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-200 leading-snug">{ev.rule_name}</p>
                  <p className="text-xs text-zinc-500 mt-0.5">
                    {new Date(ev.created_at).toLocaleString('tr-TR')}
                    {' · '}
                    <span className="font-mono">{ev.event_type}</span>
                    {' · '}
                    {ev.matched_count} olay / {ev.window_seconds}s
                  </p>
                  {((ev.mitre_techniques?.length ?? 0) > 0 || (ev.mitre_tactics?.length ?? 0) > 0) && (
                    <div className="flex gap-1 flex-wrap mt-1">
                      {(ev.mitre_tactics ?? []).map(t => <TacticBadge key={t} tactic={t} />)}
                      {(ev.mitre_techniques ?? []).map(t => <MitreBadge key={t} tech={t} />)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      )}
    </Card>
  )
}

export default function TimelinePage() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['timeline-events'],
    queryFn:  () => correlationApi.listEvents({ limit: 500 }),
    refetchInterval: 30_000,
  })

  const events = data?.events ?? []

  // IP bazında grupla
  const byIp = events.reduce<Record<string, CorrelatedEvent[]>>((acc: Record<string, CorrelatedEvent[]>, ev: CorrelatedEvent) => {
    const key = ev.group_value
    if (!acc[key]) acc[key] = []
    acc[key].push(ev)
    return acc
  }, {})

  // En yüksek severity'ye ve olay sayısına göre sırala
  const sevOrder: Record<string, number> = { critical: 3, warning: 2, high: 2, info: 1 }
  const sortedGroups = (Object.entries(byIp) as [string, CorrelatedEvent[]][]).sort(([, a], [, b]) => {
    const sa = Math.max(...a.map((e: CorrelatedEvent) => sevOrder[e.severity] ?? 0))
    const sb = Math.max(...b.map((e: CorrelatedEvent) => sevOrder[e.severity] ?? 0))
    if (sb !== sa) return sb - sa
    return b.length - a.length
  })

  const chainGroups = sortedGroups.filter(([, evs]) => evs.length > 1)
  const singleGroups = sortedGroups.filter(([, evs]) => evs.length === 1)

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Swords className="w-5 h-5 text-red-400" />
          <h1 className="text-xl font-semibold">Saldırı Timeline</h1>
          <span className="text-xs text-zinc-500">Kill chain ve korelasyon olayları</span>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {isLoading ? (
        <p className="text-zinc-500 text-sm">Yükleniyor...</p>
      ) : sortedGroups.length === 0 ? (
        <p className="text-zinc-500 text-sm">Henüz korelasyon olayı yok.</p>
      ) : (
        <>
          {chainGroups.length > 0 && (
            <div>
              <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
                Çoklu Aşama Zincirleri ({chainGroups.length})
              </h2>
              {chainGroups.map(([ip, evs]) => (
                <ChainGroup key={ip} ip={ip} events={evs} />
              ))}
            </div>
          )}

          {singleGroups.length > 0 && (
            <div>
              <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
                Tekil Olaylar ({singleGroups.length})
              </h2>
              {singleGroups.map(([ip, evs]) => (
                <ChainGroup key={ip} ip={ip} events={evs} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
