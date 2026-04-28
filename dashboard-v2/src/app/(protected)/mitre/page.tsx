'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw } from 'lucide-react'
import { mitreApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

const TACTIC_ORDER = [
  'reconnaissance',
  'initial_access',
  'execution',
  'persistence',
  'privilege_escalation',
  'defense_evasion',
  'credential_access',
  'discovery',
  'lateral_movement',
  'collection',
  'command_and_control',
  'exfiltration',
  'impact',
]

const TACTIC_LABELS: Record<string, string> = {
  reconnaissance:       'Reconnaissance',
  resource_development: 'Resource Dev.',
  initial_access:       'Initial Access',
  execution:            'Execution',
  persistence:          'Persistence',
  privilege_escalation: 'Privilege Esc.',
  defense_evasion:      'Defense Evasion',
  credential_access:    'Credential Access',
  discovery:            'Discovery',
  lateral_movement:     'Lateral Movement',
  collection:           'Collection',
  command_and_control:  'C2',
  exfiltration:         'Exfiltration',
  impact:               'Impact',
}

const TACTIC_IDS: Record<string, string> = {
  reconnaissance:       'TA0043',
  initial_access:       'TA0001',
  execution:            'TA0002',
  persistence:          'TA0003',
  privilege_escalation: 'TA0004',
  defense_evasion:      'TA0005',
  credential_access:    'TA0006',
  discovery:            'TA0007',
  lateral_movement:     'TA0008',
  collection:           'TA0009',
  command_and_control:  'TA0011',
  exfiltration:         'TA0010',
  impact:               'TA0040',
}

function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return 'bg-zinc-800 border-zinc-700 text-zinc-400'
  const ratio = count / maxCount
  if (ratio >= 0.8) return 'bg-red-900/80   border-red-600   text-red-200'
  if (ratio >= 0.5) return 'bg-red-800/60   border-red-700   text-red-300'
  if (ratio >= 0.2) return 'bg-orange-900/60 border-orange-700 text-orange-300'
  return 'bg-yellow-900/40 border-yellow-800 text-yellow-400'
}

function heatDot(count: number): string {
  if (count === 0)  return 'bg-zinc-700'
  if (count < 3)   return 'bg-yellow-500'
  if (count < 10)  return 'bg-orange-500'
  return 'bg-red-500'
}

export default function MitrePage() {
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null)
  const [timeWindow, setTimeWindow] = useState<'24h' | '7d'>('24h')

  const { data: coverage, isLoading, refetch } = useQuery({
    queryKey: ['mitre-coverage'],
    queryFn:  () => mitreApi.coverage(),
  })

  const { data: activity } = useQuery({
    queryKey: ['mitre-activity'],
    queryFn:  () => mitreApi.activity(),
    refetchInterval: 60_000,
  })

  const { data: techData } = useQuery({
    queryKey: ['mitre-techniques'],
    queryFn:  () => mitreApi.techniques(),
  })

  const handleDownloadHeatmap = async () => {
    try {
      const heatmap = await mitreApi.heatmap(30)
      const blob = new Blob([JSON.stringify(heatmap, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'netguard-attack-layer.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* ignore */ }
  }

  const tacticsActivity = activity?.tactics ?? {}
  const maxCount = Math.max(
    1,
    ...TACTIC_ORDER.map(t => tacticsActivity[t]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0),
  )

  const coveredTactics   = TACTIC_ORDER.filter(t => coverage?.tactics[t])
  const uncoveredTactics = TACTIC_ORDER.filter(t => !coverage?.tactics[t])

  const totalAlerts24h = TACTIC_ORDER.reduce(
    (s, t) => s + (tacticsActivity[t]?.count_24h ?? 0), 0,
  )
  const totalAlerts7d = TACTIC_ORDER.reduce(
    (s, t) => s + (tacticsActivity[t]?.count_7d ?? 0), 0,
  )
  const activeTactics24h = TACTIC_ORDER.filter(t => (tacticsActivity[t]?.count_24h ?? 0) > 0).length

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Crosshair className="w-5 h-5 text-indigo-400" />
          <h1 className="text-xl font-semibold">MITRE ATT&CK Kapsama</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button size="sm" variant="outline" onClick={handleDownloadHeatmap}>
            <Download className="w-4 h-4 mr-1" />
            Navigator Layer
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-400 mb-1">Kapsanan Teknik</p>
            <p className="text-2xl font-bold text-indigo-400">{coverage?.total_techniques ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-400 mb-1">MITRE Etiketli Kural</p>
            <p className="text-2xl font-bold text-emerald-400">{coverage?.total_rules_with_mitre ?? 0}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-400 mb-1">Aktif Taktik (24s)</p>
            <p className="text-2xl font-bold text-orange-400">{activeTactics24h}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-400 mb-1">Toplam Tetiklenme</p>
            <p className="text-2xl font-bold text-red-400">{timeWindow === '24h' ? totalAlerts24h : totalAlerts7d}</p>
          </CardContent>
        </Card>
      </div>

      {/* Heat Map */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-2 pt-4 px-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm text-zinc-300">ATT&CK Isı Haritası — Tetiklenme Sıklığı</CardTitle>
            <div className="flex gap-1">
              {(['24h', '7d'] as const).map(w => (
                <button
                  key={w}
                  onClick={() => setTimeWindow(w)}
                  className={`px-2.5 py-1 text-xs rounded transition-colors ${
                    timeWindow === w
                      ? 'bg-indigo-600 text-white'
                      : 'bg-zinc-800 text-zinc-400 hover:text-zinc-100'
                  }`}
                >
                  Son {w}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          {isLoading ? (
            <p className="text-zinc-500 text-sm py-8 text-center">Yükleniyor...</p>
          ) : (
            <div className="grid grid-cols-4 sm:grid-cols-7 xl:grid-cols-13 gap-2">
              {TACTIC_ORDER.map(tactic => {
                const count    = tacticsActivity[tactic]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0
                const covered  = !!coverage?.tactics[tactic]
                const cellColor = covered
                  ? heatColor(count, maxCount)
                  : 'bg-zinc-900 border-zinc-800 text-zinc-700'
                const isExpanded = expandedTactic === tactic
                const tacticInfo = coverage?.tactics[tactic]

                return (
                  <div
                    key={tactic}
                    onClick={() => setExpandedTactic(isExpanded ? null : tactic)}
                    className={`relative border rounded-lg p-2.5 cursor-pointer transition-all hover:opacity-90 ${cellColor} ${isExpanded ? 'ring-1 ring-indigo-500' : ''}`}
                  >
                    <div className="flex items-start justify-between gap-1 mb-1">
                      <span className="text-[9px] font-mono text-zinc-500">{TACTIC_IDS[tactic]}</span>
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 mt-0.5 ${covered ? heatDot(count) : 'bg-zinc-800'}`} />
                    </div>
                    <p className="text-[11px] font-medium leading-tight mb-1.5">{TACTIC_LABELS[tactic]}</p>
                    {covered ? (
                      <>
                        <p className="text-[10px] opacity-70">{tacticInfo?.techniques.length ?? 0} teknik</p>
                        {count > 0 && (
                          <p className="text-[11px] font-bold mt-0.5">{count}×</p>
                        )}
                      </>
                    ) : (
                      <p className="text-[10px] opacity-50">kapsama yok</p>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* Legend */}
          <div className="flex items-center flex-wrap gap-4 mt-4 pt-3 border-t border-zinc-800">
            <span className="text-xs text-zinc-500">Yoğunluk:</span>
            {[
              { label: 'Kapsama yok', cls: 'bg-zinc-900 border-zinc-800' },
              { label: 'Kapsanıyor',  cls: 'bg-zinc-800 border-zinc-700' },
              { label: 'Az',          cls: 'bg-yellow-900/40 border-yellow-800' },
              { label: 'Orta',        cls: 'bg-orange-900/60 border-orange-700' },
              { label: 'Yüksek',      cls: 'bg-red-800/60 border-red-700' },
              { label: 'Kritik',      cls: 'bg-red-900/80 border-red-600' },
            ].map(({ label, cls }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div className={`w-3 h-3 rounded border ${cls}`} />
                <span className="text-xs text-zinc-500">{label}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Expanded tactic detail */}
      {expandedTactic && coverage?.tactics[expandedTactic] && (
        <Card className="bg-zinc-900 border-indigo-700/50">
          <CardHeader className="pb-2 pt-3 px-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm text-indigo-300">
                {coverage.tactics[expandedTactic].label}
                <span className="ml-2 text-xs text-zinc-500 font-mono">
                  {coverage.tactics[expandedTactic].tactic_id}
                </span>
              </CardTitle>
              <button
                onClick={() => setExpandedTactic(null)}
                className="text-zinc-500 hover:text-zinc-300 text-xs"
              >
                Kapat ✕
              </button>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-4 space-y-3">
            <div className="flex gap-6 text-sm">
              <span className="text-zinc-400">
                <span className="text-zinc-200 font-medium">
                  {coverage.tactics[expandedTactic].rule_count}
                </span>{' '}kural
              </span>
              <span className="text-zinc-400">
                <span className="text-orange-400 font-medium">
                  {tacticsActivity[expandedTactic]?.count_24h ?? 0}
                </span>{' '}tetiklenme (24s)
              </span>
              <span className="text-zinc-400">
                <span className="text-zinc-300 font-medium">
                  {tacticsActivity[expandedTactic]?.count_7d ?? 0}
                </span>{' '}tetiklenme (7g)
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {coverage.tactics[expandedTactic].techniques.length > 0 ? (
                coverage.tactics[expandedTactic].techniques.map(t => (
                  <a
                    key={t}
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-1 rounded text-xs font-mono bg-zinc-800 text-indigo-300 border border-zinc-700 hover:border-indigo-500 transition-colors"
                  >
                    {t}
                  </a>
                ))
              ) : (
                <span className="text-xs text-zinc-600">Teknik etiket yok</span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Blind spots */}
      {uncoveredTactics.length > 0 && (
        <div>
          <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
            Kör Noktalar — Kapsama Yok
          </h2>
          <div className="flex flex-wrap gap-2">
            {uncoveredTactics.map(t => (
              <span key={t} className="px-3 py-1 rounded border border-zinc-700 text-xs text-zinc-500 bg-zinc-900">
                {TACTIC_LABELS[t] ?? t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Rule-technique table */}
      {techData && techData.rules.length > 0 && (
        <div>
          <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
            Kural — Teknik Eşleştirme
          </h2>
          <Card className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-left">
                    <th className="px-4 py-2.5 text-zinc-400 font-medium">Kural</th>
                    <th className="px-4 py-2.5 text-zinc-400 font-medium">Taktikler</th>
                    <th className="px-4 py-2.5 text-zinc-400 font-medium">Teknikler</th>
                    <th className="px-4 py-2.5 text-zinc-400 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {techData.rules.map(rule => (
                    <tr key={rule.rule_id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                      <td className="px-4 py-2.5">
                        <p className="font-medium text-zinc-200">{rule.rule_name}</p>
                        <p className="text-xs text-zinc-500 font-mono">{rule.rule_id}</p>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_tactics.map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-800/50">
                              {TACTIC_LABELS[t] ?? t.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_techniques.map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-800/50">
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`text-xs font-medium uppercase ${
                          rule.severity === 'critical' ? 'text-red-400' :
                          rule.severity === 'high'     ? 'text-orange-400' :
                          rule.severity === 'warning'  ? 'text-yellow-400' : 'text-blue-400'
                        }`}>{rule.severity}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
