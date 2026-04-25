'use client'

import { useQuery } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw } from 'lucide-react'
import { mitreApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

const TACTIC_ORDER = [
  'reconnaissance', 'initial_access', 'execution', 'persistence',
  'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection', 'command_and_control',
  'exfiltration', 'impact',
]

const TACTIC_COLORS: Record<string, string> = {
  reconnaissance:       'border-slate-500  bg-slate-500/10  text-slate-300',
  initial_access:       'border-orange-500 bg-orange-500/10 text-orange-300',
  execution:            'border-red-500    bg-red-500/10    text-red-300',
  persistence:          'border-yellow-500 bg-yellow-500/10 text-yellow-300',
  privilege_escalation: 'border-amber-500  bg-amber-500/10  text-amber-300',
  defense_evasion:      'border-cyan-500   bg-cyan-500/10   text-cyan-300',
  credential_access:    'border-purple-500 bg-purple-500/10 text-purple-300',
  discovery:            'border-blue-500   bg-blue-500/10   text-blue-300',
  lateral_movement:     'border-indigo-500 bg-indigo-500/10 text-indigo-300',
  collection:           'border-teal-500   bg-teal-500/10   text-teal-300',
  command_and_control:  'border-rose-500   bg-rose-500/10   text-rose-300',
  exfiltration:         'border-pink-500   bg-pink-500/10   text-pink-300',
  impact:               'border-red-700    bg-red-700/10    text-red-400',
}

export default function MitrePage() {
  const { data: coverage, isLoading, refetch } = useQuery({
    queryKey: ['mitre-coverage'],
    queryFn:  () => mitreApi.coverage(),
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

  const orderedTactics = TACTIC_ORDER.filter(t => coverage?.tactics[t])
  const uncoveredTactics = TACTIC_ORDER.filter(t => !coverage?.tactics[t])

  return (
    <div className="p-6 space-y-6">
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

      {/* Özet */}
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
            <p className="text-xs text-zinc-400 mb-1">Kapsanan Taktik</p>
            <p className="text-2xl font-bold text-purple-400">{orderedTactics.length}</p>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-zinc-400 mb-1">Kör Nokta Taktik</p>
            <p className="text-2xl font-bold text-zinc-500">{uncoveredTactics.length}</p>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <p className="text-zinc-500 text-sm">Yükleniyor...</p>
      ) : (
        <>
          {/* Kapsanan taktikler */}
          <div>
            <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
              Kapsanan Taktikler
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {orderedTactics.map(tactic => {
                const info = coverage!.tactics[tactic]
                const color = TACTIC_COLORS[tactic] ?? 'border-zinc-500 bg-zinc-500/10 text-zinc-300'
                return (
                  <Card key={tactic} className={`border ${color.split(' ')[0]} bg-zinc-900`}>
                    <CardHeader className="pb-2 pt-3 px-4">
                      <div className="flex items-center justify-between">
                        <CardTitle className={`text-sm ${color.split(' ')[2]}`}>
                          {info.label}
                        </CardTitle>
                        <span className="text-xs text-zinc-500">{info.tactic_id}</span>
                      </div>
                    </CardHeader>
                    <CardContent className="px-4 pb-3">
                      <div className="flex flex-wrap gap-1 mb-2">
                        {info.techniques.map(t => (
                          <span key={t} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300 border border-zinc-700">
                            {t}
                          </span>
                        ))}
                        {info.techniques.length === 0 && (
                          <span className="text-xs text-zinc-600">Teknik etiket yok</span>
                        )}
                      </div>
                      <p className="text-xs text-zinc-500">{info.rule_count} kural</p>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>

          {/* Kör noktalar */}
          {uncoveredTactics.length > 0 && (
            <div>
              <h2 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wide">
                Kör Noktalar — Kapsama Yok
              </h2>
              <div className="flex flex-wrap gap-2">
                {uncoveredTactics.map(t => (
                  <span key={t} className="px-3 py-1 rounded border border-zinc-700 text-xs text-zinc-500 bg-zinc-900">
                    {t.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Kural detayları */}
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
                        <th className="px-4 py-2 text-zinc-400 font-medium">Kural</th>
                        <th className="px-4 py-2 text-zinc-400 font-medium">Taktikler</th>
                        <th className="px-4 py-2 text-zinc-400 font-medium">Teknikler</th>
                        <th className="px-4 py-2 text-zinc-400 font-medium">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {techData.rules.map(rule => (
                        <tr key={rule.rule_id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                          <td className="px-4 py-2">
                            <p className="font-medium text-zinc-200">{rule.rule_name}</p>
                            <p className="text-xs text-zinc-500 font-mono">{rule.rule_id}</p>
                          </td>
                          <td className="px-4 py-2">
                            <div className="flex flex-wrap gap-1">
                              {rule.mitre_tactics.map(t => (
                                <span key={t} className="px-1 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300">
                                  {t.replace(/_/g, ' ')}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-2">
                            <div className="flex flex-wrap gap-1">
                              {rule.mitre_techniques.map(t => (
                                <span key={t} className="px-1 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-2">
                            <span className={`text-xs uppercase ${
                              rule.severity === 'critical' ? 'text-red-400' :
                              rule.severity === 'high' ? 'text-orange-400' :
                              rule.severity === 'warning' ? 'text-yellow-400' : 'text-blue-400'
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
        </>
      )}
    </div>
  )
}
