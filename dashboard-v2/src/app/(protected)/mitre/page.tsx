'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { mitreApi } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import { SkeletonChart } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const TACTIC_ORDER = [
  'reconnaissance', 'initial_access', 'execution', 'persistence',
  'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection', 'command_and_control',
  'exfiltration', 'impact',
] as const

type Tactic = typeof TACTIC_ORDER[number]

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

const TECHNIQUE_NAMES: Record<string, string> = {
  'T1046':     'Network Service Scanning',
  'T1110':     'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.003': 'Password Spraying',
  'T1071':     'Application Layer Protocol',
  'T1071.001': 'Web Protocols',
  'T1071.004': 'DNS',
  'T1041':     'Exfiltration Over C2 Channel',
  'T1048':     'Exfiltration Over Alternative Protocol',
  'T1190':     'Exploit Public-Facing Application',
  'T1078':     'Valid Accounts',
  'T1021':     'Remote Services',
  'T1021.004': 'SSH',
  'T1133':     'External Remote Services',
  'T1595':     'Active Scanning',
  'T1595.001': 'Scanning IP Blocks',
  'T1595.002': 'Vulnerability Scanning',
  'T1040':     'Network Sniffing',
  'T1056':     'Input Capture',
  'T1059':     'Command and Scripting Interpreter',
  'T1098':     'Account Manipulation',
  'T1136':     'Create Account',
  'T1049':     'System Network Connections Discovery',
  'T1018':     'Remote System Discovery',
  'T1016':     'System Network Configuration Discovery',
  'T1005':     'Data from Local System',
  'T1560':     'Archive Collected Data',
  'T1486':     'Data Encrypted for Impact',
  'T1562':     'Impair Defenses',
  'T1055':     'Process Injection',
  'T1003':     'OS Credential Dumping',
}

function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return 'bg-sky-950/20 border-sky-900/20 text-slate-400'
  const ratio = count / maxCount
  if (ratio >= 0.8) return 'bg-red-900/80   border-red-600   text-red-200'
  if (ratio >= 0.5) return 'bg-red-800/60   border-red-700   text-red-300'
  if (ratio >= 0.2) return 'bg-orange-900/60 border-orange-700 text-orange-300'
  return 'bg-yellow-900/40 border-yellow-800 text-yellow-400'
}

function heatDot(count: number): string {
  if (count === 0) return 'bg-slate-700'
  if (count < 3)  return 'bg-yellow-500'
  if (count < 10) return 'bg-orange-500'
  return 'bg-red-500'
}

function CoverageMeter({
  coveredTactics, totalTactics, totalTech, totalRules,
}: { coveredTactics: number; totalTactics: number; totalTech: number; totalRules: number }) {
  const tacticPct = Math.round((coveredTactics / totalTactics) * 100)
  return (
    <div className="ui-panel p-4 space-y-3">
      <p className="ui-section-label">Kapsama Özeti</p>
      <div className="grid grid-cols-3 gap-4 text-center">
        <div>
          <p className="text-2xl font-bold text-sky-400">{tacticPct}%</p>
          <p className="text-[11px] text-slate-500 mt-0.5">Taktik Kapsama</p>
        </div>
        <div>
          <p className="text-2xl font-bold text-emerald-400">{totalTech}</p>
          <p className="text-[11px] text-slate-500 mt-0.5">Kapsanan Teknik</p>
        </div>
        <div>
          <p className="text-2xl font-bold text-orange-400">{totalRules}</p>
          <p className="text-[11px] text-slate-500 mt-0.5">MITRE Etiketli Kural</p>
        </div>
      </div>
      <div>
        <div className="flex justify-between text-[10px] text-slate-600 mb-1">
          <span>{coveredTactics}/{totalTactics} taktik</span>
          <span>MITRE ATT&CK v17</span>
        </div>
        <div className="h-2 bg-sky-950/30 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-sky-600 to-sky-400 transition-all"
            style={{ width: `${tacticPct}%` }}
          />
        </div>
      </div>
    </div>
  )
}

function TacticActivityChart({
  tacticsActivity, timeWindow,
}: {
  tacticsActivity: Record<string, { count_24h: number; count_7d: number }>
  timeWindow: '24h' | '7d'
}) {
  const key = timeWindow === '24h' ? 'count_24h' : 'count_7d'
  const items = TACTIC_ORDER
    .map((t) => ({ label: TACTIC_LABELS[t] ?? t, value: tacticsActivity[t]?.[key] ?? 0 }))
    .sort((a, b) => b.value - a.value)

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 4, right: 40, bottom: 4, left: 110, containLabel: false },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}: <b>${params[0].value}</b> tetiklenme`,
    },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category',
      data: items.map((i) => i.label),
      axisLabel: { color: '#64748b', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    series: [{
      type: 'bar',
      data: items.map((i) => ({
        value: i.value,
        itemStyle: {
          color: i.value === 0 ? 'rgba(56,189,248,0.08)'
            : i.value >= 10 ? '#ef4444'
            : i.value >= 5  ? '#f97316'
            : '#38bdf8',
        },
      })),
      barMaxWidth: 20,
      label: {
        show: true,
        position: 'right',
        color: '#475569',
        fontSize: 10,
        formatter: (p: { value: number }) => p.value > 0 ? String(p.value) : '',
      },
    }],
  }

  return <ReactECharts option={option} style={{ height: TACTIC_ORDER.length * 28 }} notMerge />
}

function TopTechniquesPanel({ rules }: {
  rules: { rule_id: string; rule_name: string; severity: string; mitre_techniques: string[]; mitre_tactics: string[] }[]
}) {
  const freq = useMemo(() => {
    const m: Record<string, { count: number; rules: string[] }> = {}
    rules.forEach((r) => {
      r.mitre_techniques.forEach((t) => {
        if (!m[t]) m[t] = { count: 0, rules: [] }
        m[t].count++
        m[t].rules.push(r.rule_name)
      })
    })
    return Object.entries(m)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
  }, [rules])

  if (freq.length === 0) return null
  const max = freq[0][1].count

  return (
    <div className="ui-panel p-4">
      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-3">
        En Çok Kapsanan Teknikler
      </p>
      <div className="space-y-2">
        {freq.map(([tid, info]) => (
          <div key={tid} className="flex items-center gap-3">
            <a
              href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[11px] text-sky-400 hover:text-sky-300 w-28 flex-shrink-0 transition-colors"
              onClick={(e) => e.stopPropagation()}
            >
              {tid}
            </a>
            <div className="flex-1 h-1.5 bg-sky-950/30 rounded-full overflow-hidden">
              <div
                className="h-full bg-sky-500 rounded-full"
                style={{ width: `${(info.count / max) * 100}%` }}
              />
            </div>
            <span className="text-[11px] font-mono text-slate-500 w-4 text-right">{info.count}</span>
            <span className="text-[11px] text-slate-600 flex-1 truncate hidden lg:block">
              {TECHNIQUE_NAMES[tid] ?? ''}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

const TIME_BTN = (active: boolean) =>
  `px-2 py-0.5 text-[11px] rounded-md border transition-colors ${
    active
      ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
      : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300'
  }`

export default function MitrePage() {
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null)
  const [timeWindow, setTimeWindow]         = useState<'24h' | '7d'>('24h')
  const [showRuleTable, setShowRuleTable]   = useState(false)

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

  const tacticsActivity  = activity?.tactics ?? {}
  const maxCount = Math.max(1, ...TACTIC_ORDER.map(t =>
    tacticsActivity[t]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0
  ))

  const coveredTactics   = TACTIC_ORDER.filter(t => coverage?.tactics[t])
  const uncoveredTactics = TACTIC_ORDER.filter(t => !coverage?.tactics[t])
  const activeTactics24h = TACTIC_ORDER.filter(t => (tacticsActivity[t]?.count_24h ?? 0) > 0).length

  const totalAlerts = TACTIC_ORDER.reduce(
    (s, t) => s + (tacticsActivity[t]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0), 0,
  )

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Crosshair size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">MITRE ATT&CK Kapsama</h1>
            <p className="text-xs text-slate-600">ATT&CK v17 · {coveredTactics.length}/{TACTIC_ORDER.length} taktik</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={12} />
          </button>
          <button
            onClick={handleDownloadHeatmap}
            className="ui-btn ui-btn-secondary"
          >
            <Download size={12} />
            Navigator Layer
          </button>
        </div>
      </div>

      {/* Coverage meter + Top Techniques */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {isLoading ? (
          <SkeletonChart height={144} className="rounded-xl" />
        ) : (
          <CoverageMeter
            coveredTactics={coveredTactics.length}
            totalTactics={TACTIC_ORDER.length}
            totalTech={coverage?.total_techniques ?? 0}
            totalRules={coverage?.total_rules_with_mitre ?? 0}
          />
        )}
        {techData && techData.rules.length > 0 && (
          <TopTechniquesPanel rules={techData.rules} />
        )}
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Aktif Taktik (24s)',                    value: activeTactics24h,        color: 'text-orange-400' },
          { label: `Toplam Tetiklenme (${timeWindow})`,     value: totalAlerts,             color: 'text-red-400' },
          { label: 'Kör Nokta',                             value: uncoveredTactics.length, color: 'text-slate-400' },
          { label: 'Kapsanan Taktik',                       value: coveredTactics.length,   color: 'text-emerald-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="ui-panel p-4">
            <p className="text-xs text-slate-500 mb-1">{label}</p>
            <p className={`text-3xl font-bold leading-none ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Taktik Aktivitesi + ATT&CK Isı Haritası */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        {/* Aktivite bar chart */}
        <div className="xl:col-span-2 ui-panel">
          <div className="ui-panel-header justify-between">
            <p className="ui-section-label">
              Taktik Aktivitesi
            </p>
            <div className="flex gap-1">
              {(['24h', '7d'] as const).map(w => (
                <button key={w} onClick={() => setTimeWindow(w)} className={TIME_BTN(timeWindow === w)}>
                  {w}
                </button>
              ))}
            </div>
          </div>
          <div className="p-3">
            <TacticActivityChart tacticsActivity={tacticsActivity} timeWindow={timeWindow} />
          </div>
        </div>

        {/* Isı haritası */}
        <div className="xl:col-span-3 ui-panel">
          <div className="ui-panel-header justify-between">
            <p className="ui-section-label">
              ATT&CK Isı Haritası — Tetiklenme Sıklığı
            </p>
            <div className="flex gap-1">
              {(['24h', '7d'] as const).map(w => (
                <button key={w} onClick={() => setTimeWindow(w)} className={TIME_BTN(timeWindow === w)}>
                  {w}
                </button>
              ))}
            </div>
          </div>
          <div className="p-4">
            {isLoading ? (
              <p className="text-slate-500 text-sm py-8 text-center">Yükleniyor...</p>
            ) : (
              <div className="grid grid-cols-4 sm:grid-cols-7 gap-1.5">
                {TACTIC_ORDER.map(tactic => {
                  const count    = tacticsActivity[tactic]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0
                  const covered  = !!coverage?.tactics[tactic]
                  const cellColor = covered
                    ? heatColor(count, maxCount)
                    : 'bg-[#040911] border-sky-900/10 text-slate-700'
                  const isExp = expandedTactic === tactic
                  const info  = coverage?.tactics[tactic]

                  return (
                    <div
                      key={tactic}
                      onClick={() => setExpandedTactic(isExp ? null : tactic)}
                      className={cn(
                        'relative border rounded-lg p-2 cursor-pointer transition-all hover:opacity-90',
                        cellColor,
                        isExp && 'ring-1 ring-sky-500',
                      )}
                    >
                      <div className="flex items-start justify-between gap-1 mb-1">
                        <span className="text-[9px] font-mono text-slate-600">{TACTIC_IDS[tactic]}</span>
                        <span className={cn('w-2 h-2 rounded-full flex-shrink-0 mt-0.5', covered ? heatDot(count) : 'bg-sky-950/50')} />
                      </div>
                      <p className="text-[10px] font-medium leading-tight mb-1">{TACTIC_LABELS[tactic]}</p>
                      {covered ? (
                        <>
                          <p className="text-[9px] opacity-70">{info?.techniques.length ?? 0} teknik</p>
                          {count > 0 && <p className="text-[10px] font-bold mt-0.5">{count}×</p>}
                        </>
                      ) : (
                        <p className="text-[9px] opacity-50">kapsama yok</p>
                      )}
                    </div>
                  )
                })}
              </div>
            )}

            {/* Legend */}
            <div className="flex items-center flex-wrap gap-3 mt-3 pt-3 border-t border-sky-900/15">
              {[
                { label: 'Kapsama yok', cls: 'bg-[#040911] border-sky-900/10' },
                { label: 'Kapsanıyor',  cls: 'bg-sky-950/20 border-sky-900/20' },
                { label: 'Az',          cls: 'bg-yellow-900/40 border-yellow-800' },
                { label: 'Orta',        cls: 'bg-orange-900/60 border-orange-700' },
                { label: 'Yüksek',      cls: 'bg-red-800/60 border-red-700' },
                { label: 'Kritik',      cls: 'bg-red-900/80 border-red-600' },
              ].map(({ label, cls }) => (
                <div key={label} className="flex items-center gap-1.5">
                  <div className={cn('w-3 h-3 rounded border', cls)} />
                  <span className="text-[10px] text-slate-500">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Expanded tactic detail */}
      {expandedTactic && coverage?.tactics[expandedTactic] && (
        <div className="bg-[#0a1120] border border-sky-500/30 rounded-xl overflow-hidden">
          <div className="ui-panel-header justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-sky-300">
                {coverage.tactics[expandedTactic].label}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {coverage.tactics[expandedTactic].tactic_id}
              </span>
            </div>
            <button
              onClick={() => setExpandedTactic(null)}
              className="text-slate-500 hover:text-slate-300 text-xs transition-colors"
            >
              Kapat ✕
            </button>
          </div>
          <div className="px-4 py-3 space-y-3">
            <div className="flex gap-6 text-sm flex-wrap">
              <span className="text-slate-400">
                <span className="text-slate-200 font-medium">{coverage.tactics[expandedTactic].rule_count}</span> kural
              </span>
              <span className="text-slate-400">
                <span className="text-orange-400 font-medium">
                  {tacticsActivity[expandedTactic]?.count_24h ?? 0}
                </span> tetiklenme (24s)
              </span>
              <span className="text-slate-400">
                <span className="text-slate-300 font-medium">
                  {tacticsActivity[expandedTactic]?.count_7d ?? 0}
                </span> tetiklenme (7g)
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
                    title={TECHNIQUE_NAMES[t]}
                    className="px-2 py-1 rounded text-xs font-mono bg-sky-500/10 text-sky-300 border border-sky-500/25 hover:border-sky-400/50 transition-colors group"
                  >
                    {t}
                    {TECHNIQUE_NAMES[t] && (
                      <span className="hidden group-hover:inline ml-1 text-slate-500 font-sans">
                        — {TECHNIQUE_NAMES[t]}
                      </span>
                    )}
                  </a>
                ))
              ) : (
                <span className="text-xs text-slate-600">Teknik etiket yok</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Blind spots */}
      {uncoveredTactics.length > 0 && (
        <div>
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
            Kör Noktalar — Kapsama Yok
          </h2>
          <div className="flex flex-wrap gap-2">
            {uncoveredTactics.map(t => (
              <span key={t} className="px-3 py-1 rounded-lg border border-sky-900/20 text-xs text-slate-500 bg-sky-950/20">
                {TACTIC_LABELS[t] ?? t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Kural tablosu — collapsible */}
      {techData && techData.rules.length > 0 && (
        <div>
          <button
            onClick={() => setShowRuleTable(r => !r)}
            className="flex items-center gap-2 text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3 hover:text-slate-300 transition-colors"
          >
            {showRuleTable ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            Kural — Teknik Eşleştirme ({techData.rules.length} kural)
          </button>

          {showRuleTable && (
            <div className="ui-panel">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-sky-900/20">
                    <th className="ui-th">Kural</th>
                    <th className="ui-th">Taktikler</th>
                    <th className="ui-th">Teknikler</th>
                    <th className="ui-th">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sky-900/10">
                  {techData.rules.map(rule => (
                    <tr key={rule.rule_id} className="hover:bg-sky-950/20 transition-colors">
                      <td className="ui-td">
                        <p className="font-medium text-slate-200 text-xs">{rule.rule_name}</p>
                        <p className="text-[11px] text-slate-500 font-mono">{rule.rule_id}</p>
                      </td>
                      <td className="ui-td">
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_tactics.map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-violet-500/15 text-violet-300 border border-violet-500/25">
                              {TACTIC_LABELS[t] ?? t.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="ui-td">
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_techniques.map(t => (
                            <a
                              key={t}
                              href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              title={TECHNIQUE_NAMES[t]}
                              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/25 hover:border-sky-400/50 transition-colors"
                            >
                              {t}
                            </a>
                          ))}
                        </div>
                      </td>
                      <td className="ui-td">
                        <span className={cn('text-xs font-medium uppercase',
                          rule.severity === 'critical' ? 'text-red-400' :
                          rule.severity === 'high'     ? 'text-orange-400' :
                          rule.severity === 'warning'  ? 'text-yellow-400' : 'text-sky-400',
                        )}>
                          {rule.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
