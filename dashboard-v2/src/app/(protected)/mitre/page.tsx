'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { mitreApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

// ─── Sabitler ────────────────────────────────────────────────────────────────

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

// MITRE ATT&CK v17 — NetGuard kural setindeki teknik isimleri
const TECHNIQUE_NAMES: Record<string, string> = {
  'T1046':  'Network Service Scanning',
  'T1110':  'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.003': 'Password Spraying',
  'T1071':  'Application Layer Protocol',
  'T1071.001': 'Web Protocols',
  'T1071.004': 'DNS',
  'T1041':  'Exfiltration Over C2 Channel',
  'T1048':  'Exfiltration Over Alternative Protocol',
  'T1190':  'Exploit Public-Facing Application',
  'T1078':  'Valid Accounts',
  'T1021':  'Remote Services',
  'T1021.004': 'SSH',
  'T1133':  'External Remote Services',
  'T1595':  'Active Scanning',
  'T1595.001': 'Scanning IP Blocks',
  'T1595.002': 'Vulnerability Scanning',
  'T1040':  'Network Sniffing',
  'T1056':  'Input Capture',
  'T1059':  'Command and Scripting Interpreter',
  'T1098':  'Account Manipulation',
  'T1136':  'Create Account',
  'T1049':  'System Network Connections Discovery',
  'T1018':  'Remote System Discovery',
  'T1016':  'System Network Configuration Discovery',
  'T1005':  'Data from Local System',
  'T1560':  'Archive Collected Data',
  'T1486':  'Data Encrypted for Impact',
  'T1562':  'Impair Defenses',
  'T1055':  'Process Injection',
  'T1003':  'OS Credential Dumping',
}

function techniqueLabel(id: string): string {
  return TECHNIQUE_NAMES[id] ? `${id} — ${TECHNIQUE_NAMES[id]}` : id
}

// ─── Renk yardımcıları ────────────────────────────────────────────────────────

function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return 'bg-zinc-800 border-zinc-700 text-zinc-400'
  const ratio = count / maxCount
  if (ratio >= 0.8) return 'bg-red-900/80   border-red-600   text-red-200'
  if (ratio >= 0.5) return 'bg-red-800/60   border-red-700   text-red-300'
  if (ratio >= 0.2) return 'bg-orange-900/60 border-orange-700 text-orange-300'
  return 'bg-yellow-900/40 border-yellow-800 text-yellow-400'
}

function heatDot(count: number): string {
  if (count === 0) return 'bg-zinc-700'
  if (count < 3)  return 'bg-yellow-500'
  if (count < 10) return 'bg-orange-500'
  return 'bg-red-500'
}

// ─── Coverage Meter ──────────────────────────────────────────────────────────

function CoverageMeter({
  coveredTactics, totalTactics, totalTech, totalRules,
}: { coveredTactics: number; totalTactics: number; totalTech: number; totalRules: number }) {
  const tacticPct = Math.round((coveredTactics / totalTactics) * 100)
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 space-y-3">
      <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Kapsama Özeti</p>
      <div className="grid grid-cols-3 gap-4 text-center">
        <div>
          <p className="text-2xl font-bold text-indigo-400">{tacticPct}%</p>
          <p className="text-[11px] text-zinc-500 mt-0.5">Taktik Kapsama</p>
        </div>
        <div>
          <p className="text-2xl font-bold text-emerald-400">{totalTech}</p>
          <p className="text-[11px] text-zinc-500 mt-0.5">Kapsanan Teknik</p>
        </div>
        <div>
          <p className="text-2xl font-bold text-orange-400">{totalRules}</p>
          <p className="text-[11px] text-zinc-500 mt-0.5">MITRE Etiketli Kural</p>
        </div>
      </div>
      <div>
        <div className="flex justify-between text-[10px] text-zinc-600 mb-1">
          <span>{coveredTactics}/{totalTactics} taktik</span>
          <span>MITRE ATT&CK v17</span>
        </div>
        <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-indigo-600 to-indigo-400 transition-all"
            style={{ width: `${tacticPct}%` }}
          />
        </div>
      </div>
    </div>
  )
}

// ─── Taktik Aktivite Bar Chart ────────────────────────────────────────────────

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
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: '#18181b',
      borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 11 },
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}: <b>${params[0].value}</b> tetiklenme`,
    },
    xAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    yAxis: {
      type: 'category',
      data: items.map((i) => i.label),
      axisLabel: { color: '#a1a1aa', fontSize: 10 },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { show: false },
    },
    series: [{
      type: 'bar',
      data: items.map((i) => ({
        value: i.value,
        itemStyle: {
          color: i.value === 0 ? '#27272a'
            : i.value >= 10 ? '#ef4444'
            : i.value >= 5  ? '#f97316'
            : '#6366f1',
        },
      })),
      barMaxWidth: 20,
      label: {
        show: true,
        position: 'right',
        color: '#71717a',
        fontSize: 10,
        formatter: (p: { value: number }) => p.value > 0 ? String(p.value) : '',
      },
    }],
  }

  return <ReactECharts option={option} style={{ height: TACTIC_ORDER.length * 28 }} notMerge />
}

// ─── Top Techniques ──────────────────────────────────────────────────────────

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
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-3">
        En Çok Kapsanan Teknikler
      </p>
      <div className="space-y-2">
        {freq.map(([tid, info]) => (
          <div key={tid} className="flex items-center gap-3">
            <a
              href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[11px] text-indigo-400 hover:text-indigo-300 w-28 flex-shrink-0"
              onClick={(e) => e.stopPropagation()}
            >
              {tid}
            </a>
            <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-indigo-500 rounded-full"
                style={{ width: `${(info.count / max) * 100}%` }}
              />
            </div>
            <span className="text-[11px] font-mono text-zinc-500 w-4 text-right">{info.count}</span>
            <span className="text-[11px] text-zinc-600 flex-1 truncate hidden lg:block">
              {TECHNIQUE_NAMES[tid] ?? ''}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Ana sayfa ────────────────────────────────────────────────────────────────

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
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Crosshair className="w-5 h-5 text-indigo-400" />
          <h1 className="text-xl font-semibold text-zinc-100">MITRE ATT&CK Kapsama</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800">
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button size="sm" variant="outline" onClick={handleDownloadHeatmap}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800">
            <Download className="w-4 h-4 mr-1.5" />
            Navigator Layer
          </Button>
        </div>
      </div>

      {/* Coverage meter + Top Techniques */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {isLoading ? (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl h-36 animate-pulse" />
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
          { label: 'Aktif Taktik (24s)', value: activeTactics24h,      color: 'text-orange-400' },
          { label: `Toplam Tetiklenme (${timeWindow})`, value: totalAlerts, color: 'text-red-400' },
          { label: 'Kör Nokta', value: uncoveredTactics.length,        color: 'text-zinc-400' },
          { label: 'Kapsanan Taktik', value: coveredTactics.length,    color: 'text-emerald-400' },
        ].map(({ label, value, color }) => (
          <Card key={label} className="bg-zinc-900 border-zinc-800">
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-zinc-500 mb-1">{label}</p>
              <p className={cn('text-2xl font-bold', color)}>{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Taktik Aktivite Grafiği + Isı Haritası */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        {/* Aktivite bar chart */}
        <div className="xl:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
            <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">
              Taktik Aktivitesi
            </p>
            <div className="flex gap-1">
              {(['24h', '7d'] as const).map(w => (
                <button
                  key={w}
                  onClick={() => setTimeWindow(w)}
                  className={cn(
                    'px-2 py-0.5 text-[11px] rounded',
                    timeWindow === w
                      ? 'bg-indigo-600 text-white'
                      : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200',
                  )}
                >
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
        <Card className="xl:col-span-3 bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-2 pt-3 px-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">
                ATT&CK Isı Haritası — Tetiklenme Sıklığı
              </CardTitle>
              <div className="flex gap-1">
                {(['24h', '7d'] as const).map(w => (
                  <button
                    key={w}
                    onClick={() => setTimeWindow(w)}
                    className={cn(
                      'px-2 py-0.5 text-[11px] rounded',
                      timeWindow === w
                        ? 'bg-indigo-600 text-white'
                        : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200',
                    )}
                  >
                    {w}
                  </button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            {isLoading ? (
              <p className="text-zinc-500 text-sm py-8 text-center">Yükleniyor...</p>
            ) : (
              <div className="grid grid-cols-4 sm:grid-cols-7 gap-1.5">
                {TACTIC_ORDER.map(tactic => {
                  const count    = tacticsActivity[tactic]?.[timeWindow === '24h' ? 'count_24h' : 'count_7d'] ?? 0
                  const covered  = !!coverage?.tactics[tactic]
                  const cellColor = covered
                    ? heatColor(count, maxCount)
                    : 'bg-zinc-900 border-zinc-800 text-zinc-700'
                  const isExp = expandedTactic === tactic
                  const info  = coverage?.tactics[tactic]

                  return (
                    <div
                      key={tactic}
                      onClick={() => setExpandedTactic(isExp ? null : tactic)}
                      className={cn(
                        'relative border rounded-lg p-2 cursor-pointer transition-all hover:opacity-90',
                        cellColor,
                        isExp && 'ring-1 ring-indigo-500',
                      )}
                    >
                      <div className="flex items-start justify-between gap-1 mb-1">
                        <span className="text-[9px] font-mono text-zinc-500">{TACTIC_IDS[tactic]}</span>
                        <span className={cn('w-2 h-2 rounded-full flex-shrink-0 mt-0.5', covered ? heatDot(count) : 'bg-zinc-800')} />
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
            <div className="flex items-center flex-wrap gap-3 mt-3 pt-3 border-t border-zinc-800">
              {[
                { label: 'Kapsama yok', cls: 'bg-zinc-900 border-zinc-800' },
                { label: 'Kapsanıyor',  cls: 'bg-zinc-800 border-zinc-700' },
                { label: 'Az',          cls: 'bg-yellow-900/40 border-yellow-800' },
                { label: 'Orta',        cls: 'bg-orange-900/60 border-orange-700' },
                { label: 'Yüksek',      cls: 'bg-red-800/60 border-red-700' },
                { label: 'Kritik',      cls: 'bg-red-900/80 border-red-600' },
              ].map(({ label, cls }) => (
                <div key={label} className="flex items-center gap-1.5">
                  <div className={cn('w-3 h-3 rounded border', cls)} />
                  <span className="text-[10px] text-zinc-500">{label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

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
              <button onClick={() => setExpandedTactic(null)} className="text-zinc-500 hover:text-zinc-300 text-xs">
                Kapat ✕
              </button>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-4 space-y-3">
            <div className="flex gap-6 text-sm flex-wrap">
              <span className="text-zinc-400">
                <span className="text-zinc-200 font-medium">{coverage.tactics[expandedTactic].rule_count}</span> kural
              </span>
              <span className="text-zinc-400">
                <span className="text-orange-400 font-medium">
                  {tacticsActivity[expandedTactic]?.count_24h ?? 0}
                </span> tetiklenme (24s)
              </span>
              <span className="text-zinc-400">
                <span className="text-zinc-300 font-medium">
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
                    className="px-2 py-1 rounded text-xs font-mono bg-zinc-800 text-indigo-300 border border-zinc-700 hover:border-indigo-500 transition-colors group"
                  >
                    {t}
                    {TECHNIQUE_NAMES[t] && (
                      <span className="hidden group-hover:inline ml-1 text-zinc-500 font-sans">
                        — {TECHNIQUE_NAMES[t]}
                      </span>
                    )}
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
          <h2 className="text-sm font-medium text-zinc-400 mb-2 uppercase tracking-wide">
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

      {/* Kural tablosu — collapsible */}
      {techData && techData.rules.length > 0 && (
        <div>
          <button
            onClick={() => setShowRuleTable(r => !r)}
            className="flex items-center gap-2 text-sm font-medium text-zinc-400 uppercase tracking-wide mb-3 hover:text-zinc-200 transition-colors"
          >
            {showRuleTable ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            Kural — Teknik Eşleştirme ({techData.rules.length} kural)
          </button>

          {showRuleTable && (
            <Card className="bg-zinc-900 border-zinc-800">
              <CardContent className="p-0">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 text-left">
                      <th className="px-4 py-2.5 text-zinc-400 font-medium text-xs">Kural</th>
                      <th className="px-4 py-2.5 text-zinc-400 font-medium text-xs">Taktikler</th>
                      <th className="px-4 py-2.5 text-zinc-400 font-medium text-xs">Teknikler</th>
                      <th className="px-4 py-2.5 text-zinc-400 font-medium text-xs">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {techData.rules.map(rule => (
                      <tr key={rule.rule_id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="px-4 py-2.5">
                          <p className="font-medium text-zinc-200 text-xs">{rule.rule_name}</p>
                          <p className="text-[11px] text-zinc-500 font-mono">{rule.rule_id}</p>
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
                              <a
                                key={t}
                                href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                                target="_blank"
                                rel="noopener noreferrer"
                                title={TECHNIQUE_NAMES[t]}
                                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-800/50 hover:border-indigo-500"
                              >
                                {t}
                              </a>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={cn('text-xs font-medium uppercase',
                            rule.severity === 'critical' ? 'text-red-400' :
                            rule.severity === 'high'     ? 'text-orange-400' :
                            rule.severity === 'warning'  ? 'text-yellow-400' : 'text-blue-400',
                          )}>
                            {rule.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
