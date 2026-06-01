'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw, AlertTriangle, Shield, ShieldOff } from 'lucide-react'
import { mitreApi, MitreTacticRow, MitreTechniqueRow, MitreSubtechnique } from '@/lib/api'
import { SkeletonChart, SkeletonStatGrid } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// ── helpers ────────────────────────────────────────────────────────────────────

function coverageColor(pct: number): string {
  if (pct === 0)   return 'bg-[#040911] border-sky-900/15 text-slate-600'
  if (pct < 25)    return 'bg-emerald-950/30 border-emerald-900/30 text-emerald-500'
  if (pct < 60)    return 'bg-emerald-900/40 border-emerald-700/40 text-emerald-400'
  return               'bg-emerald-800/50 border-emerald-600/50 text-emerald-300'
}

function techCellColor(covered: boolean, hits: number): string {
  if (!covered)  return 'bg-slate-900/40 border-slate-800/40 text-slate-600 hover:border-slate-700/60'
  if (hits === 0) return 'bg-sky-950/25 border-sky-800/30 text-sky-300 hover:border-sky-700/50'
  if (hits < 5)  return 'bg-yellow-950/40 border-yellow-800/40 text-yellow-300 hover:border-yellow-700/60'
  if (hits < 20) return 'bg-orange-950/50 border-orange-700/50 text-orange-300 hover:border-orange-600/70'
  return              'bg-red-950/60 border-red-700/60 text-red-300 hover:border-red-600/80'
}

function hitsBadgeColor(hits: number): string {
  if (hits === 0) return 'text-slate-600'
  if (hits < 5)  return 'text-yellow-500'
  if (hits < 20) return 'text-orange-400'
  return              'text-red-400'
}

// ── sub-components ─────────────────────────────────────────────────────────────

function SummaryKpis({ summary }: { summary: { total_techniques: number; covered_techniques: number; coverage_pct: number; top_gaps: unknown[] } }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[
        { label: 'Toplam Teknik',    value: summary.total_techniques,   color: 'text-slate-300' },
        { label: 'Kapsanan',         value: summary.covered_techniques, color: 'text-emerald-400' },
        { label: 'Kapsama %',        value: `${summary.coverage_pct}%`, color: 'text-sky-400' },
        { label: 'Kör Nokta',        value: summary.top_gaps.length,    color: 'text-orange-400' },
      ].map(({ label, value, color }) => (
        <div key={label} className="ui-panel p-4 text-center">
          <p className={cn('text-3xl font-bold leading-none', color)}>{value}</p>
          <p className="text-[11px] text-slate-500 mt-1.5">{label}</p>
        </div>
      ))}
    </div>
  )
}

function TacticHeader({ tactic, onClick, active }: { tactic: MitreTacticRow; onClick: () => void; active: boolean }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-2 py-1.5 rounded-lg border transition-all',
        active
          ? 'bg-sky-500/15 border-sky-500/30'
          : coverageColor(tactic.coverage_pct),
      )}
    >
      <p className="text-[10px] font-mono text-slate-500 leading-none mb-0.5">{tactic.id}</p>
      <p className={cn('text-[11px] font-semibold leading-tight', active ? 'text-sky-300' : '')}>
        {tactic.label}
      </p>
      <div className="mt-1 flex items-center gap-1.5">
        <div className="flex-1 h-1 bg-sky-950/30 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-emerald-500/70 transition-all"
            style={{ width: `${tactic.coverage_pct}%` }}
          />
        </div>
        <span className="text-[9px] text-slate-500 flex-shrink-0">{Math.round(tactic.coverage_pct)}%</span>
      </div>
    </button>
  )
}

function TechniqueCell({
  tech,
  onClick,
  selected,
}: {
  tech: MitreTechniqueRow | MitreSubtechnique
  onClick: () => void
  selected: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-2 py-1.5 rounded border transition-all text-[10px] leading-tight',
        techCellColor(tech.covered, tech.hits_30d),
        selected && 'ring-1 ring-sky-500',
      )}
    >
      <p className="font-mono font-semibold">{tech.id}</p>
      <p className="text-slate-400 mt-0.5 truncate">{tech.name}</p>
      {tech.hits_30d > 0 && (
        <p className={cn('font-bold mt-0.5', hitsBadgeColor(tech.hits_30d))}>
          {tech.hits_30d}×
        </p>
      )}
    </button>
  )
}

function TechniqueDetail({ tech, onClose }: { tech: MitreTechniqueRow | MitreSubtechnique; onClose: () => void }) {
  const attackUrl = `https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`
  return (
    <div className="bg-[#0a1120] border border-sky-500/30 rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-sm text-sky-300 font-bold">{tech.id}</span>
            {tech.covered
              ? <span className="flex items-center gap-1 text-[10px] text-emerald-400"><Shield size={10} /> Kapsanıyor</span>
              : <span className="flex items-center gap-1 text-[10px] text-slate-500"><ShieldOff size={10} /> Kapsama yok</span>
            }
          </div>
          <p className="text-sm text-slate-200">{tech.name}</p>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors text-xs flex-shrink-0">✕</button>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="bg-sky-950/20 rounded-lg p-3">
          <p className="text-[10px] text-slate-500 mb-1">Son 30 Gün Hit</p>
          <p className={cn('text-2xl font-bold', hitsBadgeColor(tech.hits_30d))}>{tech.hits_30d}</p>
        </div>
        <div className="bg-sky-950/20 rounded-lg p-3">
          <p className="text-[10px] text-slate-500 mb-1">Kural Sayısı</p>
          <p className="text-2xl font-bold text-slate-300">{tech.rules.length}</p>
        </div>
      </div>

      {tech.rules.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-1.5">Kurallar</p>
          <div className="flex flex-wrap gap-1.5">
            {tech.rules.map(r => (
              <span key={r} className="px-2 py-0.5 rounded text-[10px] bg-sky-500/10 text-sky-300 border border-sky-500/20">
                {r}
              </span>
            ))}
          </div>
        </div>
      )}

      {'subtechniques' in tech && (tech as MitreTechniqueRow).subtechniques.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-1.5">Alt Teknikler</p>
          <div className="space-y-1">
            {(tech as MitreTechniqueRow).subtechniques.map(sub => (
              <div key={sub.id} className={cn(
                'flex items-center gap-2 px-2 py-1 rounded text-[10px]',
                sub.covered ? 'bg-emerald-950/20 text-emerald-400' : 'bg-slate-900/30 text-slate-600',
              )}>
                <span className="font-mono font-semibold">{sub.id}</span>
                <span className="flex-1 text-slate-400">{sub.name}</span>
                {sub.hits_30d > 0 && <span className={cn('font-bold', hitsBadgeColor(sub.hits_30d))}>{sub.hits_30d}×</span>}
                {sub.covered ? <Shield size={9} className="text-emerald-500 flex-shrink-0" /> : <ShieldOff size={9} className="text-slate-700 flex-shrink-0" />}
              </div>
            ))}
          </div>
        </div>
      )}

      <a
        href={attackUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="block text-center text-[11px] text-sky-400 hover:text-sky-300 border border-sky-900/30 hover:border-sky-700/50 rounded-lg py-1.5 transition-colors"
      >
        MITRE ATT&CK ↗
      </a>
    </div>
  )
}

function GapPanel({ gaps }: { gaps: { id: string; name: string; tactic_slug: string; tactic_label: string }[] }) {
  if (gaps.length === 0) return null
  return (
    <div className="ui-panel">
      <div className="ui-panel-header">
        <AlertTriangle size={13} className="text-orange-400" />
        <p className="ui-section-label text-orange-400">Kapsama Açıkları — Öncelikli</p>
      </div>
      <div className="p-3 space-y-1.5">
        {gaps.map(g => (
          <div key={`${g.tactic_slug}-${g.id}`} className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-orange-950/20 border border-orange-900/20">
            <span className="font-mono text-[11px] text-orange-300 font-semibold w-24 flex-shrink-0">{g.id}</span>
            <span className="text-[11px] text-slate-400 flex-1 truncate">{g.name}</span>
            <span className="text-[10px] text-slate-600 flex-shrink-0 hidden sm:block">{g.tactic_label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── main page ──────────────────────────────────────────────────────────────────

type SelectedTech = { tactic: string; techId: string } | null

export default function MitrePage() {
  const [days, setDays] = useState(30)
  const [activeTactic, setActiveTactic] = useState<string | null>(null)
  const [selected, setSelected] = useState<SelectedTech>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['mitre-matrix', days],
    queryFn: () => mitreApi.matrix(days),
    staleTime: 60_000,
  })

  const handleDownload = async () => {
    try {
      const heatmap = await mitreApi.heatmap(days)
      const blob = new Blob([JSON.stringify(heatmap, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'netguard-attack-layer.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* ignore */ }
  }

  const shownTactics = activeTactic
    ? (data?.tactics ?? []).filter(t => t.slug === activeTactic)
    : (data?.tactics ?? [])

  const selectedTech = (() => {
    if (!selected || !data) return null
    for (const tac of data.tactics) {
      for (const tech of tac.techniques) {
        if (tech.id === selected.techId && tac.slug === selected.tactic) return tech
        for (const sub of tech.subtechniques) {
          if (sub.id === selected.techId && tac.slug === selected.tactic) return sub
        }
      }
    }
    return null
  })()

  const DAYS_OPTS = [7, 14, 30, 90] as const

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Crosshair size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">MITRE ATT&CK Matrix</h1>
            <p className="text-xs text-slate-600">ATT&CK Enterprise v17 · {data?.tactics.length ?? 13} taktik</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {DAYS_OPTS.map(d => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={cn(
                  'px-2 py-0.5 text-[11px] rounded-md border transition-colors',
                  days === d
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
                )}
              >
                {d}g
              </button>
            ))}
          </div>
          <button onClick={() => refetch()} className="ui-btn ui-btn-secondary">
            <RefreshCw size={12} />
          </button>
          <button onClick={handleDownload} className="ui-btn ui-btn-secondary">
            <Download size={12} />
            Navigator
          </button>
        </div>
      </div>

      {/* KPIs */}
      {isLoading ? (
        <SkeletonStatGrid cols={4} />
      ) : data ? (
        <SummaryKpis summary={data.summary} />
      ) : null}

      {/* Coverage progress bar */}
      {data && (
        <div className="ui-panel px-4 py-3">
          <div className="flex items-center gap-3 mb-1.5">
            <span className="text-[11px] text-slate-500">Genel Kapsama</span>
            <span className="text-[11px] font-semibold text-emerald-400">{data.summary.coverage_pct}%</span>
            <span className="text-[10px] text-slate-600 ml-auto">
              {data.summary.covered_techniques}/{data.summary.total_techniques} teknik · ATT&CK v17
            </span>
          </div>
          <div className="h-2.5 bg-sky-950/30 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-700 to-emerald-500 transition-all duration-500"
              style={{ width: `${data.summary.coverage_pct}%` }}
            />
          </div>
        </div>
      )}

      {/* Main content: matrix + detail */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-5">
        {/* ATT&CK Matrix */}
        <div className="space-y-4">
          {/* Tactic header row */}
          {isLoading ? (
            <SkeletonChart height={80} className="rounded-xl" />
          ) : (
            <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${data?.tactics.length ?? 13}, minmax(0, 1fr))` }}>
              {data?.tactics.map(tac => (
                <TacticHeader
                  key={tac.slug}
                  tactic={tac}
                  onClick={() => setActiveTactic(activeTactic === tac.slug ? null : tac.slug)}
                  active={activeTactic === tac.slug}
                />
              ))}
            </div>
          )}

          {/* Technique cells */}
          {isLoading ? (
            <SkeletonChart height={400} className="rounded-xl" />
          ) : activeTactic ? (
            // Single-tactic expanded view
            <div className="ui-panel p-4">
              {shownTactics.map(tac => (
                <div key={tac.slug} className="space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">{tac.label}</p>
                    <button
                      onClick={() => setActiveTactic(null)}
                      className="text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
                    >
                      Tüm taktikleri göster
                    </button>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                    {tac.techniques.map(tech => (
                      <div key={tech.id} className="space-y-1">
                        <TechniqueCell
                          tech={tech}
                          onClick={() => setSelected(
                            selected?.techId === tech.id && selected.tactic === tac.slug
                              ? null
                              : { tactic: tac.slug, techId: tech.id }
                          )}
                          selected={selected?.techId === tech.id && selected?.tactic === tac.slug}
                        />
                        {tech.subtechniques.map(sub => (
                          <div key={sub.id} className="ml-3">
                            <TechniqueCell
                              tech={sub}
                              onClick={() => setSelected(
                                selected?.techId === sub.id && selected.tactic === tac.slug
                                  ? null
                                  : { tactic: tac.slug, techId: sub.id }
                              )}
                              selected={selected?.techId === sub.id && selected?.tactic === tac.slug}
                            />
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            // All tactics overview — compact grid per tactic column
            <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${data?.tactics.length ?? 13}, minmax(0, 1fr))` }}>
              {data?.tactics.map(tac => (
                <div key={tac.slug} className="space-y-1">
                  {tac.techniques.map(tech => (
                    <div key={tech.id} className="space-y-0.5">
                      <TechniqueCell
                        tech={tech}
                        onClick={() => setSelected(
                          selected?.techId === tech.id && selected.tactic === tac.slug
                            ? null
                            : { tactic: tac.slug, techId: tech.id }
                        )}
                        selected={selected?.techId === tech.id && selected?.tactic === tac.slug}
                      />
                      {tech.subtechniques.map(sub => (
                        <div key={sub.id} className="ml-1.5">
                          <TechniqueCell
                            tech={sub}
                            onClick={() => setSelected(
                              selected?.techId === sub.id && selected.tactic === tac.slug
                                ? null
                                : { tactic: tac.slug, techId: sub.id }
                            )}
                            selected={selected?.techId === sub.id && selected?.tactic === tac.slug}
                          />
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* Legend */}
          <div className="flex flex-wrap gap-3">
            {[
              { label: 'Kapsama yok',      cls: 'bg-slate-900/40 border-slate-800/40' },
              { label: 'Kapsanıyor',        cls: 'bg-sky-950/25 border-sky-800/30' },
              { label: 'Hit < 5',           cls: 'bg-yellow-950/40 border-yellow-800/40' },
              { label: 'Hit 5-20',          cls: 'bg-orange-950/50 border-orange-700/50' },
              { label: 'Hit ≥ 20',          cls: 'bg-red-950/60 border-red-700/60' },
            ].map(({ label, cls }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div className={cn('w-3 h-3 rounded border', cls)} />
                <span className="text-[10px] text-slate-500">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right panel: detail + gaps */}
        <div className="space-y-4">
          {selectedTech && (
            <TechniqueDetail
              tech={selectedTech}
              onClose={() => setSelected(null)}
            />
          )}

          {data && <GapPanel gaps={data.summary.top_gaps} />}
        </div>
      </div>
    </div>
  )
}
