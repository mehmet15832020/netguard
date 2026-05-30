'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert, ChevronDown, ChevronUp, TrendingUp,
  Activity, Link2, Shield,
} from 'lucide-react'
import { analyticsApi, type AssetRiskEntry } from '@/lib/api'
import { AssetRiskHeatmapChart } from '@/components/charts/AssetRiskHeatmapChart'
import { SkeletonStatGrid, SkeletonChart } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// ─── Risk tier ────────────────────────────────────────────────────────────────

type Tier = 'critical' | 'high' | 'medium' | 'low'

function tier(score: number): Tier {
  if (score >= 70) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

const TIER_META: Record<Tier, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'Kritik',  color: 'text-red-400',     bg: 'bg-red-950/30',     border: 'border-red-700/60' },
  high:     { label: 'Yüksek', color: 'text-orange-400',  bg: 'bg-orange-950/20',  border: 'border-orange-700/50' },
  medium:   { label: 'Orta',   color: 'text-yellow-400',  bg: 'bg-yellow-950/20',  border: 'border-yellow-700/50' },
  low:      { label: 'Düşük',  color: 'text-slate-400',   bg: 'bg-[#0a1120]',      border: 'border-sky-900/20' },
}

const TIER_ORDER: Tier[] = ['critical', 'high', 'medium', 'low']

// ─── Score bar ────────────────────────────────────────────────────────────────

function ScoreBar({ value, maxValue, color }: { value: number; maxValue: number; color: string }) {
  const pct = maxValue > 0 ? Math.round((value / maxValue) * 100) : 0
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-sky-950/30 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] font-mono text-slate-400 w-6 text-right">{value}</span>
    </div>
  )
}

// ─── Tier KPI cards ───────────────────────────────────────────────────────────

function TierCards({ assets }: { assets: AssetRiskEntry[] }) {
  const counts = useMemo(() => {
    const c: Record<Tier, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    assets.forEach((a) => { c[tier(a.total_score)]++ })
    return c
  }, [assets])

  const icons: Record<Tier, React.ElementType> = {
    critical: ShieldAlert,
    high:     TrendingUp,
    medium:   Activity,
    low:      Shield,
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {TIER_ORDER.map((t) => {
        const m = TIER_META[t]
        const Icon = icons[t]
        return (
          <div key={t} className={cn('rounded-xl border p-4', m.bg, m.border)}>
            <div className="flex items-center justify-between mb-1">
              <span className={cn('text-xs font-medium uppercase tracking-wide', m.color)}>{m.label}</span>
              <Icon size={14} className={m.color} />
            </div>
            <p className={cn('text-2xl font-bold', m.color)}>{counts[t]}</p>
            <p className="text-[11px] text-slate-600 mt-0.5">varlık</p>
          </div>
        )
      })}
    </div>
  )
}

// ─── Risk table ───────────────────────────────────────────────────────────────

type SortKey = 'total_score' | 'activity_score' | 'chain_score' | 'block_score'

function RiskTable({ assets }: { assets: AssetRiskEntry[] }) {
  const [sortKey, setSortKey]     = useState<SortKey>('total_score')
  const [sortDesc, setSortDesc]   = useState(true)
  const [tierFilter, setTierFilter] = useState<Tier | 'all'>('all')

  const sorted = useMemo(() => {
    let list = tierFilter === 'all'
      ? [...assets]
      : assets.filter((a) => tier(a.total_score) === tierFilter)
    list.sort((a, b) => sortDesc ? b[sortKey] - a[sortKey] : a[sortKey] - b[sortKey])
    return list
  }, [assets, sortKey, sortDesc, tierFilter])

  const maxAct   = Math.max(1, ...assets.map((a) => a.activity_score))
  const maxChain = Math.max(1, ...assets.map((a) => a.chain_score))
  const maxBlock = Math.max(1, ...assets.map((a) => a.block_score))
  const maxTotal = Math.max(1, ...assets.map((a) => a.total_score))

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDesc((d) => !d)
    else { setSortKey(k); setSortDesc(true) }
  }

  function SortHeader({ col, label }: { col: SortKey; label: string }) {
    return (
      <th
        className="px-3 py-2 text-left text-[11px] font-medium text-slate-500 cursor-pointer select-none hover:text-slate-300 whitespace-nowrap"
        onClick={() => toggleSort(col)}
      >
        <span className="flex items-center gap-1">
          {label}
          {sortKey === col
            ? sortDesc ? <ChevronDown size={10} /> : <ChevronUp size={10} />
            : <span className="opacity-0"><ChevronDown size={10} /></span>}
        </span>
      </th>
    )
  }

  return (
    <div className="ui-panel">
      {/* Tier filter */}
      <div className="ui-panel-header flex-wrap">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide mr-2">Risk Tablosu</span>
        {(['all', ...TIER_ORDER] as const).map((t) => {
          const m = t === 'all' ? null : TIER_META[t]
          return (
            <button
              key={t}
              onClick={() => setTierFilter(t)}
              className={cn(
                'px-2.5 py-0.5 text-[11px] rounded border transition-colors',
                tierFilter === t
                  ? t === 'all'
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : cn(m?.bg, m?.border, m?.color)
                  : 'border-sky-900/20 text-slate-500 hover:text-slate-300 bg-sky-950/20',
              )}
            >
              {t === 'all' ? 'Tümü' : TIER_META[t].label}
            </button>
          )
        })}
        <span className="ml-auto text-[11px] text-slate-600">{sorted.length} varlık</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-sky-900/20 bg-[#0a1120]/50">
              <th className="ui-th">IP</th>
              <th className="ui-th">Risk</th>
              <SortHeader col="activity_score" label="Aktivite" />
              <SortHeader col="chain_score"    label="Kill Chain" />
              <SortHeader col="block_score"    label="Blok" />
              <SortHeader col="total_score"    label="Toplam" />
              <th className="ui-th">Olay</th>
              <th className="ui-th">Durum</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((asset) => {
              const t  = tier(asset.total_score)
              const m  = TIER_META[t]
              return (
                <tr key={asset.ip} className="border-b border-sky-900/10 hover:bg-sky-950/20">
                  <td className="ui-td">
                    <span className="font-mono text-xs text-slate-200">{asset.ip}</span>
                    {asset.top_severity && (
                      <span className={cn('ml-2 text-[10px] font-medium',
                        asset.top_severity === 'critical' ? 'text-red-400' :
                        asset.top_severity === 'high'     ? 'text-orange-400' :
                        asset.top_severity === 'warning'  ? 'text-yellow-400' : 'text-blue-400',
                      )}>
                        {asset.top_severity}
                      </span>
                    )}
                  </td>
                  <td className="ui-td">
                    <span className={cn('text-[11px] font-medium px-1.5 py-0.5 rounded border', m.color, m.bg, m.border)}>
                      {m.label}
                    </span>
                  </td>
                  <td className="ui-td w-32">
                    <ScoreBar value={asset.activity_score} maxValue={maxAct} color="bg-blue-500" />
                  </td>
                  <td className="ui-td w-32">
                    <ScoreBar value={asset.chain_score} maxValue={maxChain} color="bg-orange-500" />
                  </td>
                  <td className="ui-td w-32">
                    <ScoreBar value={asset.block_score} maxValue={maxBlock} color="bg-red-500" />
                  </td>
                  <td className="ui-td">
                    <span className={cn('text-sm font-bold', m.color)}>{asset.total_score}</span>
                    <span className="text-[10px] text-slate-600">/100</span>
                  </td>
                  <td className="ui-td text-xs text-slate-500">{asset.event_count}</td>
                  <td className="ui-td">
                    {asset.is_blocked ? (
                      <span className="flex items-center gap-1 text-[11px] text-red-400">
                        <Link2 size={11} /> Bloklu
                      </span>
                    ) : (
                      <span className="text-[11px] text-slate-600">—</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Ana sayfa ────────────────────────────────────────────────────────────────

const HOUR_OPTIONS = [
  { label: '6s',  value: 6   },
  { label: '24s', value: 24  },
  { label: '48s', value: 48  },
  { label: '7g',  value: 168 },
]

export default function AssetRiskPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['analytics', 'asset-risk', hours],
    queryFn:  () => analyticsApi.assetRisk(hours),
    staleTime: 60_000,
    refetchInterval: 120_000,
  })

  const topAsset     = data?.assets[0]
  const blockedCount = data?.assets.filter(a => a.is_blocked).length ?? 0

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-6 w-6 text-rose-400" />
          <div>
            <h1 className="text-xl font-semibold text-slate-100">Asset Risk Haritası</h1>
            <p className="text-sm text-slate-400">İç ağ varlıklarının çok boyutlu risk analizi</p>
          </div>
        </div>
        <div className="flex gap-1">
          {HOUR_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setHours(o.value)}
              className={cn(
                'px-3 py-1.5 rounded text-sm font-medium transition-colors',
                hours === o.value
                  ? 'bg-rose-600 text-white'
                  : 'bg-sky-950/20 text-slate-400 hover:bg-sky-950/40',
              )}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* Summary strip */}
      {data && (
        <div className="flex gap-6 text-sm text-zinc-400 flex-wrap">
          <span>
            <span className="text-slate-200 font-medium">{data.assets.length}</span> izlenen varlık
          </span>
          {blockedCount > 0 && (
            <span>
              <span className="text-red-400 font-medium">{blockedCount}</span> bloklandı
            </span>
          )}
          {topAsset && (
            <span>
              En riskli:{' '}
              <span className="font-mono text-slate-200">{topAsset.ip}</span>
              {' · '}
              <span className="text-rose-400 font-medium">{topAsset.total_score}/100</span>
            </span>
          )}
        </div>
      )}

      {/* Tier KPI cards */}
      {isLoading ? (
        <SkeletonStatGrid cols={4} height={80} />
      ) : data && data.assets.length > 0 ? (
        <TierCards assets={data.assets} />
      ) : null}

      {/* Heatmap */}
      <div className="ui-panel p-4">
        <p className="ui-section-label mb-3">Isı Haritası</p>
        {isLoading && <SkeletonChart height={384} />}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">
            Veri yüklenemedi
          </div>
        )}
        {data && data.assets.length === 0 && (
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-slate-500">
            <ShieldAlert className="h-8 w-8 text-slate-700" />
            <p className="text-sm">Bu zaman aralığında izlenecek iç ağ varlığı bulunamadı</p>
          </div>
        )}
        {data && data.assets.length > 0 && (
          <AssetRiskHeatmapChart
            assets={data.assets}
            height={Math.max(280, data.assets.length * 30)}
          />
        )}
      </div>

      {/* Risk Table */}
      {data && data.assets.length > 0 && (
        <RiskTable assets={data.assets} />
      )}

      {/* Skor formülü */}
      <div className="grid grid-cols-3 gap-3 text-xs text-zinc-500">
        <div className="rounded border border-sky-900/15 bg-sky-950/10 p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <div className="w-2 h-2 rounded-full bg-blue-500" />
            <span className="font-medium text-slate-400">Ağ Aktivitesi ×0.5</span>
          </div>
          Severity ağırlıklı olay yoğunluğu: critical×40, high×15, warning×5, info×1 — maks 100
        </div>
        <div className="rounded border border-sky-900/15 bg-sky-950/10 p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <div className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="font-medium text-slate-400">Kill Chain ×0.3</span>
          </div>
          MITRE ATT&amp;CK eşleşen olaylar: keşif×2, silahlanma×8, yanal hareket×20 — maks 100
        </div>
        <div className="rounded border border-sky-900/15 bg-sky-950/10 p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <span className="font-medium text-slate-400">Blok Durumu ×0.2</span>
          </div>
          Aktif blok listesinde → 100; değil → 0. Risk: ≥70 Kritik · ≥50 Yüksek · ≥30 Orta · &lt;30 Düşük
        </div>
      </div>
    </div>
  )
}
