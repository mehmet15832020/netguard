'use client'

import { useQuery } from '@tanstack/react-query'
import { useRef, useState, useLayoutEffect } from 'react'
import { GitBranch, RefreshCw, Shield, AlertTriangle, Activity } from 'lucide-react'
import { attackChainsApi, analyticsApi, type KillChainRow, type KillChainEvent, type ChainStats } from '@/lib/api'

// ─── Sabit veriler ────────────────────────────────────────────────────────────

const STAGE_ORDER = ['recon', 'weaponize', 'access', 'lateral'] as const
type Stage = typeof STAGE_ORDER[number]

const STAGE_META: Record<Stage, { label: string; color: string; bg: string; dot: string }> = {
  recon:     { label: 'Keşif',         color: 'text-blue-400',   bg: 'bg-blue-500/20',   dot: '#60a5fa' },
  weaponize: { label: 'Silahlanma',    color: 'text-amber-400',  bg: 'bg-amber-500/20',  dot: '#fbbf24' },
  access:    { label: 'Erişim',        color: 'text-orange-400', bg: 'bg-orange-500/20', dot: '#fb923c' },
  lateral:   { label: 'Yanal Hareket', color: 'text-red-400',    bg: 'bg-red-500/20',    dot: '#f87171' },
}

const HOURS_OPTIONS = [6, 24, 48, 168]

// ─── Yardımcı ─────────────────────────────────────────────────────────────────

function toMs(iso: string): number {
  return new Date(iso).getTime()
}

function fmtTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
}

function fmtDateTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('tr-TR', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ─── Küçük bileşenler ─────────────────────────────────────────────────────────

function StatCard({
  label, value, icon: Icon, colorClass,
}: { label: string; value: number | string; icon: React.ElementType; colorClass: string }) {
  return (
    <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-4">
      <div className={`p-2 rounded-lg ${colorClass}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xs text-zinc-500">{label}</p>
        <p className="text-xl font-bold text-zinc-100">{value}</p>
      </div>
    </div>
  )
}

function ChainBadge({ type }: { type: string }) {
  const full = type === 'FULL_ATTACK_CHAIN'
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
      full
        ? 'bg-red-950/60 text-red-400 border-red-800'
        : 'bg-zinc-800 text-zinc-400 border-zinc-700'
    }`}>
      {full ? 'TAM' : 'KISMİ'}
    </span>
  )
}

// ─── Swimlane bileşeni ────────────────────────────────────────────────────────

interface Tooltip {
  x: number
  y: number
  event: KillChainEvent
}

function SwimlaneChart({
  rows,
  windowStart,
  windowEnd,
}: {
  rows: KillChainRow[]
  windowStart: string
  windowEnd: string
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(800)
  const [tooltip, setTooltip] = useState<Tooltip | null>(null)

  useLayoutEffect(() => {
    if (!containerRef.current) return
    setWidth(containerRef.current.getBoundingClientRect().width)
    const ro = new ResizeObserver(([entry]) => {
      setWidth(entry.contentRect.width)
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
        <GitBranch className="w-8 h-8 mb-2 opacity-30" />
        <p className="text-sm">Seçilen zaman aralığında kill chain verisi yok</p>
      </div>
    )
  }

  const IP_COL   = 120
  const BADGE_COL = 50
  const PAD_RIGHT = 12
  const TIMELINE_W = Math.max(300, width - IP_COL - BADGE_COL - PAD_RIGHT)
  const ROW_H    = 48
  const DOT_R    = 6
  const AXIS_H   = 24
  const wStart   = toMs(windowStart)
  const wEnd     = toMs(windowEnd)
  const wRange   = wEnd - wStart || 1

  function xOf(iso: string): number {
    return IP_COL + ((toMs(iso) - wStart) / wRange) * TIMELINE_W
  }

  // Axis tick count based on width
  const tickCount = Math.max(3, Math.min(8, Math.floor(TIMELINE_W / 90)))
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) =>
    new Date(wStart + (wRange * i) / tickCount)
  )

  const svgH = rows.length * ROW_H + AXIS_H + 8

  return (
    <div ref={containerRef} className="relative w-full select-none">
      <svg width={width} height={svgH} className="overflow-visible">
        {/* Axis */}
        <g transform={`translate(0, ${rows.length * ROW_H + 4})`}>
          <line x1={IP_COL} y1={0} x2={IP_COL + TIMELINE_W} y2={0} stroke="#3f3f46" strokeWidth={1} />
          {ticks.map((t, i) => {
            const tx = IP_COL + (i / tickCount) * TIMELINE_W
            const label = t.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
            return (
              <g key={i}>
                <line x1={tx} y1={0} x2={tx} y2={4} stroke="#52525b" strokeWidth={1} />
                <text x={tx} y={16} textAnchor="middle" fill="#71717a" fontSize={10}>{label}</text>
              </g>
            )
          })}
        </g>

        {/* Rows */}
        {rows.map((row, ri) => {
          const cy = ri * ROW_H + ROW_H / 2
          const x1 = xOf(row.first_seen)
          const x2 = xOf(row.last_seen)

          // Vertical grid line
          return (
            <g key={row.source_ip}>
              {/* Zebra background */}
              {ri % 2 === 0 && (
                <rect x={0} y={ri * ROW_H} width={width} height={ROW_H} fill="#18181b" />
              )}

              {/* IP label */}
              <text
                x={IP_COL - 8}
                y={cy + 4}
                textAnchor="end"
                fill="#a1a1aa"
                fontSize={11}
                fontFamily="monospace"
              >
                {row.source_ip.length > 15 ? row.source_ip.slice(0, 14) + '…' : row.source_ip}
              </text>

              {/* Chain badge */}
              {/* rendered as foreignObject for full CSS support */}
              <foreignObject x={IP_COL + TIMELINE_W + 4} y={cy - 10} width={BADGE_COL} height={20}>
                <div className="h-full flex items-center">
                  <ChainBadge type={row.chain_type} />
                </div>
              </foreignObject>

              {/* Baseline */}
              <line
                x1={x1} y1={cy} x2={x2} y2={cy}
                stroke="#3f3f46" strokeWidth={1.5}
                strokeDasharray={row.chain_type === 'FULL_ATTACK_CHAIN' ? undefined : '4 3'}
              />

              {/* Events */}
              {row.events.map((ev, ei) => {
                const stage = ev.stage as Stage
                const meta = STAGE_META[stage] ?? { dot: '#a1a1aa', label: ev.stage }
                const cx = xOf(ev.occurred_at)
                return (
                  <circle
                    key={ei}
                    cx={cx}
                    cy={cy}
                    r={DOT_R}
                    fill={meta.dot}
                    stroke="#09090b"
                    strokeWidth={1.5}
                    className="cursor-pointer transition-opacity hover:opacity-80"
                    onMouseEnter={(e) => {
                      const svgRect = (e.currentTarget.ownerSVGElement as SVGSVGElement)
                        .getBoundingClientRect()
                      setTooltip({
                        x: cx,
                        y: ri * ROW_H,
                        event: ev,
                      })
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  />
                )
              })}
            </g>
          )
        })}

        {/* Vertical "now" line */}
        {(() => {
          const nowX = xOf(windowEnd)
          return (
            <line
              x1={nowX} y1={0} x2={nowX} y2={rows.length * ROW_H}
              stroke="#27272a" strokeWidth={1}
            />
          )
        })()}
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="pointer-events-none absolute z-10 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-xs shadow-lg"
          style={{
            left: Math.min(tooltip.x + 10, width - 160),
            top: Math.max(0, tooltip.y - 8),
          }}
        >
          <div className="font-semibold text-zinc-100 mb-1">
            {STAGE_META[tooltip.event.stage as Stage]?.label ?? tooltip.event.stage}
          </div>
          <div className="text-zinc-400">{fmtDateTime(tooltip.event.occurred_at)}</div>
        </div>
      )}
    </div>
  )
}

// ─── Ana sayfa ────────────────────────────────────────────────────────────────

export default function KillChainTimelinePage() {
  const [hours, setHours] = useState(24)

  const { data: timelineData, isLoading: loadingTimeline, isFetching, refetch: refetchTimeline } =
    useQuery({
      queryKey: ['kill-chain-timeline', hours],
      queryFn:  () => analyticsApi.killChainTimeline(hours, 20),
      refetchInterval: 30_000,
      staleTime: 15_000,
    })

  const { data: statsData, isLoading: loadingStats, refetch: refetchStats } =
    useQuery({
      queryKey: ['attack-chains-stats'],
      queryFn:  () => attackChainsApi.stats(),
      refetchInterval: 30_000,
      staleTime: 15_000,
    })

  const isLoading = loadingTimeline || loadingStats

  function refetch() {
    void refetchTimeline()
    void refetchStats()
  }

  const stats: ChainStats = statsData ?? {
    active_ips: 0, chains_24h: 0, critical_24h: 0,
    unique_ips_24h: 0, stage_distribution: {},
  }

  const rows = timelineData?.rows ?? []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GitBranch className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Kill Chain Timeline</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          {/* Hours selector */}
          <div className="flex rounded-lg overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map((h) => (
              <button
                key={h}
                onClick={() => setHours(h)}
                className={`px-3 py-1 text-xs font-medium transition-colors ${
                  hours === h
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-900 text-zinc-400 hover:text-zinc-100'
                }`}
              >
                {h < 48 ? `${h}s` : `${h / 24}g`}
              </button>
            ))}
          </div>
          <button
            onClick={refetch}
            className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
            title="Yenile"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stat kartlar */}
      {isLoading ? (
        <div className="grid grid-cols-3 gap-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          <StatCard label="Aktif Saldırı IP"  value={stats.active_ips}   icon={Activity}      colorClass="bg-indigo-500/15 text-indigo-400" />
          <StatCard label="Son 24s Zincir"     value={stats.chains_24h}   icon={Shield}        colorClass="bg-orange-500/15 text-orange-400" />
          <StatCard label="Son 24s Kritik"     value={stats.critical_24h} icon={AlertTriangle} colorClass="bg-red-500/15 text-red-400" />
        </div>
      )}

      {/* Swimlane */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-200">Saldırı Zinciri Zaman Çizelgesi</h2>
          <span className="text-xs text-zinc-500">{rows.length} IP</span>
        </div>

        <div className="p-4">
          {isLoading ? (
            <div className="space-y-3">
              {[0, 1, 2].map((i) => (
                <div key={i} className="h-10 rounded bg-zinc-800 animate-pulse" />
              ))}
            </div>
          ) : (
            <SwimlaneChart
              rows={rows}
              windowStart={timelineData?.window_start ?? new Date(Date.now() - hours * 3600_000).toISOString()}
              windowEnd={timelineData?.window_end ?? new Date().toISOString()}
            />
          )}
        </div>

        {/* Lejant */}
        <div className="px-4 pb-4 flex flex-wrap gap-4">
          {STAGE_ORDER.map((stage) => {
            const m = STAGE_META[stage]
            return (
              <span key={stage} className="flex items-center gap-1.5 text-xs text-zinc-500">
                <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: m.dot }} />
                {m.label}
              </span>
            )
          })}
          <span className="flex items-center gap-1.5 text-xs text-zinc-500 ml-2">
            <span className="inline-block w-5 h-px border-t border-zinc-400" />
            Tam Zincir
          </span>
          <span className="flex items-center gap-1.5 text-xs text-zinc-500">
            <span className="inline-block w-5 h-px border-t border-dashed border-zinc-500" />
            Kısmi Zincir
          </span>
        </div>
      </div>
    </div>
  )
}
