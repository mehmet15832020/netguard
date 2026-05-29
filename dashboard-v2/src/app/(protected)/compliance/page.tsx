'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import { complianceApi } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const STATUS_STYLE: Record<string, string> = {
  compliant: 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
  partial:   'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  gap:       'text-red-400 border-red-500/40 bg-red-500/10',
}

const STATUS_LABEL: Record<string, string> = {
  compliant: 'Uyumlu',
  partial:   'Kısmi',
  gap:       'Açık',
}

const STATUS_DOT: Record<string, string> = {
  compliant: 'bg-emerald-500',
  partial:   'bg-yellow-500',
  gap:       'bg-red-500',
}

const FRAMEWORKS = ['', 'PCI DSS v4.0', 'ISO 27001:2022']
const FRAMEWORK_LABELS: Record<string, string> = {
  '':               'Tümü',
  'PCI DSS v4.0':   'PCI DSS v4.0',
  'ISO 27001:2022': 'ISO 27001:2022',
}

function ScoreRing({ score, size = 80 }: { score: number; size?: number }) {
  const r      = (size / 2) - 8
  const circ   = 2 * Math.PI * r
  const filled = (score / 100) * circ
  const color  = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#ef4444'
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(56,189,248,0.08)" strokeWidth={8} />
      <circle
        cx={size/2} cy={size/2} r={r}
        fill="none" stroke={color} strokeWidth={8}
        strokeDasharray={`${filled} ${circ - filled}`}
        strokeLinecap="round"
      />
      <text
        x="50%" y="50%"
        dominantBaseline="middle" textAnchor="middle"
        fill={color} fontSize={size * 0.22} fontWeight="bold"
        transform={`rotate(90, ${size/2}, ${size/2})`}
      >
        {score}%
      </text>
    </svg>
  )
}

type ControlItem = {
  control_id: string; title: string; framework: string; event_category: string;
  status: string; score: number; evidence: string[]; recommendations: string[]
}

function ControlRow({ ctrl }: { ctrl: ControlItem }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-b border-sky-900/10 last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-sky-950/20 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <span className={cn('w-2 h-2 rounded-full flex-shrink-0', STATUS_DOT[ctrl.status] ?? 'bg-slate-600')} />
        <span className="font-mono text-xs text-slate-600 w-24 flex-shrink-0">{ctrl.control_id}</span>
        <span className="flex-1 text-sm text-slate-200 min-w-0 truncate">{ctrl.title}</span>
        <span className="text-xs text-slate-600 hidden md:block w-32 flex-shrink-0">{ctrl.event_category}</span>
        <span className={cn('text-xs px-2 py-0.5 rounded border flex-shrink-0 backdrop-blur-sm', STATUS_STYLE[ctrl.status] ?? '')}>
          {STATUS_LABEL[ctrl.status] ?? ctrl.status}
        </span>
        <span className="text-xs text-slate-600 w-8 text-right flex-shrink-0 font-mono">{ctrl.score}%</span>
        {open
          ? <ChevronDown  size={14} className="text-slate-600 flex-shrink-0" />
          : <ChevronRight size={14} className="text-slate-600 flex-shrink-0" />
        }
      </div>
      {open && (
        <div className="px-4 pb-4 pt-0 ml-5 space-y-2 bg-sky-950/10">
          {ctrl.evidence.length > 0 && (
            <div className="pt-3">
              <p className="text-xs font-medium text-slate-500 mb-1">Kanıt</p>
              <ul className="space-y-0.5">
                {ctrl.evidence.map((e, i) => (
                  <li key={i} className="text-xs text-emerald-400 flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-emerald-500 flex-shrink-0" />
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {ctrl.recommendations.length > 0 && (
            <div>
              <p className="text-xs font-medium text-slate-500 mb-1">Öneri</p>
              <ul className="space-y-0.5">
                {ctrl.recommendations.map((r, i) => (
                  <li key={i} className="text-xs text-yellow-400 flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-yellow-500 flex-shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function CompliancePage() {
  const [framework,    setFramework]    = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['compliance-report', framework],
    queryFn:  () => complianceApi.report(framework),
  })

  const controls = (data?.controls ?? []).filter(c =>
    statusFilter === 'all' || c.status === statusFilter
  )

  const byCategory = controls.reduce<Record<string, typeof controls>>((acc, c) => {
    if (!acc[c.event_category]) acc[c.event_category] = []
    acc[c.event_category].push(c)
    return acc
  }, {})

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <ShieldCheck size={15} className="text-emerald-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Compliance Raporu</h1>
            <p className="text-xs text-slate-600">PCI DSS v4.0 · ISO 27001:2022</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
          Yenile
        </button>
      </div>

      {/* Framework filter */}
      <div className="flex gap-2 flex-wrap">
        {FRAMEWORKS.map(fw => (
          <button
            key={fw}
            onClick={() => setFramework(fw)}
            className={cn(
              'px-3 py-1 rounded-lg text-xs font-medium border transition-colors',
              framework === fw
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
            )}
          >
            {FRAMEWORK_LABELS[fw]}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <SkeletonTable rows={8} height={44} />
        </div>
      ) : (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl flex items-center justify-center py-4 px-3">
              <div className="flex flex-col items-center gap-1">
                <ScoreRing score={data?.overall_score ?? 0} />
                <p className="text-xs text-slate-500 mt-1">Genel Uyum</p>
              </div>
            </div>

            {[
              { key: 'compliant', label: 'Uyumlu',    value: data?.compliant ?? 0, color: 'text-emerald-400', active: 'border-emerald-500/50' },
              { key: 'partial',   label: 'Kısmi Uyum', value: data?.partial ?? 0,   color: 'text-yellow-400',  active: 'border-yellow-500/50' },
              { key: 'gap',       label: 'Açık',       value: data?.gaps ?? 0,      color: 'text-red-400',     active: 'border-red-500/50' },
            ].map(({ key, label, value, color, active }) => (
              <div
                key={key}
                onClick={() => setStatusFilter(f => f === key ? 'all' : key)}
                className={cn(
                  'bg-[#0a1120] rounded-xl p-4 cursor-pointer border transition-colors hover:border-sky-700/30',
                  statusFilter === key ? active : 'border-sky-900/20',
                )}
              >
                <p className="text-xs text-slate-500 mb-1">{label}</p>
                <p className={cn('text-2xl font-bold', color)}>{value}</p>
                <p className="text-xs text-slate-700 mt-0.5">kontrol</p>
              </div>
            ))}
          </div>

          {/* Framework score comparison */}
          {!framework && data?.by_framework && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(data.by_framework).map(([fw, info]) => {
                const fwInfo = info as { score: number; compliant: number; partial: number; gap: number; total: number }
                return (
                  <div key={fw} className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-sky-900/15">
                      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">{fw}</span>
                    </div>
                    <div className="p-4 flex items-center gap-4">
                      <ScoreRing score={fwInfo.score} size={64} />
                      <div className="space-y-1.5 text-xs flex-1">
                        <div className="flex gap-2">
                          <span className="text-emerald-400">{fwInfo.compliant} uyumlu</span>
                          <span className="text-slate-700">·</span>
                          <span className="text-yellow-400">{fwInfo.partial} kısmi</span>
                          <span className="text-slate-700">·</span>
                          <span className="text-red-400">{fwInfo.gap} açık</span>
                        </div>
                        <div className="w-full bg-sky-950/30 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full transition-all"
                            style={{ width: `${fwInfo.score}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* Controls grouped by category */}
          {Object.entries(byCategory).map(([event_category, items]) => (
            <div key={event_category}>
              <h2 className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">
                {event_category} ({items.length})
              </h2>
              <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
                {items.map(ctrl => <ControlRow key={ctrl.control_id} ctrl={ctrl} />)}
              </div>
            </div>
          ))}

          {controls.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-700">
              <ShieldCheck size={28} className="opacity-20" />
              <p className="text-sm">Bu filtre için kontrol bulunamadı.</p>
            </div>
          )}
        </>
      )}
    </div>
  )
}
