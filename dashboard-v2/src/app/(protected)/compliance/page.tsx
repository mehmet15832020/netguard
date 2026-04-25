'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import { complianceApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

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
  '':              'Tümü',
  'PCI DSS v4.0':  'PCI DSS v4.0',
  'ISO 27001:2022':'ISO 27001:2022',
}

function ScoreRing({ score, size = 80 }: { score: number; size?: number }) {
  const r = (size / 2) - 8
  const circ = 2 * Math.PI * r
  const filled = (score / 100) * circ
  const color = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#ef4444'
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#27272a" strokeWidth={8} />
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

function ControlRow({ ctrl }: { ctrl: {
  control_id: string; title: string; framework: string; category: string;
  status: string; score: number; evidence: string[]; recommendations: string[]
}}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-b border-zinc-800/60 last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-zinc-800/30 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${STATUS_DOT[ctrl.status] ?? 'bg-zinc-500'}`} />
        <span className="font-mono text-xs text-zinc-500 w-24 flex-shrink-0">{ctrl.control_id}</span>
        <span className="flex-1 text-sm text-zinc-200 min-w-0 truncate">{ctrl.title}</span>
        <span className="text-xs text-zinc-500 hidden md:block w-32 flex-shrink-0">{ctrl.category}</span>
        <span className={`text-xs px-2 py-0.5 rounded border flex-shrink-0 ${STATUS_STYLE[ctrl.status] ?? ''}`}>
          {STATUS_LABEL[ctrl.status] ?? ctrl.status}
        </span>
        <span className="text-xs text-zinc-500 w-8 text-right flex-shrink-0">{ctrl.score}%</span>
        {open
          ? <ChevronDown size={14} className="text-zinc-500 flex-shrink-0" />
          : <ChevronRight size={14} className="text-zinc-500 flex-shrink-0" />
        }
      </div>
      {open && (
        <div className="px-4 pb-4 pt-0 ml-5 space-y-2">
          {ctrl.evidence.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1">Kanıt</p>
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
              <p className="text-xs font-medium text-zinc-400 mb-1">Öneri</p>
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
  const [framework, setFramework] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['compliance-report', framework],
    queryFn:  () => complianceApi.report(framework),
  })

  const controls = (data?.controls ?? []).filter(c =>
    statusFilter === 'all' || c.status === statusFilter
  )

  const byCategory = controls.reduce<Record<string, typeof controls>>((acc, c) => {
    if (!acc[c.category]) acc[c.category] = []
    acc[c.category].push(c)
    return acc
  }, {})

  return (
    <div className="p-6 space-y-6">
      {/* Başlık */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <h1 className="text-xl font-semibold">Compliance Raporu</h1>
          <span className="text-xs text-zinc-500">PCI DSS v4.0 · ISO 27001:2022</span>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {/* Framework seçici */}
      <div className="flex gap-2 flex-wrap">
        {FRAMEWORKS.map(fw => (
          <button
            key={fw}
            onClick={() => setFramework(fw)}
            className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
              framework === fw
                ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
            }`}
          >
            {FRAMEWORK_LABELS[fw]}
          </button>
        ))}
      </div>

      {isLoading ? (
        <p className="text-zinc-500 text-sm">Yükleniyor...</p>
      ) : (
        <>
          {/* Özet kartlar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="bg-zinc-900 border-zinc-800 flex items-center justify-center py-4">
              <CardContent className="pt-0 pb-0 flex flex-col items-center gap-1">
                <ScoreRing score={data?.overall_score ?? 0} />
                <p className="text-xs text-zinc-500 mt-1">Genel Uyum</p>
              </CardContent>
            </Card>
            <Card
              className={`bg-zinc-900 border-zinc-800 cursor-pointer transition-colors ${statusFilter === 'compliant' ? 'border-emerald-500/50' : 'hover:border-zinc-600'}`}
              onClick={() => setStatusFilter(f => f === 'compliant' ? 'all' : 'compliant')}
            >
              <CardContent className="pt-4 pb-4">
                <p className="text-xs text-zinc-400 mb-1">Uyumlu</p>
                <p className="text-2xl font-bold text-emerald-400">{data?.compliant ?? 0}</p>
                <p className="text-xs text-zinc-600 mt-0.5">kontrol</p>
              </CardContent>
            </Card>
            <Card
              className={`bg-zinc-900 border-zinc-800 cursor-pointer transition-colors ${statusFilter === 'partial' ? 'border-yellow-500/50' : 'hover:border-zinc-600'}`}
              onClick={() => setStatusFilter(f => f === 'partial' ? 'all' : 'partial')}
            >
              <CardContent className="pt-4 pb-4">
                <p className="text-xs text-zinc-400 mb-1">Kısmi Uyum</p>
                <p className="text-2xl font-bold text-yellow-400">{data?.partial ?? 0}</p>
                <p className="text-xs text-zinc-600 mt-0.5">kontrol</p>
              </CardContent>
            </Card>
            <Card
              className={`bg-zinc-900 border-zinc-800 cursor-pointer transition-colors ${statusFilter === 'gap' ? 'border-red-500/50' : 'hover:border-zinc-600'}`}
              onClick={() => setStatusFilter(f => f === 'gap' ? 'all' : 'gap')}
            >
              <CardContent className="pt-4 pb-4">
                <p className="text-xs text-zinc-400 mb-1">Açık</p>
                <p className="text-2xl font-bold text-red-400">{data?.gaps ?? 0}</p>
                <p className="text-xs text-zinc-600 mt-0.5">kontrol</p>
              </CardContent>
            </Card>
          </div>

          {/* Framework skor karşılaştırması */}
          {!framework && data?.by_framework && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(data.by_framework).map(([fw, info]) => {
                const fwInfo = info as { score: number; compliant: number; partial: number; gap: number; total: number }
                return (
                  <Card key={fw} className="bg-zinc-900 border-zinc-800">
                    <CardHeader className="pb-2 pt-4 px-4">
                      <CardTitle className="text-sm text-zinc-300">{fw}</CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-4">
                      <div className="flex items-center gap-4">
                        <ScoreRing score={fwInfo.score} size={64} />
                        <div className="space-y-1 text-xs">
                          <div className="flex gap-2">
                            <span className="text-emerald-400">{fwInfo.compliant} uyumlu</span>
                            <span className="text-zinc-600">·</span>
                            <span className="text-yellow-400">{fwInfo.partial} kısmi</span>
                            <span className="text-zinc-600">·</span>
                            <span className="text-red-400">{fwInfo.gap} açık</span>
                          </div>
                          <div className="w-full bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className="h-full bg-emerald-500 rounded-full"
                              style={{ width: `${fwInfo.score}%` }}
                            />
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}

          {/* Kontrol listesi — kategoriye göre gruplu */}
          {Object.entries(byCategory).map(([category, items]) => (
            <div key={category}>
              <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wide mb-2">
                {category} ({items.length})
              </h2>
              <Card className="bg-zinc-900 border-zinc-800">
                <CardContent className="p-0">
                  {items.map(ctrl => (
                    <ControlRow key={ctrl.control_id} ctrl={ctrl} />
                  ))}
                </CardContent>
              </Card>
            </div>
          ))}

          {controls.length === 0 && (
            <p className="text-zinc-500 text-sm">Bu filtre için kontrol bulunamadı.</p>
          )}
        </>
      )}
    </div>
  )
}
