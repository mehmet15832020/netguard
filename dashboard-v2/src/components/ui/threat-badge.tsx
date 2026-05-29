'use client'

import { useQuery } from '@tanstack/react-query'
import { threatIntelApi } from '@/lib/api'
import { cn } from '@/lib/utils'

function scoreStyle(score: number) {
  if (score >= 80) return {
    badge: 'bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_8px_rgba(239,68,68,0.12)]',
    dot:   'bg-red-400 shadow-[0_0_4px_rgba(239,68,68,0.8)]',
  }
  if (score >= 40) return {
    badge: 'bg-orange-500/10 border-orange-500/30 text-orange-400 shadow-[0_0_8px_rgba(249,115,22,0.12)]',
    dot:   'bg-orange-400 shadow-[0_0_4px_rgba(249,115,22,0.7)]',
  }
  if (score >= 10) return {
    badge: 'bg-yellow-500/10 border-yellow-500/25 text-yellow-400 shadow-[0_0_6px_rgba(234,179,8,0.1)]',
    dot:   'bg-yellow-400',
  }
  return {
    badge: 'bg-sky-950/40 border-sky-900/30 text-slate-500',
    dot:   'bg-slate-600',
  }
}

export function ThreatBadge({ ip }: { ip: string }) {
  const { data } = useQuery({
    queryKey: ['threat-intel', ip],
    queryFn:  () => threatIntelApi.lookup(ip),
    staleTime: 1000 * 60 * 60,
    retry: false,
  })

  if (!data || data.score === null) return null

  const { badge, dot } = scoreStyle(data.score)

  return (
    <span className="relative group inline-flex items-center ml-1.5">
      <span className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0 text-[10px] font-mono rounded border cursor-default backdrop-blur-sm',
        badge,
      )}>
        <span className={cn('w-1.5 h-1.5 rounded-full', dot)} />
        {data.score}
      </span>

      {/* Tooltip */}
      <span className="pointer-events-none absolute left-0 bottom-full mb-1.5 z-50 hidden group-hover:flex flex-col w-52 rounded-lg bg-[#0a1120] border border-sky-900/30 shadow-[0_8px_24px_rgba(0,0,0,0.5),0_0_0_1px_rgba(56,189,248,0.05)] text-xs p-2.5 gap-1">
        <span className="font-semibold text-slate-200">AbuseIPDB</span>
        <span className="text-slate-500">Skor: <span className="text-slate-200 font-mono">{data.score}/100</span></span>
        <span className="text-slate-500">Raporlar: <span className="text-slate-200">{data.total_reports}</span></span>
        {data.isp && <span className="text-slate-500">ISP: <span className="text-slate-200">{data.isp}</span></span>}
        {data.country_code && <span className="text-slate-500">Ülke: <span className="text-slate-200">{data.country_code}</span></span>}
      </span>
    </span>
  )
}
