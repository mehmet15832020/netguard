'use client'

import { useQuery } from '@tanstack/react-query'
import { threatIntelApi } from '@/lib/api'

function scoreColor(score: number) {
  if (score >= 80) return { badge: 'bg-red-900/60 text-red-300 border-red-800',    dot: 'bg-red-400' }
  if (score >= 40) return { badge: 'bg-orange-900/60 text-orange-300 border-orange-800', dot: 'bg-orange-400' }
  if (score >= 10) return { badge: 'bg-yellow-900/60 text-yellow-300 border-yellow-800', dot: 'bg-yellow-400' }
  return           { badge: 'bg-zinc-800 text-zinc-400 border-zinc-700',            dot: 'bg-zinc-500' }
}

export function ThreatBadge({ ip }: { ip: string }) {
  const { data } = useQuery({
    queryKey: ['threat-intel', ip],
    queryFn:  () => threatIntelApi.lookup(ip),
    staleTime: 1000 * 60 * 60,
    retry: false,
  })

  if (!data || data.score === null) return null

  const { badge, dot } = scoreColor(data.score)

  return (
    <span className="relative group inline-flex items-center ml-1.5">
      <span className={`inline-flex items-center gap-1 px-1.5 py-0 text-[10px] font-mono rounded border cursor-default ${badge}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        {data.score}
      </span>
      {/* Tooltip */}
      <span className="pointer-events-none absolute left-0 bottom-full mb-1.5 z-50 hidden group-hover:flex flex-col w-52 rounded-md bg-zinc-800 border border-zinc-700 shadow-lg text-xs p-2.5 gap-1">
        <span className="font-semibold text-zinc-200">AbuseIPDB</span>
        <span className="text-zinc-400">Skor: <span className="text-zinc-200 font-mono">{data.score}/100</span></span>
        <span className="text-zinc-400">Raporlar: <span className="text-zinc-200">{data.total_reports}</span></span>
        {data.isp && <span className="text-zinc-400">ISP: <span className="text-zinc-200">{data.isp}</span></span>}
        {data.country_code && <span className="text-zinc-400">Ülke: <span className="text-zinc-200">{data.country_code}</span></span>}
      </span>
    </span>
  )
}
