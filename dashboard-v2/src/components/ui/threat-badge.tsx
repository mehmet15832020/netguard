'use client'

import { useQuery } from '@tanstack/react-query'
import { threatIntelApi } from '@/lib/api'

function scoreColor(score: number): string {
  if (score >= 80) return 'bg-red-900/60 text-red-300 border-red-800'
  if (score >= 40) return 'bg-orange-900/60 text-orange-300 border-orange-800'
  if (score >= 10) return 'bg-yellow-900/60 text-yellow-300 border-yellow-800'
  return 'bg-zinc-800 text-zinc-400 border-zinc-700'
}

export function ThreatBadge({ ip }: { ip: string }) {
  const { data } = useQuery({
    queryKey: ['threat-intel', ip],
    queryFn:  () => threatIntelApi.lookup(ip),
    staleTime: 1000 * 60 * 60,
    retry: false,
  })

  if (!data || data.score === null) return null

  const color = scoreColor(data.score)
  return (
    <span
      className={`inline-flex items-center ml-1.5 px-1.5 py-0 text-[10px] font-mono rounded border ${color}`}
      title={`AbuseIPDB: ${data.score}/100 (${data.total_reports} rapor) — ${data.isp || '—'} ${data.country_code || ''}`}
    >
      {data.score}
    </span>
  )
}
