'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { AssetRiskHeatmapChart } from '@/components/charts/AssetRiskHeatmapChart'

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
  })

  const topAsset  = data?.assets[0]
  const blockedCount = data?.assets.filter(a => a.is_blocked).length ?? 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-6 w-6 text-rose-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">Asset Risk Haritası</h1>
            <p className="text-sm text-zinc-400">İç ağ varlıklarının çok boyutlu risk analizi</p>
          </div>
        </div>
        <div className="flex gap-1">
          {HOUR_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setHours(o.value)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                hours === o.value
                  ? 'bg-rose-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* Summary */}
      {data && (
        <div className="flex gap-6 text-sm text-zinc-400 flex-wrap">
          <span>
            <span className="text-zinc-200 font-medium">{data.assets.length}</span> izlenen varlık
          </span>
          {blockedCount > 0 && (
            <span>
              <span className="text-red-400 font-medium">{blockedCount}</span> bloklandı
            </span>
          )}
          {topAsset && (
            <span>
              En riskli:{' '}
              <span className="font-mono text-zinc-200">{topAsset.ip}</span>
              {' · '}
              <span className="text-rose-400 font-medium">{topAsset.total_score}</span>
            </span>
          )}
        </div>
      )}

      {/* Chart */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        {isLoading && <div className="h-96 animate-pulse bg-zinc-800 rounded" />}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">
            Veri yüklenemedi
          </div>
        )}
        {data && data.assets.length === 0 && (
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-zinc-500">
            <ShieldAlert className="h-8 w-8 text-zinc-700" />
            <p className="text-sm">Bu zaman aralığında izlenecek iç ağ varlığı bulunamadı</p>
          </div>
        )}
        {data && data.assets.length > 0 && (
          <AssetRiskHeatmapChart
            assets={data.assets}
            height={Math.max(300, data.assets.length * 30)}
          />
        )}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-3 gap-3 text-xs text-zinc-500">
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-3">
          <div className="font-medium text-zinc-400 mb-1">Ağ Aktivitesi</div>
          Severity ağırlıklı olay yoğunluğu: critical×40, high×15, warning×5, info×1 — maks 100
        </div>
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-3">
          <div className="font-medium text-zinc-400 mb-1">Kill Chain</div>
          MITRE ATT&amp;CK eşleşen olaylar: keşif×2, silahlanma×8, yanal hareket×20 — maks 100
        </div>
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-3">
          <div className="font-medium text-zinc-400 mb-1">Blok Durumu</div>
          Aktif blok listesinde → 100; değil → 0. Toplam = Aktivite×0.5 + Zincir×0.3 + Blok×0.2
        </div>
      </div>
    </div>
  )
}
