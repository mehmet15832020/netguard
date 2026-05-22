'use client'

import { useQuery } from '@tanstack/react-query'
import { GitBranch, RefreshCw, Shield, AlertTriangle, Activity } from 'lucide-react'
import { attackChainsApi, type ActiveChain, type ChainStats } from '@/lib/api'

const STAGE_ORDER = ['RECON', 'WEAPONIZE', 'ACCESS', 'LATERAL', 'FULL_ATTACK_CHAIN'] as const
type Stage = typeof STAGE_ORDER[number]

const STAGE_LABELS: Record<Stage, string> = {
  RECON:             'Keşif',
  WEAPONIZE:         'Silahlanma',
  ACCESS:            'Erişim',
  LATERAL:           'Yanal',
  FULL_ATTACK_CHAIN: 'Tam Zincir',
}

const STAGE_COLORS: Record<Stage, string> = {
  RECON:             'bg-blue-500',
  WEAPONIZE:         'bg-yellow-500',
  ACCESS:            'bg-orange-500',
  LATERAL:           'bg-red-400',
  FULL_ATTACK_CHAIN: 'bg-red-600',
}

function StageProgress({ stages }: { stages: Record<string, number> }) {
  return (
    <div className="flex items-center gap-1">
      {STAGE_ORDER.map((stage, i) => {
        const hit = stage in stages
        const color = STAGE_COLORS[stage]
        return (
          <div key={stage} className="flex items-center gap-1">
            <div
              title={STAGE_LABELS[stage]}
              className={`w-3 h-3 rounded-full border-2 transition-colors ${
                hit
                  ? `${color} border-transparent`
                  : 'bg-transparent border-zinc-600'
              }`}
            />
            {i < STAGE_ORDER.length - 1 && (
              <div className={`w-3 h-px ${hit ? 'bg-zinc-500' : 'bg-zinc-700'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string
  value: number | string
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-4">
      <div className={`p-2 rounded-lg ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xs text-zinc-500">{label}</p>
        <p className="text-xl font-bold text-zinc-100">{value}</p>
      </div>
    </div>
  )
}

function ChainTypeTag({ type }: { type: string }) {
  const full = type === 'FULL_ATTACK_CHAIN'
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold ${
        full
          ? 'bg-red-950/60 text-red-400 border border-red-800'
          : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
      }`}
    >
      {full ? 'TAM ZİNCİR' : 'KISMİ'}
    </span>
  )
}

export default function KillChainTimelinePage() {
  const {
    data: activeData,
    isLoading: loadingActive,
    isError: errorActive,
    isFetching: fetchingActive,
    refetch: refetchActive,
  } = useQuery({
    queryKey: ['attack-chains-active'],
    queryFn:  () => attackChainsApi.active(),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const {
    data: statsData,
    isLoading: loadingStats,
    isError: errorStats,
    refetch: refetchStats,
  } = useQuery({
    queryKey: ['attack-chains-stats'],
    queryFn:  () => attackChainsApi.stats(),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const isLoading = loadingActive || loadingStats
  const isError   = errorActive || errorStats

  function refetch() {
    void refetchActive()
    void refetchStats()
  }

  const stats: ChainStats = statsData ?? {
    active_ips:         0,
    chains_24h:         0,
    critical_24h:       0,
    unique_ips_24h:     0,
    stage_distribution: {},
  }

  const chains: ActiveChain[] = activeData?.chains ?? []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GitBranch className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Kill Chain Timeline</h1>
          {fetchingActive && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
        </div>
        <button
          onClick={refetch}
          className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
          title="Yenile"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button onClick={refetch} className="text-xs underline hover:text-red-300">
            Tekrar dene
          </button>
        </div>
      )}

      {/* Stat kartlar */}
      {isLoading ? (
        <div className="grid grid-cols-3 gap-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-24 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          <StatCard
            label="Aktif Saldırı IP"
            value={stats.active_ips}
            icon={Activity}
            color="bg-indigo-500/15 text-indigo-400"
          />
          <StatCard
            label="Son 24s Zincir"
            value={stats.chains_24h}
            icon={Shield}
            color="bg-orange-500/15 text-orange-400"
          />
          <StatCard
            label="Son 24s Kritik"
            value={stats.critical_24h}
            icon={AlertTriangle}
            color="bg-red-500/15 text-red-400"
          />
        </div>
      )}

      {/* Aktif Zincirler tablosu */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Aktif Zincirler</h2>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-10 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : chains.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <GitBranch className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
            <p className="text-xs mt-1">Aktif kill chain zinciri bulunamadı</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">Kaynak IP</th>
                  <th className="text-left px-4 py-2.5 font-medium">Aşamalar</th>
                  <th className="text-left px-4 py-2.5 font-medium">İlerleme</th>
                  <th className="text-left px-4 py-2.5 font-medium">Tip</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {chains.map((chain) => (
                  <tr key={chain.source_ip} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-zinc-300 text-xs">
                      {chain.source_ip}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {chain.stage_count} / {STAGE_ORDER.length}
                    </td>
                    <td className="px-4 py-3">
                      <StageProgress stages={chain.stages} />
                    </td>
                    <td className="px-4 py-3">
                      <ChainTypeTag type={chain.chain_type} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Stage legend */}
      <div className="flex flex-wrap gap-4 text-xs text-zinc-500">
        {STAGE_ORDER.map((stage) => (
          <span key={stage} className="flex items-center gap-1.5">
            <span className={`inline-block w-2.5 h-2.5 rounded-full ${STAGE_COLORS[stage]}`} />
            {STAGE_LABELS[stage]}
          </span>
        ))}
      </div>
    </div>
  )
}
