'use client'

import { useQuery } from '@tanstack/react-query'
import { Swords, RefreshCw, Shield, AlertTriangle, Activity, Target } from 'lucide-react'
import { attackChainsApi, correlationApi } from '@/lib/api'
import type { ActiveChain } from '@/lib/api'
import type { CorrelatedEvent } from '@/types/models'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

// Kill chain aşamaları sabit sırada
const STAGE_ORDER = ['recon', 'weaponize', 'access', 'execute', 'lateral'] as const
const STAGE_TR: Record<string, string> = {
  recon:      'Keşif',
  weaponize:  'Erişim Denemeleri',
  access:     'İlk Erişim',
  execute:    'Komut Çalıştırma',
  lateral:    'Yanal Hareket',
}

const SEV_COLOR: Record<string, { border: string; bg: string; text: string; dot: string }> = {
  critical: { border: 'border-red-500/40',    bg: 'bg-red-500/10',    text: 'text-red-400',    dot: 'bg-red-500' },
  warning:  { border: 'border-yellow-500/40', bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  high:     { border: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-400', dot: 'bg-orange-500' },
  info:     { border: 'border-blue-500/40',   bg: 'bg-blue-500/10',   text: 'text-blue-400',   dot: 'bg-blue-500' },
}

// ------------------------------------------------------------------ //
//  Kill Chain Pipeline — bir IP için 5 aşama görselleştirmesi
// ------------------------------------------------------------------ //

function KillChainPipeline({ chain }: { chain: ActiveChain }) {
  const cfg = SEV_COLOR[chain.severity] ?? SEV_COLOR.info
  const completedStages = STAGE_ORDER.filter(s => chain.stages[s])

  return (
    <div className={cn('rounded-lg border p-4', cfg.border, cfg.bg)}>
      {/* Başlık */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={cn('w-2 h-2 rounded-full flex-shrink-0', cfg.dot)} />
          <span className="font-mono text-sm font-semibold text-zinc-100">{chain.src_ip}</span>
          <span className={cn('text-xs px-1.5 py-0.5 rounded border', cfg.text, cfg.border, cfg.bg)}>
            {chain.severity.toUpperCase()} · {chain.stage_count} AŞAMA
          </span>
        </div>
        <span className="text-[11px] text-zinc-600 uppercase tracking-wide">
          {chain.chain_type === 'FULL_ATTACK_CHAIN' ? 'TAM ZİNCİR' : 'KISMİ ZİNCİR'}
        </span>
      </div>

      {/* 5 Aşama Pipeline */}
      <div className="flex items-center gap-1">
        {STAGE_ORDER.map((stage, idx) => {
          const isActive  = !!chain.stages[stage]
          const eventCount = chain.stages[stage] ?? 0
          const isLast    = idx === STAGE_ORDER.length - 1

          return (
            <div key={stage} className="flex items-center flex-1">
              <div className={cn(
                'flex-1 rounded-md px-2 py-2 text-center transition-all',
                isActive
                  ? cn('border', cfg.border, cfg.bg)
                  : 'border border-zinc-800 bg-zinc-800/30',
              )}>
                <p className={cn('text-[10px] font-semibold uppercase tracking-wide',
                  isActive ? cfg.text : 'text-zinc-600'
                )}>
                  {STAGE_TR[stage] ?? stage}
                </p>
                {isActive && (
                  <p className={cn('text-lg font-bold tabular-nums mt-0.5', cfg.text)}>
                    {eventCount}
                  </p>
                )}
                {!isActive && (
                  <p className="text-zinc-700 text-sm mt-0.5">—</p>
                )}
              </div>
              {!isLast && (
                <div className={cn('w-4 h-px flex-shrink-0 mx-0.5',
                  isActive && completedStages.includes(STAGE_ORDER[idx + 1])
                    ? cfg.dot.replace('bg-', 'bg-') + ' opacity-60'
                    : 'bg-zinc-700'
                )} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Geçmiş olay satırı
// ------------------------------------------------------------------ //

function HistoryRow({ ev }: { ev: CorrelatedEvent }) {
  const cfg = SEV_COLOR[ev.severity] ?? SEV_COLOR.info
  const isChain = ev.rule_id.includes('attack_chain')

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-zinc-800/60 last:border-0 hover:bg-zinc-800/30 transition-colors">
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', cfg.dot)} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs text-zinc-200 font-medium">{ev.group_value}</span>
          {isChain && (
            <span className={cn('text-[10px] px-1.5 py-0.5 rounded border', cfg.text, cfg.border)}>
              {ev.rule_id === 'full_attack_chain' ? 'TAM ZİNCİR' : 'KISMİ ZİNCİR'}
            </span>
          )}
          <span className="text-[10px] text-zinc-500">{ev.rule_name}</span>
        </div>
        <p className="text-[11px] text-zinc-500 mt-0.5 truncate">{ev.message}</p>
      </div>
      <span className="text-[11px] text-zinc-600 flex-shrink-0 tabular-nums">
        {new Date(ev.created_at).toLocaleString('tr-TR', {
          month: '2-digit', day: '2-digit',
          hour: '2-digit', minute: '2-digit',
        })}
      </span>
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Ana sayfa
// ------------------------------------------------------------------ //

export default function TimelinePage() {
  const { data: activeData, isLoading: activeLoading, refetch: refetchActive } = useQuery({
    queryKey: ['attack-chains-active'],
    queryFn:  () => attackChainsApi.active(),
    refetchInterval: 15_000,
  })

  const { data: statsData } = useQuery({
    queryKey: ['attack-chains-stats'],
    queryFn:  () => attackChainsApi.stats(),
    refetchInterval: 30_000,
  })

  const { data: historyData } = useQuery({
    queryKey: ['attack-chains-history'],
    queryFn:  () => attackChainsApi.history(30),
    refetchInterval: 30_000,
  })

  const { data: corrData } = useQuery({
    queryKey: ['corr-events-timeline'],
    queryFn:  () => correlationApi.listEvents({ limit: 20 }),
    refetchInterval: 30_000,
  })

  const activeChains = activeData?.chains ?? []
  const historyEvents = historyData?.events ?? []
  const otherEvents   = (corrData?.events ?? []).filter(e => !e.rule_id.includes('attack_chain')).slice(0, 10)
  const stats = statsData

  return (
    <div className="p-5 space-y-5 max-w-[1400px]">

      {/* Başlık */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Swords size={18} className="text-red-400" />
          <h1 className="text-xl font-semibold text-zinc-100">Kill Chain & Saldırı Timeline</h1>
        </div>
        <Button variant="outline" size="sm"
          onClick={() => refetchActive()}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
        >
          <RefreshCw size={14} className="mr-1.5" /> Yenile
        </Button>
      </div>

      {/* İstatistik kartları */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          {
            label: 'Aktif Saldırı IP',
            value: stats?.active_ips ?? 0,
            icon: Target,
            color: (stats?.active_ips ?? 0) > 0 ? 'text-red-400 bg-red-500/10' : 'text-zinc-400 bg-zinc-800',
          },
          {
            label: 'Zincir (24 saat)',
            value: stats?.chains_24h ?? 0,
            icon: Swords,
            color: (stats?.chains_24h ?? 0) > 0 ? 'text-orange-400 bg-orange-500/10' : 'text-zinc-400 bg-zinc-800',
          },
          {
            label: 'Kritik (24 saat)',
            value: stats?.critical_24h ?? 0,
            icon: AlertTriangle,
            color: (stats?.critical_24h ?? 0) > 0 ? 'text-red-400 bg-red-500/10' : 'text-zinc-400 bg-zinc-800',
          },
          {
            label: 'Etkilenen IP (24s)',
            value: stats?.unique_ips_24h ?? 0,
            icon: Shield,
            color: (stats?.unique_ips_24h ?? 0) > 0 ? 'text-yellow-400 bg-yellow-500/10' : 'text-zinc-400 bg-zinc-800',
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-4 flex items-center gap-3">
              <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0', color)}>
                <Icon size={16} />
              </div>
              <div>
                <p className="text-2xl font-bold text-zinc-100 tabular-nums">{value}</p>
                <p className="text-[11px] text-zinc-500">{label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Aktif Kill Chain'ler */}
      <div>
        <h2 className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-3 flex items-center gap-2">
          <span className={cn('w-2 h-2 rounded-full', activeChains.length > 0 ? 'bg-red-500 animate-pulse' : 'bg-zinc-600')} />
          Aktif Saldırı Zincirleri ({activeChains.length})
        </h2>

        {activeLoading ? (
          <p className="text-zinc-600 text-sm">Yükleniyor...</p>
        ) : activeChains.length === 0 ? (
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-8 text-center">
            <Shield size={24} className="text-emerald-500/40 mx-auto mb-2" />
            <p className="text-zinc-500 text-sm">Son 30 dakikada aktif saldırı zinciri tespit edilmedi</p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeChains.map((chain) => (
              <KillChainPipeline key={chain.src_ip} chain={chain} />
            ))}
          </div>
        )}
      </div>

      {/* Geçmiş + Diğer Olaylar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Kill Chain Geçmişi */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
            <Swords size={13} className="text-zinc-500" />
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">
              Kill Chain Geçmişi ({historyEvents.length})
            </span>
          </div>
          {historyEvents.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">
              Kayıt yok
            </div>
          ) : (
            <div>
              {historyEvents.map((ev) => (
                <HistoryRow key={ev.corr_id} ev={ev} />
              ))}
            </div>
          )}
        </div>

        {/* Diğer Korelasyon Olayları */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
            <Activity size={13} className="text-zinc-500" />
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">
              Diğer Korelasyon ({otherEvents.length})
            </span>
          </div>
          {otherEvents.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-zinc-600 text-sm">
              Kayıt yok
            </div>
          ) : (
            <div>
              {otherEvents.map((ev) => (
                <HistoryRow key={ev.corr_id} ev={ev} />
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
