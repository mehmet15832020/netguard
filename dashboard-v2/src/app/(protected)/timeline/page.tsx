'use client'

import { useQuery } from '@tanstack/react-query'
import { Swords, RefreshCw, Shield, AlertTriangle, Activity, Target } from 'lucide-react'
import { attackChainsApi, correlationApi } from '@/lib/api'
import type { ActiveChain } from '@/lib/api'
import type { CorrelatedEvent } from '@/types/models'
import { cn } from '@/lib/utils'

const STAGE_ORDER = ['recon', 'weaponize', 'access', 'execute', 'lateral'] as const
const STAGE_TR: Record<string, string> = {
  recon:     'Keşif',
  weaponize: 'Erişim Denemeleri',
  access:    'İlk Erişim',
  execute:   'Komut Çalıştırma',
  lateral:   'Yanal Hareket',
}

const SEV_COLOR: Record<string, { border: string; bg: string; text: string; dot: string }> = {
  critical: { border: 'border-red-500/40',    bg: 'bg-red-500/10',    text: 'text-red-400',    dot: 'bg-red-500' },
  warning:  { border: 'border-yellow-500/40', bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  high:     { border: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-400', dot: 'bg-orange-500' },
  info:     { border: 'border-sky-500/40',    bg: 'bg-sky-500/10',    text: 'text-sky-400',    dot: 'bg-sky-500' },
}

function KillChainPipeline({ chain }: { chain: ActiveChain }) {
  const cfg = SEV_COLOR[chain.severity] ?? SEV_COLOR.info
  const completedStages = STAGE_ORDER.filter(s => chain.stages[s])

  return (
    <div className={cn('rounded-xl border p-4', cfg.border, cfg.bg)}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={cn('w-2 h-2 rounded-full flex-shrink-0', cfg.dot)} />
          <span className="font-mono text-sm font-semibold text-slate-100">{chain.source_ip}</span>
          <span className={cn('text-xs px-1.5 py-0.5 rounded border backdrop-blur-sm', cfg.text, cfg.border, cfg.bg)}>
            {chain.severity.toUpperCase()} · {chain.stage_count} AŞAMA
          </span>
        </div>
        <span className="text-[11px] text-slate-600 uppercase tracking-wide">
          {chain.chain_type === 'FULL_ATTACK_CHAIN' ? 'TAM ZİNCİR' : 'KISMİ ZİNCİR'}
        </span>
      </div>

      <div className="flex items-center gap-1">
        {STAGE_ORDER.map((stage, idx) => {
          const isActive   = !!chain.stages[stage]
          const eventCount = chain.stages[stage] ?? 0
          const isLast     = idx === STAGE_ORDER.length - 1

          return (
            <div key={stage} className="flex items-center flex-1">
              <div className={cn(
                'flex-1 rounded-md px-2 py-2 text-center transition-all',
                isActive
                  ? cn('border', cfg.border, cfg.bg)
                  : 'border border-sky-900/15 bg-sky-950/10',
              )}>
                <p className={cn('text-[10px] font-semibold uppercase tracking-wide',
                  isActive ? cfg.text : 'text-slate-700'
                )}>
                  {STAGE_TR[stage] ?? stage}
                </p>
                {isActive ? (
                  <p className={cn('text-lg font-bold tabular-nums mt-0.5', cfg.text)}>
                    {eventCount}
                  </p>
                ) : (
                  <p className="text-slate-700 text-sm mt-0.5">—</p>
                )}
              </div>
              {!isLast && (
                <div className={cn(
                  'w-4 h-px flex-shrink-0 mx-0.5',
                  isActive && completedStages.includes(STAGE_ORDER[idx + 1])
                    ? cfg.dot + ' opacity-60'
                    : 'bg-sky-900/20'
                )} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function HistoryRow({ ev }: { ev: CorrelatedEvent }) {
  const cfg = SEV_COLOR[ev.severity] ?? SEV_COLOR.info
  const isChain = ev.rule_id.includes('attack_chain')

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-sky-900/10 last:border-0 hover:bg-sky-950/20 transition-colors">
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', cfg.dot)} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs text-slate-200 font-medium">{ev.group_value}</span>
          {isChain && (
            <span className={cn('text-[10px] px-1.5 py-0.5 rounded border backdrop-blur-sm', cfg.text, cfg.border)}>
              {ev.rule_id === 'full_attack_chain' ? 'TAM ZİNCİR' : 'KISMİ ZİNCİR'}
            </span>
          )}
          <span className="text-[10px] text-slate-500">{ev.rule_name}</span>
        </div>
        <p className="text-[11px] text-slate-500 mt-0.5 truncate">{ev.message}</p>
      </div>
      <span className="text-[11px] text-slate-600 flex-shrink-0 tabular-nums">
        {new Date(ev.created_at).toLocaleString('tr-TR', {
          month: '2-digit', day: '2-digit',
          hour: '2-digit', minute: '2-digit',
        })}
      </span>
    </div>
  )
}

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

  const activeChains  = activeData?.chains ?? []
  const historyEvents = historyData?.events ?? []
  const otherEvents   = (corrData?.events ?? []).filter(e => !e.rule_id.includes('attack_chain')).slice(0, 10)
  const stats = statsData

  const KPI_ITEMS = [
    {
      label: 'Aktif Saldırı IP',
      value: stats?.active_ips ?? 0,
      icon: Target,
      active: (stats?.active_ips ?? 0) > 0,
      activeColor: 'text-red-400',
      activeBg: 'bg-red-500/10 border-red-500/20',
    },
    {
      label: 'Zincir (24 saat)',
      value: stats?.chains_24h ?? 0,
      icon: Swords,
      active: (stats?.chains_24h ?? 0) > 0,
      activeColor: 'text-orange-400',
      activeBg: 'bg-orange-500/10 border-orange-500/20',
    },
    {
      label: 'Kritik (24 saat)',
      value: stats?.critical_24h ?? 0,
      icon: AlertTriangle,
      active: (stats?.critical_24h ?? 0) > 0,
      activeColor: 'text-red-400',
      activeBg: 'bg-red-500/10 border-red-500/20',
    },
    {
      label: 'Etkilenen IP (24s)',
      value: stats?.unique_ips_24h ?? 0,
      icon: Shield,
      active: (stats?.unique_ips_24h ?? 0) > 0,
      activeColor: 'text-yellow-400',
      activeBg: 'bg-yellow-500/10 border-yellow-500/20',
    },
  ]

  return (
    <div className="p-6 space-y-5 max-w-[1400px]">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <Swords size={15} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Kill Chain & Saldırı Timeline</h1>
            <p className="text-xs text-slate-600">
              {activeChains.length > 0
                ? `${activeChains.length} aktif zincir`
                : 'Aktif saldırı zinciri yok'}
            </p>
          </div>
        </div>
        <button
          onClick={() => refetchActive()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors"
        >
          <RefreshCw size={12} /> Yenile
        </button>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {KPI_ITEMS.map(({ label, value, icon: Icon, active, activeColor, activeBg }) => (
          <div key={label} className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 flex items-center gap-3">
            <div className={cn(
              'w-9 h-9 rounded-lg border flex items-center justify-center flex-shrink-0',
              active ? cn(activeBg, activeColor) : 'bg-sky-950/20 border-sky-900/15 text-slate-600',
            )}>
              <Icon size={16} />
            </div>
            <div>
              <p className={cn('text-2xl font-bold tabular-nums', active ? activeColor : 'text-slate-100')}>{value}</p>
              <p className="text-[11px] text-slate-500">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Aktif Kill Chain'ler */}
      <div>
        <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3 flex items-center gap-2">
          <span className={cn('w-2 h-2 rounded-full', activeChains.length > 0 ? 'bg-red-500 animate-pulse' : 'bg-slate-700')} />
          Aktif Saldırı Zincirleri ({activeChains.length})
        </h2>

        {activeLoading ? (
          <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-8 text-center text-slate-600 text-sm">
            Yükleniyor...
          </div>
        ) : activeChains.length === 0 ? (
          <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-8 text-center">
            <Shield size={24} className="text-emerald-500/30 mx-auto mb-2" />
            <p className="text-slate-500 text-sm">Son 30 dakikada aktif saldırı zinciri tespit edilmedi</p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeChains.map((chain) => (
              <KillChainPipeline key={chain.source_ip} chain={chain} />
            ))}
          </div>
        )}
      </div>

      {/* Geçmiş + Diğer Olaylar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
            <Swords size={13} className="text-slate-500" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
              Kill Chain Geçmişi ({historyEvents.length})
            </span>
          </div>
          {historyEvents.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-slate-600 text-sm">
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

        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
            <Activity size={13} className="text-slate-500" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
              Diğer Korelasyon ({otherEvents.length})
            </span>
          </div>
          {otherEvents.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-slate-600 text-sm">
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
