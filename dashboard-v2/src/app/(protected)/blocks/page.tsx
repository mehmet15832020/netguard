'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldOff, RefreshCw, ShieldCheck, AlertTriangle, Zap, Plus, X,
  Flame, Clock, User, Bot, ChevronUp, ChevronDown,
} from 'lucide-react'
import { activeResponse, type BlockedIP, type BlockVerifyResponse } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'

const INP = 'ui-input'
const SEL = 'ui-select'

function formatTtl(expiresAt: string | null): { label: string; cls: string } {
  if (!expiresAt) return { label: 'Süresiz', cls: 'text-slate-500' }
  const diff = new Date(expiresAt).getTime() - Date.now()
  if (diff <= 0) return { label: 'Süresi doldu', cls: 'text-red-400' }
  const h = Math.floor(diff / 3_600_000)
  const m = Math.floor((diff % 3_600_000) / 60_000)
  if (h === 0) return { label: `${m}dk`, cls: 'text-orange-400' }
  if (h < 24) return { label: `${h}s ${m}dk`, cls: 'text-yellow-400' }
  return { label: `${Math.floor(h / 24)}g ${h % 24}s`, cls: 'text-slate-400' }
}

function offenseTier(count: number) {
  if (count >= 3) return { cls: 'bg-red-500/10 text-red-300 border-red-500/30' }
  if (count === 2) return { cls: 'bg-orange-500/10 text-orange-300 border-orange-500/30' }
  return { cls: 'bg-sky-950/30 text-slate-400 border-sky-900/20' }
}

type SortKey = 'blocked_at' | 'offense_count' | 'expires_at'

const PROVIDER_COLORS: Record<string, string> = {
  opnsense: 'bg-orange-500/10 text-orange-300 border-orange-500/25 backdrop-blur-sm',
  vyos:     'bg-sky-500/10 text-sky-300 border-sky-500/25 backdrop-blur-sm',
  iptables: 'bg-violet-500/10 text-violet-300 border-violet-500/25 backdrop-blur-sm',
}

function ProviderBadge({ provider }: { provider: string }) {
  const cls = PROVIDER_COLORS[provider.toLowerCase()] ?? 'bg-sky-950/30 text-slate-300 border-sky-900/20 backdrop-blur-sm'
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-mono uppercase ${cls}`}>
      {provider}
    </span>
  )
}

function StatusBadge({ up, label }: { up: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium backdrop-blur-sm ${
      up
        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
        : 'bg-red-500/10 text-red-300 border-red-500/25'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${up ? 'bg-emerald-400' : 'bg-red-400'}`} />
      {label}
    </span>
  )
}

function KpiCard({
  label, value, sub, accent,
}: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="ui-panel p-4">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-bold tabular-nums ${accent ?? 'text-slate-100'}`}>{value}</p>
      {sub && <p className="text-xs text-slate-700 mt-0.5">{sub}</p>}
    </div>
  )
}

function VerifyPanel({ result }: { result: BlockVerifyResponse }) {
  const ok = result.status === 'ok'
  return (
    <div className="ui-panel p-4 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <StatusBadge up={result.opnsense_up} label="OPNsense" />
        <StatusBadge up={result.vyos_up} label="VyOS" />
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium backdrop-blur-sm ${
          ok
            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25'
            : 'bg-yellow-500/10 text-yellow-300 border-yellow-500/25'
        }`}>
          {ok ? 'Senkronize' : 'Uyumsuzluk Var'}
        </span>
        <span className="text-xs text-slate-500">
          Eşleşen: {result.synced.length} · Phantom: {result.phantom.length} · Orphan: {result.orphan.length}
        </span>
      </div>

      {result.phantom.length > 0 && (
        <div>
          <p className="text-xs font-medium text-red-400 mb-1">DB'de var, firewall'da yok — phantom ({result.phantom.length})</p>
          <div className="flex flex-wrap gap-1">
            {result.phantom.map(ip => (
              <span key={ip} className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/25 text-xs font-mono text-red-300">
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {result.orphan.length > 0 && (
        <div>
          <p className="text-xs font-medium text-yellow-400 mb-1">Firewall'da var, DB'de yok — orphan ({result.orphan.length})</p>
          <div className="flex flex-wrap gap-1">
            {result.orphan.map(ip => (
              <span key={ip} className="px-2 py-0.5 rounded bg-yellow-500/10 border border-yellow-500/25 text-xs font-mono text-yellow-300">
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {ok && (
        <p className="text-xs text-emerald-400">Tüm bloklar firewall ile senkronize.</p>
      )}
    </div>
  )
}

function ManualBlockForm({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false)
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('')
  const [ttl, setTtl] = useState('')
  const [error, setError] = useState('')

  const blockMutation = useMutation({
    mutationFn: () => activeResponse.block({
      ip: ip.trim(),
      reason: reason.trim(),
      destination_port: port ? parseInt(port, 10) : null,
      network_protocol: protocol || null,
      ttl_hours: ttl ? parseFloat(ttl) : null,
    }),
    onSuccess: () => {
      setOpen(false)
      setIp(''); setReason(''); setPort(''); setProtocol(''); setTtl(''); setError('')
      onSuccess()
    },
    onError: (err: Error) => setError(err.message),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    blockMutation.mutate()
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-sky-600 hover:bg-sky-500 text-white transition-colors"
      >
        <Plus size={13} /> Manuel Blok
      </button>
    )
  }

  return (
    <div className="ui-panel p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-200">Manuel IP Blokla</h3>
        <button onClick={() => { setOpen(false); setError('') }} className="text-slate-500 hover:text-slate-300 transition-colors">
          <X size={14} />
        </button>
      </div>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-slate-500">IP Adresi *</label>
            <input
              value={ip} onChange={e => setIp(e.target.value)}
              placeholder="1.2.3.4"
              required
              className={`${INP} w-full font-mono`}
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-500">Sebep *</label>
            <input
              value={reason} onChange={e => setReason(e.target.value)}
              placeholder="Manuel blok"
              required
              className={`${INP} w-full`}
            />
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-slate-500">Port <span className="text-slate-700">(opsiyonel)</span></label>
            <input
              value={port} onChange={e => setPort(e.target.value.replace(/\D/g, ''))}
              placeholder="443"
              maxLength={5}
              className={`${INP} w-full font-mono`}
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-500">Protokol <span className="text-slate-700">(opsiyonel)</span></label>
            <select
              value={protocol} onChange={e => setProtocol(e.target.value)}
              className={`${SEL} w-full`}
            >
              <option value="">—</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
              <option value="any">ANY</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-slate-500">TTL (saat) <span className="text-slate-700">(opsiyonel)</span></label>
            <input
              value={ttl} onChange={e => setTtl(e.target.value)}
              placeholder="24"
              className={`${INP} w-full font-mono`}
            />
          </div>
        </div>
        {error && (
          <p className="text-xs text-red-400 flex items-center gap-1">
            <AlertTriangle size={12} className="flex-shrink-0" /> {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={() => { setOpen(false); setError('') }}
            className="text-xs px-3 py-1.5 rounded-lg border border-sky-900/25 text-slate-400 hover:text-slate-200 hover:bg-sky-950/30 transition-colors">
            İptal
          </button>
          <button type="submit" disabled={blockMutation.isPending}
            className="text-xs px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:text-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5">
            {blockMutation.isPending && <RefreshCw size={11} className="animate-spin" />}
            Blokla
          </button>
        </div>
      </form>
    </div>
  )
}

function SortHeader({
  label, col, sort, dir, onSort,
}: {
  label: string; col: SortKey; sort: SortKey; dir: 'asc' | 'desc'
  onSort: (c: SortKey) => void
}) {
  const active = sort === col
  return (
    <button
      className={`flex items-center gap-1 text-xs font-medium hover:text-slate-200 transition-colors ${active ? 'text-slate-200' : 'text-slate-500'}`}
      onClick={() => onSort(col)}
    >
      {label}
      {active
        ? dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
        : <ChevronDown size={12} className="opacity-30" />}
    </button>
  )
}

function BreakGlassModal({
  ip, token, error, isPending,
  onClose, onTokenChange, onSubmit,
}: {
  ip: string; token: string; error: string | null; isPending: boolean
  onClose: () => void
  onTokenChange: (v: string) => void
  onSubmit: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#040911]/80 backdrop-blur-sm">
      <div className="w-full max-w-md bg-[#0a1120] border border-red-500/30 rounded-xl shadow-[0_24px_64px_rgba(0,0,0,0.8)] p-6">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle size={16} className="text-red-400 flex-shrink-0" />
          <h2 className="text-sm font-semibold text-red-400">Acil Blok Kaldırma (Break-Glass)</h2>
        </div>
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            <span className="font-mono text-slate-200">{ip}</span> adresinin bloğu JWT bypass ile kaldırılacak. Bu işlem denetim günlüğüne kaydedilir.
          </p>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-500">Break-Glass Token</label>
            <input
              type="password"
              placeholder="BREAK_GLASS_TOKEN değeri"
              value={token}
              onChange={e => onTokenChange(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') onSubmit() }}
              className={`${INP} w-full font-mono`}
            />
          </div>
          {error && (
            <p className="text-xs text-red-400 flex items-center gap-1">
              <AlertTriangle size={11} className="flex-shrink-0" />
              {error}
            </p>
          )}
        </div>
        <div className="flex justify-end gap-2 mt-5">
          <button
            onClick={onClose}
            className="text-xs px-3 py-1.5 rounded-lg border border-sky-900/25 text-slate-400 hover:text-slate-200 hover:bg-sky-950/30 transition-colors"
          >
            İptal
          </button>
          <button
            onClick={onSubmit}
            disabled={!token.trim() || isPending}
            className="text-xs px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:text-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
          >
            {isPending && <RefreshCw size={11} className="animate-spin" />}
            <Zap size={11} />
            Acil Kaldır
          </button>
        </div>
      </div>
    </div>
  )
}

export default function BlocksPage() {
  const qc = useQueryClient()

  const [breakGlassTarget, setBreakGlassTarget] = useState<string | null>(null)
  const [breakGlassToken, setBreakGlassToken] = useState('')
  const [breakGlassError, setBreakGlassError] = useState<string | null>(null)
  const [sort, setSort] = useState<SortKey>('blocked_at')
  const [dir, setDir] = useState<'asc' | 'desc'>('desc')
  const [originFilter, setOriginFilter] = useState<'all' | 'auto' | 'manual'>('all')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['active-blocks'],
    queryFn: () => activeResponse.listBlocks(),
    refetchInterval: 30_000,
    retry: false,
  })

  const { data: verifyData, isFetching: isVerifying, refetch: runVerify } = useQuery({
    queryKey: ['blocks-verify'],
    queryFn: () => activeResponse.verify(),
    enabled: false,
    refetchOnWindowFocus: false,
    retry: false,
  })

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => activeResponse.unblock(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['active-blocks'] }),
  })

  const breakGlassMutation = useMutation({
    mutationFn: ({ ip, token }: { ip: string; token: string }) =>
      activeResponse.breakGlass(ip, token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['active-blocks'] })
      setBreakGlassTarget(null)
      setBreakGlassToken('')
      setBreakGlassError(null)
    },
    onError: (err: Error) => setBreakGlassError(err.message),
  })

  const allBlocks: BlockedIP[] = (data?.blocks ?? []).filter(b => Boolean(b.is_active))
  const autoBlocks = allBlocks.filter(b => b.blocked_by === 'system')
  const manualBlocks = allBlocks.filter(b => b.blocked_by !== 'system')
  const expiringSoon = allBlocks.filter(b => {
    if (!b.expires_at) return false
    const diff = new Date(b.expires_at).getTime() - Date.now()
    return diff > 0 && diff < 3_600_000
  })
  const repeatOffenders = allBlocks.filter(b => (b.offense_count ?? 1) >= 3)

  const filtered = allBlocks.filter(b => {
    if (originFilter === 'auto') return b.blocked_by === 'system'
    if (originFilter === 'manual') return b.blocked_by !== 'system'
    return true
  })

  const sorted = [...filtered].sort((a, b) => {
    let av: number, bv: number
    if (sort === 'offense_count') {
      av = a.offense_count ?? 1; bv = b.offense_count ?? 1
    } else if (sort === 'expires_at') {
      av = a.expires_at ? new Date(a.expires_at).getTime() : Infinity
      bv = b.expires_at ? new Date(b.expires_at).getTime() : Infinity
    } else {
      av = new Date(a.blocked_at).getTime()
      bv = new Date(b.blocked_at).getTime()
    }
    return dir === 'asc' ? av - bv : bv - av
  })

  const handleSort = (col: SortKey) => {
    if (sort === col) setDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSort(col); setDir('desc') }
  }

  const handleUnblock = (ip: string) => {
    if (window.confirm(`${ip} adresinin bloğunu kaldırmak istediğinize emin misiniz?`)) {
      unblockMutation.mutate(ip)
    }
  }

  const openBreakGlass = (ip: string) => {
    setBreakGlassTarget(ip)
    setBreakGlassToken('')
    setBreakGlassError(null)
  }

  const closeBreakGlass = () => {
    setBreakGlassTarget(null)
    setBreakGlassToken('')
    setBreakGlassError(null)
  }

  const handleBreakGlassSubmit = () => {
    if (!breakGlassTarget || !breakGlassToken.trim()) return
    setBreakGlassError(null)
    breakGlassMutation.mutate({ ip: breakGlassTarget, token: breakGlassToken.trim() })
  }

  const providers = [...new Set(allBlocks.map(b => b.provider))]

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <ShieldOff size={15} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Aktif IP Blokları</h1>
            <p className="text-xs text-slate-600">OPNsense · VyOS aktif yanıt</p>
          </div>
          {allBlocks.length > 0 && (
            <span className="px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 text-xs font-bold border border-red-500/30">
              {allBlocks.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <ManualBlockForm onSuccess={() => qc.invalidateQueries({ queryKey: ['active-blocks'] })} />
          <button
            onClick={() => runVerify()}
            disabled={isVerifying}
            className="ui-btn ui-btn-secondary"
          >
            {isVerifying ? <RefreshCw size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
            {isVerifying ? 'Doğrulanıyor...' : "Firewall'ı Doğrula"}
          </button>
          <button
            onClick={() => refetch()}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={12} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          label="Toplam Aktif Blok"
          value={allBlocks.length}
          sub={providers.join(' · ') || 'provider yok'}
          accent={allBlocks.length > 0 ? 'text-red-400' : 'text-slate-100'}
        />
        <KpiCard
          label="Otomatik Blok"
          value={autoBlocks.length}
          sub="Kill chain / anomaly"
          accent={autoBlocks.length > 0 ? 'text-orange-400' : 'text-slate-100'}
        />
        <KpiCard
          label="Manuel Blok"
          value={manualBlocks.length}
          sub="Operatör tarafından"
        />
        <KpiCard
          label="Tekrar Saldırgan"
          value={repeatOffenders.length}
          sub="≥3 offense — progressive TTL"
          accent={repeatOffenders.length > 0 ? 'text-red-400' : 'text-slate-100'}
        />
      </div>

      {/* Verify panel */}
      {verifyData && <VerifyPanel result={verifyData} />}

      {/* Expiring soon alert */}
      {expiringSoon.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-300 text-sm">
          <Clock size={14} className="flex-shrink-0" />
          <span>
            <strong>{expiringSoon.length}</strong> blok 1 saat içinde sona erecek:{' '}
            {expiringSoon.map((b, i) => (
              <span key={b.ip}>{i > 0 && ', '}<span className="font-mono">{b.ip}</span></span>
            ))}
          </span>
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex items-center gap-1.5">
        {(['all', 'auto', 'manual'] as const).map(f => (
          <button
            key={f}
            onClick={() => setOriginFilter(f)}
            className={`px-3 py-1 rounded-lg text-xs font-medium border transition-colors ${
              originFilter === f
                ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300'
            }`}
          >
            {f === 'all' ? `Tümü (${allBlocks.length})` : f === 'auto' ? `Otomatik (${autoBlocks.length})` : `Manuel (${manualBlocks.length})`}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="ui-panel">
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={6} height={44} />
          </div>
        ) : sorted.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-700">
            <ShieldOff size={28} className="opacity-20" />
            <p className="text-sm">Henüz bloklu IP yok</p>
            <p className="text-xs">Incident detaylarından IP bloklama yapabilirsiniz</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-sky-900/20">
                <th className="ui-th">IP Adresi</th>
                <th className="ui-th">Sebep</th>
                <th className="ui-th">Kaynak</th>
                <th className="ui-th">Provider</th>
                <th className="ui-th">
                  <SortHeader label="Bloklandığı Zaman" col="blocked_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="ui-th">
                  <SortHeader label="Kalan TTL" col="expires_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="ui-th">
                  <SortHeader label="Offense" col="offense_count" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="ui-th" />
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {sorted.map(block => {
                const ttl = formatTtl(block.expires_at)
                const offense = block.offense_count ?? 1
                const tier = offenseTier(offense)
                const isAuto = block.blocked_by === 'system'
                return (
                  <tr key={block.block_id} className="hover:bg-sky-950/20 transition-colors">
                    <td className="ui-td font-mono text-sm text-slate-200">{block.ip}</td>
                    <td className="ui-td text-xs text-slate-400 max-w-xs truncate" title={block.reason}>
                      {block.reason}
                    </td>
                    <td className="ui-td">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs backdrop-blur-sm ${
                        isAuto
                          ? 'bg-orange-500/10 text-orange-300 border-orange-500/25'
                          : 'bg-sky-950/30 text-slate-400 border-sky-900/20'
                      }`}>
                        {isAuto ? <Bot size={11} /> : <User size={11} />}
                        {isAuto ? 'Sistem' : block.blocked_by}
                      </span>
                    </td>
                    <td className="ui-td">
                      <ProviderBadge provider={block.provider} />
                    </td>
                    <td className="ui-td text-xs text-slate-500">
                      {new Date(block.blocked_at).toLocaleString('tr-TR')}
                    </td>
                    <td className="ui-td">
                      <span className={`text-xs font-mono flex items-center gap-1 ${ttl.cls}`}>
                        <Clock size={11} />
                        {ttl.label}
                      </span>
                    </td>
                    <td className="ui-td">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-mono ${tier.cls}`}>
                        {offense >= 3 && <Flame size={11} />}
                        {offense}×
                      </span>
                    </td>
                    <td className="ui-td">
                      <div className="flex items-center gap-1.5">
                        <button
                          disabled={unblockMutation.isPending}
                          onClick={() => handleUnblock(block.ip)}
                          className="text-xs px-2 py-1 rounded-md border border-sky-900/25 text-slate-400 hover:border-red-500/40 hover:text-red-400 hover:bg-red-500/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Bloku Kaldır
                        </button>
                        <button
                          disabled={breakGlassMutation.isPending}
                          onClick={() => openBreakGlass(block.ip)}
                          title="Acil durum: Break-glass token ile kaldır"
                          className="text-xs px-2 py-1 rounded-md border border-red-500/25 text-red-500 hover:border-red-500/50 hover:text-red-300 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                        >
                          <Zap size={11} />
                          Acil
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Break-glass modal */}
      {breakGlassTarget !== null && (
        <BreakGlassModal
          ip={breakGlassTarget}
          token={breakGlassToken}
          error={breakGlassError}
          isPending={breakGlassMutation.isPending}
          onClose={closeBreakGlass}
          onTokenChange={setBreakGlassToken}
          onSubmit={handleBreakGlassSubmit}
        />
      )}
    </div>
  )
}
