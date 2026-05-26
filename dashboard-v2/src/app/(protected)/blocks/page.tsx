'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldOff, RefreshCw, ShieldCheck, AlertTriangle, Zap, Plus, X,
  Flame, Clock, User, Bot, ChevronUp, ChevronDown,
} from 'lucide-react'
import { activeResponse, type BlockedIP, type BlockVerifyResponse } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTtl(expiresAt: string | null): { label: string; cls: string } {
  if (!expiresAt) return { label: 'Süresiz', cls: 'text-zinc-500' }
  const diff = new Date(expiresAt).getTime() - Date.now()
  if (diff <= 0) return { label: 'Süresi doldu', cls: 'text-red-400' }
  const h = Math.floor(diff / 3_600_000)
  const m = Math.floor((diff % 3_600_000) / 60_000)
  if (h === 0) return { label: `${m}dk`, cls: 'text-orange-400' }
  if (h < 24) return { label: `${h}s ${m}dk`, cls: 'text-yellow-400' }
  return { label: `${Math.floor(h / 24)}g ${h % 24}s`, cls: 'text-zinc-400' }
}

function offenseTier(count: number) {
  if (count >= 3) return { cls: 'bg-red-900/50 text-red-300 border-red-700/50', dot: 'bg-red-400' }
  if (count === 2) return { cls: 'bg-orange-900/50 text-orange-300 border-orange-700/50', dot: 'bg-orange-400' }
  return { cls: 'bg-zinc-800 text-zinc-400 border-zinc-700', dot: 'bg-zinc-500' }
}

type SortKey = 'blocked_at' | 'offense_count' | 'expires_at'

// ── Sub-components ────────────────────────────────────────────────────────────

const PROVIDER_COLORS: Record<string, string> = {
  opnsense: 'bg-orange-900/40 text-orange-300 border-orange-800/40',
  vyos:     'bg-blue-900/40 text-blue-300 border-blue-800/40',
  iptables: 'bg-purple-900/40 text-purple-300 border-purple-800/40',
}

function ProviderBadge({ provider }: { provider: string }) {
  const cls = PROVIDER_COLORS[provider.toLowerCase()] ?? 'bg-zinc-700/40 text-zinc-300 border-zinc-600/40'
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-mono uppercase ${cls}`}>
      {provider}
    </span>
  )
}

function StatusBadge({ up, label }: { up: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${
      up
        ? 'bg-green-900/40 text-green-300 border-green-800/40'
        : 'bg-red-900/40 text-red-300 border-red-800/40'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${up ? 'bg-green-400' : 'bg-red-400'}`} />
      {label}
    </span>
  )
}

function KpiCard({
  label, value, sub, accent,
}: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardContent className="p-4">
        <p className="text-xs text-zinc-500 mb-1">{label}</p>
        <p className={`text-2xl font-bold tabular-nums ${accent ?? 'text-zinc-100'}`}>{value}</p>
        {sub && <p className="text-xs text-zinc-600 mt-0.5">{sub}</p>}
      </CardContent>
    </Card>
  )
}

function VerifyPanel({ result }: { result: BlockVerifyResponse }) {
  const ok = result.status === 'ok'
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900/60 p-4 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <StatusBadge up={result.opnsense_up} label="OPNsense" />
        <StatusBadge up={result.vyos_up} label="VyOS" />
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${
          ok
            ? 'bg-green-900/40 text-green-300 border-green-800/40'
            : 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40'
        }`}>
          {ok ? 'Senkronize' : 'Uyumsuzluk Var'}
        </span>
        <span className="text-xs text-zinc-500">
          Eşleşen: {result.synced.length} · Phantom: {result.phantom.length} · Orphan: {result.orphan.length}
        </span>
      </div>

      {result.phantom.length > 0 && (
        <div>
          <p className="text-xs font-medium text-red-400 mb-1">DB'de var, firewall'da yok — phantom ({result.phantom.length})</p>
          <div className="flex flex-wrap gap-1">
            {result.phantom.map(ip => (
              <span key={ip} className="px-2 py-0.5 rounded bg-red-900/30 border border-red-800/40 text-xs font-mono text-red-300">
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
              <span key={ip} className="px-2 py-0.5 rounded bg-yellow-900/30 border border-yellow-800/40 text-xs font-mono text-yellow-300">
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {ok && (
        <p className="text-xs text-green-400">Tüm bloklar firewall ile senkronize.</p>
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
      <Button size="sm" onClick={() => setOpen(true)} className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white">
        <Plus className="w-4 h-4" /> Manuel Blok
      </Button>
    )
  }

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-zinc-200">Manuel IP Blokla</h3>
        <button onClick={() => { setOpen(false); setError('') }} className="text-zinc-500 hover:text-zinc-300">
          <X className="w-4 h-4" />
        </button>
      </div>
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">IP Adresi *</label>
            <Input
              value={ip} onChange={e => setIp(e.target.value)}
              placeholder="1.2.3.4"
              required
              className="font-mono text-sm bg-zinc-800 border-zinc-700 text-zinc-100 h-8"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Sebep *</label>
            <Input
              value={reason} onChange={e => setReason(e.target.value)}
              placeholder="Manuel blok"
              required
              className="text-sm bg-zinc-800 border-zinc-700 text-zinc-100 h-8"
            />
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Port <span className="text-zinc-600">(opsiyonel)</span></label>
            <Input
              value={port} onChange={e => setPort(e.target.value.replace(/\D/g, ''))}
              placeholder="443"
              maxLength={5}
              className="font-mono text-sm bg-zinc-800 border-zinc-700 text-zinc-100 h-8"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">Protokol <span className="text-zinc-600">(opsiyonel)</span></label>
            <select
              value={protocol} onChange={e => setProtocol(e.target.value)}
              className="w-full h-8 rounded-md border border-zinc-700 bg-zinc-800 text-sm text-zinc-100 px-2 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="">—</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
              <option value="any">ANY</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-zinc-400">TTL (saat) <span className="text-zinc-600">(opsiyonel)</span></label>
            <Input
              value={ttl} onChange={e => setTtl(e.target.value)}
              placeholder="24"
              className="font-mono text-sm bg-zinc-800 border-zinc-700 text-zinc-100 h-8"
            />
          </div>
        </div>
        {error && (
          <p className="text-xs text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 flex-shrink-0" /> {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={() => { setOpen(false); setError('') }}
            className="text-xs px-3 py-1.5 rounded border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors">
            İptal
          </button>
          <button type="submit" disabled={blockMutation.isPending}
            className="text-xs px-3 py-1.5 rounded border border-red-700 bg-red-900/30 text-red-300 hover:bg-red-900/50 hover:text-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5">
            {blockMutation.isPending && <RefreshCw className="w-3 h-3 animate-spin" />}
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
      className={`flex items-center gap-1 text-xs font-medium hover:text-zinc-200 transition-colors ${active ? 'text-zinc-200' : 'text-zinc-500'}`}
      onClick={() => onSort(col)}
    >
      {label}
      {active
        ? dir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
        : <ChevronDown className="w-3 h-3 opacity-30" />}
    </button>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

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
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff className="w-5 h-5 text-red-400" />
          <h1 className="text-xl font-semibold">Aktif IP Blokları</h1>
          {allBlocks.length > 0 && (
            <span className="ml-1 px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold border border-red-700/40">
              {allBlocks.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <ManualBlockForm onSuccess={() => qc.invalidateQueries({ queryKey: ['active-blocks'] })} />
          <Button
            variant="outline" size="sm"
            onClick={() => runVerify()}
            disabled={isVerifying}
            className="flex items-center gap-1.5"
          >
            {isVerifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            {isVerifying ? 'Doğrulanıyor...' : "Firewall'ı Doğrula"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          label="Toplam Aktif Blok"
          value={allBlocks.length}
          sub={providers.join(' · ') || 'provider yok'}
          accent={allBlocks.length > 0 ? 'text-red-400' : 'text-zinc-100'}
        />
        <KpiCard
          label="Otomatik Blok"
          value={autoBlocks.length}
          sub="Kill chain / anomaly"
          accent={autoBlocks.length > 0 ? 'text-orange-400' : 'text-zinc-100'}
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
          accent={repeatOffenders.length > 0 ? 'text-red-400' : 'text-zinc-100'}
        />
      </div>

      {/* Verify panel */}
      {verifyData && <VerifyPanel result={verifyData} />}

      {/* Expiring soon alert */}
      {expiringSoon.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-orange-700/40 bg-orange-900/20 text-orange-300 text-sm">
          <Clock className="w-4 h-4 flex-shrink-0" />
          <span>
            <strong>{expiringSoon.length}</strong> blok 1 saat içinde sona erecek: {' '}
            {expiringSoon.map(b => <span key={b.ip} className="font-mono">{b.ip}</span>).reduce((a, b) => <>{a}, {b}</>)}
          </span>
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex items-center gap-1">
        {(['all', 'auto', 'manual'] as const).map(f => (
          <button
            key={f}
            onClick={() => setOriginFilter(f)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              originFilter === f
                ? 'bg-zinc-700 text-zinc-100'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {f === 'all' ? `Tümü (${allBlocks.length})` : f === 'auto' ? `Otomatik (${autoBlocks.length})` : `Manuel (${manualBlocks.length})`}
          </button>
        ))}
      </div>

      {/* Table */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800">
                <TableHead>IP Adresi</TableHead>
                <TableHead>Sebep</TableHead>
                <TableHead>Kaynak</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>
                  <SortHeader label="Bloklandığı Zaman" col="blocked_at" sort={sort} dir={dir} onSort={handleSort} />
                </TableHead>
                <TableHead>
                  <SortHeader label="Kalan TTL" col="expires_at" sort={sort} dir={dir} onSort={handleSort} />
                </TableHead>
                <TableHead>
                  <SortHeader label="Offense" col="offense_count" sort={sort} dir={dir} onSort={handleSort} />
                </TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-zinc-500 py-8">
                    Yükleniyor...
                  </TableCell>
                </TableRow>
              ) : sorted.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-zinc-500 py-12">
                    <div className="flex flex-col items-center gap-2">
                      <ShieldOff className="w-8 h-8 text-zinc-700" />
                      <p>Henüz bloklu IP yok</p>
                      <p className="text-xs text-zinc-600">Incident detaylarından IP bloklama yapabilirsiniz</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map(block => {
                  const ttl = formatTtl(block.expires_at)
                  const offense = block.offense_count ?? 1
                  const tier = offenseTier(offense)
                  const isAuto = block.blocked_by === 'system'
                  return (
                    <TableRow key={block.block_id} className="border-zinc-800 hover:bg-zinc-800/50">
                      <TableCell className="font-mono text-sm text-zinc-200">
                        {block.ip}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-400 max-w-xs truncate" title={block.reason}>
                        {block.reason}
                      </TableCell>
                      <TableCell>
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs ${
                          isAuto
                            ? 'bg-orange-900/30 text-orange-300 border-orange-800/40'
                            : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                        }`}>
                          {isAuto ? <Bot className="w-3 h-3" /> : <User className="w-3 h-3" />}
                          {isAuto ? 'Sistem' : block.blocked_by}
                        </span>
                      </TableCell>
                      <TableCell>
                        <ProviderBadge provider={block.provider} />
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">
                        {new Date(block.blocked_at).toLocaleString('tr-TR')}
                      </TableCell>
                      <TableCell>
                        <span className={`text-xs font-mono flex items-center gap-1 ${ttl.cls}`}>
                          <Clock className="w-3 h-3" />
                          {ttl.label}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-mono ${tier.cls}`}>
                          {offense >= 3 && <Flame className="w-3 h-3" />}
                          {offense}×
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <button
                            disabled={unblockMutation.isPending}
                            onClick={() => handleUnblock(block.ip)}
                            className="text-xs px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-red-700/50 hover:text-red-400 hover:bg-red-500/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          >
                            Bloku Kaldır
                          </button>
                          <button
                            disabled={breakGlassMutation.isPending}
                            onClick={() => openBreakGlass(block.ip)}
                            title="Acil durum: Break-glass token ile kaldır"
                            className="text-xs px-2 py-1 rounded border border-red-900/60 text-red-500 hover:border-red-600 hover:text-red-300 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                          >
                            <Zap className="w-3 h-3" />
                            Acil Kaldır
                          </button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Break-glass dialog */}
      <Dialog open={breakGlassTarget !== null} onOpenChange={(open) => { if (!open) closeBreakGlass() }}>
        <DialogContent className="sm:max-w-md bg-zinc-900 border-zinc-700">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-4 h-4" />
              Acil Blok Kaldırma (Break-Glass)
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-sm text-zinc-400">
              <span className="font-mono text-zinc-200">{breakGlassTarget}</span> adresinin bloğu JWT bypass ile kaldırılacak. Bu işlem denetim günlüğüne kaydedilir.
            </p>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400">Break-Glass Token</label>
              <Input
                type="password"
                placeholder="BREAK_GLASS_TOKEN değeri"
                value={breakGlassToken}
                onChange={e => setBreakGlassToken(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleBreakGlassSubmit() }}
                className="font-mono text-sm"
              />
            </div>
            {breakGlassError && (
              <p className="text-xs text-red-400 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                {breakGlassError}
              </p>
            )}
          </div>
          <DialogFooter>
            <button
              onClick={closeBreakGlass}
              className="text-sm px-3 py-1.5 rounded border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
            >
              İptal
            </button>
            <button
              onClick={handleBreakGlassSubmit}
              disabled={!breakGlassToken.trim() || breakGlassMutation.isPending}
              className="text-sm px-3 py-1.5 rounded border border-red-700 bg-red-900/30 text-red-300 hover:bg-red-900/50 hover:text-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
            >
              {breakGlassMutation.isPending && <RefreshCw className="w-3 h-3 animate-spin" />}
              Acil Kaldır
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
