'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldOff, RefreshCw, ShieldCheck, AlertTriangle, Zap, Plus, X } from 'lucide-react'
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

function VerifyPanel({ result }: { result: BlockVerifyResponse }) {
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900/60 p-4 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <StatusBadge up={result.opnsense_up} label="OPNsense" />
        <StatusBadge up={result.vyos_up} label="VyOS" />
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${
          result.ok
            ? 'bg-green-900/40 text-green-300 border-green-800/40'
            : 'bg-yellow-900/40 text-yellow-300 border-yellow-800/40'
        }`}>
          {result.ok ? 'Senkronize' : 'Uyumsuzluk Var'}
        </span>
        <span className="text-xs text-zinc-500">
          DB: {result.db_count} blok · Firewall: {result.fw_count} blok
        </span>
      </div>

      {result.missing.length > 0 && (
        <div>
          <p className="text-xs font-medium text-red-400 mb-1">Firewall'da eksik ({result.missing.length})</p>
          <div className="flex flex-wrap gap-1">
            {result.missing.map(ip => (
              <span key={ip} className="px-2 py-0.5 rounded bg-red-900/30 border border-red-800/40 text-xs font-mono text-red-300">
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {result.extra.length > 0 && (
        <div>
          <p className="text-xs font-medium text-yellow-400 mb-1">Firewall'da fazla ({result.extra.length})</p>
          <div className="flex flex-wrap gap-1">
            {result.extra.map(ip => (
              <span key={ip} className="px-2 py-0.5 rounded bg-yellow-900/30 border border-yellow-800/40 text-xs font-mono text-yellow-300">
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {result.ok && result.missing.length === 0 && result.extra.length === 0 && (
        <p className="text-xs text-green-400">Tum bloklar firewall ile senkronize.</p>
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

export default function BlocksPage() {
  const qc = useQueryClient()

  const [breakGlassTarget, setBreakGlassTarget] = useState<string | null>(null)
  const [breakGlassToken, setBreakGlassToken] = useState('')
  const [breakGlassError, setBreakGlassError] = useState<string | null>(null)

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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['active-blocks'] })
    },
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
    onError: (err: Error) => {
      setBreakGlassError(err.message)
    },
  })

  const activeBlocks: BlockedIP[] = (data?.blocks ?? []).filter(b => Boolean(b.is_active))

  const handleUnblock = (ip: string) => {
    if (window.confirm(`${ip} adresinin blogunu kaldirmak istediginize emin misiniz?`)) {
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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff className="w-5 h-5 text-red-400" />
          <h1 className="text-xl font-semibold">Aktif IP Bloklari</h1>
          {activeBlocks.length > 0 && (
            <span className="ml-1 px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold border border-red-700/40">
              {activeBlocks.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <ManualBlockForm onSuccess={() => qc.invalidateQueries({ queryKey: ['active-blocks'] })} />
          <Button
            variant="outline"
            size="sm"
            onClick={() => runVerify()}
            disabled={isVerifying}
            className="flex items-center gap-1.5"
          >
            {isVerifying ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
            {isVerifying ? 'Dogrulanıyor...' : "Firewall'i Dogrula"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {verifyData && <VerifyPanel result={verifyData} />}

      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800">
                <TableHead>IP Adresi</TableHead>
                <TableHead>Sebep</TableHead>
                <TableHead>Bloklayan</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Bloklandigi Zaman</TableHead>
                <TableHead>Kaynak Incident</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-zinc-500 py-8">
                    Yukleniyor...
                  </TableCell>
                </TableRow>
              ) : activeBlocks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-zinc-500 py-12">
                    <div className="flex flex-col items-center gap-2">
                      <ShieldOff className="w-8 h-8 text-zinc-700" />
                      <p>Henuz bloklu IP yok</p>
                      <p className="text-xs text-zinc-600">Incident detaylarindan IP bloklama yapabilirsiniz</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                activeBlocks.map(block => (
                  <TableRow key={block.block_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell className="font-mono text-sm text-zinc-200">
                      {block.ip}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400 max-w-xs truncate">
                      {block.reason}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">
                      {block.blocked_by}
                    </TableCell>
                    <TableCell>
                      <ProviderBadge provider={block.provider} />
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">
                      {new Date(block.blocked_at).toLocaleString('tr-TR')}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-600 font-mono">
                      {block.source_incident_id ? (
                        <span className="text-indigo-400 truncate max-w-[120px] inline-block align-bottom">
                          {block.source_incident_id.slice(0, 8)}...
                        </span>
                      ) : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <button
                          disabled={unblockMutation.isPending}
                          onClick={() => handleUnblock(block.ip)}
                          className="text-xs px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-red-700/50 hover:text-red-400 hover:bg-red-500/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Bloku Kaldir
                        </button>
                        <button
                          disabled={breakGlassMutation.isPending}
                          onClick={() => openBreakGlass(block.ip)}
                          title="Acil durum: Break-glass token ile kaldir"
                          className="text-xs px-2 py-1 rounded border border-red-900/60 text-red-500 hover:border-red-600 hover:text-red-300 hover:bg-red-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                        >
                          <Zap className="w-3 h-3" />
                          Acil Kaldir
                        </button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={breakGlassTarget !== null} onOpenChange={(open) => { if (!open) closeBreakGlass() }}>
        <DialogContent className="sm:max-w-md bg-zinc-900 border-zinc-700">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-4 h-4" />
              Acil Blok Kaldirma (Break-Glass)
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-sm text-zinc-400">
              <span className="font-mono text-zinc-200">{breakGlassTarget}</span> adresinin bloku JWT bypass ile kaldirilacak. Bu islem denetim gunlugune kaydedilir.
            </p>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400">Break-Glass Token</label>
              <Input
                type="password"
                placeholder="BREAK_GLASS_TOKEN degeri"
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
              Iptal
            </button>
            <button
              onClick={handleBreakGlassSubmit}
              disabled={!breakGlassToken.trim() || breakGlassMutation.isPending}
              className="text-sm px-3 py-1.5 rounded border border-red-700 bg-red-900/30 text-red-300 hover:bg-red-900/50 hover:text-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
            >
              {breakGlassMutation.isPending && <RefreshCw className="w-3 h-3 animate-spin" />}
              Acil Kaldir
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
