'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, AlertTriangle, RefreshCw, X, ChevronDown, ChevronUp } from 'lucide-react'
import { fpRulesApi, type FPRule, type FPRuleCreate } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

type SortKey = 'hit_count' | 'created_at' | 'expires_at'

function daysRemaining(expiresAt: string | null): number | null {
  if (!expiresAt) return null
  return Math.floor((new Date(expiresAt).getTime() - Date.now()) / 86_400_000)
}

function ExpiryBadge({ expiresAt }: { expiresAt: string | null }) {
  if (!expiresAt) return <span className="text-slate-600 text-xs">Süresiz</span>
  const days = daysRemaining(expiresAt)
  if (days === null) return null
  if (days < 0)  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-400 backdrop-blur-sm">Süresi Doldu</span>
  if (days < 3)  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/10 border border-red-500/25 text-red-400 backdrop-blur-sm">{days} gün</span>
  if (days < 7)  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-500/10 border border-yellow-500/25 text-yellow-400 backdrop-blur-sm">{days} gün</span>
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-sky-950/30 border border-sky-900/20 text-slate-400">{days} gün</span>
}

function FieldCombination({ rule }: { rule: FPRule }) {
  const parts: string[] = []
  if (rule.event_action)     parts.push(`action=${rule.event_action}`)
  if (rule.source_ip)        parts.push(`src=${rule.source_ip}`)
  if (rule.destination_ip)   parts.push(`dst=${rule.destination_ip}`)
  if (rule.destination_port) parts.push(`port=${rule.destination_port}`)
  if (rule.observer_hostname) parts.push(`host=${rule.observer_hostname}`)
  if (parts.length === 0) return <span className="text-slate-600 italic text-xs">Genel kural</span>
  return (
    <div className="flex flex-wrap gap-1">
      {parts.map(p => (
        <span key={p} className="px-1.5 py-0.5 rounded bg-sky-950/30 border border-sky-900/20 text-sky-300 text-xs font-mono">{p}</span>
      ))}
    </div>
  )
}

function SortHeader({
  label, col, sort, dir, onSort,
}: { label: string; col: SortKey; sort: SortKey; dir: 'asc' | 'desc'; onSort: (c: SortKey) => void }) {
  const active = sort === col
  return (
    <button
      className={cn('flex items-center gap-1 text-xs font-medium uppercase tracking-wide transition-colors', active ? 'text-sky-400' : 'text-slate-600 hover:text-slate-300')}
      onClick={() => onSort(col)}
    >
      {label}
      {active
        ? dir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
        : <ChevronDown className="w-3 h-3 opacity-30" />}
    </button>
  )
}

const INPUT_CLS = "w-full bg-sky-950/20 border border-sky-900/25 rounded px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors"

function NewRuleModal({ onClose, onCreate }: { onClose: () => void; onCreate: (d: FPRuleCreate) => void }) {
  const [form, setForm] = useState<FPRuleCreate>({ reason: '' })
  const [error, setError] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.reason.trim()) { setError('Neden alanı zorunlu'); return }
    const fields = [form.event_action, form.source_ip, form.destination_ip, form.destination_port, form.observer_hostname]
    if (fields.every(f => !f?.toString().trim())) { setError('En az bir alan kombinasyonu girilmeli'); return }
    onCreate(form)
  }

  return (
    <div className="fixed inset-0 bg-[#040911]/80 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#0a1120] border border-sky-900/30 rounded-xl w-full max-w-md p-6 shadow-[0_24px_64px_rgba(0,0,0,0.7),0_0_0_1px_rgba(56,189,248,0.04)]">
        <div className="flex justify-between items-center mb-5">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-sky-400" />
            <h2 className="text-sm font-semibold text-slate-100">Yeni FP Kuralı</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors"><X size={16} /></button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Event Action</label>
            <input className={INPUT_CLS} placeholder="ssh_failure, port_scan, ..." value={form.event_action ?? ''}
              onChange={e => setForm(f => ({ ...f, event_action: e.target.value || undefined }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Kaynak IP / CIDR</label>
              <input className={INPUT_CLS} placeholder="10.0.0.5 veya 10.0.0.0/24" value={form.source_ip ?? ''}
                onChange={e => setForm(f => ({ ...f, source_ip: e.target.value || undefined }))} />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">Hedef IP / CIDR</label>
              <input className={INPUT_CLS} placeholder="192.168.1.0/24" value={form.destination_ip ?? ''}
                onChange={e => setForm(f => ({ ...f, destination_ip: e.target.value || undefined }))} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Hedef Port</label>
              <input className={INPUT_CLS} placeholder="443" value={form.destination_port ?? ''}
                onChange={e => setForm(f => ({ ...f, destination_port: e.target.value || undefined }))} />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">Observer Hostname</label>
              <input className={INPUT_CLS} placeholder="firewall-01" value={form.observer_hostname ?? ''}
                onChange={e => setForm(f => ({ ...f, observer_hostname: e.target.value || undefined }))} />
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Geçerlilik (gün)</label>
            <input className={INPUT_CLS} type="number" min={1} max={365} placeholder="30"
              value={form.expires_in_days ?? ''}
              onChange={e => setForm(f => ({ ...f, expires_in_days: e.target.value ? Number(e.target.value) : undefined }))} />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Neden <span className="text-red-400">*</span></label>
            <input className={INPUT_CLS} placeholder="Dahili tarama aracı, planlı bakım, vb." value={form.reason}
              onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose}
              className="px-4 py-1.5 rounded text-sm text-slate-300 hover:text-slate-100 bg-sky-950/30 hover:bg-sky-950/50 border border-sky-900/20 transition-colors">
              İptal
            </button>
            <button type="submit"
              className="px-4 py-1.5 rounded text-sm bg-sky-600 hover:bg-sky-500 text-white font-medium transition-colors">
              Oluştur
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function FPManagementPage() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [actionFilter, setActionFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'expired'>('all')
  const [sort, setSort] = useState<SortKey>('hit_count')
  const [dir, setDir] = useState<'asc' | 'desc'>('desc')

  const { data: rules = [], isLoading, refetch } = useQuery({
    queryKey: ['fp-rules'],
    queryFn: () => fpRulesApi.list(false),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const createMut = useMutation({
    mutationFn: fpRulesApi.create,
    onSuccess: () => { setShowModal(false); qc.invalidateQueries({ queryKey: ['fp-rules'] }) },
  })

  const deleteMut = useMutation({
    mutationFn: fpRulesApi.deactivate,
    onSuccess: () => { setConfirmDelete(null); qc.invalidateQueries({ queryKey: ['fp-rules'] }) },
  })

  const activeRules  = useMemo(() => rules.filter(r =>  r.is_active && (daysRemaining(r.expires_at) ?? 1) >= 0), [rules])
  const expiredRules = useMemo(() => rules.filter(r => !r.is_active || (r.expires_at && (daysRemaining(r.expires_at) ?? 1) < 0)), [rules])
  const totalHits    = useMemo(() => activeRules.reduce((s, r) => s + r.hit_count, 0), [activeRules])

  const uniqueActions = useMemo(() => {
    const s = new Set(rules.map(r => r.event_action).filter(Boolean) as string[])
    return Array.from(s).sort()
  }, [rules])

  const handleSort = (col: SortKey) => {
    if (sort === col) setDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSort(col); setDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = statusFilter === 'active' ? activeRules : statusFilter === 'expired' ? expiredRules : rules
    if (actionFilter) list = list.filter(r => r.event_action === actionFilter)
    return [...list].sort((a, b) => {
      let av: number, bv: number
      if (sort === 'hit_count') {
        av = a.hit_count; bv = b.hit_count
      } else if (sort === 'expires_at') {
        av = a.expires_at ? new Date(a.expires_at).getTime() : Infinity
        bv = b.expires_at ? new Date(b.expires_at).getTime() : Infinity
      } else {
        av = new Date(a.created_at).getTime()
        bv = new Date(b.created_at).getTime()
      }
      return dir === 'asc' ? av - bv : bv - av
    })
  }, [rules, activeRules, expiredRules, statusFilter, actionFilter, sort, dir])

  const topHitter = activeRules.reduce<FPRule | null>((best, r) => (!best || r.hit_count > best.hit_count) ? r : best, null)
  const expiringSoon = activeRules.filter(r => { const d = daysRemaining(r.expires_at); return d !== null && d >= 0 && d < 7 }).length

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Shield size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">False Positive Yönetimi</h1>
            <p className="text-xs text-slate-600">CIDR destekli olay bastırma kuralları</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-sky-950/40 transition-colors"
            title="Yenile"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium transition-colors shadow-[0_0_12px_rgba(56,189,248,0.15)]"
          >
            <Plus size={14} /> Yeni Kural
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <div className="text-xs text-slate-500 mb-1">Aktif Kural</div>
          <div className="text-2xl font-bold text-slate-100">{isLoading ? '—' : activeRules.length}</div>
          <div className="text-xs text-slate-700 mt-0.5">{expiredRules.length} süresi dolmuş</div>
        </div>
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <div className="text-xs text-slate-500 mb-1">Toplam Bastırılan</div>
          <div className="text-2xl font-bold text-emerald-400">{isLoading ? '—' : totalHits.toLocaleString()}</div>
          <div className="text-xs text-slate-700 mt-0.5">lifetime hit count</div>
        </div>
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <div className="text-xs text-slate-500 mb-1">En Çok Hit</div>
          <div className="text-2xl font-bold text-slate-100">{isLoading ? '—' : topHitter ? topHitter.hit_count.toLocaleString() : '—'}</div>
          {topHitter && (
            <div className="text-xs text-slate-600 mt-0.5 font-mono truncate">
              {topHitter.event_action ?? topHitter.source_ip ?? 'genel'}
            </div>
          )}
        </div>
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <div className="text-xs text-slate-500 mb-1">Süresi Dolmak Üzere</div>
          <div className={cn('text-2xl font-bold', expiringSoon > 0 ? 'text-yellow-400' : 'text-slate-100')}>
            {isLoading ? '—' : expiringSoon}
          </div>
          <div className="text-xs text-slate-700 mt-0.5">7 gün içinde</div>
        </div>
      </div>

      {/* Expiring alert */}
      {expiredRules.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-yellow-500/20 bg-yellow-500/5 text-yellow-300 text-sm">
          <AlertTriangle size={14} className="flex-shrink-0 text-yellow-400" />
          <span><strong>{expiredRules.length}</strong> kural süresi dolmuş — eşleşen olaylar yeniden uyarı üretiyor olabilir</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
          className="bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-sky-500/50 transition-colors"
        >
          <option value="">Tüm Event Action'lar</option>
          {uniqueActions.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <div className="flex rounded-lg overflow-hidden border border-sky-900/20">
          {(['all', 'active', 'expired'] as const).map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={cn(
                'px-3 py-1.5 text-xs transition-colors',
                statusFilter === s
                  ? 'bg-sky-500/15 text-sky-400 border-x border-sky-500/30'
                  : 'bg-[#0a1120] text-slate-500 hover:text-slate-300',
              )}>
              {s === 'all' ? `Tümü (${rules.length})` : s === 'active' ? `Aktif (${activeRules.length})` : `Dolmuş (${expiredRules.length})`}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={6} height={40} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Shield size={32} className="opacity-20" />
            <p className="text-sm">Kural bulunamadı</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-sky-900/15">
                <th className="text-left px-4 py-3 text-xs text-slate-600 font-medium uppercase tracking-wide">Alan Kombinasyonu</th>
                <th className="text-left px-4 py-3 text-xs text-slate-600 font-medium uppercase tracking-wide">Neden</th>
                <th className="text-right px-4 py-3">
                  <SortHeader label="Hit" col="hit_count" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="text-left px-4 py-3">
                  <SortHeader label="Kalan Süre" col="expires_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="text-left px-4 py-3 text-xs text-slate-600 font-medium uppercase tracking-wide">Oluşturan</th>
                <th className="text-left px-4 py-3">
                  <SortHeader label="Oluşturulma" col="created_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {filtered.map(rule => (
                <tr key={rule.fp_rule_id} className={cn('transition-colors hover:bg-sky-950/20', !rule.is_active && 'opacity-50')}>
                  <td className="px-4 py-3">
                    <FieldCombination rule={rule} />
                  </td>
                  <td className="px-4 py-3 text-slate-500 max-w-xs truncate text-xs" title={rule.reason}>
                    {rule.reason}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs">
                    {rule.hit_count > 0
                      ? <span className="text-emerald-400 font-semibold">{rule.hit_count.toLocaleString()}</span>
                      : <span className="text-slate-700">0</span>}
                  </td>
                  <td className="px-4 py-3">
                    <ExpiryBadge expiresAt={rule.expires_at} />
                  </td>
                  <td className="px-4 py-3 text-slate-600 text-xs">{rule.created_by}</td>
                  <td className="px-4 py-3 text-slate-700 text-xs whitespace-nowrap">
                    {new Date(rule.created_at).toLocaleDateString('tr-TR')}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {rule.is_active && (
                      <button
                        onClick={() => setConfirmDelete(rule.fp_rule_id)}
                        className="p-1 rounded text-slate-700 hover:text-red-400 hover:bg-red-950/30 transition-colors"
                        title="Devre dışı bırak"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showModal && (
        <NewRuleModal
          onClose={() => setShowModal(false)}
          onCreate={data => createMut.mutate(data)}
        />
      )}

      {confirmDelete && (
        <div className="fixed inset-0 bg-[#040911]/80 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0a1120] border border-sky-900/30 rounded-xl p-6 w-80 shadow-[0_24px_64px_rgba(0,0,0,0.7)]">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={15} className="text-yellow-400" />
              <h3 className="text-sm font-semibold text-slate-100">Kuralı Devre Dışı Bırak</h3>
            </div>
            <p className="text-xs text-slate-400 mb-5">
              Bu FP kuralı devre dışı bırakılacak. Eşleşen olaylar tekrar uyarı üretecek.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirmDelete(null)}
                className="px-4 py-1.5 rounded text-sm text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors">
                İptal
              </button>
              <button onClick={() => deleteMut.mutate(confirmDelete)}
                disabled={deleteMut.isPending}
                className="px-4 py-1.5 rounded text-sm bg-red-700 hover:bg-red-600 text-white transition-colors disabled:opacity-60">
                {deleteMut.isPending ? 'Siliniyor...' : 'Devre Dışı Bırak'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
