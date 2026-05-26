'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, AlertTriangle, RefreshCw, X, ChevronDown, ChevronUp } from 'lucide-react'
import { fpRulesApi, type FPRule, type FPRuleCreate } from '@/lib/api'

type SortKey = 'hit_count' | 'created_at' | 'expires_at'

function daysRemaining(expiresAt: string | null): number | null {
  if (!expiresAt) return null
  return Math.floor((new Date(expiresAt).getTime() - Date.now()) / 86_400_000)
}

function ExpiryBadge({ expiresAt }: { expiresAt: string | null }) {
  if (!expiresAt) return <span className="text-zinc-500 text-xs">Süresiz</span>
  const days = daysRemaining(expiresAt)
  if (days === null) return null
  if (days < 0)  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-950/60 text-red-400">Süresi Doldu</span>
  if (days < 3)  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-950/40 text-red-400">{days} gün</span>
  if (days < 7)  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-950/40 text-yellow-400">{days} gün</span>
  return <span className="px-2 py-0.5 rounded text-xs font-medium bg-zinc-800 text-zinc-300">{days} gün</span>
}

function FieldCombination({ rule }: { rule: FPRule }) {
  const parts: string[] = []
  if (rule.event_action)     parts.push(`action=${rule.event_action}`)
  if (rule.source_ip)        parts.push(`src=${rule.source_ip}`)
  if (rule.destination_ip)   parts.push(`dst=${rule.destination_ip}`)
  if (rule.destination_port) parts.push(`port=${rule.destination_port}`)
  if (rule.observer_hostname) parts.push(`host=${rule.observer_hostname}`)
  if (parts.length === 0) return <span className="text-zinc-500 italic text-xs">Genel kural</span>
  return (
    <div className="flex flex-wrap gap-1">
      {parts.map(p => (
        <span key={p} className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-xs font-mono">{p}</span>
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
      className={`flex items-center gap-1 text-xs font-medium uppercase hover:text-zinc-200 transition-colors ${active ? 'text-zinc-200' : 'text-zinc-500'}`}
      onClick={() => onSort(col)}
    >
      {label}
      {active
        ? dir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
        : <ChevronDown className="w-3 h-3 opacity-30" />}
    </button>
  )
}

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

  const inp = "w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-indigo-500"

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-zinc-900 border border-zinc-700 rounded-lg w-full max-w-md p-6 shadow-xl">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-base font-semibold text-zinc-100">Yeni FP Kuralı</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-200"><X size={16} /></button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Event Action</label>
            <input className={inp} placeholder="ssh_failure, port_scan, ..." value={form.event_action ?? ''}
              onChange={e => setForm(f => ({ ...f, event_action: e.target.value || undefined }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Kaynak IP / CIDR</label>
              <input className={inp} placeholder="10.0.0.5 veya 10.0.0.0/24" value={form.source_ip ?? ''}
                onChange={e => setForm(f => ({ ...f, source_ip: e.target.value || undefined }))} />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Hedef IP / CIDR</label>
              <input className={inp} placeholder="192.168.1.0/24" value={form.destination_ip ?? ''}
                onChange={e => setForm(f => ({ ...f, destination_ip: e.target.value || undefined }))} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Hedef Port</label>
              <input className={inp} placeholder="443" value={form.destination_port ?? ''}
                onChange={e => setForm(f => ({ ...f, destination_port: e.target.value || undefined }))} />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Observer Hostname</label>
              <input className={inp} placeholder="firewall-01" value={form.observer_hostname ?? ''}
                onChange={e => setForm(f => ({ ...f, observer_hostname: e.target.value || undefined }))} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Geçerlilik (gün)</label>
              <input className={inp} type="number" min={1} max={365} placeholder="30"
                value={form.expires_in_days ?? ''}
                onChange={e => setForm(f => ({ ...f, expires_in_days: e.target.value ? Number(e.target.value) : undefined }))} />
            </div>
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Neden <span className="text-red-400">*</span></label>
            <input className={inp} placeholder="Dahili tarama aracı, planlı bakım, vb." value={form.reason}
              onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="px-4 py-1.5 rounded text-sm text-zinc-300 hover:text-zinc-100 bg-zinc-800 hover:bg-zinc-700">
              İptal
            </button>
            <button type="submit"
              className="px-4 py-1.5 rounded text-sm bg-indigo-600 hover:bg-indigo-500 text-white font-medium">
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

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield size={20} className="text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">False Positive Yönetimi</h1>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="p-1.5 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800">
            <RefreshCw size={14} />
          </button>
          <button onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium">
            <Plus size={14} /> Yeni Kural
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-xs text-zinc-500 mb-1">Aktif Kural</div>
          <div className="text-2xl font-bold text-zinc-100">{activeRules.length}</div>
          <div className="text-xs text-zinc-600 mt-0.5">{expiredRules.length} süresi dolmuş</div>
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-xs text-zinc-500 mb-1">Toplam Bastırılan</div>
          <div className="text-2xl font-bold text-emerald-400">{totalHits.toLocaleString()}</div>
          <div className="text-xs text-zinc-600 mt-0.5">lifetime hit count</div>
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-xs text-zinc-500 mb-1">En Çok Hit</div>
          <div className="text-2xl font-bold text-zinc-100">
            {topHitter ? topHitter.hit_count.toLocaleString() : '—'}
          </div>
          {topHitter && (
            <div className="text-xs text-zinc-600 mt-0.5 font-mono truncate">
              {topHitter.event_action ?? topHitter.source_ip ?? 'genel'}
            </div>
          )}
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-xs text-zinc-500 mb-1">Süresi Dolmak Üzere</div>
          <div className={`text-2xl font-bold ${activeRules.filter(r => { const d = daysRemaining(r.expires_at); return d !== null && d >= 0 && d < 7 }).length > 0 ? 'text-yellow-400' : 'text-zinc-100'}`}>
            {activeRules.filter(r => { const d = daysRemaining(r.expires_at); return d !== null && d >= 0 && d < 7 }).length}
          </div>
          <div className="text-xs text-zinc-600 mt-0.5">7 gün içinde</div>
        </div>
      </div>

      {/* Expiring soon alert */}
      {expiredRules.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-yellow-700/40 bg-yellow-900/20 text-yellow-300 text-sm">
          <AlertTriangle size={14} className="flex-shrink-0" />
          <span><strong>{expiredRules.length}</strong> kural süresi dolmuş — uyarılar yeniden üretiliyor olabilir</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
          className="bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">Tüm Event Action'lar</option>
          {uniqueActions.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <div className="flex rounded overflow-hidden border border-zinc-700">
          {(['all', 'active', 'expired'] as const).map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 text-sm ${statusFilter === s ? 'bg-indigo-600 text-white' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'}`}>
              {s === 'all' ? `Tümü (${rules.length})` : s === 'active' ? `Aktif (${activeRules.length})` : `Dolmuş (${expiredRules.length})`}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-zinc-500 text-sm">Yükleniyor...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-zinc-500">
            <Shield size={32} className="mx-auto mb-2 opacity-20" />
            <p className="text-sm">Kural bulunamadı</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                <th className="text-left px-4 py-3 text-xs text-zinc-500 font-medium uppercase">Alan Kombinasyonu</th>
                <th className="text-left px-4 py-3 text-xs text-zinc-500 font-medium uppercase">Neden</th>
                <th className="text-right px-4 py-3">
                  <SortHeader label="Hit" col="hit_count" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="text-left px-4 py-3">
                  <SortHeader label="Kalan Süre" col="expires_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="text-left px-4 py-3 text-xs text-zinc-500 font-medium uppercase">Oluşturan</th>
                <th className="text-left px-4 py-3">
                  <SortHeader label="Oluşturulma" col="created_at" sort={sort} dir={dir} onSort={handleSort} />
                </th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(rule => (
                <tr key={rule.fp_rule_id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                  <td className="px-4 py-3">
                    <FieldCombination rule={rule} />
                  </td>
                  <td className="px-4 py-3 text-zinc-400 max-w-xs truncate text-xs" title={rule.reason}>
                    {rule.reason}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-zinc-300 text-xs">
                    {rule.hit_count > 0
                      ? <span className="text-emerald-400 font-semibold">{rule.hit_count.toLocaleString()}</span>
                      : <span className="text-zinc-600">0</span>}
                  </td>
                  <td className="px-4 py-3">
                    <ExpiryBadge expiresAt={rule.expires_at} />
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">{rule.created_by}</td>
                  <td className="px-4 py-3 text-zinc-600 text-xs whitespace-nowrap">
                    {new Date(rule.created_at).toLocaleDateString('tr-TR')}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {rule.is_active && (
                      <button
                        onClick={() => setConfirmDelete(rule.fp_rule_id)}
                        className="p-1 rounded text-zinc-600 hover:text-red-400 hover:bg-red-950/30"
                        title="Devre dışı bırak"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* New Rule Modal */}
      {showModal && (
        <NewRuleModal
          onClose={() => setShowModal(false)}
          onCreate={data => createMut.mutate(data)}
        />
      )}

      {/* Delete Confirm */}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-6 w-80 shadow-xl">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={16} className="text-yellow-400" />
              <h3 className="text-sm font-semibold text-zinc-100">Kuralı Devre Dışı Bırak</h3>
            </div>
            <p className="text-sm text-zinc-400 mb-4">
              Bu FP kuralı devre dışı bırakılacak. Eşleşen olaylar tekrar uyarı üretecek.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirmDelete(null)}
                className="px-4 py-1.5 rounded text-sm text-zinc-300 bg-zinc-800 hover:bg-zinc-700">
                İptal
              </button>
              <button onClick={() => deleteMut.mutate(confirmDelete)}
                disabled={deleteMut.isPending}
                className="px-4 py-1.5 rounded text-sm bg-red-700 hover:bg-red-600 text-white">
                {deleteMut.isPending ? 'Siliniyor...' : 'Devre Dışı Bırak'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
