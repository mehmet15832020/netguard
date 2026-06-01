'use client'

import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Search, Star, StarOff, Trash2, Play, Save, Plus,
  ChevronRight, RefreshCw, Download, X, Target,
} from 'lucide-react'
import { huntsApi, type HuntFilters, type SavedHunt, type HuntResult, type NormalizedLog } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { Severity } from '@/types/models'

// ── sabitler ──────────────────────────────────────────────────────────────────

const DEFAULT_FILTERS: HuntFilters = {
  source_ip: null, destination_ip: null, event_action: null,
  event_category: null, severity: null, source_type: null,
  network_protocol: null, keyword: null, hours: 24, limit: 200,
}

const HOURS_OPTS  = [1, 6, 24, 48, 168, 720] as const
const LIMIT_OPTS  = [100, 200, 500, 1000] as const
const SEV_OPTS    = ['', 'info', 'warning', 'critical'] as const
const CAT_OPTS    = ['', 'authentication', 'network', 'intrusion', 'system', 'endpoint', 'file'] as const
const SRC_OPTS    = ['', 'suricata', 'zeek', 'syslog', 'auth_log', 'netflow', 'windows', 'pfsense', 'opnsense', 'cisco_asa', 'fortigate'] as const

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400',
  warning: 'text-yellow-400', info: 'text-sky-400',
}

function fmt(iso?: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  })
}

// ── FiltersPanel ──────────────────────────────────────────────────────────────

function FiltersPanel({
  filters, onChange,
}: { filters: HuntFilters; onChange: (f: HuntFilters) => void }) {
  const set = (key: keyof HuntFilters, value: unknown) =>
    onChange({ ...filters, [key]: value || null })

  const inputCls = 'w-full bg-[#040911] border border-sky-900/30 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-sky-600/50'
  const selectCls = inputCls + ' appearance-none'

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-2.5">
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Kaynak IP</label>
        <input className={inputCls} placeholder="192.168.1.50"
          value={filters.source_ip ?? ''} onChange={e => set('source_ip', e.target.value)} />
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Hedef IP</label>
        <input className={inputCls} placeholder="10.0.0.5"
          value={filters.destination_ip ?? ''} onChange={e => set('destination_ip', e.target.value)} />
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Event Action</label>
        <input className={inputCls} placeholder="ssh_failure"
          value={filters.event_action ?? ''} onChange={e => set('event_action', e.target.value)} />
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Keyword (mesaj)</label>
        <input className={inputCls} placeholder="failed password"
          value={filters.keyword ?? ''} onChange={e => set('keyword', e.target.value)} />
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Kategori</label>
        <select className={selectCls} value={filters.event_category ?? ''}
          onChange={e => set('event_category', e.target.value)}>
          {CAT_OPTS.map(o => <option key={o} value={o}>{o || 'Tümü'}</option>)}
        </select>
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Severity</label>
        <select className={selectCls} value={filters.severity ?? ''}
          onChange={e => set('severity', e.target.value)}>
          {SEV_OPTS.map(o => <option key={o} value={o}>{o || 'Tümü'}</option>)}
        </select>
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Kaynak Tipi</label>
        <select className={selectCls} value={filters.source_type ?? ''}
          onChange={e => set('source_type', e.target.value)}>
          {SRC_OPTS.map(o => <option key={o} value={o}>{o || 'Tümü'}</option>)}
        </select>
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Protokol</label>
        <input className={inputCls} placeholder="TCP"
          value={filters.network_protocol ?? ''} onChange={e => set('network_protocol', e.target.value)} />
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Zaman Aralığı</label>
        <select className={selectCls} value={filters.hours}
          onChange={e => onChange({ ...filters, hours: Number(e.target.value) })}>
          {HOURS_OPTS.map(h => (
            <option key={h} value={h}>
              {h < 24 ? `Son ${h} saat` : h === 168 ? 'Son 7 gün' : h === 720 ? 'Son 30 gün' : `Son ${h / 24} gün`}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label className="text-[10px] text-slate-600 mb-1 block">Limit</label>
        <select className={selectCls} value={filters.limit}
          onChange={e => onChange({ ...filters, limit: Number(e.target.value) })}>
          {LIMIT_OPTS.map(l => <option key={l} value={l}>{l} kayıt</option>)}
        </select>
      </div>
    </div>
  )
}

// ── LogRow (virtual) ──────────────────────────────────────────────────────────

function LogRow({ log }: { log: NormalizedLog }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      onClick={() => setOpen(o => !o)}
      className="border-b border-sky-900/10 hover:bg-sky-950/20 cursor-pointer transition-colors"
    >
      <div className="grid grid-cols-[80px_100px_120px_1fr_120px] gap-2 items-center px-3 py-2 text-xs">
        <SeverityBadge severity={log.severity ?? 'info'} />
        <span className="font-mono text-slate-400 truncate">{log.source_ip ?? '—'}</span>
        <span className="text-slate-500 truncate">{log.event_action ?? '—'}</span>
        <span className="text-slate-300 truncate">{log.message}</span>
        <span className="text-slate-600 text-right">{fmt(log.timestamp)}</span>
      </div>
      {open && (
        <div className="px-4 py-2 bg-sky-950/10 grid grid-cols-2 gap-x-6 gap-y-1 text-[11px] text-slate-500">
          {(
            [
              ['Log ID',      log.log_id],
              ['Source',      String(log.source_type)],
              ['Src IP:Port', `${log.source_ip ?? ''}${log.source_port ? ':' + log.source_port : ''}`],
              ['Dst IP:Port', `${log.destination_ip ?? ''}${log.destination_port ? ':' + log.destination_port : ''}`],
              ['Protocol',    log.network_protocol ?? ''],
              ['Category',    String(log.event_category)],
              ['Username',    log.username ?? ''],
              ['Observer',    log.observer_hostname ?? ''],
            ] satisfies [string, string][]
          ).filter(([, v]) => v !== '').map(([k, v]) => (
            <div key={k} className="flex gap-2">
              <span className="text-slate-700 w-24 flex-shrink-0">{k}</span>
              <span className="text-slate-300 break-all">{v}</span>
            </div>
          ))}
          {log.message ? (
            <div className="col-span-2 flex gap-2 mt-1">
              <span className="text-slate-700 w-24 flex-shrink-0">Mesaj</span>
              <span className="text-slate-300 font-mono break-all">{log.message}</span>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}

function VirtualResults({ logs }: { logs: NormalizedLog[] }) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: logs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 10,
  })

  return (
    <div ref={parentRef} className="overflow-auto" style={{ height: '420px' }}>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualizer.getVirtualItems().map(item => (
          <div
            key={item.key}
            style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${item.start}px)` }}
            ref={virtualizer.measureElement}
            data-index={item.index}
          >
            <LogRow log={logs[item.index]} />
          </div>
        ))}
      </div>
    </div>
  )
}

// ── StatsPanel ────────────────────────────────────────────────────────────────

function StatsPanel({ stats }: { stats: HuntResult['stats'] }) {
  const sections = [
    { label: 'Kaynak IP',     data: stats.source_ip,      color: 'bg-sky-500' },
    { label: 'Event Action',  data: stats.event_action,   color: 'bg-violet-500' },
    { label: 'Kategori',      data: stats.event_category, color: 'bg-emerald-500' },
    { label: 'Severity',      data: stats.severity,       color: 'bg-orange-500' },
  ]
  const maxPerSection = sections.map(s => Math.max(1, ...s.data.map(d => d.count)))

  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
      {sections.map((sec, si) => (
        <div key={sec.label} className="ui-panel p-3">
          <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-2">{sec.label}</p>
          <div className="space-y-1.5">
            {sec.data.slice(0, 8).map(d => (
              <div key={d.value} className="flex items-center gap-2">
                <span className="text-[10px] text-slate-400 w-24 truncate flex-shrink-0">{d.value}</span>
                <div className="flex-1 h-1 bg-sky-950/30 rounded-full overflow-hidden">
                  <div className={cn('h-full rounded-full', sec.color)} style={{ width: `${d.count / maxPerSection[si] * 100}%` }} />
                </div>
                <span className="text-[10px] font-mono text-slate-600 w-8 text-right">{d.count}</span>
              </div>
            ))}
            {sec.data.length === 0 && <p className="text-[10px] text-slate-700">Veri yok</p>}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── SaveHuntModal ─────────────────────────────────────────────────────────────

function SaveHuntModal({
  filters, onSave, onClose,
}: { filters: HuntFilters; onSave: (name: string, desc: string) => void; onClose: () => void }) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const inputCls = 'w-full bg-[#040911] border border-sky-900/30 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-sky-600/50'
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1526] border border-sky-500/20 rounded-xl p-5 w-full max-w-md space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold text-slate-200">Hunt Kaydet</p>
          <button onClick={onClose} className="text-slate-600 hover:text-slate-400"><X size={14} /></button>
        </div>
        <div className="space-y-2">
          <input className={inputCls} placeholder="Hunt adı *" value={name} onChange={e => setName(e.target.value)} />
          <input className={inputCls} placeholder="Açıklama (opsiyonel)" value={desc} onChange={e => setDesc(e.target.value)} />
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="ui-btn ui-btn-secondary">İptal</button>
          <button
            onClick={() => { if (name.trim()) { onSave(name.trim(), desc.trim()); onClose() } }}
            disabled={!name.trim()}
            className="ui-btn ui-btn-primary"
          >
            <Save size={11} /> Kaydet
          </button>
        </div>
      </div>
    </div>
  )
}

// ── SavedHuntRow ──────────────────────────────────────────────────────────────

function SavedHuntRow({
  hunt, onLoad, onDelete, onFavorite, isActive,
}: {
  hunt: SavedHunt
  onLoad: () => void
  onDelete: () => void
  onFavorite: () => void
  isActive: boolean
}) {
  return (
    <div
      onClick={onLoad}
      className={cn(
        'group px-3 py-2.5 rounded-lg border cursor-pointer transition-all',
        isActive
          ? 'bg-sky-500/10 border-sky-500/25'
          : 'bg-sky-950/10 border-sky-900/15 hover:border-sky-800/30',
      )}
    >
      <div className="flex items-start gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-slate-200 truncate">{hunt.name}</p>
          {hunt.description && (
            <p className="text-[10px] text-slate-600 truncate mt-0.5">{hunt.description}</p>
          )}
          <div className="flex gap-2 mt-1 text-[10px] text-slate-600">
            <span>{hunt.run_count} çalıştırma</span>
            {hunt.last_run_at && <span>· {fmt(hunt.last_run_at)}</span>}
            {hunt.last_run_count !== null && <span>· {hunt.last_run_count} kayıt</span>}
          </div>
        </div>
        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
          <button
            onClick={e => { e.stopPropagation(); onFavorite() }}
            className="p-0.5 text-slate-600 hover:text-yellow-400 transition-colors"
          >
            {hunt.is_favorite ? <Star size={11} className="text-yellow-400" /> : <StarOff size={11} />}
          </button>
          <button
            onClick={e => { e.stopPropagation(); onDelete() }}
            className="p-0.5 text-slate-600 hover:text-red-400 transition-colors"
          >
            <Trash2 size={11} />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Ana sayfa ─────────────────────────────────────────────────────────────────

export default function HuntsPage() {
  const qc = useQueryClient()
  const [filters, setFilters] = useState<HuntFilters>(DEFAULT_FILTERS)
  const [result, setResult]   = useState<HuntResult | null>(null)
  const [activeHuntId, setActiveHuntId] = useState<string | null>(null)
  const [showSave, setShowSave] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const { data: huntsData, isLoading: huntsLoading } = useQuery({
    queryKey: ['saved-hunts'],
    queryFn: () => huntsApi.list(),
  })

  const executeMut = useMutation({
    mutationFn: (f: HuntFilters) => huntsApi.executeAdhoc(f),
    onSuccess: data => setResult(data),
  })

  const executeHuntMut = useMutation({
    mutationFn: (id: string) => huntsApi.execute(id),
    onSuccess: data => setResult(data),
  })

  const createMut = useMutation({
    mutationFn: (args: { name: string; description: string }) =>
      huntsApi.create({ name: args.name, description: args.description, filters }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-hunts'] }),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => huntsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['saved-hunts'] })
      if (activeHuntId) setActiveHuntId(null)
    },
  })

  const favMut = useMutation({
    mutationFn: (id: string) => huntsApi.toggleFavorite(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-hunts'] }),
  })

  const runFilters = useCallback(() => {
    setActiveHuntId(null)
    executeMut.mutate(filters)
  }, [filters, executeMut])

  const loadHunt = useCallback((hunt: SavedHunt) => {
    setFilters({ ...DEFAULT_FILTERS, ...hunt.filter_params })
    setActiveHuntId(hunt.hunt_id)
    executeHuntMut.mutate(hunt.hunt_id)
  }, [executeHuntMut])

  const exportCSV = () => {
    if (!result?.logs.length) return
    const header = ['timestamp', 'severity', 'source_ip', 'destination_ip', 'event_action', 'message']
    const rows = result.logs.map(l =>
      header.map(k => JSON.stringify((l as unknown as Record<string, unknown>)[k] ?? '')).join(',')
    )
    const csv = [header.join(','), ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'hunt-results.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const isRunning = executeMut.isPending || executeHuntMut.isPending
  const hunts = huntsData?.hunts ?? []

  return (
    <div className="flex h-[calc(100vh-56px)] overflow-hidden">
      {/* Sol panel — Saved Hunts */}
      <div className={cn(
        'flex-shrink-0 border-r border-sky-900/20 flex flex-col transition-all duration-200',
        sidebarOpen ? 'w-64' : 'w-10',
      )}>
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-sky-900/20">
          {sidebarOpen && (
            <p className="text-xs font-semibold text-slate-400 flex-1 uppercase tracking-wide">
              Saved Hunts
            </p>
          )}
          <button
            onClick={() => setSidebarOpen(o => !o)}
            className="text-slate-600 hover:text-slate-400 transition-colors"
          >
            <ChevronRight size={13} className={cn('transition-transform', sidebarOpen && 'rotate-180')} />
          </button>
        </div>

        {sidebarOpen && (
          <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
            {huntsLoading ? (
              <SkeletonTable rows={4} height={52} />
            ) : hunts.length === 0 ? (
              <p className="text-[11px] text-slate-700 text-center py-6">Hunt kaydı yok</p>
            ) : (
              hunts.map(h => (
                <SavedHuntRow
                  key={h.hunt_id}
                  hunt={h}
                  isActive={activeHuntId === h.hunt_id}
                  onLoad={() => loadHunt(h)}
                  onDelete={() => deleteMut.mutate(h.hunt_id)}
                  onFavorite={() => favMut.mutate(h.hunt_id)}
                />
              ))
            )}
          </div>
        )}
      </div>

      {/* Sağ panel — Builder + Sonuçlar */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4 min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
              <Target size={15} className="text-sky-400" />
            </div>
            <div>
              <h1 className="text-base font-semibold text-slate-100 leading-tight">Threat Hunt</h1>
              <p className="text-xs text-slate-600">
                {result ? `${result.count} kayıt bulundu` : 'Filtre seç ve çalıştır'}
              </p>
            </div>
          </div>
          <div className="flex gap-2 flex-wrap">
            {result && (
              <button onClick={exportCSV} className="ui-btn ui-btn-secondary">
                <Download size={12} /> CSV
              </button>
            )}
            <button
              onClick={() => setShowSave(true)}
              className="ui-btn ui-btn-secondary"
              disabled={!filters.source_ip && !filters.event_action && !filters.keyword && !filters.severity && !filters.source_type}
            >
              <Plus size={12} /> Kaydet
            </button>
            <button
              onClick={runFilters}
              disabled={isRunning}
              className="ui-btn ui-btn-primary"
            >
              {isRunning
                ? <><RefreshCw size={12} className="animate-spin" /> Çalışıyor…</>
                : <><Play size={12} /> Çalıştır</>
              }
            </button>
          </div>
        </div>

        {/* Filtreler */}
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-3">
            <Search size={12} className="text-sky-500" />
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Filtreler</p>
            <button
              onClick={() => { setFilters(DEFAULT_FILTERS); setResult(null); setActiveHuntId(null) }}
              className="ml-auto text-[10px] text-slate-600 hover:text-slate-400 transition-colors"
            >
              Temizle
            </button>
          </div>
          <FiltersPanel filters={filters} onChange={setFilters} />
        </div>

        {/* Hata */}
        {(executeMut.isError || executeHuntMut.isError) && (
          <div className="bg-red-950/20 border border-red-900/30 rounded-lg px-4 py-2.5 text-xs text-red-400">
            Sorgu çalıştırılamadı. Filtreleri kontrol edin.
          </div>
        )}

        {/* Sonuçlar */}
        {result && (
          <>
            {/* Tablo başlığı */}
            <div className="ui-panel overflow-hidden">
              <div className="ui-panel-header justify-between">
                <p className="ui-section-label">
                  Sonuçlar
                  <span className="ml-2 text-sky-400 font-bold">{result.count}</span>
                </p>
              </div>
              {/* Sütun başlıkları */}
              <div className="grid grid-cols-[80px_100px_120px_1fr_120px] gap-2 px-3 py-1.5 border-b border-sky-900/20 text-[10px] text-slate-600 uppercase tracking-wide">
                <span>Seviye</span><span>Kaynak IP</span><span>Event Action</span>
                <span>Mesaj</span><span className="text-right">Zaman</span>
              </div>
              {result.logs.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-700">Eşleşen log yok</div>
              ) : (
                <VirtualResults logs={result.logs} />
              )}
            </div>

            {/* İstatistikler */}
            {result.logs.length > 0 && <StatsPanel stats={result.stats} />}
          </>
        )}
      </div>

      {/* Save Modal */}
      {showSave && (
        <SaveHuntModal
          filters={filters}
          onClose={() => setShowSave(false)}
          onSave={(name, desc) => createMut.mutate({ name, description: desc })}
        />
      )}
    </div>
  )
}
