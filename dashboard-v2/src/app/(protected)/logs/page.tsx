'use client'

import { useState, useEffect, useMemo } from 'react'
import {
  FileText, RefreshCw, Search, X, ChevronDown, ChevronRight,
  Radio, Wifi, WifiOff,
} from 'lucide-react'
import { SkeletonTable, SkeletonChart } from '@/components/ui/skeleton'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { logsApi, analyticsApi, type LogFacetItem } from '@/lib/api'
import { TOOLTIP_BASE, SEVERITY_COLORS } from '@/lib/echarts-theme'
import { SeverityBadge } from '@/components/ui/severity-badge'
import type { NormalizedLog, Severity } from '@/types/models'
import { cn } from '@/lib/utils'

// ─── Sabitler ─────────────────────────────────────────────────────────────────

const SOURCE_LABELS: Record<string, string> = {
  syslog: 'Syslog', opnsense: 'OPNsense', vyos: 'VyOS', pfsense: 'pfSense',
  cisco_asa: 'Cisco ASA', fortigate: 'FortiGate', nginx: 'Nginx',
  apache: 'Apache', netflow: 'NetFlow', auth_log: 'Auth Log',
  netguard: 'NetGuard', suricata: 'Suricata', zeek: 'Zeek', wazuh: 'Wazuh',
}

const CATEGORY_LABELS: Record<string, string> = {
  authentication: 'Kimlik Doğrulama',
  network: 'Ağ',
  intrusion: 'Saldırı',
  system: 'Sistem',
  unknown: 'Bilinmiyor',
}

const SEV_CHART_COLORS: Record<string, string> = {
  critical: SEVERITY_COLORS.critical,
  high:     SEVERITY_COLORS.high,
  warning:  SEVERITY_COLORS.warning,
  info:     SEVERITY_COLORS.info,
}

// ─── Yardımcı ─────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

// ─── Log Volume Histogram ─────────────────────────────────────────────────────

function LogVolumeChart({
  series, hours,
}: {
  series: Record<string, { t: string; v: number }[]>
  hours: number
}) {
  const labels = (series.info ?? []).map((p) => {
    const d = new Date(p.t)
    if (hours <= 24) return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
    return d.toLocaleDateString('tr-TR', { day: '2-digit', month: '2-digit', hour: '2-digit' })
  })

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 8, bottom: 28, left: 36, containLabel: false },
    tooltip: { ...TOOLTIP_BASE, trigger: 'axis' },
    xAxis: {
      type: 'category', data: labels,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false }, axisTick: { show: false }, splitLine: { show: false },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: (['critical', 'high', 'warning', 'info'] as const).map((sev) => ({
      name: sev, type: 'bar', stack: 'total',
      data: (series[sev] ?? []).map((p) => p.v),
      itemStyle: { color: SEV_CHART_COLORS[sev] },
      barMaxWidth: 24,
    })),
  }

  return <ReactECharts option={option} style={{ height: 120 }} notMerge />
}

// ─── Source pill ──────────────────────────────────────────────────────────────

function SourcePill({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono border border-sky-900/25 bg-sky-950/20 text-slate-500">
      {SOURCE_LABELS[type] ?? type}
    </span>
  )
}

// ─── Facet Sidebar ────────────────────────────────────────────────────────────

function FacetList({
  title, items, active, onToggle,
}: {
  title:    string
  items:    LogFacetItem[]
  active:   string
  onToggle: (key: string) => void
}) {
  if (items.length === 0) return null
  return (
    <div className="mb-4">
      <p className="text-[9px] text-slate-700 uppercase tracking-[0.18em] mb-1.5 select-none">{title}</p>
      <div className="space-y-0.5">
        {items.map((item) => (
          <button
            key={item.key}
            onClick={() => onToggle(item.key)}
            className={cn(
              'w-full flex items-center justify-between px-2 py-1 rounded text-xs transition-colors border',
              active === item.key
                ? 'bg-sky-500/10 text-sky-300 border-sky-500/25'
                : 'text-slate-500 hover:bg-sky-950/20 hover:text-slate-300 border-transparent',
            )}
          >
            <span className="truncate">
              {SOURCE_LABELS[item.key] ?? CATEGORY_LABELS[item.key] ?? item.key}
            </span>
            <span className="font-mono text-[10px] ml-1 flex-shrink-0 text-slate-700">{item.count}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

// ─── Expandable Row ───────────────────────────────────────────────────────────

function LogRow({ log }: { log: NormalizedLog }) {
  const [open, setOpen] = useState(false)
  const ext = log as unknown as Record<string, string>

  return (
    <>
      <tr
        className={cn(
          'cursor-pointer transition-colors border-b border-sky-900/10',
          open ? 'bg-sky-950/25' : 'hover:bg-sky-950/20',
        )}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="ui-td w-4">
          {open
            ? <ChevronDown size={12} className="text-slate-600" />
            : <ChevronRight size={12} className="text-slate-700" />}
        </td>
        <td className="ui-td">
          <SeverityBadge severity={log.severity as Severity} />
        </td>
        <td className="ui-td">
          <SourcePill type={log.source_type} />
        </td>
        <td className="ui-td text-xs text-slate-500">
          {CATEGORY_LABELS[log.event_category] ?? log.event_category}
        </td>
        <td className="ui-td text-xs text-slate-200 max-w-xs truncate">{log.message}</td>
        <td className="ui-td text-xs text-slate-500 font-mono">
          {log.source_hostname
            ? <><span className="text-slate-300">{log.source_hostname}</span><span className="text-slate-700 ml-1">({log.source_ip})</span></>
            : log.source_ip ?? <span className="text-slate-700">—</span>}
        </td>
        <td className="ui-td text-xs text-slate-700 whitespace-nowrap">{formatDate(log.timestamp)}</td>
      </tr>
      {open && (
        <tr className="border-b border-sky-900/10 bg-sky-950/10">
          <td colSpan={7} className="px-8 py-3">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-6 gap-y-1.5 text-[11px]">
              {[
                ['Log ID',         log.log_id],
                ['Event Action',   ext.event_action ?? '—'],
                ['Kaynak IP',      log.source_ip ?? '—'],
                ['Hedef IP',       ext.destination_ip ?? '—'],
                ['Kaynak Port',    ext.source_port ?? '—'],
                ['Hedef Port',     ext.destination_port ?? '—'],
                ['Protokol',       ext.network_protocol ?? '—'],
                ['Hostname',       log.source_hostname ?? '—'],
                ['Observer',       ext.observer_hostname ?? '—'],
                ['Zaman',          formatDate(log.timestamp)],
              ].map(([k, v]) => (
                <div key={k as string}>
                  <span className="text-slate-700">{k}: </span>
                  <span className="text-slate-300 font-mono break-all">{v ?? '—'}</span>
                </div>
              ))}
            </div>
            {log.message && (
              <div className="mt-2 px-3 py-2 bg-sky-950/20 border border-sky-900/15 rounded text-[11px] font-mono text-slate-400 break-all">
                {log.message}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Ana Sayfa ────────────────────────────────────────────────────────────────

const SEV_FILTER_OPTIONS = [
  { value: 'all',      label: 'Tümü' },
  { value: 'critical', label: 'Kritik' },
  { value: 'high',     label: 'Yüksek' },
  { value: 'warning',  label: 'Uyarı' },
  { value: 'info',     label: 'Bilgi' },
]

const INPUT_CLS = "ui-input"

export default function LogsPage() {
  const queryClient = useQueryClient()
  const [sourceFilter, setSourceFilter]     = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [searchInput, setSearchInput]       = useState('')
  const [liveMode, setLiveMode]             = useState(false)
  const [hours, setHours]                   = useState(24)
  const [filterSrcIp, setFilterSrcIp]       = useState('')
  const [filterDstIp, setFilterDstIp]       = useState('')
  const [filterProtocol, setFilterProtocol] = useState('')
  const [filterAction, setFilterAction]     = useState('')

  const debouncedSearch   = useDebounce(searchInput, 300)
  const debouncedSrcIp    = useDebounce(filterSrcIp, 400)
  const debouncedDstIp    = useDebounce(filterDstIp, 400)
  const debouncedProtocol = useDebounce(filterProtocol, 400)
  const debouncedAction   = useDebounce(filterAction, 400)
  const isSearching       = debouncedSearch.trim().length > 0

  const facetSourceFilter   = sourceFilter   !== 'all' ? sourceFilter   : undefined
  const facetCategoryFilter = categoryFilter !== 'all' ? categoryFilter : undefined

  const listQuery = useQuery({
    queryKey: ['logs-list', sourceFilter, categoryFilter, severityFilter, debouncedSrcIp, debouncedDstIp, debouncedProtocol, debouncedAction],
    queryFn: () =>
      logsApi.listNormalized({
        source_type:      sourceFilter   !== 'all' ? sourceFilter   : undefined,
        event_category:   categoryFilter !== 'all' ? categoryFilter : undefined,
        source_ip:        debouncedSrcIp     || undefined,
        destination_ip:   debouncedDstIp     || undefined,
        network_protocol: debouncedProtocol  || undefined,
        event_action:     debouncedAction    || undefined,
        limit: 200,
      }),
    refetchInterval: liveMode ? 5_000 : 20_000,
    enabled: !isSearching,
  })

  const searchQuery = useQuery({
    queryKey: ['logs-search', debouncedSearch, sourceFilter, categoryFilter, severityFilter],
    queryFn: () =>
      logsApi.searchLogs({
        q:              debouncedSearch,
        source_type:    sourceFilter   !== 'all' ? sourceFilter   : undefined,
        event_category: categoryFilter !== 'all' ? categoryFilter : undefined,
        severity:       severityFilter !== 'all' ? severityFilter : undefined,
        limit: 200,
      }),
    enabled: isSearching,
  })

  const { data: volumeData } = useQuery({
    queryKey: ['log-volume', hours, facetSourceFilter, facetCategoryFilter],
    queryFn:  () => analyticsApi.logVolume(hours, facetSourceFilter, facetCategoryFilter),
    refetchInterval: liveMode ? 10_000 : 60_000,
    staleTime: 30_000,
  })

  const { data: facetsData } = useQuery({
    queryKey: ['log-facets', hours],
    queryFn:  () => analyticsApi.logFacets(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const active   = isSearching ? searchQuery : listQuery
  const allLogs  = active.data?.logs ?? []
  const count    = active.data?.count ?? 0
  const loading  = active.isLoading
  const fetching = active.isFetching

  const logs = useMemo(() => {
    if (severityFilter === 'all' || isSearching) return allLogs
    return allLogs.filter((l) => l.severity === severityFilter)
  }, [allLogs, severityFilter, isSearching])

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['logs-list'] })
    queryClient.invalidateQueries({ queryKey: ['log-volume'] })
    queryClient.invalidateQueries({ queryKey: ['log-facets'] })
  }

  const hasFieldFilters = filterSrcIp || filterDstIp || filterProtocol || filterAction
  const hasActiveFilters = sourceFilter !== 'all' || categoryFilter !== 'all' || severityFilter !== 'all'

  return (
    <div className="p-6 flex gap-4 min-h-0">
      {/* ── Sidebar: Facets ───────────────────────────────────────────── */}
      <aside className="w-44 flex-shrink-0">
        <div className="ui-panel p-3">
          {facetsData ? (
            <>
              <p className="text-[9px] text-slate-700 uppercase tracking-[0.18em] mb-2 select-none">
                {facetsData.total.toLocaleString('tr-TR')} log · {hours}s
              </p>
              <FacetList
                title="Kaynak"
                items={facetsData.sources}
                active={sourceFilter}
                onToggle={(k) => setSourceFilter(s => s === k ? 'all' : k)}
              />
              <FacetList
                title="Kategori"
                items={facetsData.categories}
                active={categoryFilter}
                onToggle={(k) => setCategoryFilter(c => c === k ? 'all' : k)}
              />
              <FacetList
                title="Seviye"
                items={facetsData.severities}
                active={severityFilter}
                onToggle={(k) => setSeverityFilter(s => s === k ? 'all' : k)}
              />
            </>
          ) : (
            <SkeletonTable rows={5} height={20} />
          )}
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────── */}
      <div className="flex-1 min-w-0 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
              <FileText size={15} className="text-sky-400" />
            </div>
            <div>
              <h1 className="text-base font-semibold text-slate-100 leading-tight flex items-center gap-2">
                Normalize Edilmiş Loglar
                {liveMode && <Radio size={12} className="text-emerald-400 animate-pulse" />}
              </h1>
              <p className="text-xs text-slate-600">
                {isSearching
                  ? `"${debouncedSearch}" için ${count} sonuç`
                  : `${logs.length} kayıt${logs.length < count ? ` (${count} toplam)` : ''}`}
              </p>
            </div>
            {fetching && <RefreshCw size={13} className="text-slate-500 animate-spin" />}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Zaman aralığı */}
            <div className="flex rounded-lg overflow-hidden border border-sky-900/20">
              {([6, 24, 48] as const).map((h) => (
                <button key={h} onClick={() => setHours(h)}
                  className={cn('px-3 py-1.5 text-xs transition-colors',
                    hours === h
                      ? 'bg-sky-500/15 text-sky-400 border-x border-sky-500/30'
                      : 'bg-[#0a1120] text-slate-500 hover:text-slate-300')}>
                  {h}s
                </button>
              ))}
            </div>
            {/* Live toggle */}
            <button
              onClick={() => setLiveMode(m => !m)}
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs border transition-colors',
                liveMode
                  ? 'bg-emerald-900/20 border-emerald-700/40 text-emerald-400'
                  : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300',
              )}
            >
              {liveMode ? <Wifi size={12} /> : <WifiOff size={12} />}
              {liveMode ? 'Canlı' : 'Durduruldu'}
            </button>
            <button
              onClick={handleRefresh}
              disabled={fetching}
              className="ui-btn ui-btn-secondary"
            >
              <RefreshCw size={13} className={fetching ? 'animate-spin' : ''} />
              Yenile
            </button>
          </div>
        </div>

        {/* Field-level Filter Bar */}
        <div className="ui-panel px-4 py-2.5 flex flex-wrap gap-2 items-center">
          <span className="text-[10px] text-slate-700 uppercase tracking-[0.15em] flex-shrink-0 select-none">Filtrele</span>
          {[
            { placeholder: 'Kaynak IP',    value: filterSrcIp,    set: setFilterSrcIp    },
            { placeholder: 'Hedef IP',     value: filterDstIp,    set: setFilterDstIp    },
            { placeholder: 'Protokol',     value: filterProtocol, set: setFilterProtocol },
            { placeholder: 'Event Action', value: filterAction,   set: setFilterAction   },
          ].map(({ placeholder, value, set }) => (
            <div key={placeholder} className="relative">
              <input
                placeholder={placeholder}
                value={value}
                onChange={e => set(e.target.value)}
                className={cn(INPUT_CLS, 'w-28 pr-5')}
              />
              {value && (
                <button onClick={() => set('')}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400">
                  <X size={10} />
                </button>
              )}
            </div>
          ))}
          {hasFieldFilters && (
            <button
              onClick={() => { setFilterSrcIp(''); setFilterDstIp(''); setFilterProtocol(''); setFilterAction('') }}
              className="text-[11px] text-sky-500 hover:text-sky-400 transition-colors"
            >
              Temizle
            </button>
          )}
        </div>

        {/* Log Volume Histogram */}
        <div className="ui-panel">
          <div className="ui-panel-header justify-between">
            <span className="ui-section-label">Log Hacmi</span>
            <span className="text-[11px] text-slate-700">Severity bazında · {hours}s</span>
          </div>
          {volumeData ? (
            <div className="px-2 pt-1 pb-2">
              <LogVolumeChart series={volumeData.series} hours={hours} />
            </div>
          ) : (
            <SkeletonChart height={112} className="m-3" />
          )}
        </div>

        {/* Table panel */}
        <div className="ui-panel">
          {/* Table header controls */}
          <div className="ui-panel-header flex-wrap gap-2">
            <span className="text-xs text-slate-500 font-medium flex-shrink-0">Loglar</span>

            {/* Search */}
            <div className="relative flex-1 min-w-[160px] max-w-xs">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
              <input
                placeholder="Mesaj, IP, kullanıcı..."
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                className={cn(INPUT_CLS, 'pl-7 pr-7 w-full')}
              />
              {searchInput && (
                <button onClick={() => setSearchInput('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400">
                  <X size={11} />
                </button>
              )}
            </div>

            {/* Severity quick-filters */}
            <div className="flex gap-1">
              {SEV_FILTER_OPTIONS.map((opt) => (
                <button key={opt.value}
                  onClick={() => setSeverityFilter(severityFilter === opt.value ? 'all' : opt.value)}
                  className={cn(
                    'px-2 py-1 text-[11px] rounded border transition-colors',
                    severityFilter === opt.value
                      ? 'border-sky-500/30 bg-sky-500/10 text-sky-300'
                      : 'border-sky-900/20 bg-sky-950/20 text-slate-600 hover:text-slate-300',
                  )}>
                  {opt.label}
                </button>
              ))}
            </div>

            {/* Source dropdown */}
            <select
              value={sourceFilter}
              onChange={e => setSourceFilter(e.target.value)}
              className={cn(INPUT_CLS, 'w-32')}
            >
              <option value="all">Tüm kaynaklar</option>
              {Object.entries(SOURCE_LABELS).map(([val, label]) => (
                <option key={val} value={val}>{label}</option>
              ))}
            </select>

            {hasActiveFilters && (
              <button
                onClick={() => { setSourceFilter('all'); setCategoryFilter('all'); setSeverityFilter('all') }}
                className="text-[11px] text-slate-600 hover:text-slate-400 flex items-center gap-1 transition-colors"
              >
                <X size={11} /> Temizle
              </button>
            )}
          </div>

          {/* Table body */}
          {loading ? (
            <div className="p-4">
              <SkeletonTable rows={8} height={40} />
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
              <FileText size={28} className="opacity-20" />
              <p className="text-sm">
                {isSearching ? `"${debouncedSearch}" için log bulunamadı` : 'Log bulunamadı'}
              </p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr >
                  <th className="ui-th w-4" />
                  <th className="ui-th w-24">Seviye</th>
                  <th className="ui-th w-24">Kaynak</th>
                  <th className="ui-th w-32">Kategori</th>
                  <th className="ui-th">Mesaj</th>
                  <th className="ui-th w-36">Kaynak IP</th>
                  <th className="ui-th w-36">Zaman</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <LogRow key={log.log_id} log={log} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
