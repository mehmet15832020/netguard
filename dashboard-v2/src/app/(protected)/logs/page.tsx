'use client'

import { useState, useEffect, useMemo } from 'react'
import {
  FileText, RefreshCw, Search, X, ChevronDown, ChevronRight,
  Radio, Wifi, WifiOff,
} from 'lucide-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { logsApi, analyticsApi, type LogFacetItem } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { NormalizedLog, Severity } from '@/types/models'
import { cn } from '@/lib/utils'

// ─── Sabitler ────────────────────────────────────────────────────────────────

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

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  warning: '#eab308',
  info: '#6366f1',
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

// ─── Log Volume Histogram ────────────────────────────────────────────────────

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
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#18181b',
      borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 11 },
    },
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    series: (['critical', 'high', 'warning', 'info'] as const).map((sev) => ({
      name: sev,
      type: 'bar',
      stack: 'total',
      data: (series[sev] ?? []).map((p) => p.v),
      itemStyle: { color: SEV_COLORS[sev] },
      barMaxWidth: 24,
    })),
  }

  return <ReactECharts option={option} style={{ height: 120 }} notMerge />
}

// ─── Facet Pill ──────────────────────────────────────────────────────────────

function FacetList({
  title, items, active, onToggle,
}: {
  title: string
  items: LogFacetItem[]
  active: string
  onToggle: (key: string) => void
}) {
  if (items.length === 0) return null
  return (
    <div className="mb-4">
      <p className="text-[10px] text-zinc-600 uppercase tracking-widest mb-1.5">{title}</p>
      <div className="space-y-0.5">
        {items.map((item) => (
          <button
            key={item.key}
            onClick={() => onToggle(item.key)}
            className={cn(
              'w-full flex items-center justify-between px-2 py-1 rounded text-xs transition-colors',
              active === item.key
                ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-600/30'
                : 'text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 border border-transparent',
            )}
          >
            <span className="truncate">{SOURCE_LABELS[item.key] ?? CATEGORY_LABELS[item.key] ?? item.key}</span>
            <span className="font-mono text-[10px] ml-1 flex-shrink-0 text-zinc-600">{item.count}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

// ─── Expandable Row ──────────────────────────────────────────────────────────

function LogRow({ log }: { log: NormalizedLog }) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <TableRow
        className={cn(
          'border-zinc-800 cursor-pointer transition-colors',
          open ? 'bg-zinc-800/60' : 'hover:bg-zinc-800/50',
        )}
        onClick={() => setOpen((o) => !o)}
      >
        <TableCell className="w-4 pr-0">
          {open
            ? <ChevronDown size={12} className="text-zinc-500" />
            : <ChevronRight size={12} className="text-zinc-500" />}
        </TableCell>
        <TableCell><SeverityBadge severity={log.severity as Severity} /></TableCell>
        <TableCell>
          <Badge variant="outline" className="text-xs border-zinc-700 text-zinc-400">
            {SOURCE_LABELS[log.source_type] ?? log.source_type}
          </Badge>
        </TableCell>
        <TableCell className="text-xs text-zinc-400">
          {CATEGORY_LABELS[log.event_category] ?? log.event_category}
        </TableCell>
        <TableCell className="text-sm text-zinc-200 max-w-xs truncate">{log.message}</TableCell>
        <TableCell className="text-xs text-zinc-400 font-mono">
          {log.source_hostname
            ? <><span className="text-zinc-200">{log.source_hostname}</span><span className="text-zinc-600 ml-1">({log.source_ip})</span></>
            : log.source_ip ?? '—'}
        </TableCell>
        <TableCell className="text-xs text-zinc-500">{formatDate(log.timestamp)}</TableCell>
      </TableRow>
      {open && (
        <TableRow className="border-zinc-800 bg-zinc-900/80">
          <TableCell colSpan={7} className="px-8 py-3">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-6 gap-y-1.5 text-[11px]">
              {[
                ['Log ID',         log.log_id],
                ['Event Action',   (log as unknown as Record<string,string>).event_action ?? '—'],
                ['Kaynak IP',      log.source_ip ?? '—'],
                ['Hedef IP',       (log as unknown as Record<string,string>).destination_ip ?? '—'],
                ['Kaynak Port',    (log as unknown as Record<string,string>).source_port ?? '—'],
                ['Hedef Port',     (log as unknown as Record<string,string>).destination_port ?? '—'],
                ['Protokol',       (log as unknown as Record<string,string>).network_protocol ?? '—'],
                ['Hostname',       log.source_hostname ?? '—'],
                ['Observer',       (log as unknown as Record<string,string>).observer_hostname ?? '—'],
                ['Zaman',          formatDate(log.timestamp)],
              ].map(([k, v]) => (
                <div key={k as string}>
                  <span className="text-zinc-600">{k}: </span>
                  <span className="text-zinc-300 font-mono break-all">{v ?? '—'}</span>
                </div>
              ))}
            </div>
            {log.message && (
              <div className="mt-2 px-2 py-1.5 bg-zinc-800 rounded text-[11px] font-mono text-zinc-300 break-all">
                {log.message}
              </div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

// ─── Ana Sayfa ────────────────────────────────────────────────────────────────

const SEV_FILTER_OPTIONS = [
  { value: 'all',      label: 'Tüm' },
  { value: 'critical', label: 'Kritik' },
  { value: 'high',     label: 'Yüksek' },
  { value: 'warning',  label: 'Uyarı' },
  { value: 'info',     label: 'Bilgi' },
]

export default function LogsPage() {
  const queryClient = useQueryClient()
  const [sourceFilter, setSourceFilter]         = useState('all')
  const [categoryFilter, setCategoryFilter]     = useState('all')
  const [severityFilter, setSeverityFilter]     = useState('all')
  const [searchInput, setSearchInput]           = useState('')
  const [liveMode, setLiveMode]                 = useState(false)
  const [hours, setHours]                       = useState(24)
  // Field-level filters (IBM QRadar AQL / Elastic KQL modeli)
  const [filterSrcIp, setFilterSrcIp]           = useState('')
  const [filterDstIp, setFilterDstIp]           = useState('')
  const [filterProtocol, setFilterProtocol]     = useState('')
  const [filterAction, setFilterAction]         = useState('')

  const debouncedSearch = useDebounce(searchInput, 300)
  const isSearching = debouncedSearch.trim().length > 0

  // Facet sidebar kaynağı aktif filtreye göre seçilir
  const facetSourceFilter  = sourceFilter  !== 'all' ? sourceFilter  : undefined
  const facetCategoryFilter = categoryFilter !== 'all' ? categoryFilter : undefined

  const debouncedSrcIp    = useDebounce(filterSrcIp, 400)
  const debouncedDstIp    = useDebounce(filterDstIp, 400)
  const debouncedProtocol = useDebounce(filterProtocol, 400)
  const debouncedAction   = useDebounce(filterAction, 400)

  const listQuery = useQuery({
    queryKey: ['logs-list', sourceFilter, categoryFilter, severityFilter, debouncedSrcIp, debouncedDstIp, debouncedProtocol, debouncedAction],
    queryFn: () =>
      logsApi.listNormalized({
        source_type:      sourceFilter !== 'all' ? sourceFilter : undefined,
        event_category:   categoryFilter !== 'all' ? categoryFilter : undefined,
        source_ip:        debouncedSrcIp || undefined,
        destination_ip:   debouncedDstIp || undefined,
        network_protocol: debouncedProtocol || undefined,
        event_action:     debouncedAction || undefined,
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
        source_type:    sourceFilter !== 'all' ? sourceFilter : undefined,
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

  // Severity client-side filter (listQuery result)
  const logs = useMemo(() => {
    if (severityFilter === 'all' || isSearching) return allLogs
    return allLogs.filter((l) => l.severity === severityFilter)
  }, [allLogs, severityFilter, isSearching])

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['logs-list'] })
    queryClient.invalidateQueries({ queryKey: ['log-volume'] })
    queryClient.invalidateQueries({ queryKey: ['log-facets'] })
  }

  const facetToggle = (type: 'source' | 'category', key: string) => {
    if (type === 'source')   setSourceFilter(s => s === key ? 'all' : key)
    if (type === 'category') setCategoryFilter(c => c === key ? 'all' : key)
  }

  return (
    <div className="p-6 flex gap-4 min-h-0">
      {/* ── Sidebar: Facets ─────────────────────────────────────────── */}
      <aside className="w-44 flex-shrink-0 space-y-1">
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
          {facetsData ? (
            <>
              <p className="text-[10px] text-zinc-600 uppercase tracking-widest mb-2">
                {facetsData.total.toLocaleString('tr-TR')} log · {hours}s
              </p>
              <FacetList
                title="Kaynak"
                items={facetsData.sources}
                active={sourceFilter}
                onToggle={(k) => facetToggle('source', k)}
              />
              <FacetList
                title="Kategori"
                items={facetsData.categories}
                active={categoryFilter}
                onToggle={(k) => facetToggle('category', k)}
              />
              <FacetList
                title="Seviye"
                items={facetsData.severities}
                active={severityFilter}
                onToggle={(k) => setSeverityFilter(s => s === k ? 'all' : k)}
              />
            </>
          ) : (
            <div className="space-y-1.5">
              {[0,1,2,3,4].map(i => <div key={i} className="h-5 bg-zinc-800 rounded animate-pulse" />)}
            </div>
          )}
        </div>
      </aside>

      {/* ── Main content ────────────────────────────────────────────── */}
      <div className="flex-1 min-w-0 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div>
            <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
              <FileText size={18} />
              Normalize Edilmiş Loglar
              {liveMode && <Radio size={13} className="text-emerald-400 animate-pulse" />}
            </h1>
            <p className="text-sm text-zinc-500 mt-0.5">
              {isSearching
                ? `"${debouncedSearch}" için ${count} sonuç`
                : `${logs.length} kayıt${logs.length < count ? ` (${count} toplam)` : ''}`}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Zaman aralığı */}
            <div className="flex rounded-md overflow-hidden border border-zinc-700">
              {([6, 24, 48] as const).map((h) => (
                <button
                  key={h}
                  onClick={() => setHours(h)}
                  className={cn(
                    'px-2.5 py-1 text-xs',
                    hours === h
                      ? 'bg-indigo-600 text-white'
                      : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700',
                  )}
                >
                  {h}s
                </button>
              ))}
            </div>
            {/* Live toggle */}
            <button
              onClick={() => setLiveMode(m => !m)}
              title={liveMode ? 'Canlı mod: Kapat' : 'Canlı mod: Aç'}
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs border transition-colors',
                liveMode
                  ? 'bg-emerald-900/30 border-emerald-700 text-emerald-400'
                  : 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:text-zinc-200',
              )}
            >
              {liveMode ? <Wifi size={12} /> : <WifiOff size={12} />}
              {liveMode ? 'Canlı' : 'Durduruldu'}
            </button>
            <Button
              variant="outline" size="sm"
              onClick={handleRefresh}
              disabled={fetching}
              className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              <RefreshCw size={14} className={fetching ? 'animate-spin' : ''} />
              <span className="ml-1.5">Yenile</span>
            </Button>
          </div>
        </div>

        {/* Field-level Filter Bar */}
        <div className="bg-zinc-900 rounded-lg border border-zinc-800 px-3 py-2.5 flex flex-wrap gap-2 items-center">
          <span className="text-[11px] text-zinc-600 uppercase tracking-wide flex-shrink-0">Filtrele</span>
          {[
            { placeholder: 'Kaynak IP',   value: filterSrcIp,    set: setFilterSrcIp },
            { placeholder: 'Hedef IP',    value: filterDstIp,    set: setFilterDstIp },
            { placeholder: 'Protokol',    value: filterProtocol, set: setFilterProtocol },
            { placeholder: 'Event Action', value: filterAction,  set: setFilterAction },
          ].map(({ placeholder, value, set }) => (
            <div key={placeholder} className="relative">
              <Input
                placeholder={placeholder}
                value={value}
                onChange={e => set(e.target.value)}
                className="h-7 w-32 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600 pr-5"
              />
              {value && (
                <button
                  onClick={() => set('')}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                >
                  <X size={10} />
                </button>
              )}
            </div>
          ))}
          {(filterSrcIp || filterDstIp || filterProtocol || filterAction) && (
            <button
              onClick={() => { setFilterSrcIp(''); setFilterDstIp(''); setFilterProtocol(''); setFilterAction('') }}
              className="text-[11px] text-indigo-400 hover:text-indigo-300 ml-1"
            >
              Temizle
            </button>
          )}
        </div>

        {/* Log Volume Histogram */}
        <div className="bg-zinc-900 rounded-lg border border-zinc-800">
          <div className="px-4 py-2 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Log Hacmi</span>
            <span className="text-[11px] text-zinc-600">Severity bazında — {hours}s</span>
          </div>
          {volumeData ? (
            <div className="px-2 pt-1 pb-2">
              <LogVolumeChart series={volumeData.series} hours={hours} />
            </div>
          ) : (
            <div className="h-28 animate-pulse bg-zinc-800/30 m-3 rounded" />
          )}
        </div>

        {/* Table Card */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <CardTitle className="text-sm text-zinc-300 flex-shrink-0">Loglar</CardTitle>

              {/* Arama */}
              <div className="relative flex-1 min-w-[180px] max-w-xs">
                <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
                <Input
                  placeholder="Mesaj, IP, kullanıcı..."
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  className="pl-7 pr-7 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600"
                />
                {searchInput && (
                  <button
                    onClick={() => setSearchInput('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                  >
                    <X size={12} />
                  </button>
                )}
              </div>

              {/* Severity butonları */}
              <div className="flex gap-1">
                {SEV_FILTER_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setSeverityFilter(severityFilter === opt.value ? 'all' : opt.value)}
                    className={cn(
                      'px-2 py-1 text-[11px] rounded border transition-colors',
                      severityFilter === opt.value
                        ? 'border-indigo-600 bg-indigo-600/20 text-indigo-300'
                        : 'border-zinc-700 bg-zinc-800 text-zinc-500 hover:text-zinc-300',
                    )}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              {/* Kaynak dropdown */}
              <Select value={sourceFilter} onValueChange={(v) => setSourceFilter(v ?? 'all')}>
                <SelectTrigger className="w-32 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  <SelectItem value="all" className="text-zinc-300">Tüm kaynaklar</SelectItem>
                  {Object.entries(SOURCE_LABELS).map(([val, label]) => (
                    <SelectItem key={val} value={val} className="text-zinc-300">{label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              {/* Aktif filtre temizle */}
              {(sourceFilter !== 'all' || categoryFilter !== 'all' || severityFilter !== 'all') && (
                <button
                  onClick={() => { setSourceFilter('all'); setCategoryFilter('all'); setSeverityFilter('all') }}
                  className="text-[11px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1"
                >
                  <X size={11} /> Temizle
                </button>
              )}
            </div>
          </CardHeader>

          <CardContent className="p-0">
            {loading ? (
              <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
            ) : logs.length === 0 ? (
              <p className="text-zinc-600 text-sm text-center py-10">
                {isSearching ? `"${debouncedSearch}" için log bulunamadı` : 'Log bulunamadı'}
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="w-4" />
                    <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-24">Kaynak</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-32">Kategori</TableHead>
                    <TableHead className="text-zinc-500 text-xs">Mesaj</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-32">Kaynak IP</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((log) => (
                    <LogRow key={log.log_id} log={log} />
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
