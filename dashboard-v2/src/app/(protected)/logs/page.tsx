'use client'

import { useState, useEffect } from 'react'
import { FileText, RefreshCw, Search, X } from 'lucide-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { logsApi } from '@/lib/api'
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
import type { Severity } from '@/types/models'

const SOURCE_LABELS: Record<string, string> = {
  syslog:    'Syslog',
  opnsense:  'OPNsense',
  vyos:      'VyOS',
  pfsense:   'pfSense',
  cisco_asa: 'Cisco ASA',
  fortigate: 'FortiGate',
  nginx:     'Nginx',
  apache:    'Apache',
  netflow:   'NetFlow',
  auth_log:  'Auth Log',
  netguard:  'NetGuard',
  suricata:  'Suricata',
  zeek:      'Zeek',
  wazuh:     'Wazuh',
}

const CATEGORY_LABELS: Record<string, string> = {
  authentication: 'Kimlik Doğrulama',
  network:        'Ağ',
  intrusion:      'Saldırı',
  system:         'Sistem',
  unknown:        'Bilinmiyor',
}

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

export default function LogsPage() {
  const queryClient = useQueryClient()
  const [sourceFilter, setSourceFilter]   = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [searchInput, setSearchInput]     = useState('')

  const debouncedSearch = useDebounce(searchInput, 300)
  const isSearching = debouncedSearch.trim().length > 0

  const listQuery = useQuery({
    queryKey: ['logs-list', sourceFilter, categoryFilter],
    queryFn: () =>
      logsApi.listNormalized({
        source_type: sourceFilter !== 'all' ? sourceFilter : undefined,
        category:    categoryFilter !== 'all' ? categoryFilter : undefined,
        limit: 200,
      }),
    refetchInterval: 20_000,
    enabled: !isSearching,
  })

  const searchQuery = useQuery({
    queryKey: ['logs-search', debouncedSearch, sourceFilter, categoryFilter],
    queryFn: () =>
      logsApi.searchLogs({
        q:           debouncedSearch,
        source_type: sourceFilter !== 'all' ? sourceFilter : undefined,
        category:    categoryFilter !== 'all' ? categoryFilter : undefined,
        limit: 200,
      }),
    enabled: isSearching,
  })

  const active  = isSearching ? searchQuery : listQuery
  const logs    = active.data?.logs ?? []
  const count   = active.data?.count ?? 0
  const loading = active.isLoading
  const fetching = active.isFetching

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <FileText size={18} /> Normalize Edilmiş Loglar
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {isSearching
              ? `"${debouncedSearch}" için ${count} sonuç`
              : `${count} kayıt`}
          </p>
        </div>
        <Button
          variant="outline" size="sm"
          onClick={() => queryClient.invalidateQueries({ queryKey: ['logs-list'] })}
          disabled={fetching}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
        >
          <RefreshCw size={14} className={fetching ? 'animate-spin' : ''} />
          <span className="ml-1.5">Yenile</span>
        </Button>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <CardTitle className="text-sm text-zinc-300 flex-shrink-0">Loglar</CardTitle>

            {/* Arama kutusu */}
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
              <Input
                placeholder="Mesaj, IP, kullanıcı, olay tipi..."
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

            <Select value={sourceFilter} onValueChange={(v) => setSourceFilter(v ?? 'all')}>
              <SelectTrigger className="w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="all" className="text-zinc-300">Tüm kaynaklar</SelectItem>
                {Object.entries(SOURCE_LABELS).map(([val, label]) => (
                  <SelectItem key={val} value={val} className="text-zinc-300">{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={categoryFilter} onValueChange={(v) => setCategoryFilter(v ?? 'all')}>
              <SelectTrigger className="w-40 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="all" className="text-zinc-300">Tüm kategoriler</SelectItem>
                {Object.entries(CATEGORY_LABELS).map(([val, label]) => (
                  <SelectItem key={val} value={val} className="text-zinc-300">{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
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
                  <TableRow key={log.log_id} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell><SeverityBadge severity={log.severity as Severity} /></TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs border-zinc-700 text-zinc-400">
                        {SOURCE_LABELS[log.source_type] ?? log.source_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-zinc-400">
                      {CATEGORY_LABELS[log.category] ?? log.category}
                    </TableCell>
                    <TableCell className="text-sm text-zinc-200 max-w-xs truncate">{log.message}</TableCell>
                    <TableCell className="text-xs text-zinc-400 font-mono">{log.src_ip ?? '—'}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{formatDate(log.timestamp)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
