'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldOff, RefreshCw } from 'lucide-react'
import { activeResponse, type BlockedIP } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

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

export default function BlocksPage() {
  const qc = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['active-blocks'],
    queryFn: () => activeResponse.listBlocks(),
    refetchInterval: 30_000,
    retry: false,
  })

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => activeResponse.unblock(ip),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['active-blocks'] })
    },
  })

  const activeBlocks: BlockedIP[] = (data?.blocks ?? []).filter(b => b.is_active === 1)

  const handleUnblock = (ip: string) => {
    if (window.confirm(`${ip} adresinin bloğunu kaldırmak istediğinize emin misiniz?`)) {
      unblockMutation.mutate(ip)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldOff className="w-5 h-5 text-red-400" />
          <h1 className="text-xl font-semibold">Aktif IP Blokları</h1>
          {activeBlocks.length > 0 && (
            <span className="ml-1 px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold border border-red-700/40">
              {activeBlocks.length}
            </span>
          )}
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800">
                <TableHead>IP Adresi</TableHead>
                <TableHead>Sebep</TableHead>
                <TableHead>Bloklayan</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Bloklandığı Zaman</TableHead>
                <TableHead>Kaynak Incident</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-zinc-500 py-8">
                    Yükleniyor...
                  </TableCell>
                </TableRow>
              ) : activeBlocks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-zinc-500 py-12">
                    <div className="flex flex-col items-center gap-2">
                      <ShieldOff className="w-8 h-8 text-zinc-700" />
                      <p>Henüz bloklu IP yok</p>
                      <p className="text-xs text-zinc-600">Incident detaylarından IP bloklama yapabilirsiniz</p>
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
                      <button
                        disabled={unblockMutation.isPending}
                        onClick={() => handleUnblock(block.ip)}
                        className="text-xs px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-red-700/50 hover:text-red-400 hover:bg-red-500/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        Bloku Kaldır
                      </button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
