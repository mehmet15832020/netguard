'use client'

import { GitMerge, Play, RefreshCw } from 'lucide-react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { correlationApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { Severity } from '@/types/models'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export default function CorrelationPage() {
  const queryClient = useQueryClient()

  const { data: eventsData, isLoading, isFetching } = useQuery({
    queryKey: ['correlated-events'],
    queryFn: () => correlationApi.listEvents({ limit: 200 }),
    refetchInterval: 30_000,
  })

  const { data: rulesData } = useQuery({
    queryKey: ['correlation-rules'],
    queryFn: () => correlationApi.listRules(),
  })

  const runMutation = useMutation({
    mutationFn: () => correlationApi.runNow(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['correlated-events'] }),
  })

  const reloadMutation = useMutation({
    mutationFn: () => correlationApi.reloadRules(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  const events = eventsData?.events ?? []
  const rules  = rulesData?.rules ?? []

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <GitMerge size={18} /> Korelasyon
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">{eventsData?.count ?? 0} olay · {rules.length} kural</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ['correlated-events'] })}
            disabled={isFetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            <span className="ml-1.5">Yenile</span>
          </Button>
          <Button
            size="sm"
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            <Play size={14} />
            <span className="ml-1.5">
              {runMutation.isPending ? 'Çalışıyor...' : 'Şimdi Çalıştır'}
            </span>
          </Button>
        </div>
      </div>

      <Tabs defaultValue="events">
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="events" className="text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100">
            Olaylar
          </TabsTrigger>
          <TabsTrigger value="rules" className="text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100">
            Kurallar
          </TabsTrigger>
        </TabsList>

        {/* Korelasyon olayları */}
        <TabsContent value="events">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-0">
              {isLoading ? (
                <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
              ) : events.length === 0 ? (
                <p className="text-zinc-600 text-sm text-center py-10">Korelasyon olayı yok</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                      <TableHead className="text-zinc-500 text-xs">Kural</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-40">Grup Değeri</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-24">Eşleşme</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-20">Pencere</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((ev) => (
                      <TableRow key={ev.corr_id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell><SeverityBadge severity={ev.severity as Severity} /></TableCell>
                        <TableCell>
                          <p className="text-sm text-zinc-200">{ev.rule_name}</p>
                          <p className="text-xs text-zinc-500">{ev.event_type}</p>
                        </TableCell>
                        <TableCell className="text-xs text-zinc-300 font-mono">{ev.group_value}</TableCell>
                        <TableCell>
                          <Badge className="bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs">
                            {ev.matched_count} olay
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-zinc-500">{ev.window_seconds}s</TableCell>
                        <TableCell className="text-xs text-zinc-500">{formatDate(ev.created_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Kurallar */}
        <TabsContent value="rules">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-zinc-300">Aktif Kurallar</CardTitle>
                <Button
                  variant="outline" size="sm"
                  onClick={() => reloadMutation.mutate()}
                  disabled={reloadMutation.isPending}
                  className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-xs"
                >
                  {reloadMutation.isPending ? 'Yükleniyor...' : 'Kuralları Yeniden Yükle'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-zinc-500 text-xs">Kural Adı</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-32">Eşleşen Tip</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-24">Grup</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-20">Pencere</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-20">Eşik</TableHead>
                    <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => (
                    <TableRow key={rule.rule_id} className="border-zinc-800 hover:bg-zinc-800/50">
                      <TableCell>
                        <p className="text-sm text-zinc-200">{rule.name}</p>
                        <p className="text-xs text-zinc-500">{rule.description}</p>
                      </TableCell>
                      <TableCell className="text-xs text-zinc-400 font-mono">{rule.match_event_type}</TableCell>
                      <TableCell className="text-xs text-zinc-400">{rule.group_by}</TableCell>
                      <TableCell className="text-xs text-zinc-400">{rule.window_seconds}s</TableCell>
                      <TableCell className="text-xs text-zinc-400">{rule.threshold}</TableCell>
                      <TableCell><SeverityBadge severity={rule.severity} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
