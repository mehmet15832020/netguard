'use client'

import { useRef, useEffect, useState } from 'react'
import { Share2, RefreshCw, Loader2, Info } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as echarts from 'echarts'
import { topologyApi } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { TopologyNode, TopologyEdge } from '@/types/models'

// ------------------------------------------------------------------ //
//  Node renk ve şekil haritalama
// ------------------------------------------------------------------ //

const NODE_COLOR: Record<string, string> = {
  router:     '#6366f1',
  switch:     '#3b82f6',
  server:     '#10b981',
  agent:      '#8b5cf6',
  snmp:       '#06b6d4',
  discovered: '#f59e0b',
  unknown:    '#71717a',
}

const NODE_SYMBOL: Record<string, string> = {
  router:     'diamond',
  switch:     'rect',
  server:     'roundRect',
  agent:      'circle',
  snmp:       'circle',
  discovered: 'triangle',
  unknown:    'circle',
}

function nodeColor(type: string) {
  return NODE_COLOR[type] ?? NODE_COLOR.unknown
}

function nodeSymbol(type: string) {
  return NODE_SYMBOL[type] ?? 'circle'
}

// ------------------------------------------------------------------ //
//  Efsane (legend) bileşeni
// ------------------------------------------------------------------ //

const LEGEND_ITEMS = [
  { type: 'router',     label: 'Router' },
  { type: 'switch',     label: 'Switch' },
  { type: 'server',     label: 'Sunucu' },
  { type: 'agent',      label: 'Agent' },
  { type: 'snmp',       label: 'SNMP' },
  { type: 'discovered', label: 'Keşfedilen' },
  { type: 'unknown',    label: 'Bilinmiyor' },
]

function Legend() {
  return (
    <div className="flex flex-wrap gap-3 px-4 py-3 border-b border-zinc-800">
      {LEGEND_ITEMS.map(({ type, label }) => (
        <div key={type} className="flex items-center gap-1.5">
          <div
            className="w-2.5 h-2.5 rounded-full shrink-0"
            style={{ backgroundColor: nodeColor(type) }}
          />
          <span className="text-xs text-zinc-400">{label}</span>
        </div>
      ))}
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Detay paneli (sağ tık / tıklama)
// ------------------------------------------------------------------ //

function NodeDetail({ node, onClose }: { node: TopologyNode; onClose: () => void }) {
  return (
    <div className="absolute top-4 right-4 w-56 bg-zinc-900/95 border border-zinc-700 rounded-lg p-4 shadow-xl backdrop-blur-sm z-10">
      <div className="flex items-start justify-between mb-3">
        <h3 className="text-sm font-semibold text-zinc-100 truncate">{node.name}</h3>
        <button
          onClick={onClose}
          className="text-zinc-500 hover:text-zinc-200 text-xs ml-2 shrink-0"
        >✕</button>
      </div>
      <dl className="space-y-1.5 text-xs">
        {[
          { label: 'IP',     value: node.ip || '—' },
          { label: 'Tür',    value: node.type },
          { label: 'Vendor', value: node.vendor || '—' },
          { label: 'OS',     value: node.os_info || '—' },
          { label: 'Katman', value: `L${node.layer}` },
        ].map(({ label, value }) => (
          <div key={label} className="flex gap-2">
            <dt className="text-zinc-500 w-14 shrink-0">{label}</dt>
            <dd className="text-zinc-300 truncate font-mono">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-3 pt-3 border-t border-zinc-800">
        <div
          className="w-2.5 h-2.5 rounded-full inline-block mr-1.5"
          style={{ backgroundColor: nodeColor(node.type) }}
        />
        <span className="text-xs text-zinc-400">{node.type}</span>
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ //
//  Ana bileşen
// ------------------------------------------------------------------ //

export default function TopologyPage() {
  const queryClient = useQueryClient()
  const chartRef = useRef<HTMLDivElement>(null)
  const chartInstance = useRef<echarts.ECharts | null>(null)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['topology-graph'],
    queryFn: () => topologyApi.graph(),
    refetchInterval: 60_000,
  })

  const refreshMutation = useMutation({
    mutationFn: () => topologyApi.refresh(),
    onSuccess: () => {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['topology-graph'] })
        refetch()
      }, 3000)
    },
  })

  const nodes: TopologyNode[] = data?.nodes ?? []
  const edges: TopologyEdge[] = data?.edges ?? []

  // ECharts grafiğini kur / güncelle
  useEffect(() => {
    if (!chartRef.current) return

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, 'dark')
    }

    const chart = chartInstance.current

    if (nodes.length === 0) {
      chart.clear()
      return
    }

    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: (params: any) => {
          if (params.dataType !== 'node') return ''
          const n = params.data as TopologyNode & { value?: unknown }
          return `
            <div style="font-size:12px;line-height:1.6">
              <b style="color:#e4e4e7">${n.name}</b><br/>
              IP: <span style="color:#a1a1aa">${n.ip || '—'}</span><br/>
              Tür: <span style="color:#a1a1aa">${n.type}</span><br/>
              ${n.vendor ? `Vendor: <span style="color:#a1a1aa">${n.vendor}</span><br/>` : ''}
            </div>
          `
        },
        backgroundColor: '#18181b',
        borderColor: '#3f3f46',
        textStyle: { color: '#e4e4e7' },
      },
      series: [
        {
          type: 'graph',
          layout: 'force',
          roam: true,
          draggable: true,
          animation: true,
          animationDuration: 800,
          force: {
            repulsion: 180,
            gravity: 0.05,
            edgeLength: [80, 180],
            layoutAnimation: true,
          },
          label: {
            show: true,
            position: 'bottom',
            fontSize: 10,
            color: '#a1a1aa',
            formatter: (params: any) => {
              const name = (params.data as TopologyNode).name
              return name.length > 14 ? name.slice(0, 12) + '…' : name
            },
          },
          edgeLabel: {
            show: false,
          },
          lineStyle: {
            color: '#3f3f46',
            width: 1.5,
            curveness: 0.1,
          },
          emphasis: {
            focus: 'adjacency',
            lineStyle: { width: 2.5, color: '#6366f1' },
            label: { color: '#e4e4e7', fontSize: 11 },
          },
          nodes: nodes.map((n) => ({
            id: n.device_id,
            name: n.name,
            ip: n.ip,
            type: n.type,
            vendor: n.vendor,
            os_info: n.os_info,
            layer: n.layer,
            updated_at: n.updated_at,
            symbolSize: n.type === 'router' ? 20 : n.type === 'switch' ? 18 : 14,
            symbol: nodeSymbol(n.type),
            itemStyle: {
              color: nodeColor(n.type),
              borderColor: nodeColor(n.type) + '66',
              borderWidth: 2,
              shadowBlur: 6,
              shadowColor: nodeColor(n.type) + '44',
            },
          })),
          edges: edges.map((e) => ({
            source: e.src_id,
            target: e.dst_id,
            lineStyle: {
              color: e.link_type === 'lldp' ? '#6366f1' : '#3f3f46',
              width: e.link_type === 'lldp' ? 2 : 1.5,
            },
          })),
        },
      ],
    }

    chart.setOption(option, { notMerge: true })

    chart.off('click')
    chart.on('click', (params: any) => {
      if (params.dataType === 'node') {
        const nodeData = params.data as TopologyNode
        setSelectedNode(nodeData)
      } else {
        setSelectedNode(null)
      }
    })
  }, [nodes, edges])

  // Resize observer
  useEffect(() => {
    const el = chartRef.current
    if (!el) return

    const ro = new ResizeObserver(() => {
      chartInstance.current?.resize()
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Temizlik
  useEffect(() => {
    return () => {
      chartInstance.current?.dispose()
      chartInstance.current = null
    }
  }, [])

  return (
    <div className="space-y-4">
      {/* Başlık */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Share2 size={18} /> Ağ Topolojisi
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {data?.node_count ?? 0} cihaz · {data?.edge_count ?? 0} bağlantı
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            <span className="ml-1.5">Yenile</span>
          </Button>
          <Button
            size="sm"
            onClick={() => refreshMutation.mutate()}
            disabled={refreshMutation.isPending}
            className="bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            {refreshMutation.isPending
              ? <><Loader2 size={14} className="animate-spin" /><span className="ml-1.5">Yenileniyor...</span></>
              : <><Share2 size={14} /><span className="ml-1.5">Topolojiyi Oluştur</span></>
            }
          </Button>
        </div>
      </div>

      {/* Grafik kartı */}
      <Card className="bg-zinc-900 border-zinc-800 overflow-hidden">
        <Legend />
        <div className="relative">
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center bg-zinc-900/80 z-10">
              <Loader2 size={24} className="text-indigo-400 animate-spin" />
            </div>
          )}

          {!isLoading && nodes.length === 0 && (
            <div className="flex flex-col items-center justify-center h-96">
              <Share2 size={40} className="text-zinc-700 mb-3" />
              <p className="text-zinc-500 text-sm">Topoloji verisi yok</p>
              <p className="text-zinc-600 text-xs mt-1 mb-4">
                SNMP cihazları ekleyip "Topolojiyi Oluştur" butonuna tıklayın
              </p>
              <Button
                size="sm"
                onClick={() => refreshMutation.mutate()}
                disabled={refreshMutation.isPending}
                className="bg-indigo-600 hover:bg-indigo-500 text-white"
              >
                {refreshMutation.isPending ? 'Oluşturuluyor...' : 'Topolojiyi Oluştur'}
              </Button>
            </div>
          )}

          <div
            ref={chartRef}
            className="w-full"
            style={{ height: nodes.length > 0 ? '520px' : '0px' }}
          />

          {selectedNode && (
            <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
          )}
        </div>
      </Card>

      {/* İpuçları */}
      <div className="flex items-start gap-2 text-xs text-zinc-500">
        <Info size={12} className="mt-0.5 shrink-0 text-zinc-600" />
        <span>
          Cihaza tıklayarak detay görebilirsiniz. Fare tekerleği ile yakınlaştırın, sürükleyerek hareket ettirin.
          Mor renkli bağlantılar LLDP ile, gri bağlantılar ARP ile keşfedildi.
        </span>
      </div>
    </div>
  )
}
