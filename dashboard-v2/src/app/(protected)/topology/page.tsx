'use client'

import { useRef, useEffect, useState } from 'react'
import { Share2, RefreshCw, Loader2, Info } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as echarts from 'echarts'
import { topologyApi } from '@/lib/api'
import type { TopologyNode, TopologyEdge } from '@/types/models'

const NODE_COLOR: Record<string, string> = {
  router:     '#38bdf8',
  switch:     '#3b82f6',
  server:     '#10b981',
  agent:      '#8b5cf6',
  snmp:       '#06b6d4',
  discovered: '#f59e0b',
  unknown:    '#475569',
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

function nodeColor(type: string) { return NODE_COLOR[type] ?? NODE_COLOR.unknown }
function nodeSymbol(type: string) { return NODE_SYMBOL[type] ?? 'circle' }

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
    <div className="ui-panel-header flex-wrap gap-3">
      {LEGEND_ITEMS.map(({ type, label }) => (
        <div key={type} className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: nodeColor(type) }} />
          <span className="text-xs text-slate-400">{label}</span>
        </div>
      ))}
    </div>
  )
}

function NodeDetail({ node, onClose }: { node: TopologyNode; onClose: () => void }) {
  return (
    <div className="absolute top-4 right-4 w-56 bg-[#0a1120]/95 border border-sky-900/30 rounded-xl p-4 shadow-[0_8px_32px_rgba(0,0,0,0.6)] backdrop-blur-sm z-10">
      <div className="flex items-start justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-100 truncate">{node.name}</h3>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-slate-200 text-xs ml-2 shrink-0 transition-colors"
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
            <dt className="text-slate-500 w-14 shrink-0">{label}</dt>
            <dd className="text-slate-300 truncate font-mono">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-3 pt-3 border-t border-sky-900/15 flex items-center gap-1.5">
        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: nodeColor(node.type) }} />
        <span className="text-xs text-slate-400">{node.type}</span>
      </div>
    </div>
  )
}

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

  useEffect(() => {
    if (!chartRef.current) return
    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, 'dark')
    }
    const chart = chartInstance.current
    if (nodes.length === 0) { chart.clear(); return }

    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: (params: any) => {
          if (params.dataType !== 'node') return ''
          const n = params.data as TopologyNode & { value?: unknown }
          return `
            <div style="font-size:12px;line-height:1.6">
              <b style="color:#cbd5e1">${n.name}</b><br/>
              IP: <span style="color:#64748b">${n.ip || '—'}</span><br/>
              Tür: <span style="color:#64748b">${n.type}</span><br/>
              ${n.vendor ? `Vendor: <span style="color:#64748b">${n.vendor}</span><br/>` : ''}
            </div>
          `
        },
        backgroundColor: '#0a1120',
        borderColor: 'rgba(56,189,248,0.18)',
        textStyle: { color: '#cbd5e1' },
        extraCssText: 'box-shadow: 0 8px 24px rgba(0,0,0,0.5);',
      },
      series: [{
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
          color: '#64748b',
          formatter: (params: any) => {
            const name = (params.data as TopologyNode).name
            return name.length > 14 ? name.slice(0, 12) + '…' : name
          },
        },
        edgeLabel: { show: false },
        lineStyle: {
          color: 'rgba(56,189,248,0.15)',
          width: 1.5,
          curveness: 0.1,
        },
        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 2.5, color: '#38bdf8' },
          label: { color: '#cbd5e1', fontSize: 11 },
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
            color: e.link_type === 'lldp' ? '#38bdf8' : 'rgba(56,189,248,0.15)',
            width: e.link_type === 'lldp' ? 2 : 1.5,
          },
        })),
      }],
    }

    chart.setOption(option, { notMerge: true })
    chart.off('click')
    chart.on('click', (params: any) => {
      if (params.dataType === 'node') {
        setSelectedNode(params.data as TopologyNode)
      } else {
        setSelectedNode(null)
      }
    })
  }, [nodes, edges])

  useEffect(() => {
    const el = chartRef.current
    if (!el) return
    const ro = new ResizeObserver(() => { chartInstance.current?.resize() })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    return () => { chartInstance.current?.dispose(); chartInstance.current = null }
  }, [])

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Share2 size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Ağ Topolojisi</h1>
            <p className="text-xs text-slate-600">
              {data?.node_count ?? 0} cihaz · {data?.edge_count ?? 0} bağlantı
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
            Yenile
          </button>
          <button
            onClick={() => refreshMutation.mutate()}
            disabled={refreshMutation.isPending}
            className="ui-btn ui-btn-primary"
          >
            {refreshMutation.isPending
              ? <><Loader2 size={12} className="animate-spin" />Yenileniyor...</>
              : <><Share2 size={12} />Topolojiyi Oluştur</>
            }
          </button>
        </div>
      </div>

      {/* Graph card */}
      <div className="ui-panel">
        <Legend />
        <div className="relative">
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center bg-[#0a1120]/80 z-10">
              <Loader2 size={24} className="text-sky-400 animate-spin" />
            </div>
          )}

          {!isLoading && nodes.length === 0 && (
            <div className="flex flex-col items-center justify-center h-96 gap-2">
              <Share2 size={40} className="text-slate-700 mb-1" />
              <p className="text-slate-500 text-sm">Topoloji verisi yok</p>
              <p className="text-slate-600 text-xs mb-3">
                SNMP cihazları ekleyip "Topolojiyi Oluştur" butonuna tıklayın
              </p>
              <button
                onClick={() => refreshMutation.mutate()}
                disabled={refreshMutation.isPending}
                className="ui-btn ui-btn-primary"
              >
                {refreshMutation.isPending ? 'Oluşturuluyor...' : 'Topolojiyi Oluştur'}
              </button>
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
      </div>

      {/* Hint */}
      <div className="flex items-start gap-2 text-xs text-slate-500">
        <Info size={12} className="mt-0.5 shrink-0 text-slate-600" />
        <span>
          Cihaza tıklayarak detay görebilirsiniz. Fare tekerleği ile yakınlaştırın, sürükleyerek hareket ettirin.
          Mavi bağlantılar LLDP ile, gri bağlantılar ARP ile keşfedildi.
        </span>
      </div>
    </div>
  )
}
