'use client'

import { useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import * as echarts from 'echarts'
import { topologyApi } from '@/lib/api'
import type { TopologyNode, TopologyEdge } from '@/types/models'

const NODE_COLOR: Record<string, string> = {
  router:     '#6366f1',
  switch:     '#3b82f6',
  server:     '#10b981',
  agent:      '#8b5cf6',
  snmp:       '#06b6d4',
  discovered: '#f59e0b',
  unknown:    '#71717a',
}

function nodeColor(type: string) {
  return NODE_COLOR[type] ?? NODE_COLOR.unknown
}

export function MiniTopology() {
  const chartRef = useRef<HTMLDivElement>(null)
  const chartInstance = useRef<echarts.ECharts | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['topology-mini'],
    queryFn: () => topologyApi.getGraph(),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const nodes: TopologyNode[] = data?.nodes ?? []
  const edges: TopologyEdge[] = data?.edges ?? []

  useEffect(() => {
    if (!chartRef.current) return
    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current, 'dark')
    }
    const chart = chartInstance.current

    if (nodes.length === 0) return

    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      animation: false,
      tooltip: {
        trigger: 'item',
        formatter: (params: unknown) => {
          const p = params as { data?: { name?: string; type?: string } }
          const d = p.data
          if (!d?.name) return ''
          return `<span style="font-size:12px">${d.name}<br/><span style="color:#71717a">${d.type ?? ''}</span></span>`
        },
      },
      series: [{
        type: 'graph',
        layout: 'force',
        roam: false,
        draggable: false,
        force: { repulsion: 80, gravity: 0.15, edgeLength: 60 },
        label: {
          show: nodes.length <= 20,
          position: 'bottom',
          fontSize: 10,
          color: '#a1a1aa',
          formatter: (params: unknown) => {
            const p = params as { data?: { name?: string } }
            const name = p.data?.name ?? ''
            return name.length > 12 ? name.slice(0, 12) + '…' : name
          },
        },
        data: nodes.map((n) => ({
          ...n,
          id: n.device_id,
          symbolSize: n.type === 'router' ? 16 : n.type === 'switch' ? 14 : 10,
          itemStyle: { color: nodeColor(n.type) },
        })),
        edges: edges.map((e) => ({
          source: e.src_id,
          target: e.dst_id,
          lineStyle: { color: '#3f3f46', width: 1 },
        })),
      }],
    }
    chart.setOption(option, true)

    const el = chartRef.current
    const ro = new ResizeObserver(() => chart.resize())
    ro.observe(el)
    return () => ro.disconnect()
  }, [nodes, edges])

  useEffect(() => {
    return () => chartInstance.current?.dispose()
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
        Yükleniyor...
      </div>
    )
  }

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
        Topoloji verisi yok
      </div>
    )
  }

  return <div ref={chartRef} className="w-full h-full" />
}
