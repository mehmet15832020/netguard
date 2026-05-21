'use client'

import ReactECharts from 'echarts-for-react'

interface ProtoItem {
  protocol: string
  count: number
  pct: number
}

interface ProtocolDonutChartProps {
  protocols: ProtoItem[]
  total: number
  height?: number
}

const COLOR_PALETTE = [
  '#6366f1', '#0ea5e9', '#10b981', '#f97316',
  '#eab308', '#ef4444', '#8b5cf6', '#ec4899',
]

export function ProtocolDonutChart({ protocols, total, height = 320 }: ProtocolDonutChartProps) {
  if (protocols.length === 0) return null

  const seriesData = protocols.map((p, i) => ({
    name: p.protocol.toUpperCase(),
    value: p.count,
    itemStyle: { color: COLOR_PALETTE[i % COLOR_PALETTE.length] },
  }))

  const option = {
    backgroundColor: 'transparent',
    legend: {
      orient: 'vertical' as const,
      right: '5%',
      top: 'center',
      textStyle: { color: '#a1a1aa', fontSize: 12 },
      itemWidth: 10,
      itemHeight: 10,
      formatter: (name: string) => {
        const item = protocols.find((p) => p.protocol.toUpperCase() === name)
        return item ? `${name}  ${item.pct.toFixed(1)}%` : name
      },
    },
    graphic: [
      {
        type: 'text',
        left: '38%',
        top: '47%',
        style: {
          text: total.toLocaleString('tr-TR'),
          textAlign: 'center',
          fill: '#f4f4f5',
          fontSize: 20,
          fontWeight: 'bold',
        },
      },
      {
        type: 'text',
        left: '38%',
        top: '57%',
        style: {
          text: 'toplam',
          textAlign: 'center',
          fill: '#71717a',
          fontSize: 11,
        },
      },
    ],
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['40%', '50%'],
        data: seriesData,
        label: {
          color: '#a1a1aa',
          fontSize: 11,
          formatter: '{b}\n{d}%',
        },
        itemStyle: {
          borderRadius: 4,
          borderColor: '#18181b',
          borderWidth: 2,
        },
        emphasis: {
          scale: true,
          scaleSize: 5,
        },
      },
    ],
    tooltip: {
      trigger: 'item',
      backgroundColor: '#18181b',
      borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 12 },
      formatter: (params: { name: string; value: number; percent: number }) => {
        const safe = params.name.replace(/[<>&"']/g, (c) =>
          ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] ?? c)
        )
        return `<span style="color:#a1a1aa">${safe}</span><br/><b>${params.value.toLocaleString()}</b> (${params.percent.toFixed(1)}%)`
      },
    },
  }

  return (
    <ReactECharts option={option} style={{ height }} notMerge />
  )
}
