'use client'

import ReactECharts from 'echarts-for-react'
import { TOOLTIP_BASE, SERIES_PALETTE, LEGEND_TEXT } from '@/lib/echarts-theme'

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

export function ProtocolDonutChart({ protocols, total, height = 320 }: ProtocolDonutChartProps) {
  if (protocols.length === 0) return null

  const seriesData = protocols.map((p, i) => ({
    name: p.protocol.toUpperCase(),
    value: p.count,
    itemStyle: { color: SERIES_PALETTE[i % SERIES_PALETTE.length] },
  }))

  const option = {
    backgroundColor: 'transparent',
    legend: {
      orient: 'vertical' as const,
      right: '5%',
      top: 'center',
      textStyle: { ...LEGEND_TEXT, fontSize: 12 },
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
          fill: '#cbd5e1',
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
          fill: '#475569',
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
          color: '#64748b',
          fontSize: 11,
          formatter: '{b}\n{d}%',
        },
        itemStyle: {
          borderRadius: 4,
          borderColor: '#0a1120',
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
      ...TOOLTIP_BASE,
      formatter: (params: { name: string; value: number; percent: number }) => {
        const safe = params.name.replace(/[<>&"']/g, (c) =>
          ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] ?? c)
        )
        return `<span style="color:#64748b">${safe}</span><br/><b>${params.value.toLocaleString()}</b> (${params.percent.toFixed(1)}%)`
      },
    },
  }

  return (
    <ReactECharts option={option} style={{ height }} notMerge />
  )
}
