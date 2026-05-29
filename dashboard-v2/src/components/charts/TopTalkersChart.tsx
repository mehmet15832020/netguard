'use client'

import ReactECharts from 'echarts-for-react'
import { TOOLTIP_BASE, CHART_COLORS } from '@/lib/echarts-theme'

interface RankedItem {
  label: string
  count: number
}

interface TopTalkersChartProps {
  title: string
  items: RankedItem[]
  color?: string
  height?: number
}

export function TopTalkersChart({
  title,
  items,
  color = CHART_COLORS.cyber,
  height = 220,
}: TopTalkersChartProps) {
  const sorted = [...items].sort((a, b) => a.count - b.count)
  const labels = sorted.map((d) => d.label)
  const values = sorted.map((d) => d.count)
  const max    = values.reduce((m, v) => (v > m ? v : m), 1)

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 16, bottom: 8, left: 8, containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      max,
    },
    yAxis: {
      type: 'category',
      data: labels,
      axisLabel: {
        color: '#64748b',
        fontSize: 11,
        overflow: 'truncate',
        width: 120,
        formatter: (v: string) => (v.length > 18 ? v.slice(0, 16) + '…' : v),
      },
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
    },
    series: [
      {
        type: 'bar',
        data: values,
        barMaxWidth: 20,
        itemStyle: { color, borderRadius: [0, 4, 4, 0] },
        label: {
          show: true,
          position: 'right',
          color: '#64748b',
          fontSize: 10,
          formatter: '{c}',
        },
      },
    ],
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      ...TOOLTIP_BASE,
      formatter: (params: { name: string; value: number }[]) => {
        const p = params[0]
        const safeName = p.name.replace(/[<>&"']/g, (c) =>
          ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] ?? c)
        )
        return `<span style="color:#64748b">${safeName}</span><br/><b>${p.value.toLocaleString()}</b> paket`
      },
    },
  }

  return (
    <div>
      <p className="text-xs font-medium text-slate-400 mb-2 px-1">{title}</p>
      <ReactECharts option={option} style={{ height }} notMerge />
    </div>
  )
}
