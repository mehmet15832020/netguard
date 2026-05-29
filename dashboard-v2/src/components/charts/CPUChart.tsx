'use client'

import ReactECharts from 'echarts-for-react'
import type { MetricSnapshot } from '@/types/models'
import { TOOLTIP_BASE, CATEGORY_AXIS, VALUE_AXIS, CHART_COLORS } from '@/lib/echarts-theme'

interface CPUChartProps {
  snapshots: MetricSnapshot[]
}

export function CPUChart({ snapshots }: CPUChartProps) {
  const times = snapshots.map((s) =>
    new Date(s.collected_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  )
  const values = snapshots.map((s) => s.cpu.usage_percent.toFixed(1))

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 16, right: 16, bottom: 32, left: 48, containLabel: false },
    xAxis: {
      type: 'category',
      data: times,
      ...CATEGORY_AXIS,
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: 100,
      ...VALUE_AXIS,
      axisLabel: { ...VALUE_AXIS.axisLabel, formatter: '{value}%' },
    },
    series: [
      {
        data: values,
        type: 'line',
        smooth: true,
        symbol: 'none',
        lineStyle: { color: CHART_COLORS.cyber, width: 2 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(56,189,248,0.25)' },
              { offset: 1, color: 'rgba(56,189,248,0.02)' },
            ],
          },
        },
      },
    ],
    tooltip: {
      trigger: 'axis',
      ...TOOLTIP_BASE,
      formatter: (params: { name: string; value: string }[]) =>
        `${params[0].name}<br/>CPU: <b>${params[0].value}%</b>`,
    },
  }

  return (
    <ReactECharts
      option={option}
      style={{ height: '180px', width: '100%' }}
      notMerge
    />
  )
}
