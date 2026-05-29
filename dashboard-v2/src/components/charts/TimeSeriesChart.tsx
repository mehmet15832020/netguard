'use client'

import ReactECharts from 'echarts-for-react'
import type { TimeSeries } from '@/lib/api'
import { TOOLTIP_BASE, CATEGORY_AXIS, VALUE_AXIS, CHART_COLORS } from '@/lib/echarts-theme'

interface TimeSeriesChartProps {
  data: TimeSeries[]
  label: string
  color?: string
  unit?: string
  height?: number
}

export function TimeSeriesChart({
  data,
  label,
  color = CHART_COLORS.cyber,
  unit = '',
  height = 160,
}: TimeSeriesChartProps) {
  const times = data.map((d) =>
    new Date(d.t).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
  )
  const values = data.map((d) => d.v)

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 12, right: 12, bottom: 28, left: 44, containLabel: false },
    xAxis: {
      type: 'category',
      data: times,
      ...CATEGORY_AXIS,
    },
    yAxis: {
      type: 'value',
      ...VALUE_AXIS,
      axisLabel: { ...VALUE_AXIS.axisLabel, formatter: `{value}${unit}` },
    },
    series: [
      {
        data: values,
        type: 'line',
        smooth: true,
        symbol: 'none',
        lineStyle: { color, width: 2 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: color + '4d' },
              { offset: 1, color: color + '05' },
            ],
          },
        },
      },
    ],
    tooltip: {
      trigger: 'axis',
      ...TOOLTIP_BASE,
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}<br/>${label}: <b>${params[0].value}${unit}</b>`,
    },
  }

  return (
    <ReactECharts
      option={option}
      style={{ height: `${height}px`, width: '100%' }}
      notMerge
    />
  )
}
