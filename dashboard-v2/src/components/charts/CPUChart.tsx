'use client'

import ReactECharts from 'echarts-for-react'
import type { MetricSnapshot } from '@/types/models'

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
      axisLabel: { color: '#71717a', fontSize: 10 },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: 100,
      axisLabel: { color: '#71717a', fontSize: 10, formatter: '{value}%' },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    series: [
      {
        data: values,
        type: 'line',
        smooth: true,
        symbol: 'none',
        lineStyle: { color: '#6366f1', width: 2 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(99,102,241,0.3)' },
              { offset: 1, color: 'rgba(99,102,241,0.02)' },
            ],
          },
        },
      },
    ],
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#18181b',
      borderColor: '#3f3f46',
      textStyle: { color: '#e4e4e7', fontSize: 12 },
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
