'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { MttdMttrDayPoint } from '@/lib/api'
import { TOOLTIP_BASE, CATEGORY_AXIS, VALUE_AXIS, LEGEND_TEXT } from '@/lib/echarts-theme'

function fmtMin(m: number): string {
  if (m === 0) return '—'
  if (m < 60) return `${m.toFixed(0)}dk`
  const h = m / 60
  if (h < 24) return `${h.toFixed(1)}s`
  return `${(h / 24).toFixed(1)}g`
}

interface Props {
  trend: MttdMttrDayPoint[]
  height?: number
}

export function MttdMttrChart({ trend, height = 280 }: Props) {
  const option = useMemo(() => ({
    backgroundColor: 'transparent',
    grid: { top: 24, right: 20, bottom: 56, left: 20, containLabel: true },
    legend: {
      data: ['MTTD', 'MTTR'],
      bottom: 0,
      textStyle: { ...LEGEND_TEXT },
    },
    tooltip: {
      trigger: 'axis',
      ...TOOLTIP_BASE,
      formatter: (params: unknown) => {
        const items = params as { seriesName: string; value: number; axisValue: string }[]
        return [
          `<b>${items[0]?.axisValue}</b>`,
          ...items.map(p => `${p.seriesName}: <b>${fmtMin(p.value ?? 0)}</b>`),
        ].join('<br/>')
      },
    },
    xAxis: {
      type: 'category',
      data: trend.map(p => p.date.slice(5)),
      ...CATEGORY_AXIS,
      axisLabel: { ...CATEGORY_AXIS.axisLabel, fontSize: 9, rotate: 30, interval: Math.floor(trend.length / 10) },
    },
    yAxis: {
      type: 'value',
      name: 'Dakika',
      nameTextStyle: { color: '#475569', fontSize: 10 },
      ...VALUE_AXIS,
      axisLabel: {
        ...VALUE_AXIS.axisLabel,
        fontSize: 9,
        formatter: (v: number) => (v >= 60 ? `${(v / 60).toFixed(0)}s` : `${v}dk`),
      },
    },
    series: [
      {
        name: 'MTTD',
        type: 'line',
        data: trend.map(p => p.mttd_minutes || null),
        connectNulls: false,
        smooth: true,
        symbol: 'circle',
        symbolSize: 4,
        itemStyle: { color: '#60a5fa' },
        lineStyle: { color: '#60a5fa', width: 2 },
        areaStyle: { color: 'rgba(96,165,250,0.08)' },
      },
      {
        name: 'MTTR',
        type: 'line',
        data: trend.map(p => p.mttr_minutes || null),
        connectNulls: false,
        smooth: true,
        symbol: 'circle',
        symbolSize: 4,
        itemStyle: { color: '#fb923c' },
        lineStyle: { color: '#fb923c', width: 2 },
        areaStyle: { color: 'rgba(251,146,60,0.08)' },
      },
    ],
  }), [trend])

  return <ReactECharts option={option} style={{ height }} notMerge />
}
