'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import { TOOLTIP_BASE, CATEGORY_AXIS, VALUE_AXIS, LEGEND_TEXT, SEVERITY_COLORS } from '@/lib/echarts-theme'

interface AlertPoint {
  t: string
  v: number
}

interface AlertVolumeChartProps {
  series: {
    critical: AlertPoint[]
    high:     AlertPoint[]
    warning:  AlertPoint[]
    info:     AlertPoint[]
  }
  hours?:         number
  bucketMinutes?: number
  height?:        number
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Kritik',
  high:     'Yüksek',
  warning:  'Uyarı',
  info:     'Bilgi',
}

function fmtTime(iso: string, bucketMinutes: number): string {
  const d = new Date(iso)
  if (bucketMinutes <= 60) {
    return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
  }
  const day = d.getDate()
  const hh  = String(d.getHours()).padStart(2, '0')
  return `${day}. ${hh}:00`
}

export function AlertVolumeChart({ series, hours = 24, bucketMinutes = 60, height = 320 }: AlertVolumeChartProps) {
  const multiDay = hours > 24
  const stackOrder: Array<keyof typeof series> = ['info', 'warning', 'high', 'critical']

  const option = useMemo(() => {
    const times = (
      series.critical?.length  ? series.critical  :
      series.high?.length      ? series.high      :
      series.warning?.length   ? series.warning   :
      series.info             ?? []
    ).map((p) => fmtTime(p.t, bucketMinutes))

    return {
      backgroundColor: 'transparent',
      legend: {
        data: stackOrder.map((k) => SEVERITY_LABELS[k]),
        top: 0,
        textStyle: { ...LEGEND_TEXT },
        itemWidth: 12,
        itemHeight: 8,
      },
      grid: { top: 36, right: 16, bottom: multiDay ? 48 : 32, left: 8, containLabel: true },
      xAxis: {
        type: 'category',
        data: times,
        ...CATEGORY_AXIS,
        axisLabel: { ...CATEGORY_AXIS.axisLabel, rotate: multiDay ? 30 : 0 },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        ...VALUE_AXIS,
      },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross', label: { backgroundColor: '#0a1120' } },
        ...TOOLTIP_BASE,
      },
      series: stackOrder.map((key) => ({
        name: SEVERITY_LABELS[key],
        type: 'line',
        stack: 'total',
        smooth: true,
        areaStyle: { opacity: 0.6 },
        lineStyle: { width: 1.5 },
        itemStyle: { color: SEVERITY_COLORS[key] },
        color: SEVERITY_COLORS[key],
        data: (series[key] ?? []).map((p) => p.v),
        emphasis: { focus: 'series' },
      })),
    }
  }, [series, hours, bucketMinutes])

  return (
    <ReactECharts option={option} style={{ height }} notMerge />
  )
}
