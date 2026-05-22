'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'

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
  hours?: number
  height?: number
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  warning:  '#eab308',
  info:     '#3b82f6',
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Kritik',
  high:     'Yüksek',
  warning:  'Uyarı',
  info:     'Bilgi',
}

function fmtTime(iso: string, multiDay: boolean): string {
  const d = new Date(iso)
  const opts: Intl.DateTimeFormatOptions = multiDay
    ? { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }
    : { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }
  return multiDay
    ? d.toLocaleString('tr-TR', opts)
    : d.toLocaleTimeString('tr-TR', opts)
}

export function AlertVolumeChart({ series, hours = 24, height = 320 }: AlertVolumeChartProps) {
  const multiDay = hours > 24
  const stackOrder: Array<keyof typeof series> = ['info', 'warning', 'high', 'critical']

  const option = useMemo(() => {
    const times = (series.critical ?? []).map((p) => fmtTime(p.t, multiDay))

    return {
      backgroundColor: 'transparent',
      legend: {
        data: stackOrder.map((k) => SEVERITY_LABELS[k]),
        top: 0,
        textStyle: { color: '#a1a1aa', fontSize: 11 },
        itemWidth: 12,
        itemHeight: 8,
      },
      grid: { top: 36, right: 16, bottom: multiDay ? 48 : 32, left: 8, containLabel: true },
      xAxis: {
        type: 'category',
        data: times,
        axisLabel: { color: '#71717a', fontSize: 10, rotate: multiDay ? 30 : 0 },
        axisLine: { lineStyle: { color: '#3f3f46' } },
        splitLine: { show: false },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        axisLabel: { color: '#71717a', fontSize: 10 },
        axisLine: { show: false },
        splitLine: { lineStyle: { color: '#27272a' } },
      },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross', label: { backgroundColor: '#27272a' } },
        backgroundColor: '#18181b',
        borderColor: '#3f3f46',
        textStyle: { color: '#f4f4f5', fontSize: 12 },
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
  }, [series, hours, height])

  return (
    <ReactECharts option={option} style={{ height }} notMerge />
  )
}
