'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'

interface TrafficPoint {
  t: string
  v: number
}

interface TrafficVolumeChartProps {
  series: {
    east_west:  TrafficPoint[]
    ns_egress:  TrafficPoint[]
    ns_ingress: TrafficPoint[]
  }
  hours?: number
  height?: number
}

const TRAFFIC_COLORS: Record<string, string> = {
  east_west:  '#6366f1',
  ns_egress:  '#f97316',
  ns_ingress: '#ef4444',
}

const TRAFFIC_LABELS: Record<string, string> = {
  east_west:  'İç ↔ İç (East-West)',
  ns_egress:  'İç → Dış (N-S Egress)',
  ns_ingress: 'Dış → İç (N-S Ingress)',
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

export function TrafficVolumeChart({ series, hours = 24, height = 320 }: TrafficVolumeChartProps) {
  const multiDay = hours > 24
  const stackOrder: Array<keyof typeof series> = ['ns_ingress', 'ns_egress', 'east_west']

  const option = useMemo(() => {
    const src =
      series.east_west?.length
        ? series.east_west
        : series.ns_egress?.length
          ? series.ns_egress
          : series.ns_ingress ?? []
    const times = src.map((p) => fmtTime(p.t, multiDay))

    return {
      backgroundColor: 'transparent',
      legend: {
        data: stackOrder.map((k) => TRAFFIC_LABELS[k]),
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
        formatter: (params: unknown) => {
          if (!Array.isArray(params)) return ''
          return (params as Array<{ seriesName: string; value: number; marker: string }>)
            .map((p) => `${p.marker} ${p.seriesName}: ${p.value.toLocaleString('tr-TR')}`)
            .join('<br/>')
        },
      },
      series: stackOrder.map((key) => ({
        name: TRAFFIC_LABELS[key],
        type: 'line',
        stack: 'total',
        smooth: true,
        areaStyle: { opacity: 0.5 },
        lineStyle: { width: 1.5 },
        itemStyle: { color: TRAFFIC_COLORS[key] },
        color: TRAFFIC_COLORS[key],
        data: (series[key] ?? []).map((p) => p.v),
        emphasis: { focus: 'series' },
      })),
    }
  }, [series, hours])

  return (
    <ReactECharts option={option} style={{ height }} notMerge />
  )
}
