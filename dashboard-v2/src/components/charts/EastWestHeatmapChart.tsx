'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { EastWestMatrixRow } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'

interface Props {
  rows:      EastWestMatrixRow[]
  max_count: number
  height?:   number
}

export function EastWestHeatmapChart({ rows, max_count, height = 380 }: Props) {
  const option = useMemo(() => {
    const srcs = [...new Set(rows.map(r => r.src))]
    const dsts = [...new Set(rows.map(r => r.dst))]
    const data = rows.map(r => [
      dsts.indexOf(r.dst),
      srcs.indexOf(r.src),
      r.count,
    ])

    return {
      backgroundColor: 'transparent',
      grid: { top: 20, right: 130, bottom: 60, left: 8, containLabel: true },
      tooltip: {
        ...TOOLTIP_BASE,
        formatter: (params: unknown) => {
          const p = params as { data: [number, number, number] }
          const [xi, yi, v] = p.data
          return `${srcs[yi]} → ${dsts[xi]}<br/><b>${v.toLocaleString('tr-TR')}</b> bağlantı`
        },
      },
      xAxis: {
        type: 'category',
        data: dsts,
        name: 'Hedef IP',
        nameLocation: 'middle',
        nameGap: 40,
        axisLabel: { color: '#475569', fontSize: 9, rotate: 35, interval: 0 },
        axisLine:  { show: false },
        axisTick:  { show: false },
        splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      },
      yAxis: {
        type: 'category',
        data: srcs,
        name: 'Kaynak IP',
        nameLocation: 'middle',
        nameGap: 95,
        axisLabel: { color: '#475569', fontSize: 9 },
        axisLine:  { show: false },
        axisTick:  { show: false },
        splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      },
      visualMap: {
        min: 0,
        max: Math.max(max_count, 1),
        calculable: true,
        orient: 'vertical',
        right: 0,
        top: 'center',
        inRange: { color: ['#0d1526', '#7f1d1d', '#dc2626'] },
        textStyle: { color: '#64748b', fontSize: 10 },
        itemHeight: 120,
      },
      series: [{
        type: 'heatmap',
        data,
        itemStyle: { borderColor: '#040911', borderWidth: 1 },
        emphasis: {
          itemStyle: { shadowBlur: 8, shadowColor: 'rgba(220,38,38,0.5)' },
        },
        label: {
          show: dsts.length <= 8 && srcs.length <= 8,
          color: '#cbd5e1',
          fontSize: 9,
        },
      }],
    }
  }, [rows, max_count])

  return <ReactECharts option={option} style={{ height }} notMerge />
}
