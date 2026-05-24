'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { AssetRiskEntry } from '@/lib/api'

const DIMS = ['Ağ Aktivitesi', 'Kill Chain', 'Blok Durumu']

interface Props {
  assets: AssetRiskEntry[]
  height?: number
}

export function AssetRiskHeatmapChart({ assets, height = 400 }: Props) {
  const option = useMemo(() => {
    const ips = assets.map(a => a.ip)
    const scores = [
      (a: AssetRiskEntry) => a.activity_score,
      (a: AssetRiskEntry) => a.chain_score,
      (a: AssetRiskEntry) => a.block_score,
    ]
    const data: [number, number, number][] = assets.flatMap((asset, yi) =>
      scores.map((fn, xi) => [xi, yi, fn(asset)] as [number, number, number])
    )

    return {
      backgroundColor: 'transparent',
      grid: { top: 10, right: 130, bottom: 50, left: 8, containLabel: true },
      tooltip: {
        formatter: (params: unknown) => {
          const p = params as { data: [number, number, number] }
          const [xi, yi, score] = p.data
          const a = assets[yi]
          return [
            `<b class="font-mono">${a.ip}</b>`,
            `${DIMS[xi]}: <b>${score.toFixed(1)}</b>`,
            `Toplam Risk: <b>${a.total_score}</b>`,
            a.is_blocked ? '<span style="color:#f87171">● Bloklandı</span>' : '',
            `Olay: ${a.event_count}`,
          ].filter(Boolean).join('<br/>')
        },
      },
      xAxis: {
        type: 'category',
        data: DIMS,
        axisLabel: { color: '#a1a1aa', fontSize: 11 },
        axisLine:  { lineStyle: { color: '#3f3f46' } },
        splitLine: { lineStyle: { color: '#27272a' } },
      },
      yAxis: {
        type: 'category',
        data: ips,
        inverse: true,
        axisLabel: { color: '#a1a1aa', fontSize: 9, fontFamily: 'monospace' },
        axisLine:  { lineStyle: { color: '#3f3f46' } },
        splitLine: { lineStyle: { color: '#27272a' } },
      },
      visualMap: {
        min: 0,
        max: 100,
        calculable: true,
        orient: 'vertical',
        right: 0,
        top: 'center',
        inRange: { color: ['#1c1917', '#7f1d1d', '#dc2626'] },
        textStyle: { color: '#a1a1aa', fontSize: 10 },
        itemHeight: 120,
      },
      series: [{
        type: 'heatmap',
        data,
        itemStyle: { borderColor: '#09090b', borderWidth: 1 },
        emphasis: { itemStyle: { shadowBlur: 8, shadowColor: 'rgba(220,38,38,0.5)' } },
        label: {
          show: assets.length <= 12,
          color: '#e4e4e7',
          fontSize: 9,
          formatter: (p: unknown) => {
            const v = (p as { data: [number, number, number] }).data[2]
            return v > 0 ? v.toFixed(0) : ''
          },
        },
      }],
    }
  }, [assets])

  return <ReactECharts option={option} style={{ height }} notMerge />
}
