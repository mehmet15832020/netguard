'use client'

import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { AssetRiskEntry } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'

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
        ...TOOLTIP_BASE,
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
        axisLabel: { color: '#475569', fontSize: 11 },
        axisLine:  { show: false },
        axisTick:  { show: false },
        splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      },
      yAxis: {
        type: 'category',
        data: ips,
        inverse: true,
        axisLabel: { color: '#475569', fontSize: 9, fontFamily: 'monospace' },
        axisLine:  { show: false },
        axisTick:  { show: false },
        splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      },
      visualMap: {
        min: 0,
        max: 100,
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
