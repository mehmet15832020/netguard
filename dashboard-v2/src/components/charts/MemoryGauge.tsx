'use client'

import ReactECharts from 'echarts-for-react'
import { CHART_COLORS, SEVERITY_COLORS } from '@/lib/echarts-theme'

interface MemoryGaugeProps {
  usagePercent: number
  usedGB: number
  totalGB: number
}

function gaugeColor(pct: number): string {
  if (pct >= 90) return SEVERITY_COLORS.critical
  if (pct >= 70) return SEVERITY_COLORS.warning
  return CHART_COLORS.cyber
}

export function MemoryGauge({ usagePercent, usedGB, totalGB }: MemoryGaugeProps) {
  const color = gaugeColor(usagePercent)

  const option = {
    backgroundColor: 'transparent',
    series: [
      {
        type: 'gauge',
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        radius: '85%',
        center: ['50%', '60%'],
        pointer: { show: false },
        progress: {
          show: true,
          overlap: false,
          roundCap: true,
          clip: false,
          itemStyle: { color },
        },
        axisLine: { lineStyle: { width: 14, color: [[1, 'rgba(56,189,248,0.08)']] } },
        splitLine: { show: false },
        axisTick: { show: false },
        axisLabel: { show: false },
        detail: {
          valueAnimation: true,
          fontSize: 22,
          fontWeight: 'bold',
          color: '#cbd5e1',
          formatter: '{value}%',
          offsetCenter: [0, '0%'],
        },
        title: {
          offsetCenter: [0, '30%'],
          fontSize: 11,
          color: '#475569',
        },
        data: [{ value: usagePercent.toFixed(1), name: `${usedGB.toFixed(1)} / ${totalGB.toFixed(1)} GB` }],
      },
    ],
  }

  return (
    <ReactECharts
      option={option}
      style={{ height: '180px', width: '100%' }}
      notMerge
    />
  )
}
