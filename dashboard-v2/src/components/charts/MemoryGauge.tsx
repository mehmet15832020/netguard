'use client'

import ReactECharts from 'echarts-for-react'

interface MemoryGaugeProps {
  usagePercent: number
  usedGB: number
  totalGB: number
}

function gaugeColor(pct: number): string {
  if (pct >= 90) return '#ef4444'
  if (pct >= 70) return '#eab308'
  return '#6366f1'
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
        axisLine: { lineStyle: { width: 14, color: [[1, '#27272a']] } },
        splitLine: { show: false },
        axisTick: { show: false },
        axisLabel: { show: false },
        detail: {
          valueAnimation: true,
          fontSize: 22,
          fontWeight: 'bold',
          color: '#e4e4e7',
          formatter: '{value}%',
          offsetCenter: [0, '0%'],
        },
        title: {
          offsetCenter: [0, '30%'],
          fontSize: 11,
          color: '#71717a',
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
