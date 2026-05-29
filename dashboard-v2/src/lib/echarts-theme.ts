/**
 * NetGuard ECharts Theme — deep navy + cyber cyan palette
 * Import and spread into chart option objects for consistent styling.
 */

export const CHART_COLORS = {
  cyber:   '#38bdf8',  // sky-400  — live data, primary series
  indigo:  '#6366f1',  // indigo-500
  emerald: '#10b981',  // emerald-500
  amber:   '#f59e0b',  // amber-500
  rose:    '#f43f5e',  // rose-500
  violet:  '#8b5cf6',  // violet-500
  cyan:    '#06b6d4',  // cyan-500
  orange:  '#f97316',  // orange-500
} as const

export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  warning:  '#eab308',
  info:     '#3b82f6',
} as const

export const SERIES_PALETTE = [
  CHART_COLORS.cyber,
  CHART_COLORS.indigo,
  CHART_COLORS.emerald,
  CHART_COLORS.amber,
  CHART_COLORS.rose,
  CHART_COLORS.violet,
  CHART_COLORS.cyan,
  CHART_COLORS.orange,
]

/** Shared tooltip config */
export const TOOLTIP_BASE = {
  backgroundColor:   '#0a1120',
  borderColor:       'rgba(56,189,248,0.18)',
  textStyle:         { color: '#cbd5e1', fontSize: 12 },
  extraCssText:      'box-shadow: 0 8px 24px rgba(0,0,0,0.5);',
} as const

/** Shared axis config */
export const AXIS_BASE = {
  axisLine:  { show: false },
  axisTick:  { show: false },
  axisLabel: { color: '#475569', fontSize: 10 },
  splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
} as const

/** Legend text style */
export const LEGEND_TEXT = { color: '#64748b', fontSize: 11 } as const

/** Category axis (no split lines) */
export const CATEGORY_AXIS = {
  ...AXIS_BASE,
  splitLine: { show: false },
} as const

/** Value axis */
export const VALUE_AXIS = {
  ...AXIS_BASE,
} as const

/** Grid with reasonable padding */
export const GRID_DEFAULT = {
  top: 12, right: 12, bottom: 24, left: 44, containLabel: false,
} as const

/** Grid tight for sparklines */
export const GRID_SPARKLINE = {
  top: 4, right: 4, bottom: 4, left: 4,
} as const

/** Common line series defaults */
export function lineSeries(
  name: string,
  data: number[],
  color: string,
  opts?: { stack?: string; smooth?: number; areaOpacity?: number }
) {
  const smooth       = opts?.smooth ?? 0.3
  const areaOpacity  = opts?.areaOpacity ?? 0.12
  return {
    name,
    type:        'line',
    stack:       opts?.stack,
    smooth,
    symbol:      'none',
    data,
    lineStyle:   { color, width: 1.5 },
    itemStyle:   { color },
    areaStyle:   areaOpacity > 0 ? { color: color + Math.round(areaOpacity * 255).toString(16).padStart(2, '0') } : undefined,
  }
}
