'use client'

import Link from 'next/link'
import { cn } from '@/lib/utils'

interface StatCardProps {
  label: string
  value: string | number
  sub?: string
  icon: React.ElementType
  iconCls?: string
  valueCls?: string
  accentCls?: string
  href?: string
}

export function StatCard({ label, value, sub, icon: Icon, iconCls, valueCls, accentCls, href }: StatCardProps) {
  const inner = (
    <div className="relative bg-[#0d1526] border border-sky-900/25 rounded-xl p-4 overflow-hidden hover:border-sky-800/40 transition-colors group h-full">
      {accentCls && (
        <div className={cn('absolute left-0 top-3 bottom-3 w-0.5 rounded-r-full', accentCls)} />
      )}
      <div className="flex items-start justify-between mb-3">
        <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0', iconCls ?? 'bg-sky-500/10 border border-sky-500/20 text-sky-400')}>
          <Icon size={16} />
        </div>
      </div>
      <p className={cn('text-3xl font-bold tabular-nums leading-none', valueCls ?? 'text-slate-100')}>{value}</p>
      <p className="text-[11px] text-slate-500 mt-2 font-medium leading-tight">{label}</p>
      {sub && <p className="text-[10px] text-slate-600 mt-1.5 leading-tight">{sub}</p>}
    </div>
  )
  return href ? <Link href={href} className="block">{inner}</Link> : inner
}

interface KpiCardProps {
  label: string
  value: string | number
  sub?: string
  icon: React.ElementType
  iconCls?: string
  valueCls?: string
  href?: string
}

export function KpiCard({ label, value, sub, icon: Icon, iconCls, valueCls, href }: KpiCardProps) {
  const inner = (
    <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 flex items-center gap-3">
      <div className={cn('w-10 h-10 rounded-xl border flex items-center justify-center flex-shrink-0', iconCls ?? 'bg-sky-950/20 border-sky-900/15 text-slate-600')}>
        <Icon size={18} />
      </div>
      <div className="min-w-0">
        <p className={cn('text-3xl font-bold tabular-nums leading-none', valueCls ?? 'text-slate-100')}>{value}</p>
        <p className="text-[11px] text-slate-500 mt-1.5 leading-tight">{label}</p>
        {sub && <p className="text-[10px] text-slate-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
  return href ? <Link href={href} className="block">{inner}</Link> : inner
}
