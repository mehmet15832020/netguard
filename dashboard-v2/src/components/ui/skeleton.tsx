import { cn } from '@/lib/utils'

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div
      className={cn('relative overflow-hidden rounded-md bg-sky-950/20 border border-sky-900/15', className)}
      style={style}
    >
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-sky-400/[0.04] to-transparent" />
    </div>
  )
}

export function SkeletonChart({ height = 220, className }: { height?: number; className?: string }) {
  return <Skeleton className={cn('w-full', className)} style={{ height }} />
}

export function SkeletonStatGrid({ cols = 3, rows = 1, height = 80 }: { cols?: number; rows?: number; height?: number }) {
  return (
    <div className={`grid grid-cols-${cols} gap-4`}>
      {Array.from({ length: cols * rows }).map((_, i) => (
        <Skeleton key={i} style={{ height }} />
      ))}
    </div>
  )
}

export function SkeletonTable({ rows = 5, height = 36 }: { rows?: number; height?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} style={{ height }} className="w-full" />
      ))}
    </div>
  )
}
