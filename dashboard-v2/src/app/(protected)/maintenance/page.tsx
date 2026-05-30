'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, RefreshCw, Archive, Database, HardDrive, Clock } from 'lucide-react'
import { maintenanceApi, type RetentionReport } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'

function PolicyRow({ label, days }: { label: string; days: number }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-sky-900/10 last:border-0">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="text-sm font-mono text-slate-200">{days} gün</span>
    </div>
  )
}

function TableDataRow({ name, count }: { name: string; count: number }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-sky-900/10 last:border-0">
      <span className="text-sm font-mono text-slate-400">{name}</span>
      <span className="text-sm text-slate-200">{count < 0 ? '—' : count.toLocaleString()}</span>
    </div>
  )
}

function ReportCard({ report }: { report: RetentionReport }) {
  const tables = Object.entries(report.tables)
  return (
    <div className="bg-[#0a1120] border border-emerald-500/20 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
        <RefreshCw size={13} className="text-emerald-400" />
        <span className="text-sm font-medium text-slate-300">
          Cleanup Tamamlandı — {report.elapsed_seconds}s
        </span>
      </div>
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="bg-sky-950/30 border border-sky-900/20 rounded-lg p-3">
            <p className="text-xl font-semibold text-sky-400">{report.total_archived}</p>
            <p className="text-xs text-slate-500 mt-0.5">Arşivlendi</p>
          </div>
          <div className="bg-sky-950/30 border border-sky-900/20 rounded-lg p-3">
            <p className="text-xl font-semibold text-red-400">{report.total_deleted}</p>
            <p className="text-xs text-slate-500 mt-0.5">Silindi</p>
          </div>
          <div className="bg-sky-950/30 border border-sky-900/20 rounded-lg p-3">
            <p className="text-xl font-semibold text-amber-400">{report.purged_archives}</p>
            <p className="text-xs text-slate-500 mt-0.5">Arşiv Temizlendi</p>
          </div>
        </div>
        <div className="space-y-0.5">
          {tables.map(([table, result]) => (
            <div key={table} className="flex items-center justify-between text-xs py-1.5 border-b border-sky-900/10 last:border-0">
              <span className="font-mono text-slate-400">{table}</span>
              {'error' in result ? (
                <span className="text-red-400">{result.error}</span>
              ) : (
                <span className="text-slate-300">
                  {result.archived} arşiv · {result.deleted} silindi
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function MaintenancePage() {
  const queryClient = useQueryClient()
  const [lastReport, setLastReport] = useState<RetentionReport | null>(null)

  const { data: status, isLoading, refetch } = useQuery({
    queryKey: ['maintenance-status'],
    queryFn: maintenanceApi.status,
    refetchInterval: 30_000,
  })

  const { mutate: runCleanup, isPending } = useMutation({
    mutationFn: maintenanceApi.cleanup,
    onSuccess: (report) => {
      setLastReport(report)
      queryClient.invalidateQueries({ queryKey: ['maintenance-status'] })
    },
  })

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Database size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Bakım</h1>
            <p className="text-xs text-slate-600">Log retention politikası ve veritabanı temizliği</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors"
          >
            <RefreshCw size={12} />
            Yenile
          </button>
          <button
            onClick={() => runCleanup()}
            disabled={isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-700 hover:bg-red-600 text-white transition-colors disabled:opacity-50"
          >
            {isPending
              ? <><RefreshCw size={12} className="animate-spin" />Temizleniyor...</>
              : <><Trash2 size={12} />Manuel Cleanup</>
            }
          </button>
        </div>
      </div>

      {lastReport && <ReportCard report={lastReport} />}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Tablo Kayıt Sayıları */}
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden md:col-span-2">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
            <Database size={13} className="text-slate-500" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Tablo Durumu</span>
          </div>
          <div className="px-4 py-2">
            {isLoading ? (
              <SkeletonTable rows={6} height={36} />
            ) : status ? (
              Object.entries(status.table_counts).map(([name, count]) => (
                <TableDataRow key={name} name={name} count={count} />
              ))
            ) : null}
          </div>
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Retention Politikası */}
          <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
              <Clock size={13} className="text-slate-500" />
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Retention Politikası</span>
            </div>
            <div className="px-4 py-2">
              {status ? (
                <>
                  <PolicyRow label="Normalized Logs"   days={status.retention_policy.normalized_logs_days} />
                  <PolicyRow label="Security Events"   days={status.retention_policy.security_events_days} />
                  <PolicyRow label="Correlated Events" days={status.retention_policy.correlated_events_days} />
                  <PolicyRow label="Resolved Alerts"   days={status.retention_policy.alerts_resolved_days} />
                  <PolicyRow label="Arşiv Toplam"      days={status.retention_policy.archive_total_days} />
                </>
              ) : (
                <p className="text-sm text-slate-500 py-3">Yükleniyor...</p>
              )}
            </div>
          </div>

          {/* Arşiv */}
          <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-sky-900/15">
              <Archive size={13} className="text-slate-500" />
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Arşiv</span>
            </div>
            <div className="px-4 py-2">
              {status ? (
                <>
                  <div className="flex justify-between py-2 border-b border-sky-900/10">
                    <span className="text-xs text-slate-500">Dosya Sayısı</span>
                    <span className="text-sm text-slate-200">{status.archive.file_count}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-sky-900/10">
                    <span className="text-xs text-slate-500">Toplam Boyut</span>
                    <span className="text-sm text-slate-200">{status.archive.total_size_mb} MB</span>
                  </div>
                  <div className="py-2">
                    <span className="text-xs text-slate-600 font-mono break-all">{status.archive.directory}</span>
                  </div>
                </>
              ) : (
                <p className="text-sm text-slate-500 py-3">Yükleniyor...</p>
              )}
            </div>
          </div>

          {/* Info */}
          <div className="flex items-start gap-2 px-4 py-3 rounded-xl border border-sky-900/15 bg-sky-950/10">
            <HardDrive size={12} className="text-slate-600 mt-0.5 shrink-0" />
            <p className="text-xs text-slate-600">
              Cleanup otomatik olarak her gece 02:00 UTC'de çalışır.
              Manuel tetiklemek için "Manuel Cleanup" butonunu kullan.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
