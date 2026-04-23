'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, RefreshCw, Archive, Database, HardDrive, Clock } from 'lucide-react'
import { maintenanceApi, type RetentionReport } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

function PolicyRow({ label, days }: { label: string; days: number }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-zinc-800 last:border-0">
      <span className="text-sm text-zinc-400">{label}</span>
      <span className="text-sm font-mono text-zinc-200">{days} gün</span>
    </div>
  )
}

function TableRow({ name, count }: { name: string; count: number }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-zinc-800 last:border-0">
      <span className="text-sm font-mono text-zinc-400">{name}</span>
      <span className="text-sm text-zinc-200">{count < 0 ? '—' : count.toLocaleString()}</span>
    </div>
  )
}

function ReportCard({ report }: { report: RetentionReport }) {
  const tables = Object.entries(report.tables)
  return (
    <Card className="bg-zinc-900 border-zinc-700">
      <CardHeader className="pb-2 pt-4 px-4">
        <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
          <RefreshCw size={14} className="text-emerald-400" />
          Cleanup Tamamlandı — {report.elapsed_seconds}s
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="bg-zinc-800 rounded-md p-3">
            <p className="text-xl font-semibold text-indigo-400">{report.total_archived}</p>
            <p className="text-xs text-zinc-500 mt-0.5">Arşivlendi</p>
          </div>
          <div className="bg-zinc-800 rounded-md p-3">
            <p className="text-xl font-semibold text-red-400">{report.total_deleted}</p>
            <p className="text-xs text-zinc-500 mt-0.5">Silindi</p>
          </div>
          <div className="bg-zinc-800 rounded-md p-3">
            <p className="text-xl font-semibold text-amber-400">{report.purged_archives}</p>
            <p className="text-xs text-zinc-500 mt-0.5">Arşiv Temizlendi</p>
          </div>
        </div>
        <div className="space-y-1">
          {tables.map(([table, result]) => (
            <div key={table} className="flex items-center justify-between text-xs py-1 border-b border-zinc-800 last:border-0">
              <span className="font-mono text-zinc-400">{table}</span>
              {'error' in result ? (
                <span className="text-red-400">{result.error}</span>
              ) : (
                <span className="text-zinc-300">
                  {result.archived} arşiv · {result.deleted} silindi
                </span>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
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
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Bakım</h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            Log retention politikası ve veritabanı temizliği
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={13} className="mr-1.5" />
            Yenile
          </Button>
          <Button
            size="sm"
            onClick={() => runCleanup()}
            disabled={isPending}
            className="bg-red-700 hover:bg-red-600 text-white"
          >
            {isPending
              ? <><span className="animate-spin mr-1.5">⟳</span>Temizleniyor...</>
              : <><Trash2 size={13} className="mr-1.5" />Manuel Cleanup</>
            }
          </Button>
        </div>
      </div>

      {lastReport && <ReportCard report={lastReport} />}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Tablo Kayıt Sayıları */}
        <Card className="bg-zinc-900 border-zinc-800 md:col-span-2">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
              <Database size={14} /> Tablo Durumu
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-zinc-500">Yükleniyor...</p>
            ) : status ? (
              Object.entries(status.table_counts).map(([name, count]) => (
                <TableRow key={name} name={name} count={count} />
              ))
            ) : null}
          </CardContent>
        </Card>

        {/* Retention Politikası */}
        <div className="space-y-4">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
                <Clock size={14} /> Retention Politikası
              </CardTitle>
            </CardHeader>
            <CardContent>
              {status ? (
                <>
                  <PolicyRow label="Normalized Logs" days={status.retention_policy.normalized_logs_days} />
                  <PolicyRow label="Security Events" days={status.retention_policy.security_events_days} />
                  <PolicyRow label="Correlated Events" days={status.retention_policy.correlated_events_days} />
                  <PolicyRow label="Resolved Alerts" days={status.retention_policy.alerts_resolved_days} />
                  <PolicyRow label="Arşiv Toplam" days={status.retention_policy.archive_total_days} />
                </>
              ) : (
                <p className="text-sm text-zinc-500">Yükleniyor...</p>
              )}
            </CardContent>
          </Card>

          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
                <Archive size={14} /> Arşiv
              </CardTitle>
            </CardHeader>
            <CardContent>
              {status ? (
                <>
                  <div className="flex justify-between py-2 border-b border-zinc-800">
                    <span className="text-xs text-zinc-500">Dosya Sayısı</span>
                    <span className="text-sm text-zinc-200">{status.archive.file_count}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-zinc-800">
                    <span className="text-xs text-zinc-500">Toplam Boyut</span>
                    <span className="text-sm text-zinc-200">{status.archive.total_size_mb} MB</span>
                  </div>
                  <div className="py-2">
                    <span className="text-xs text-zinc-600 font-mono break-all">{status.archive.directory}</span>
                  </div>
                </>
              ) : (
                <p className="text-sm text-zinc-500">Yükleniyor...</p>
              )}
            </CardContent>
          </Card>

          <Card className="bg-zinc-900/50 border-zinc-800/50">
            <CardContent className="py-4">
              <div className="flex items-start gap-2">
                <HardDrive size={13} className="text-zinc-600 mt-0.5 shrink-0" />
                <p className="text-xs text-zinc-600">
                  Cleanup otomatik olarak her gece 02:00 UTC'de çalışır.
                  Manuel tetiklemek için "Manuel Cleanup" butonunu kullan.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
