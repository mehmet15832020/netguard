'use client'

import { useState } from 'react'
import { FileDown, FileText, Shield, Bell, Share2, BarChart3, Loader2, CheckCircle } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { reportsApi, type ReportSummary } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { SkeletonStatGrid } from '@/components/ui/skeleton'
import type { Severity } from '@/types/models'

type ReportType = 'devices' | 'alerts' | 'security' | 'topology'

const REPORTS: { type: ReportType; label: string; desc: string; icon: React.ElementType; color: string }[] = [
  {
    type:  'devices',
    label: 'Cihaz Envanteri',
    desc:  'Tüm kayıtlı cihazlar — tip, IP, durum, vendor',
    icon:  FileText,
    color: 'text-sky-400',
  },
  {
    type:  'alerts',
    label: 'Alert Geçmişi',
    desc:  'Aktif ve çözümlenen alertlerin tamamı',
    icon:  Bell,
    color: 'text-yellow-400',
  },
  {
    type:  'security',
    label: 'Güvenlik Olayları',
    desc:  'SSH başarısız giriş, sudo, SNMP trap',
    icon:  Shield,
    color: 'text-red-400',
  },
  {
    type:  'topology',
    label: 'Topoloji Kenarları',
    desc:  'ARP/LLDP/subnet ile keşfedilen bağlantılar',
    icon:  Share2,
    color: 'text-emerald-400',
  },
]

function SummaryCard({ summary }: { summary: ReportSummary }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div className="ui-panel p-4">
        <p className="text-xs text-slate-500 mb-1">Toplam Cihaz</p>
        <p className="text-2xl font-semibold text-slate-100">{summary.devices.total}</p>
        <div className="mt-2 flex flex-wrap gap-1">
          {Object.entries(summary.devices.by_type).map(([t, n]) => (
            <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-sky-950/30 border border-sky-900/15 text-slate-500">
              {t}: {n}
            </span>
          ))}
        </div>
      </div>

      <div className="ui-panel p-4">
        <p className="text-xs text-slate-500 mb-1">Aktif Alert</p>
        <p className="text-2xl font-semibold text-slate-100">{summary.alerts.active}</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {Object.entries(summary.alerts.by_severity).map(([s, n]) => (
            <span key={s} className="flex items-center gap-1">
              <SeverityBadge severity={s as Severity} />
              <span className="text-xs text-slate-500">{n}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="ui-panel p-4">
        <p className="text-xs text-slate-500 mb-1">Güvenlik Olayı</p>
        <p className="text-2xl font-semibold text-slate-100">{summary.security.total}</p>
        <div className="mt-2 flex flex-wrap gap-1">
          {Object.entries(summary.security.by_type).slice(0, 3).map(([t, n]) => (
            <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-sky-950/30 border border-sky-900/15 text-slate-500">
              {t}: {n}
            </span>
          ))}
        </div>
      </div>

      <div className="ui-panel p-4">
        <p className="text-xs text-slate-500 mb-1">Topoloji</p>
        <p className="text-2xl font-semibold text-slate-100">{summary.topology.nodes}</p>
        <p className="text-xs text-slate-600 mt-1">node · {summary.topology.edges} kenar</p>
      </div>
    </div>
  )
}

export default function ReportsPage() {
  const [downloading, setDownloading] = useState<ReportType | null>(null)
  const [done,        setDone]        = useState<ReportType | null>(null)

  const { data: summary, isLoading } = useQuery({
    queryKey: ['report-summary'],
    queryFn:  () => reportsApi.summary(),
    refetchInterval: 60_000,
  })

  const handleDownload = async (type: ReportType) => {
    setDownloading(type)
    setDone(null)
    try {
      await reportsApi.download(type)
      setDone(type)
      setTimeout(() => setDone(null), 3000)
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <FileDown size={15} className="text-sky-400" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-slate-100 leading-tight">Raporlar</h1>
          <p className="text-xs text-slate-600">Sistem verilerini CSV olarak dışa aktar</p>
        </div>
      </div>

      {/* Summary stats */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 size={13} className="text-slate-600" />
          <h2 className="text-sm font-medium text-slate-300">Sistem Özeti</h2>
          {isLoading && <Loader2 size={12} className="animate-spin text-slate-600" />}
          {summary && (
            <span className="text-xs text-slate-700 ml-auto">
              {new Date(summary.generated_at).toLocaleTimeString('tr-TR')}
            </span>
          )}
        </div>
        {isLoading ? (
          <SkeletonStatGrid cols={4} height={96} />
        ) : summary ? (
          <SummaryCard summary={summary} />
        ) : (
          <p className="text-sm text-slate-700">Özet yüklenemedi</p>
        )}
      </div>

      {/* Download cards */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <FileDown size={13} className="text-slate-600" />
          <h2 className="text-sm font-medium text-slate-300">CSV Raporları</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {REPORTS.map(({ type, label, desc, icon: Icon, color }) => (
            <div key={type} className="ui-panel p-4 flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Icon size={14} className={color} />
                <span className="text-sm font-medium text-slate-200">{label}</span>
              </div>
              <p className="text-xs text-slate-600 flex-1">{desc}</p>
              <button
                onClick={() => handleDownload(type)}
                disabled={downloading === type}
                className="flex items-center justify-center gap-1.5 w-full py-1.5 rounded-lg text-xs border transition-colors disabled:opacity-60
                  bg-sky-950/30 border-sky-900/20 text-slate-300 hover:bg-sky-950/50
                  data-[done=true]:bg-emerald-500/10 data-[done=true]:border-emerald-500/20 data-[done=true]:text-emerald-400"
                data-done={done === type ? 'true' : 'false'}
              >
                {downloading === type ? (
                  <><Loader2 size={12} className="animate-spin" />İndiriliyor...</>
                ) : done === type ? (
                  <><CheckCircle size={12} className="text-emerald-400" />İndirildi!</>
                ) : (
                  <><FileDown size={12} />CSV İndir</>
                )}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
