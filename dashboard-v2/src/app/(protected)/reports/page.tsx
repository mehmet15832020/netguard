'use client'

import { useState } from 'react'
import { FileDown, FileText, Shield, Bell, Share2, BarChart3, Loader2, CheckCircle } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { reportsApi, type ReportSummary } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/ui/severity-badge'
import type { Severity } from '@/types/models'

type ReportType = 'devices' | 'alerts' | 'security' | 'topology'

const REPORTS: { type: ReportType; label: string; desc: string; icon: React.ElementType; color: string }[] = [
  {
    type: 'devices',
    label: 'Cihaz Envanteri',
    desc: 'Tüm kayıtlı cihazlar — tip, IP, durum, vendor',
    icon: FileText,
    color: 'text-indigo-400',
  },
  {
    type: 'alerts',
    label: 'Alert Geçmişi',
    desc: 'Aktif ve çözümlenen alertlerin tamamı',
    icon: Bell,
    color: 'text-yellow-400',
  },
  {
    type: 'security',
    label: 'Güvenlik Olayları',
    desc: 'SSH başarısız giriş, sudo, SNMP trap',
    icon: Shield,
    color: 'text-red-400',
  },
  {
    type: 'topology',
    label: 'Topoloji Kenarları',
    desc: 'ARP/LLDP/subnet ile keşfedilen bağlantılar',
    icon: Share2,
    color: 'text-emerald-400',
  },
]

function SummaryCard({ summary }: { summary: ReportSummary }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-4">
          <p className="text-xs text-zinc-500 mb-1">Toplam Cihaz</p>
          <p className="text-2xl font-semibold text-zinc-100">{summary.devices.total}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(summary.devices.by_type).map(([t, n]) => (
              <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{t}: {n}</span>
            ))}
          </div>
        </CardContent>
      </Card>
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-4">
          <p className="text-xs text-zinc-500 mb-1">Aktif Alert</p>
          <p className="text-2xl font-semibold text-zinc-100">{summary.alerts.active}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(summary.alerts.by_severity).map(([s, n]) => (
              <span key={s} className="flex items-center gap-1">
                <SeverityBadge severity={s as Severity} />
                <span className="text-xs text-zinc-400">{n}</span>
              </span>
            ))}
          </div>
        </CardContent>
      </Card>
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-4">
          <p className="text-xs text-zinc-500 mb-1">Güvenlik Olayı</p>
          <p className="text-2xl font-semibold text-zinc-100">{summary.security.total}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(summary.security.by_type).slice(0, 3).map(([t, n]) => (
              <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{t}: {n}</span>
            ))}
          </div>
        </CardContent>
      </Card>
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-4">
          <p className="text-xs text-zinc-500 mb-1">Topoloji</p>
          <p className="text-2xl font-semibold text-zinc-100">{summary.topology.nodes}</p>
          <p className="text-xs text-zinc-500 mt-1">
            node · {summary.topology.edges} kenar
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

export default function ReportsPage() {
  const [downloading, setDownloading] = useState<ReportType | null>(null)
  const [done, setDone] = useState<ReportType | null>(null)

  const { data: summary, isLoading } = useQuery({
    queryKey: ['report-summary'],
    queryFn: () => reportsApi.summary(),
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
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Raporlar</h1>
        <p className="text-sm text-zinc-500 mt-0.5">Sistem verilerini CSV olarak dışa aktar</p>
      </div>

      {/* Özet istatistikler */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 size={14} className="text-zinc-400" />
          <h2 className="text-sm font-medium text-zinc-300">Sistem Özeti</h2>
          {isLoading && <Loader2 size={12} className="animate-spin text-zinc-500" />}
          {summary && (
            <span className="text-xs text-zinc-600 ml-auto">
              {new Date(summary.generated_at).toLocaleTimeString('tr-TR')}
            </span>
          )}
        </div>
        {summary
          ? <SummaryCard summary={summary} />
          : !isLoading && <p className="text-sm text-zinc-600">Özet yüklenemedi</p>
        }
      </div>

      {/* İndirme kartları */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <FileDown size={14} className="text-zinc-400" />
          <h2 className="text-sm font-medium text-zinc-300">CSV Raporları</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {REPORTS.map(({ type, label, desc, icon: Icon, color }) => (
            <Card key={type} className="bg-zinc-900 border-zinc-800">
              <CardHeader className="pb-2 pt-4 px-4">
                <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
                  <Icon size={14} className={color} />
                  {label}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <p className="text-xs text-zinc-500 mb-4">{desc}</p>
                <Button
                  onClick={() => handleDownload(type)}
                  disabled={downloading === type}
                  variant="outline"
                  size="sm"
                  className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 w-full"
                >
                  {downloading === type ? (
                    <><Loader2 size={12} className="mr-2 animate-spin" />İndiriliyor...</>
                  ) : done === type ? (
                    <><CheckCircle size={12} className="mr-2 text-emerald-400" />İndirildi!</>
                  ) : (
                    <><FileDown size={12} className="mr-2" />CSV İndir</>
                  )}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  )
}
