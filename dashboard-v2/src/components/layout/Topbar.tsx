'use client'

import { usePathname } from 'next/navigation'
import { useEffect, useState } from 'react'
import { Bell, User, ChevronRight, Wifi, WifiOff, Search } from 'lucide-react'
import { useAlertStore } from '@/store/alertStore'
import { useQuery } from '@tanstack/react-query'
import { analyticsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useCommandPaletteStore } from '@/store/commandPaletteStore'

const PAGE_META: Record<string, { title: string; section: string }> = {
  '/overview':              { title: 'Genel Bakış',       section: 'Operasyon' },
  '/devices':               { title: 'Cihazlar',           section: 'Ağ İzleme' },
  '/topology':              { title: 'Ağ Topolojisi',      section: 'Ağ İzleme' },
  '/discovery':             { title: 'Ağ Keşfi',           section: 'Ağ İzleme' },
  '/snmp':                  { title: 'SNMP İzleme',        section: 'Ağ İzleme' },
  '/agents':                { title: 'Agents',             section: 'Ağ İzleme' },
  '/alerts':                { title: 'Alertler',           section: 'Operasyon' },
  '/incidents':             { title: 'Incidents',          section: 'Operasyon' },
  '/timeline':              { title: 'Saldırı Timeline',   section: 'Operasyon' },
  '/blocks':                { title: 'Aktif Bloklar',      section: 'Operasyon' },
  '/security':              { title: 'Güvenlik Olayları',  section: 'Araştırma' },
  '/logs':                  { title: 'Normalize Loglar',   section: 'Araştırma' },
  '/correlation':           { title: 'Korelasyon',         section: 'Tespit' },
  '/correlation-rules':     { title: 'Korelasyon Kuralları', section: 'Tespit' },
  '/mitre':                 { title: 'MITRE ATT&CK',       section: 'Tespit' },
  '/anomaly':               { title: 'Anomali Tespiti',    section: 'Tespit' },
  '/network-intelligence':  { title: 'Network Intelligence', section: 'Tespit' },
  '/sigma-rules':           { title: 'Sigma Kuralları',    section: 'Tespit' },
  '/sigma-wizard':          { title: 'Sigma Sihirbazı',    section: 'Tespit' },
  '/sigma-editor':          { title: 'YAML Editör',        section: 'Tespit' },
  '/fp-management':         { title: 'FP Yönetimi',        section: 'Tespit' },
  '/top-talkers':           { title: 'Top Talkers',        section: 'Analitik' },
  '/alert-volume':          { title: 'Alert Hacmi',        section: 'Analitik' },
  '/protocol-distribution': { title: 'Protokol Dağılımı', section: 'Analitik' },
  '/traffic-volume':        { title: 'Trafik Hacmi',       section: 'Analitik' },
  '/kill-chain-timeline':   { title: 'Kill Chain',         section: 'Analitik' },
  '/threat-intel-summary':  { title: 'Threat Intel',       section: 'Analitik' },
  '/failed-auth':           { title: 'Başarısız Auth',     section: 'Analitik' },
  '/dns-analysis':          { title: 'DNS Analiz',         section: 'Analitik' },
  '/tls-fingerprints':      { title: 'TLS / JA4',          section: 'Analitik' },
  '/beaconing':             { title: 'Beaconing',          section: 'Analitik' },
  '/east-west-matrix':      { title: 'E-W Matrix',         section: 'Analitik' },
  '/asset-risk':            { title: 'Asset Risk',         section: 'Analitik' },
  '/mttd-mttr':             { title: 'MTTD / MTTR',        section: 'Analitik' },
  '/compliance':            { title: 'Uyumluluk',          section: 'Yönetim' },
  '/reports':               { title: 'Raporlar',           section: 'Yönetim' },
  '/audit':                 { title: 'Denetim Günlüğü',   section: 'Yönetim' },
  '/maintenance':           { title: 'Sistem Bakım',       section: 'Yönetim' },
  '/settings':              { title: 'Ayarlar',            section: 'Yönetim' },
}

function DataLiveIndicator() {
  const { data } = useQuery({
    queryKey: ['source-health-topbar'],
    queryFn:  analyticsApi.sourceHealth,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  if (!data) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
        <span className="text-[11px] text-slate-600 hidden sm:block">Bağlanıyor</span>
      </div>
    )
  }

  const totalSources = data.sources.length
  const staleSources = data.sources.filter(s => s.stale).length
  const allOk        = staleSources === 0
  const allStale     = staleSources === totalSources

  if (allStale || totalSources === 0) {
    return (
      <div className="flex items-center gap-1.5" title="Tüm kaynaklar bayat">
        <WifiOff size={12} className="text-red-500" />
        <span className="text-[11px] text-red-400 hidden sm:block">Bağlantı yok</span>
      </div>
    )
  }

  return (
    <div
      className="flex items-center gap-1.5 cursor-default"
      title={staleSources > 0 ? `${staleSources}/${totalSources} kaynak bayat` : `${totalSources} kaynak aktif`}
    >
      <Wifi size={12} className={allOk ? 'text-emerald-500' : 'text-yellow-500'} />
      <span className={cn('text-[11px] hidden sm:block', allOk ? 'text-emerald-400' : 'text-yellow-400')}>
        {allOk ? 'Canlı' : `${staleSources} bayat`}
      </span>
      <span className={cn(
        'w-1.5 h-1.5 rounded-full animate-pulse',
        allOk ? 'lamp-online' : 'lamp-warn',
      )} />
    </div>
  )
}

export function Topbar() {
  const pathname    = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const [now, setNow] = useState(new Date())

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const openPalette = useCommandPaletteStore((s) => s.open)

  const meta    = PAGE_META[pathname]
  const title   = meta?.title   ?? 'NetGuard'
  const section = meta?.section ?? ''

  const timeStr = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  const dateStr = now.toLocaleDateString('tr-TR', { day: '2-digit', month: 'short' })

  return (
    <header className="flex items-center justify-between h-12 px-5 bg-[#040911] border-b border-sky-900/30 topbar-glow-bottom flex-shrink-0">
      {/* Left: breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm min-w-0">
        {section && (
          <>
            <span className="text-slate-600 text-[11px] font-medium hidden sm:block">{section}</span>
            <ChevronRight size={12} className="text-slate-700 hidden sm:block flex-shrink-0" />
          </>
        )}
        <span className="text-slate-100 font-semibold tracking-tight truncate">{title}</span>
      </div>

      {/* Right: live tools */}
      <div className="flex items-center gap-4 flex-shrink-0">
        {/* Search hint */}
        <button
          onClick={openPalette}
          className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-md border border-sky-900/25 bg-sky-950/20 text-slate-500 hover:text-slate-300 hover:border-sky-700/35 transition-colors"
        >
          <Search size={11} />
          <span className="text-[11px]">Ara...</span>
          <kbd className="px-1 py-0.5 rounded border border-sky-900/25 font-mono text-[9px] bg-sky-950/30 text-slate-600">Ctrl K</kbd>
        </button>

        {/* Clock */}
        <div className="hidden md:flex flex-col items-end leading-none">
          <span className="text-[12px] text-slate-300 font-mono tabular-nums">{timeStr}</span>
          <span className="text-[10px] text-slate-600 font-mono mt-0.5">{dateStr}</span>
        </div>

        {/* Divider */}
        <div className="w-px h-5 bg-sky-900/40 hidden md:block" />

        {/* Data freshness indicator */}
        <DataLiveIndicator />

        {/* Notification bell */}
        <button
          className="relative p-1.5 rounded-md text-slate-500 hover:text-slate-200 hover:bg-sky-950/40 transition-colors"
          title={unreadCount > 0 ? `${unreadCount} okunmamış alert` : 'Bildirimler'}
        >
          <Bell size={15} />
          {unreadCount > 0 && (
            <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full animate-lamp-critical lamp-critical" />
          )}
        </button>

        {/* Divider */}
        <div className="w-px h-5 bg-sky-900/40" />

        {/* User */}
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-full bg-gradient-to-br from-sky-500/20 to-indigo-500/20 border border-sky-500/20 flex items-center justify-center">
            <User size={12} className="text-sky-400" />
          </div>
          <span className="text-[12px] text-slate-400 font-medium hidden sm:block">admin</span>
        </div>
      </div>
    </header>
  )
}
