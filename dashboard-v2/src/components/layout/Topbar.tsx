'use client'

import { usePathname } from 'next/navigation'
import { useEffect, useState } from 'react'
import { Bell, RefreshCw, User } from 'lucide-react'
import { useAlertStore } from '@/store/alertStore'

const PAGE_TITLES: Record<string, string> = {
  '/overview':    'Genel Bakış',
  '/devices':     'Cihazlar',
  '/topology':    'Ağ Topolojisi',
  '/discovery':   'Ağ Keşfi',
  '/snmp':        'SNMP İzleme',
  '/agents':      'Agents',
  '/alerts':      'Alertler',
  '/security':    'Güvenlik Olayları',
  '/correlation': 'Korelasyon',
  '/logs':        'Normalize Loglar',
  '/incidents':   'Incident Yönetimi',
  '/timeline':    'Saldırı Timeline',
  '/mitre':       'MITRE ATT&CK',
  '/compliance':  'Compliance Raporu',
  '/reports':     'Raporlar',
  '/audit':       'Denetim Günlüğü',
  '/maintenance': 'Sistem Bakım',
  '/settings':    'Ayarlar',
}

const PAGE_SECTIONS: Record<string, string> = {
  '/overview': 'NMS', '/devices': 'NMS', '/topology': 'NMS',
  '/discovery': 'NMS', '/snmp': 'NMS', '/agents': 'NMS',
  '/alerts': 'SIEM', '/security': 'SIEM', '/correlation': 'SIEM',
  '/logs': 'SIEM', '/incidents': 'SIEM', '/timeline': 'SIEM',
  '/mitre': 'Intelligence', '/compliance': 'Intelligence',
  '/reports': 'System', '/audit': 'System',
  '/maintenance': 'System', '/settings': 'System',
}

export function Topbar() {
  const pathname = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const [now, setNow] = useState(new Date())

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const title   = PAGE_TITLES[pathname]   ?? 'NetGuard'
  const section = PAGE_SECTIONS[pathname] ?? ''

  return (
    <header className="flex items-center justify-between h-12 px-5 bg-[#0f1117] border-b border-white/[0.06] flex-shrink-0">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        {section && (
          <>
            <span className="text-zinc-600 text-xs font-medium">{section}</span>
            <span className="text-zinc-700">/</span>
          </>
        )}
        <span className="text-zinc-200 font-semibold">{title}</span>
      </div>

      {/* Sağ araçlar */}
      <div className="flex items-center gap-3">
        {/* Saat */}
        <span className="text-xs text-zinc-600 font-mono tabular-nums hidden sm:block">
          {now.toLocaleTimeString('tr-TR')}
        </span>

        {/* Canlı indicator */}
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs text-zinc-500 hidden sm:block">Canlı</span>
        </div>

        {/* Bildirim */}
        <button className="relative p-1.5 rounded-md text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.05] transition-colors">
          <Bell size={15} />
          {unreadCount > 0 && (
            <span className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-red-500" />
          )}
        </button>

        {/* Kullanıcı */}
        <div className="flex items-center gap-1.5 pl-2 border-l border-white/[0.06]">
          <div className="w-6 h-6 rounded-full bg-indigo-500/20 flex items-center justify-center">
            <User size={12} className="text-indigo-400" />
          </div>
          <span className="text-xs text-zinc-400 font-medium hidden sm:block">admin</span>
        </div>
      </div>
    </header>
  )
}
