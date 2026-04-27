'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState } from 'react'
import {
  LayoutDashboard, Bell, Shield, FileText, GitMerge, Settings, LogOut,
  Server, Network, Monitor, Radar, Share2, FileDown, Wrench,
  ClipboardList, ShieldAlert, Crosshair, Swords, ShieldCheck, ChevronLeft,
  ChevronRight, Zap,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { auth, authApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'

const SECTIONS = [
  {
    label: '',
    items: [
      { href: '/overview', label: 'Genel Bakış', icon: LayoutDashboard },
    ],
  },
  {
    label: 'Tehdit Tespiti',
    items: [
      { href: '/alerts',      label: 'Alertler',      icon: Bell },
      { href: '/correlation', label: 'Korelasyon',    icon: GitMerge },
      { href: '/timeline',    label: 'Kill Chain',    icon: Swords },
      { href: '/mitre',       label: 'MITRE ATT&CK',  icon: Crosshair },
    ],
  },
  {
    label: 'Ağ İzleme',
    items: [
      { href: '/devices',   label: 'Cihazlar',  icon: Monitor },
      { href: '/topology',  label: 'Topoloji',  icon: Share2 },
      { href: '/agents',    label: 'Agents',    icon: Server },
      { href: '/snmp',      label: 'SNMP',      icon: Network },
      { href: '/discovery', label: 'Keşif',     icon: Radar },
    ],
  },
  {
    label: 'Araştırma',
    items: [
      { href: '/logs',      label: 'Loglar',            icon: FileText },
      { href: '/security',  label: 'Güvenlik Olayları', icon: Shield },
      { href: '/incidents', label: 'Incidents',         icon: ShieldAlert },
    ],
  },
  {
    label: 'Yönetim',
    items: [
      { href: '/compliance',  label: 'Compliance',       icon: ShieldCheck },
      { href: '/reports',     label: 'Raporlar',         icon: FileDown },
      { href: '/audit',       label: 'Denetim Günlüğü',  icon: ClipboardList },
      { href: '/maintenance', label: 'Bakım',            icon: Wrench },
      { href: '/settings',    label: 'Ayarlar',          icon: Settings },
    ],
  },
]

export function Sidebar() {
  const pathname = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const markAllRead = useAlertStore((s) => s.markAllRead)
  const [collapsed, setCollapsed] = useState(false)

  const handleLogout = async () => {
    try { await authApi.logout() } catch { /* ignore */ }
    auth.removeToken()
    window.location.href = '/login'
  }

  return (
    <aside className={cn(
      'relative flex flex-col min-h-screen bg-[#0f1117] border-r border-white/[0.06] transition-all duration-200 flex-shrink-0',
      collapsed ? 'w-[56px]' : 'w-[220px]',
    )}>
      {/* Logo */}
      <div className={cn(
        'flex items-center gap-2.5 border-b border-white/[0.06] flex-shrink-0',
        collapsed ? 'px-3 py-4 justify-center' : 'px-4 py-4',
      )}>
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-indigo-500/20 flex-shrink-0">
          <Zap size={14} className="text-indigo-400" />
        </div>
        {!collapsed && (
          <div>
            <span className="font-bold text-sm text-zinc-100 tracking-tight">NetGuard</span>
            <span className="block text-[10px] text-zinc-500 leading-tight">Açık Kaynak NDR</span>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 space-y-4 scrollbar-none">
        {SECTIONS.map((section) => (
          <div key={section.label || '__top'}>
            {!collapsed && section.label && (
              <p className="px-4 mb-1 text-[10px] font-semibold tracking-widest text-zinc-600 uppercase">
                {section.label}
              </p>
            )}
            <div className="space-y-0.5 px-2">
              {section.items.map(({ href, label, icon: Icon }) => {
                const active = pathname === href || pathname.startsWith(href + '/')
                return (
                  <Link
                    key={href}
                    href={href}
                    onClick={href === '/alerts' ? markAllRead : undefined}
                    title={collapsed ? label : undefined}
                    className={cn(
                      'flex items-center gap-2.5 rounded-md text-[13px] transition-all duration-100 relative group',
                      collapsed ? 'px-2 py-2 justify-center' : 'px-2.5 py-1.5',
                      active
                        ? 'bg-indigo-500/15 text-indigo-400'
                        : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.05]',
                    )}
                  >
                    {active && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-indigo-500 rounded-r-full" />
                    )}
                    <Icon size={15} className="flex-shrink-0" />
                    {!collapsed && <span className="flex-1 font-medium">{label}</span>}
                    {!collapsed && href === '/alerts' && unreadCount > 0 && (
                      <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold">
                        {unreadCount > 99 ? '99+' : unreadCount}
                      </span>
                    )}
                    {collapsed && href === '/alerts' && unreadCount > 0 && (
                      <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-red-500" />
                    )}
                    {collapsed && (
                      <div className="absolute left-full ml-2 px-2 py-1 rounded bg-zinc-800 text-zinc-200 text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 border border-white/10">
                        {label}
                      </div>
                    )}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Alt: Çıkış + Collapse */}
      <div className="border-t border-white/[0.06] p-2 space-y-0.5 flex-shrink-0">
        <button
          onClick={handleLogout}
          title={collapsed ? 'Çıkış Yap' : undefined}
          className={cn(
            'flex items-center gap-2.5 w-full rounded-md text-[13px] text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.05] transition-colors',
            collapsed ? 'px-2 py-2 justify-center' : 'px-2.5 py-1.5',
          )}
        >
          <LogOut size={15} className="flex-shrink-0" />
          {!collapsed && <span className="font-medium">Çıkış Yap</span>}
        </button>
      </div>

      {/* Collapse butonu */}
      <button
        onClick={() => setCollapsed(v => !v)}
        className="absolute -right-3 top-[52px] w-6 h-6 rounded-full bg-zinc-800 border border-white/10 flex items-center justify-center text-zinc-400 hover:text-zinc-100 hover:bg-zinc-700 transition-colors z-10"
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
      </button>
    </aside>
  )
}
