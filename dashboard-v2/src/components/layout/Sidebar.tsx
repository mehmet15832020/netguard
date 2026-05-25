'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Bell, Shield, FileText, GitMerge, Settings, LogOut,
  Server, Network, Monitor, Radar, Share2, FileDown, Wrench,
  ClipboardList, ShieldAlert, Crosshair, Swords, ChevronLeft,
  ChevronRight, Zap, Fingerprint, ShieldOff, CheckSquare, BarChart2, Activity, PieChart, TrendingUp,
  GitBranch, AlertTriangle, Lock, Globe, Radio, Grid2X2, Gauge, Clock,
  ShieldCheck, Wand2, FileCode2, ChevronDown, ChevronUp,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { auth, authApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'

type NavItem = {
  kind?: never
  href: string
  label: string
  icon: React.ElementType
}

type NavGroup = {
  kind: 'group'
  label: string
  icon: React.ElementType
  storeKey: string
  items: NavItem[]
}

type NavEntry = NavItem | NavGroup

type Section = {
  label: string
  entries: NavEntry[]
}

const SECTIONS: Section[] = [
  {
    label: '',
    entries: [
      { href: '/overview', label: 'Genel Bakış', icon: LayoutDashboard },
    ],
  },
  {
    label: 'Operasyon',
    entries: [
      { href: '/alerts',   label: 'Alertler',       icon: Bell },
      { href: '/incidents', label: 'Incidents',      icon: ShieldAlert },
      { href: '/timeline', label: 'Aktif Zincirler', icon: Swords },
      { href: '/blocks',   label: 'Aktif Bloklar',   icon: ShieldOff },
    ],
  },
  {
    label: 'Tespit',
    entries: [
      { href: '/correlation',          label: 'Korelasyon',          icon: GitMerge },
      { href: '/mitre',                label: 'MITRE ATT&CK',        icon: Crosshair },
      { href: '/network-intelligence', label: 'Network Intelligence', icon: Fingerprint },
      {
        kind: 'group',
        label: 'Kural Yönetimi',
        icon: ShieldCheck,
        storeKey: 'sidebar-rules',
        items: [
          { href: '/correlation-rules', label: 'Korelasyon Kuralları', icon: GitMerge },
          { href: '/sigma-rules',       label: 'Sigma Kuralları',      icon: ShieldCheck },
          { href: '/sigma-wizard',      label: 'Sigma Sihirbazı',      icon: Wand2 },
          { href: '/sigma-editor',      label: 'YAML Editör',          icon: FileCode2 },
        ],
      },
    ],
  },
  {
    label: 'Analitik',
    entries: [
      {
        kind: 'group',
        label: 'Dashboards',
        icon: BarChart2,
        storeKey: 'sidebar-dashboards',
        items: [
          { href: '/top-talkers',           label: 'Top Talkers',        icon: BarChart2 },
          { href: '/alert-volume',          label: 'Alert Hacmi',        icon: Activity },
          { href: '/protocol-distribution', label: 'Protokol Dağılımı',  icon: PieChart },
          { href: '/traffic-volume',        label: 'Trafik Hacmi',       icon: TrendingUp },
          { href: '/kill-chain-timeline',   label: 'Kill Chain Timeline', icon: GitBranch },
          { href: '/threat-intel-summary',  label: 'Threat Intel',       icon: AlertTriangle },
          { href: '/failed-auth',           label: 'Başarısız Auth',     icon: Lock },
          { href: '/dns-analysis',          label: 'DNS Analiz',         icon: Globe },
          { href: '/tls-fingerprints',      label: 'TLS / JA4',          icon: Fingerprint },
          { href: '/beaconing',             label: 'Beaconing',          icon: Radio },
          { href: '/east-west-matrix',      label: 'E-W Matrix',         icon: Grid2X2 },
          { href: '/asset-risk',            label: 'Asset Risk',         icon: Gauge },
          { href: '/mttd-mttr',             label: 'MTTD / MTTR',        icon: Clock },
        ],
      },
    ],
  },
  {
    label: 'Ağ İzleme',
    entries: [
      { href: '/devices',   label: 'Cihazlar', icon: Monitor },
      { href: '/topology',  label: 'Topoloji', icon: Share2 },
      { href: '/agents',    label: 'Agents',   icon: Server },
      { href: '/snmp',      label: 'SNMP',     icon: Network },
      { href: '/discovery', label: 'Keşif',    icon: Radar },
    ],
  },
  {
    label: 'Araştırma',
    entries: [
      { href: '/logs',     label: 'Loglar',      icon: FileText },
      { href: '/security', label: 'Ham Olaylar', icon: Shield },
    ],
  },
  {
    label: 'Yönetim',
    entries: [
      { href: '/reports',     label: 'Raporlar',        icon: FileDown },
      { href: '/compliance',  label: 'Uyumluluk',        icon: CheckSquare },
      { href: '/audit',       label: 'Denetim Günlüğü', icon: ClipboardList },
      { href: '/maintenance', label: 'Bakım',            icon: Wrench },
      { href: '/settings',    label: 'Ayarlar',          icon: Settings },
    ],
  },
]

const ALL_GROUP_KEYS = SECTIONS.flatMap(s =>
  s.entries.filter((e): e is NavGroup => 'kind' in e && e.kind === 'group').map(g => g.storeKey)
)

const INITIAL_GROUP_STATE = Object.fromEntries(ALL_GROUP_KEYS.map(k => [k, false]))

export function Sidebar() {
  const pathname = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const markAllRead = useAlertStore((s) => s.markAllRead)
  const [collapsed, setCollapsed] = useState(false)
  const [groupExpanded, setGroupExpanded] = useState<Record<string, boolean>>(INITIAL_GROUP_STATE)

  useEffect(() => {
    setGroupExpanded(prev => {
      const next = { ...prev }
      for (const key of ALL_GROUP_KEYS) {
        const stored = localStorage.getItem(key)
        if (stored !== null) next[key] = stored === 'true'
      }
      for (const section of SECTIONS) {
        for (const entry of section.entries) {
          if ('kind' in entry && entry.kind === 'group') {
            const hasActive = entry.items.some(
              item => pathname === item.href || pathname.startsWith(item.href + '/')
            )
            if (hasActive) next[entry.storeKey] = true
          }
        }
      }
      return next
    })
  }, [pathname])

  const toggleGroup = (key: string) => {
    setGroupExpanded(prev => {
      const next = { ...prev, [key]: !prev[key] }
      localStorage.setItem(key, String(next[key]))
      return next
    })
  }

  const handleLogout = async () => {
    try { await authApi.logout() } catch { /* ignore */ }
    auth.removeToken()
    window.location.href = '/login'
  }

  const renderNavItem = (item: NavItem, indented = false) => {
    const active = pathname === item.href || pathname.startsWith(item.href + '/')
    return (
      <Link
        key={item.href}
        href={item.href}
        onClick={item.href === '/alerts' ? markAllRead : undefined}
        title={collapsed ? item.label : undefined}
        className={cn(
          'flex items-center gap-2.5 rounded-md text-[13px] transition-all duration-100 relative group',
          collapsed ? 'px-2 py-2 justify-center' : 'px-2.5 py-1.5',
          indented && !collapsed && 'text-[12px]',
          active
            ? 'bg-indigo-500/15 text-indigo-400'
            : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.05]',
        )}
      >
        {active && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-indigo-500 rounded-r-full" />
        )}
        <item.icon size={indented ? 13 : 15} className="flex-shrink-0" />
        {!collapsed && <span className="flex-1 font-medium">{item.label}</span>}
        {!collapsed && item.href === '/alerts' && unreadCount > 0 && (
          <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
        {collapsed && item.href === '/alerts' && unreadCount > 0 && (
          <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-red-500" />
        )}
        {collapsed && (
          <div className="absolute left-full ml-2 px-2 py-1 rounded bg-zinc-800 text-zinc-200 text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 border border-white/10">
            {item.label}
          </div>
        )}
      </Link>
    )
  }

  const renderNavGroup = (group: NavGroup) => {
    const isExpanded = groupExpanded[group.storeKey] ?? false
    const hasActive = group.items.some(
      item => pathname === item.href || pathname.startsWith(item.href + '/')
    )

    if (collapsed) {
      return (
        <div key={group.storeKey} className="relative group/flyout">
          <div className={cn(
            'flex items-center justify-center px-2 py-2 rounded-md cursor-default',
            hasActive ? 'text-indigo-400 bg-indigo-500/15' : 'text-zinc-500',
          )}>
            <group.icon size={15} />
          </div>
          <div className="absolute left-full ml-2 top-0 bg-zinc-900 border border-white/10 rounded-md py-1 opacity-0 group-hover/flyout:opacity-100 pointer-events-none group-hover/flyout:pointer-events-auto transition-opacity z-50 min-w-[180px]">
            <p className="px-3 py-1.5 text-[10px] font-semibold tracking-widest text-zinc-500 uppercase border-b border-white/[0.06]">
              {group.label}
            </p>
            {group.items.map(item => {
              const active = pathname === item.href || pathname.startsWith(item.href + '/')
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-2.5 px-3 py-1.5 text-[13px] transition-colors',
                    active ? 'text-indigo-400' : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.05]',
                  )}
                >
                  <item.icon size={13} className="flex-shrink-0" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </div>
        </div>
      )
    }

    return (
      <div key={group.storeKey}>
        <button
          onClick={() => toggleGroup(group.storeKey)}
          className={cn(
            'flex items-center gap-2.5 w-full rounded-md text-[13px] transition-all duration-100 px-2.5 py-1.5',
            hasActive
              ? 'text-zinc-200 hover:bg-white/[0.05]'
              : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.05]',
          )}
        >
          <group.icon size={15} className="flex-shrink-0" />
          <span className="flex-1 font-medium text-left">{group.label}</span>
          {isExpanded
            ? <ChevronUp size={12} className="text-zinc-600 flex-shrink-0" />
            : <ChevronDown size={12} className="text-zinc-600 flex-shrink-0" />}
        </button>
        {isExpanded && (
          <div className="ml-3 border-l border-white/[0.06] pl-1.5 space-y-0.5 mt-0.5 mb-0.5">
            {group.items.map(item => renderNavItem(item, true))}
          </div>
        )}
      </div>
    )
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
              {section.entries.map((entry) =>
                'kind' in entry && entry.kind === 'group'
                  ? renderNavGroup(entry)
                  : renderNavItem(entry as NavItem)
              )}
            </div>
          </div>
        ))}
      </nav>

      {/* Alt: Çıkış */}
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
          {collapsed && (
            <div className="absolute left-full ml-2 px-2 py-1 rounded bg-zinc-800 text-zinc-200 text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 border border-white/10">
              Çıkış Yap
            </div>
          )}
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
