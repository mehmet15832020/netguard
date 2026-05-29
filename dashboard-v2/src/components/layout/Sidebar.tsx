'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useEffect, useRef } from 'react'
import {
  LayoutDashboard, Bell, Shield, FileText, GitMerge, Settings, LogOut,
  Server, Network, Monitor, Radar, Share2, FileDown, Wrench,
  ClipboardList, ShieldAlert, Crosshair, Swords,
  Zap, Fingerprint, ShieldOff, CheckSquare, BarChart2, Activity, PieChart, TrendingUp,
  GitBranch, AlertTriangle, Lock, Globe, Radio, Grid2X2, Gauge, Clock,
  ShieldCheck, Wand2, FileCode2, ChevronDown, ChevronUp, Pin, PinOff,
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
      { href: '/alerts',    label: 'Alertler',        icon: Bell },
      { href: '/incidents', label: 'Incidents',        icon: ShieldAlert },
      { href: '/timeline',  label: 'Aktif Zincirler',  icon: Swords },
      { href: '/blocks',    label: 'Aktif Bloklar',    icon: ShieldOff },
    ],
  },
  {
    label: 'Tespit',
    entries: [
      { href: '/correlation',          label: 'Korelasyon',          icon: GitMerge },
      { href: '/mitre',                label: 'MITRE ATT&CK',        icon: Crosshair },
      { href: '/anomaly',              label: 'Anomali Tespiti',      icon: Activity },
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
          { href: '/fp-management',     label: 'FP Yönetimi',          icon: ShieldOff },
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
          { href: '/top-talkers',           label: 'Top Talkers',         icon: BarChart2 },
          { href: '/alert-volume',          label: 'Alert Hacmi',         icon: Activity },
          { href: '/protocol-distribution', label: 'Protokol Dağılımı',   icon: PieChart },
          { href: '/traffic-volume',        label: 'Trafik Hacmi',        icon: TrendingUp },
          { href: '/kill-chain-timeline',   label: 'Kill Chain Timeline',  icon: GitBranch },
          { href: '/threat-intel-summary',  label: 'Threat Intel',         icon: AlertTriangle },
          { href: '/failed-auth',           label: 'Başarısız Auth',      icon: Lock },
          { href: '/dns-analysis',          label: 'DNS Analiz',           icon: Globe },
          { href: '/tls-fingerprints',      label: 'TLS / JA4',            icon: Fingerprint },
          { href: '/beaconing',             label: 'Beaconing',            icon: Radio },
          { href: '/east-west-matrix',      label: 'E-W Matrix',           icon: Grid2X2 },
          { href: '/asset-risk',            label: 'Asset Risk',           icon: Gauge },
          { href: '/mttd-mttr',             label: 'MTTD / MTTR',          icon: Clock },
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
      { href: '/reports',     label: 'Raporlar',         icon: FileDown },
      { href: '/compliance',  label: 'Uyumluluk',         icon: CheckSquare },
      { href: '/audit',       label: 'Denetim Günlüğü',  icon: ClipboardList },
      { href: '/maintenance', label: 'Bakım',             icon: Wrench },
      { href: '/settings',    label: 'Ayarlar',           icon: Settings },
    ],
  },
]

const ALL_GROUP_KEYS = SECTIONS.flatMap(s =>
  s.entries.filter((e): e is NavGroup => 'kind' in e && e.kind === 'group').map(g => g.storeKey)
)

const INITIAL_GROUP_STATE = Object.fromEntries(ALL_GROUP_KEYS.map(k => [k, false]))

const W_COLLAPSED = 48
const W_EXPANDED  = 228

export function Sidebar() {
  const pathname    = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const markAllRead = useAlertStore((s) => s.markAllRead)

  // Pinned = stays expanded; unpinned = icon-only, hover-expands as overlay
  const [pinned, setPinned] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false
    return localStorage.getItem('sidebar-pinned') === 'true'
  })
  const [hovered, setHovered]     = useState(false)
  const hoverTimerRef             = useRef<ReturnType<typeof setTimeout> | null>(null)
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

  const isExpanded = pinned || hovered

  const togglePin = () => {
    setPinned(v => {
      const next = !v
      localStorage.setItem('sidebar-pinned', String(next))
      if (next) setHovered(false)
      return next
    })
  }

  const toggleGroup = (key: string) => {
    setGroupExpanded(prev => {
      const next = { ...prev, [key]: !prev[key] }
      localStorage.setItem(key, String(next[key]))
      return next
    })
  }

  const handleMouseEnter = () => {
    if (pinned) return
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
    hoverTimerRef.current = setTimeout(() => setHovered(true), 80)
  }

  const handleMouseLeave = () => {
    if (pinned) return
    if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current)
    hoverTimerRef.current = setTimeout(() => setHovered(false), 150)
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
        title={!isExpanded ? item.label : undefined}
        className={cn(
          'relative flex items-center gap-2.5 rounded-md text-[13px] font-medium transition-all duration-100 group/item',
          !isExpanded ? 'px-0 py-2 justify-center' : 'px-2.5 py-1.5',
          indented && isExpanded && 'text-[12px]',
          active
            ? 'bg-sky-500/10 text-sky-400'
            : 'text-slate-500 hover:text-slate-200 hover:bg-sky-950/40',
        )}
      >
        {active && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 rounded-r-full bg-sky-400 glow-cyber-sm" />
        )}
        <item.icon
          size={indented ? 13 : 15}
          className={cn('flex-shrink-0', active ? 'text-sky-400' : '')}
        />
        {isExpanded && <span className="flex-1 truncate">{item.label}</span>}

        {/* Alert badge — expanded */}
        {isExpanded && item.href === '/alerts' && unreadCount > 0 && (
          <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
        {/* Alert badge — icon-only */}
        {!isExpanded && item.href === '/alerts' && unreadCount > 0 && (
          <span className="absolute top-1 right-0.5 w-2 h-2 rounded-full bg-red-500 animate-lamp-critical" />
        )}

        {/* Hover tooltip for collapsed state */}
        {!isExpanded && (
          <div className="pointer-events-none absolute left-full ml-3 px-2.5 py-1 rounded-md bg-[#0a1120] text-slate-200 text-[12px] font-medium whitespace-nowrap opacity-0 group-hover/item:opacity-100 transition-opacity z-[60] border border-sky-900/40 shadow-xl">
            {item.label}
          </div>
        )}
      </Link>
    )
  }

  const renderNavGroup = (group: NavGroup) => {
    const isGroupExpanded = groupExpanded[group.storeKey] ?? false
    const hasActive = group.items.some(
      item => pathname === item.href || pathname.startsWith(item.href + '/')
    )

    if (!isExpanded) {
      return (
        <div key={group.storeKey} className="relative group/flyout">
          <div className={cn(
            'flex items-center justify-center py-2 rounded-md cursor-default',
            hasActive ? 'text-sky-400 bg-sky-950/25' : 'text-slate-500',
          )}>
            <group.icon size={15} />
          </div>
          {/* Flyout menu */}
          <div className="pointer-events-none group-hover/flyout:pointer-events-auto absolute left-full ml-3 top-0 bg-[#0a1120] border border-sky-900/40 rounded-lg py-1 opacity-0 group-hover/flyout:opacity-100 transition-opacity z-[60] min-w-[196px] shadow-2xl">
            <p className="px-3 pt-2 pb-1.5 text-[9px] font-bold tracking-[0.15em] text-sky-800 uppercase border-b border-sky-900/30">
              {group.label}
            </p>
            {group.items.map(item => {
              const active = pathname === item.href || pathname.startsWith(item.href + '/')
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-2.5 px-3 py-1.5 text-[12px] font-medium transition-colors',
                    active
                      ? 'text-sky-400 bg-sky-950/30'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-sky-950/30',
                  )}
                >
                  <item.icon size={12} className="flex-shrink-0" />
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
            'flex items-center gap-2.5 w-full rounded-md text-[13px] font-medium transition-colors px-2.5 py-1.5',
            hasActive
              ? 'text-slate-200 hover:bg-sky-950/30'
              : 'text-slate-500 hover:text-slate-200 hover:bg-sky-950/30',
          )}
        >
          <group.icon size={15} className="flex-shrink-0" />
          <span className="flex-1 text-left truncate">{group.label}</span>
          {isGroupExpanded
            ? <ChevronUp size={11} className="text-slate-600 flex-shrink-0" />
            : <ChevronDown size={11} className="text-slate-600 flex-shrink-0" />}
        </button>
        {isGroupExpanded && (
          <div className="ml-3 border-l border-sky-900/30 pl-1.5 space-y-0.5 mt-0.5 mb-0.5">
            {group.items.map(item => renderNavItem(item, true))}
          </div>
        )}
      </div>
    )
  }

  return (
    /*
     * Outer aside: controls the space reserved in the flex layout.
     * When not pinned → W_COLLAPSED (48px) always.
     * When pinned → W_EXPANDED (228px).
     *
     * Inner div: the visible panel. On hover-expand it grows to W_EXPANDED
     * as an overlay (position: absolute), so content area never shifts.
     */
    <aside
      className="relative flex-shrink-0 transition-all duration-200 ease-out"
      style={{ width: pinned ? W_EXPANDED : W_COLLAPSED }}
    >
      <div
        className={cn(
          'absolute inset-y-0 left-0 flex flex-col',
          'bg-[#040911] border-r border-sky-900/25',
          'transition-all duration-200 ease-out overflow-hidden z-40',
        )}
        style={{ width: isExpanded ? W_EXPANDED : W_COLLAPSED }}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        {/* Top glow accent line */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sky-500/25 to-transparent flex-shrink-0" />

        {/* Logo */}
        <div className={cn(
          'flex items-center gap-2.5 border-b border-sky-900/25 flex-shrink-0 h-12',
          !isExpanded ? 'justify-center px-0' : 'px-3.5',
        )}>
          <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-gradient-to-br from-sky-500/20 to-indigo-500/20 border border-sky-500/20 flex-shrink-0">
            <Zap size={14} className="text-sky-400" />
          </div>
          {isExpanded && (
            <div className="min-w-0 flex-1">
              <span className="font-bold text-sm text-slate-100 tracking-tight">NetGuard</span>
              <span className="block text-[9px] text-sky-800 leading-tight font-medium tracking-wider uppercase">NDR Platform</span>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-2 space-y-3 scrollbar-none">
          {SECTIONS.map((section) => (
            <div key={section.label || '__top'}>
              {isExpanded && section.label && (
                <p className="px-3.5 mb-1 text-[9px] font-bold tracking-[0.16em] text-sky-900 uppercase">
                  {section.label}
                </p>
              )}
              {!isExpanded && section.label && (
                <div className="mx-auto my-1" style={{ width: 20, height: 1, background: 'oklch(0.74 0.18 215 / 15%)' }} />
              )}
              <div className={cn('space-y-0.5', isExpanded ? 'px-2' : 'px-1.5')}>
                {section.entries.map((entry) =>
                  'kind' in entry && entry.kind === 'group'
                    ? renderNavGroup(entry)
                    : renderNavItem(entry as NavItem)
                )}
              </div>
            </div>
          ))}
        </nav>

        {/* Bottom: pin toggle + logout */}
        <div className="border-t border-sky-900/25 p-1.5 space-y-0.5 flex-shrink-0">
          {isExpanded ? (
            <button
              onClick={togglePin}
              className="flex items-center gap-2.5 w-full rounded-md text-[13px] font-medium transition-colors px-2.5 py-1.5 text-slate-600 hover:text-sky-400 hover:bg-sky-950/30"
            >
              {pinned ? <PinOff size={14} className="flex-shrink-0" /> : <Pin size={14} className="flex-shrink-0" />}
              <span>{pinned ? 'Sabitlemeyi Kaldır' : 'Sabitle'}</span>
            </button>
          ) : (
            <button
              onClick={togglePin}
              title={pinned ? 'Sabitlemeyi kaldır' : 'Sabitle'}
              className="flex items-center justify-center w-full py-2 rounded-md text-slate-600 hover:text-sky-400 hover:bg-sky-950/30 transition-colors"
            >
              {pinned ? <PinOff size={14} /> : <Pin size={14} />}
            </button>
          )}

          {isExpanded ? (
            <button
              onClick={handleLogout}
              className="flex items-center gap-2.5 w-full rounded-md text-[13px] font-medium transition-colors px-2.5 py-1.5 text-slate-600 hover:text-red-400 hover:bg-red-950/25"
            >
              <LogOut size={15} className="flex-shrink-0" />
              <span>Çıkış Yap</span>
            </button>
          ) : (
            <div className="relative group/logout">
              <button
                onClick={handleLogout}
                className="flex items-center justify-center w-full py-2 rounded-md text-slate-600 hover:text-red-400 hover:bg-red-950/25 transition-colors"
              >
                <LogOut size={15} />
              </button>
              <div className="pointer-events-none absolute left-full ml-3 bottom-0 px-2.5 py-1 rounded-md bg-[#0a1120] text-slate-200 text-[12px] font-medium whitespace-nowrap opacity-0 group-hover/logout:opacity-100 transition-opacity z-[60] border border-sky-900/40 shadow-xl">
                Çıkış Yap
              </div>
            </div>
          )}
        </div>
      </div>
    </aside>
  )
}
