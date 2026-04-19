'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard,
  Bell,
  Shield,
  FileText,
  GitMerge,
  Settings,
  LogOut,
  Activity,
  Server,
  Network,
  Monitor,
  Radar,
  Share2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { auth } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'
import { Badge } from '@/components/ui/badge'

const NAV_ITEMS = [
  { href: '/overview',     label: 'Genel Bakış',   icon: LayoutDashboard },
  { href: '/devices',      label: 'Cihazlar',       icon: Monitor },
  { href: '/topology',     label: 'Topoloji',       icon: Share2 },
  { href: '/discovery',    label: 'Keşif',          icon: Radar },
  { href: '/agents',       label: 'Agents',         icon: Server },
  { href: '/alerts',       label: 'Alertler',       icon: Bell },
  { href: '/security',     label: 'Güvenlik',       icon: Shield },
  { href: '/correlation',  label: 'Korelasyon',     icon: GitMerge },
  { href: '/logs',         label: 'Loglar',         icon: FileText },
  { href: '/snmp',         label: 'SNMP',           icon: Network  },
  { href: '/settings',     label: 'Ayarlar',        icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const markAllRead = useAlertStore((s) => s.markAllRead)

  const handleLogout = () => {
    auth.removeToken()
    window.location.href = '/login'
  }

  return (
    <aside className="flex flex-col w-60 min-h-screen bg-zinc-900 border-r border-zinc-800">
      {/* Logo */}
      <div className="flex items-center gap-2 px-6 py-5 border-b border-zinc-800">
        <Activity className="text-indigo-400" size={20} />
        <span className="font-semibold text-zinc-100 tracking-tight">NetGuard</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              href={href}
              onClick={href === '/alerts' ? markAllRead : undefined}
              className={cn(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                active
                  ? 'bg-indigo-600/20 text-indigo-400 font-medium'
                  : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800',
              )}
            >
              <Icon size={16} />
              <span className="flex-1">{label}</span>
              {href === '/alerts' && unreadCount > 0 && (
                <Badge className="bg-red-600 text-white text-[10px] px-1.5 py-0 h-4">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </Badge>
              )}
            </Link>
          )
        })}
      </nav>

      {/* Çıkış */}
      <div className="px-3 py-4 border-t border-zinc-800">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-3 py-2 rounded-md text-sm text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
        >
          <LogOut size={16} />
          Çıkış Yap
        </button>
      </div>
    </aside>
  )
}
