'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { auth } from '@/lib/api'
import { Sidebar } from '@/components/layout/Sidebar'
import { Topbar } from '@/components/layout/Topbar'
import { CommandPalette } from '@/components/layout/CommandPalette'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useCommandPaletteStore } from '@/store/commandPaletteStore'

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [ready, setReady] = useState(false)
  const openPalette = useCommandPaletteStore((s) => s.open)
  useWebSocket()

  useEffect(() => {
    if (!auth.isLoggedIn()) {
      router.replace('/login')
    } else {
      setReady(true)
    }
  }, [router])

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        openPalette()
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [openPalette])

  if (!ready) return null

  return (
    <div className="flex h-screen overflow-hidden bg-[#060c17]">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}
