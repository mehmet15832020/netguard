'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { auth } from '@/lib/api'
import { Sidebar } from '@/components/layout/Sidebar'
import { useWebSocket } from '@/hooks/useWebSocket'

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [ready, setReady] = useState(false)
  useWebSocket()

  useEffect(() => {
    if (!auth.isLoggedIn()) {
      router.replace('/login')
    } else {
      setReady(true)
    }
  }, [router])

  if (!ready) return null

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto bg-zinc-950 p-6">
        {children}
      </main>
    </div>
  )
}
