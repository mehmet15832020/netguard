'use client'

import { auth } from '@/lib/api'

interface CurrentUser {
  username: string
  role: string
}

export function useCurrentUser(): CurrentUser | null {
  try {
    const token = auth.getToken()
    if (!token) return null

    const parts = token.split('.')
    if (parts.length !== 3) return null

    const payload = JSON.parse(atob(parts[1]))
    if (!payload?.sub) return null

    return {
      username: payload.sub as string,
      role: (payload.role as string) ?? 'viewer',
    }
  } catch {
    return null
  }
}
