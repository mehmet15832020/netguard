import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function proxy(request: NextRequest) {
  const response = NextResponse.next()

  // Static assets are content-hashed — long-lived cache is correct.
  // All HTML pages must never be cached so deploys are visible immediately.
  response.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate')
  response.headers.set('Pragma', 'no-cache')
  response.headers.set('Expires', '0')

  return response
}

export const config = {
  matcher: [
    // Run on all routes except Next.js internal paths and static files
    '/((?!_next/static|_next/image|favicon\\.ico).*)',
  ],
}
