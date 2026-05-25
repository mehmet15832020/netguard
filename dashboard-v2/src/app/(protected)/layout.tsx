import { unstable_noStore as noStore } from 'next/cache'
import ProtectedLayout from './layout-client'

export const dynamic = 'force-dynamic'
export const revalidate = 0

export default function Layout({ children }: { children: React.ReactNode }) {
  noStore()
  return <ProtectedLayout>{children}</ProtectedLayout>
}
