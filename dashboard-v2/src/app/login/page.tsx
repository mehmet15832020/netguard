'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Activity, ArrowLeft } from 'lucide-react'
import { authApi, auth } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'

export default function LoginPage() {
  const router = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [step, setStep] = useState<'password' | 'totp'>('password')
  const [mfaToken, setMfaToken] = useState('')
  const [totpCode, setTotpCode] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await authApi.login(username, password)
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token)
        setStep('totp')
        return
      }
      auth.setToken(res.access_token!)
      auth.setRefreshToken(res.refresh_token!)
      router.replace('/overview')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Giriş başarısız')
    } finally {
      setLoading(false)
    }
  }

  const handleTotp = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await authApi.totpVerify(mfaToken, totpCode)
      auth.setToken(res.access_token!)
      auth.setRefreshToken(res.refresh_token!)
      router.replace('/overview')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Geçersiz kod')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-950">
      <Card className="w-full max-w-sm bg-zinc-900 border-zinc-800">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-3">
            <div className="p-3 bg-indigo-600/20 rounded-full">
              <Activity className="text-indigo-400" size={28} />
            </div>
          </div>
          {step === 'password' ? (
            <>
              <CardTitle className="text-zinc-100 text-xl">NetGuard</CardTitle>
              <CardDescription className="text-zinc-400">
                Güvenlik izleme sistemine giriş yapın
              </CardDescription>
            </>
          ) : (
            <>
              <CardTitle className="text-zinc-100 text-xl">İki Faktörlü Doğrulama</CardTitle>
              <CardDescription className="text-zinc-400">
                Authenticator uygulamanızdaki 6 haneli kodu girin
              </CardDescription>
            </>
          )}
        </CardHeader>
        <CardContent>
          {step === 'password' ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="username" className="text-zinc-300">Kullanıcı adı</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  required
                  autoFocus
                  className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-zinc-300">Şifre</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="bg-zinc-800 border-zinc-700 text-zinc-100"
                />
              </div>
              {error && (
                <p className="text-red-400 text-sm bg-red-900/20 border border-red-800 rounded px-3 py-2">
                  {error}
                </p>
              )}
              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white"
              >
                {loading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
              </Button>
            </form>
          ) : (
            <form onSubmit={handleTotp} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="totp-code" className="text-zinc-300">Doğrulama Kodu</Label>
                <Input
                  id="totp-code"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  required
                  autoFocus
                  className="bg-zinc-800 border-zinc-700 text-zinc-100 placeholder:text-zinc-500 text-center text-xl tracking-widest"
                />
              </div>
              {error && (
                <p className="text-red-400 text-sm bg-red-900/20 border border-red-800 rounded px-3 py-2">
                  {error}
                </p>
              )}
              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white"
              >
                {loading ? 'Doğrulanıyor...' : 'Doğrula'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => { setStep('password'); setTotpCode(''); setError('') }}
                className="w-full text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
              >
                <ArrowLeft size={14} className="mr-1" /> Geri
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
