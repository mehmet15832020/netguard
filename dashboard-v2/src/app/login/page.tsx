'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Activity, ArrowLeft } from 'lucide-react'
import { authApi, auth } from '@/lib/api'

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
    <div className="min-h-screen flex items-center justify-center bg-[#040911]">
      <div className="w-full max-w-sm bg-[#0a1120] border border-sky-900/20 rounded-xl shadow-[0_24px_64px_rgba(0,0,0,0.8)] p-6">
        <div className="text-center mb-6">
          <div className="flex justify-center mb-3">
            <div className="p-3 bg-sky-500/10 rounded-full">
              <Activity className="text-sky-400" size={28} />
            </div>
          </div>
          {step === 'password' ? (
            <>
              <h1 className="text-slate-100 text-xl font-semibold">NetGuard</h1>
              <p className="text-slate-400 text-sm mt-1">
                Güvenlik izleme sistemine giriş yapın
              </p>
            </>
          ) : (
            <>
              <h1 className="text-slate-100 text-xl font-semibold">İki Faktörlü Doğrulama</h1>
              <p className="text-slate-400 text-sm mt-1">
                Authenticator uygulamanızdaki 6 haneli kodu girin
              </p>
            </>
          )}
        </div>

        {step === 'password' ? (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="username" className="text-xs font-medium text-slate-400">Kullanıcı adı</label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
                className="ui-input font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="password" className="text-xs font-medium text-slate-400">Şifre</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="ui-input font-mono"
              />
            </div>
            {error && (
              <p className="text-red-400 text-sm bg-red-900/20 border border-red-800 rounded px-3 py-2">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={loading}
              className="ui-btn ui-btn-primary w-full justify-center"
            >
              {loading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleTotp} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="totp-code" className="text-xs font-medium text-slate-400">Doğrulama Kodu</label>
              <input
                id="totp-code"
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                required
                autoFocus
                className="ui-input font-mono text-center text-xl tracking-widest"
              />
            </div>
            {error && (
              <p className="text-red-400 text-sm bg-red-900/20 border border-red-800 rounded px-3 py-2">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={loading}
              className="ui-btn ui-btn-primary w-full justify-center"
            >
              {loading ? 'Doğrulanıyor...' : 'Doğrula'}
            </button>
            <button
              type="button"
              onClick={() => { setStep('password'); setTotpCode(''); setError('') }}
              className="ui-btn ui-btn-secondary w-full justify-center"
            >
              <ArrowLeft size={14} className="inline mr-1" /> Geri
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
