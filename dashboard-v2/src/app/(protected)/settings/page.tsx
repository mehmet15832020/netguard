'use client'

import { useState, useEffect } from 'react'
import { Settings, Save, RefreshCw, ShieldCheck, ShieldOff } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { correlationApi, authApi } from '@/lib/api'
import { QRCodeSVG } from 'qrcode.react'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { SkeletonTable } from '@/components/ui/skeleton'
import type { CorrelationRule, Severity } from '@/types/models'

const INP = 'w-full bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors'
const SEL = 'w-full bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-sky-500/50 transition-colors'

function RuleCard({ rule, onSave }: { rule: CorrelationRule; onSave: (updated: CorrelationRule) => void }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft]     = useState<CorrelationRule>(rule)

  const handleSave = () => { onSave(draft); setEditing(false) }
  const handleCancel = () => { setDraft(rule); setEditing(false) }

  return (
    <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-slate-200">{rule.name}</p>
          <p className="text-xs text-slate-600 mt-0.5">{rule.description}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={rule.severity} />
          {!editing && (
            <button
              onClick={() => setEditing(true)}
              className="px-2 py-1 rounded-lg text-xs text-slate-400 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors"
            >
              Düzenle
            </button>
          )}
        </div>
      </div>

      {editing ? (
        <>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <span className="text-xs text-slate-500">Eşik (Threshold)</span>
              <input
                type="number"
                value={draft.threshold}
                onChange={e => setDraft({ ...draft, threshold: +e.target.value })}
                className={INP}
              />
            </div>
            <div className="space-y-1">
              <span className="text-xs text-slate-500">Zaman Penceresi (saniye)</span>
              <input
                type="number"
                value={draft.window_seconds}
                onChange={e => setDraft({ ...draft, window_seconds: +e.target.value })}
                className={INP}
              />
            </div>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-slate-500">Seviye</span>
            <select
              value={draft.severity}
              onChange={e => setDraft({ ...draft, severity: e.target.value as Severity })}
              className={SEL}
            >
              <option value="info">Bilgi</option>
              <option value="warning">Uyarı</option>
              <option value="critical">Kritik</option>
            </select>
          </div>
          <div className="flex gap-2 pt-1">
            <button onClick={handleSave}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs text-white bg-sky-600 hover:bg-sky-500 transition-colors">
              <Save size={11} /> Kaydet
            </button>
            <button onClick={handleCancel}
              className="px-3 py-1 rounded-lg text-xs text-slate-400 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors">
              İptal
            </button>
          </div>
        </>
      ) : (
        <div className="grid grid-cols-3 gap-4 text-xs">
          <div>
            <p className="text-slate-600">Eşik</p>
            <p className="text-slate-200 font-medium mt-0.5">{rule.threshold} olay</p>
          </div>
          <div>
            <p className="text-slate-600">Zaman penceresi</p>
            <p className="text-slate-200 font-medium mt-0.5">{rule.window_seconds}s</p>
          </div>
          <div>
            <p className="text-slate-600">Gruplama</p>
            <p className="text-slate-200 font-medium mt-0.5">{rule.group_by}</p>
          </div>
        </div>
      )}
    </div>
  )
}

type MfaSetupData = { secret: string; otpauth_uri: string }

function MfaSection() {
  const { data: me } = useQuery({
    queryKey: ['auth', 'me'],
    queryFn:  () => authApi.me(),
    staleTime: 30_000,
  })

  const [mfaEnabled,      setMfaEnabled]      = useState(false)
  const [setupData,       setSetupData]        = useState<MfaSetupData | null>(null)
  const [confirmCode,     setConfirmCode]      = useState('')
  const [setupError,      setSetupError]       = useState('')
  const [confirmLoading,  setConfirmLoading]   = useState(false)
  const [disableLoading,  setDisableLoading]   = useState(false)

  useEffect(() => { if (me) setMfaEnabled(me.totp_enabled) }, [me])

  const handleEnable = async () => {
    setSetupError('')
    try {
      const data = await authApi.totpSetup()
      setSetupData(data)
    } catch (err) {
      setSetupError(err instanceof Error ? err.message : 'Kurulum başarısız')
    }
  }

  const handleConfirm = async () => {
    setSetupError('')
    setConfirmLoading(true)
    try {
      await authApi.totpConfirm(confirmCode)
      setMfaEnabled(true); setSetupData(null); setConfirmCode('')
    } catch (err) {
      setSetupError(err instanceof Error ? err.message : 'Geçersiz kod')
    } finally { setConfirmLoading(false) }
  }

  const handleDisable = async () => {
    setSetupError('')
    setDisableLoading(true)
    try {
      await authApi.totpDisable()
      setMfaEnabled(false); setSetupData(null); setConfirmCode('')
    } catch (err) {
      setSetupError(err instanceof Error ? err.message : 'Devre dışı bırakma başarısız')
    } finally { setDisableLoading(false) }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-medium text-slate-300">İki Faktörlü Kimlik Doğrulama</h2>
          <p className="text-xs text-slate-600 mt-0.5">Hesabınızı yetkisiz erişime karşı koruyun</p>
        </div>
        {mfaEnabled ? (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 text-xs font-medium text-emerald-400">
            <ShieldCheck size={12} /> Etkin
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-sky-950/30 border border-sky-900/20 px-2.5 py-0.5 text-xs font-medium text-slate-500">
            <ShieldOff size={12} /> Devre Dışı
          </span>
        )}
      </div>

      {setupError && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-red-400 text-xs">
          {setupError}
        </div>
      )}

      {!mfaEnabled && !setupData && (
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 flex items-center justify-between gap-4">
          <p className="text-xs text-slate-500">
            TOTP tabanlı iki faktörlü kimlik doğrulamayı etkinleştirin.
            Google Authenticator veya benzeri bir uygulama gereklidir.
          </p>
          <button
            onClick={handleEnable}
            className="shrink-0 px-3 py-1.5 rounded-lg text-xs text-white bg-sky-600 hover:bg-sky-500 transition-colors shadow-[0_0_12px_rgba(56,189,248,0.15)]"
          >
            Etkinleştir
          </button>
        </div>
      )}

      {!mfaEnabled && setupData && (
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 space-y-4">
          <p className="text-xs text-slate-500">
            QR kodu Authenticator uygulamanızla tarayın veya gizli anahtarı manuel olarak girin.
          </p>
          <div className="flex justify-center p-4 bg-sky-950/20 rounded-lg border border-sky-900/15">
            <QRCodeSVG value={setupData.otpauth_uri} size={160} bgColor="#0d1526" fgColor="#cbd5e1" />
          </div>
          <div className="space-y-1">
            <span className="text-xs text-slate-500">Manuel Gizli Anahtar</span>
            <p className="font-mono text-xs text-sky-300 bg-sky-950/20 border border-sky-900/20 rounded-lg px-3 py-2 break-all select-all">
              {setupData.secret}
            </p>
          </div>
          <div className="space-y-1.5">
            <label htmlFor="totp-confirm" className="text-xs text-slate-500">Doğrulama Kodu (6 hane)</label>
            <input
              id="totp-confirm"
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={confirmCode}
              onChange={e => setConfirmCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              className={INP}
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleConfirm}
              disabled={confirmLoading || confirmCode.length !== 6}
              className="px-3 py-1.5 rounded-lg text-xs text-white bg-sky-600 hover:bg-sky-500 transition-colors disabled:opacity-60"
            >
              {confirmLoading ? 'Doğrulanıyor...' : 'Onayla ve Etkinleştir'}
            </button>
            <button
              onClick={() => { setSetupData(null); setConfirmCode(''); setSetupError('') }}
              className="px-3 py-1.5 rounded-lg text-xs text-slate-400 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors"
            >
              İptal
            </button>
          </div>
        </div>
      )}

      {mfaEnabled && (
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 flex items-center justify-between gap-4">
          <p className="text-xs text-slate-500">
            İki faktörlü kimlik doğrulama etkin. Giriş yaparken Authenticator kodunuz istenecek.
          </p>
          <button
            onClick={handleDisable}
            disabled={disableLoading}
            className="shrink-0 px-3 py-1.5 rounded-lg text-xs text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-60"
          >
            {disableLoading ? 'Devre dışı bırakılıyor...' : 'Devre Dışı Bırak'}
          </button>
        </div>
      )}
    </div>
  )
}

export default function SettingsPage() {
  const queryClient = useQueryClient()
  const [localRules, setLocalRules] = useState<CorrelationRule[] | null>(null)

  const { data: rulesData, isLoading } = useQuery({
    queryKey: ['correlation-rules'],
    queryFn:  () => correlationApi.listRules(),
    select:   (data) => data.rules,
  })

  const rules = localRules ?? rulesData ?? []

  const saveMutation = useMutation({
    mutationFn: (updatedRules: CorrelationRule[]) => correlationApi.updateRules(updatedRules),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] })
      setLocalRules(null)
    },
  })

  const reloadMutation = useMutation({
    mutationFn: () => correlationApi.reloadRules(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  const handleRuleSave = (updated: CorrelationRule) => {
    const merged = rules.map(r => r.rule_id === updated.rule_id ? updated : r)
    setLocalRules(merged)
    saveMutation.mutate(merged)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <Settings size={15} className="text-sky-400" />
        </div>
        <div>
          <h1 className="text-base font-semibold text-slate-100 leading-tight">Ayarlar</h1>
          <p className="text-xs text-slate-600">Korelasyon kuralları ve alarm eşikleri</p>
        </div>
      </div>

      {/* Correlation rules */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-medium text-slate-300">Korelasyon Kuralları</h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Eşik ve pencere değerlerini değiştirip kaydet — sunucuyu yeniden başlatmak gerekmez
            </p>
          </div>
          <button
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors disabled:opacity-50"
          >
            <RefreshCw size={12} className={reloadMutation.isPending ? 'animate-spin' : ''} />
            Kuralları Yenile
          </button>
        </div>

        {saveMutation.isSuccess && (
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2 text-emerald-400 text-xs">
            Kurallar kaydedildi ve yeniden yüklendi.
          </div>
        )}
        {saveMutation.isError && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-red-400 text-xs">
            Kaydetme başarısız — sunucu bağlantısını kontrol et.
          </div>
        )}

        {isLoading ? (
          <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
            <SkeletonTable rows={4} height={72} />
          </div>
        ) : (
          <div className="space-y-3">
            {rules.map(rule => (
              <RuleCard key={rule.rule_id} rule={rule} onSave={handleRuleSave} />
            ))}
          </div>
        )}
      </div>

      <div className="border-t border-sky-900/20" />

      <MfaSection />

      <div className="border-t border-sky-900/20" />

      {/* Detector thresholds */}
      <div className="space-y-3">
        <div>
          <h2 className="text-sm font-medium text-slate-300">Dedektör Eşikleri</h2>
          <p className="text-xs text-slate-600 mt-0.5">Sunucu ortam değişkenleriyle ayarlanır</p>
        </div>
        <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4">
          <div className="grid grid-cols-2 gap-x-8 gap-y-3 text-xs">
            {[
              ['NETGUARD_PORTSCAN_THRESHOLD', '10 port',      'Port tarama eşiği'],
              ['NETGUARD_ICMP_THRESHOLD',     '100 pkt/s',    'ICMP flood eşiği'],
              ['NETGUARD_DNS_THRESHOLD',      '30 sorgu',     'DNS anomali eşiği'],
              ['NETGUARD_NTP_SERVER',         'pool.ntp.org', 'NTP sunucusu'],
              ['NETGUARD_CLOCK_WARN_SEC',     '5s',           'Saat sapma uyarı eşiği'],
              ['NETGUARD_CLOCK_CRIT_SEC',     '60s',          'Saat sapma kritik eşiği'],
              ['NETGUARD_SYSLOG_PORT',        '5140',         'Syslog UDP portu'],
              ['NETGUARD_CORR_INTERVAL',      '60s',          'Korelasyon çalışma aralığı'],
            ].map(([env, def, desc]) => (
              <div key={env} className="flex flex-col gap-0.5">
                <span className="font-mono text-sky-400 text-[11px]">{env}</span>
                <span className="text-slate-600">{desc} <span className="text-slate-500">(varsayılan: {def})</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
