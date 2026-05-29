'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  ClipboardList, RefreshCw, Search, ShieldCheck, ShieldAlert,
  AlertTriangle, ChevronDown, ChevronUp,
} from 'lucide-react'
import { maintenanceApi } from '@/lib/api'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const ACTION_LABELS: Record<string, string> = {
  'api_key.create':      'API Key Oluşturuldu',
  'api_key.delete':      'API Key Silindi',
  'retention.cleanup':   'Temizlik Çalıştırıldı',
  'auth.logout':         'Oturum Kapatıldı',
  'auth.login':          'Oturum Açıldı',
  'auth.login_failed':   'Giriş Başarısız',
  'auth.mfa_setup':      'MFA Kuruldu',
  'auth.mfa_disabled':   'MFA Devre Dışı',
  'block.create':        'IP Bloklama',
  'block.remove':        'Blok Kaldırıldı',
  'break_glass':         'Break-Glass (Acil)',
  'break_glass.unblock': 'Break-Glass Unblock',
  'incident.create':     'Incident Oluşturuldu',
  'incident.update':     'Incident Güncellendi',
  'incident.resolve':    'Incident Çözüldü',
  'sigma.create':        'Sigma Kuralı Eklendi',
  'sigma.delete':        'Sigma Kuralı Silindi',
  'sigma.toggle':        'Sigma Kuralı Değiştirildi',
  'correlation.create':  'Korelasyon Kuralı Eklendi',
  'correlation.delete':  'Korelasyon Kuralı Silindi',
  'correlation.toggle':  'Korelasyon Kuralı Değiştirildi',
  'fp_rule.create':      'FP Kuralı Oluşturuldu',
  'fp_rule.deactivate':  'FP Kuralı Devre Dışı',
}

const ACTION_COLORS: Record<string, string> = {
  'api_key.create':      'text-emerald-400',
  'api_key.delete':      'text-red-400',
  'retention.cleanup':   'text-blue-400',
  'auth.logout':         'text-slate-500',
  'auth.login':          'text-emerald-400',
  'auth.login_failed':   'text-red-400',
  'auth.mfa_setup':      'text-sky-400',
  'auth.mfa_disabled':   'text-orange-400',
  'block.create':        'text-red-400',
  'block.remove':        'text-emerald-400',
  'break_glass':         'text-red-300',
  'break_glass.unblock': 'text-red-300',
  'incident.create':     'text-orange-400',
  'incident.resolve':    'text-emerald-400',
  'sigma.create':        'text-sky-400',
  'sigma.delete':        'text-red-400',
  'correlation.create':  'text-sky-400',
  'correlation.delete':  'text-red-400',
  'fp_rule.create':      'text-yellow-400',
  'fp_rule.deactivate':  'text-slate-500',
}

const ACTION_FILTER_OPTIONS = [
  { value: 'all',         label: 'Tüm İşlemler' },
  { value: 'auth',        label: 'Kimlik Doğrulama' },
  { value: 'block',       label: 'IP Bloklama' },
  { value: 'break_glass', label: 'Break-Glass' },
  { value: 'incident',    label: 'Incident' },
  { value: 'sigma',       label: 'Sigma Kuralı' },
  { value: 'correlation', label: 'Korelasyon' },
  { value: 'fp_rule',     label: 'FP Kuralı' },
  { value: 'api_key',     label: 'API Key' },
  { value: 'retention',   label: 'Temizlik' },
]

const LIMITS = [50, 100, 250, 500]

function isBreakGlass(action: string)  { return action.includes('break_glass') }
function isDestructive(action: string) { return action.includes('.delete') || action.includes('block.create') || action.includes('login_failed') }

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ─── Chain Integrity Panel ─────────────────────────────────────────────────────

function ChainIntegrityPanel() {
  const [lastVerified, setLastVerified] = useState<number | null>(null)

  const verifyMutation = useMutation({
    mutationFn: () => maintenanceApi.auditVerify(),
    onSuccess:  () => setLastVerified(Date.now()),
  })

  const result = verifyMutation.data

  return (
    <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck size={14} className="text-slate-500" />
          <span className="text-sm font-semibold text-slate-300">SHA-256 Hash Zinciri Bütünlüğü</span>
          <span className="text-[11px] text-slate-700">NIST SP 800-92 §3.2</span>
        </div>
        <button
          disabled={verifyMutation.isPending}
          onClick={() => verifyMutation.mutate()}
          className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors disabled:opacity-50"
        >
          {verifyMutation.isPending
            ? <><RefreshCw size={11} className="animate-spin" />Doğrulanıyor...</>
            : <><ShieldCheck size={11} />Doğrula</>
          }
        </button>
      </div>

      {verifyMutation.isError && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
          <AlertTriangle size={13} className="flex-shrink-0" />
          <span>Doğrulama isteği başarısız — rate limit veya yetki hatası</span>
        </div>
      )}

      {result && (
        <div className={cn(
          'rounded-lg border p-3 flex items-start gap-3',
          result.valid
            ? 'bg-emerald-500/10 border-emerald-500/20'
            : 'bg-red-500/10 border-red-500/20',
        )}>
          {result.valid
            ? <ShieldCheck size={18} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            : <ShieldAlert  size={18} className="text-red-400 flex-shrink-0 mt-0.5" />
          }
          <div className="flex-1 min-w-0 space-y-1">
            <p className={cn('text-sm font-semibold', result.valid ? 'text-emerald-300' : 'text-red-300')}>
              {result.valid ? 'Zincir Bütün' : 'Zincir Kırık!'}
            </p>
            <p className="text-xs text-slate-400">{result.message}</p>
            <div className="flex gap-4 mt-1">
              <span className="text-[11px] text-slate-600">Doğrulanan: <span className="text-slate-300 font-mono">{result.checked}</span></span>
              {result.skipped > 0 && (
                <span className="text-[11px] text-slate-600">Atlanan (eski): <span className="text-slate-300 font-mono">{result.skipped}</span></span>
              )}
              {result.first_broken_at !== null && (
                <span className="text-[11px] text-red-400">İlk kırılma: kayıt #{result.first_broken_at}</span>
              )}
            </div>
          </div>
          {lastVerified && (
            <span className="text-[10px] text-slate-700 flex-shrink-0">
              {new Date(lastVerified).toLocaleTimeString('tr-TR')}
            </span>
          )}
        </div>
      )}

      {!result && !verifyMutation.isError && (
        <p className="text-[11px] text-slate-700">
          Tüm audit kayıtlarının SHA-256 hash zinciri doğrulanır.
          Bir kayıt değiştirilmiş veya silinmişse tespit edilir.
          Rate limit: 2/dk (admin only).
        </p>
      )}
    </div>
  )
}

// ─── Audit Row ─────────────────────────────────────────────────────────────────

type AuditEventItem = {
  id: number; event_id: string; actor: string; action: string
  resource: string; detail: string | null; ip_address: string | null; timestamp: string
}

function AuditRow({ ev }: { ev: AuditEventItem }) {
  const [expanded, setExpanded] = useState(false)
  const breakGlass  = isBreakGlass(ev.action)
  const destructive = isDestructive(ev.action)

  return (
    <>
      <tr
        className={cn(
          'transition-colors cursor-pointer',
          breakGlass
            ? 'bg-red-950/20 hover:bg-red-950/30 border-l-2 border-l-red-500'
            : destructive
              ? 'hover:bg-sky-950/20 border-b border-sky-900/10'
              : 'hover:bg-sky-950/20 border-b border-sky-900/10',
        )}
        onClick={() => ev.detail ? setExpanded(v => !v) : undefined}
      >
        <td className="px-4 py-2.5 text-xs text-slate-600 font-mono whitespace-nowrap">
          {formatDate(ev.timestamp)}
        </td>
        <td className="px-4 py-2.5 text-xs font-medium">
          <span className={cn(breakGlass ? 'text-red-300 font-bold' : 'text-slate-200')}>
            {ev.actor}
          </span>
          {breakGlass && (
            <span className="ml-1.5 text-[10px] bg-red-500/10 text-red-400 border border-red-500/25 rounded px-1">
              BREAK-GLASS
            </span>
          )}
        </td>
        <td className={cn('px-4 py-2.5 text-xs font-medium', ACTION_COLORS[ev.action] ?? 'text-slate-300')}>
          {ACTION_LABELS[ev.action] ?? ev.action}
        </td>
        <td className="px-4 py-2.5 text-xs text-slate-500 font-mono truncate max-w-[10rem]">
          {ev.resource}
        </td>
        <td className="px-4 py-2.5 text-xs text-slate-600 max-w-xs truncate">
          {ev.detail ?? '—'}
        </td>
        <td className="px-4 py-2.5 text-xs text-slate-600 font-mono whitespace-nowrap">
          {ev.ip_address ?? '—'}
        </td>
        <td className="px-4 py-2.5 w-6">
          {ev.detail && (
            expanded
              ? <ChevronUp   size={12} className="text-slate-600" />
              : <ChevronDown size={12} className="text-slate-600" />
          )}
        </td>
      </tr>
      {expanded && ev.detail && (
        <tr className={cn('border-b border-sky-900/10', breakGlass ? 'bg-red-950/10' : 'bg-sky-950/10')}>
          <td colSpan={7} className="px-4 py-2">
            <pre className="text-[11px] text-slate-300 font-mono whitespace-pre-wrap break-all">
              {ev.detail}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

const SEL = 'bg-sky-950/20 border border-sky-900/25 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-sky-500/50 transition-colors'

export default function AuditPage() {
  const [actorFilter,  setActorFilter]  = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [limit,        setLimit]        = useState(100)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['audit-log', actorFilter, limit],
    queryFn:  () => maintenanceApi.auditLog({ limit, actor: actorFilter || undefined }),
    refetchInterval: 60_000,
  })

  const rawEvents: AuditEventItem[] = data?.events ?? []
  const events = rawEvents.filter(ev =>
    actionFilter === 'all' || ev.action.startsWith(actionFilter)
  )
  const breakGlassCount = rawEvents.filter(ev => isBreakGlass(ev.action)).length

  return (
    <div className="space-y-5 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <ClipboardList size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Denetim Günlüğü</h1>
            <p className="text-xs text-slate-600">
              {events.length} kayıt
              {breakGlassCount > 0 && (
                <span className="ml-2 text-red-400 font-medium">· {breakGlassCount} break-glass olayı</span>
              )}
              {isFetching && <RefreshCw size={10} className="inline ml-1.5 animate-spin" />}
            </p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-sky-950/30 border border-sky-900/20 hover:bg-sky-950/50 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
          Yenile
        </button>
      </div>

      {/* SHA-256 chain integrity */}
      <ChainIntegrityPanel />

      {/* Break-glass alert */}
      {breakGlassCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-red-500/25 bg-red-500/10">
          <AlertTriangle size={15} className="text-red-400 flex-shrink-0" />
          <p className="text-sm text-red-300">
            <span className="font-bold">{breakGlassCount}</span> adet break-glass olayı tespit edildi.
            Bu kayıtlar kırmızı ile vurgulanmıştır. Yetkisiz erişim varsa güvenlik ekibini bilgilendirin.
          </p>
        </div>
      )}

      {/* Table panel */}
      <div className="bg-[#0a1120] border border-sky-900/20 rounded-xl overflow-hidden">
        {/* Filters */}
        <div className="px-4 py-3 border-b border-sky-900/15 flex items-center gap-3 flex-wrap">
          <span className="text-xs font-medium text-slate-500 flex-1">Admin Eylem Geçmişi</span>

          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600" />
            <input
              placeholder="Kullanıcı filtrele..."
              value={actorFilter}
              onChange={e => setActorFilter(e.target.value)}
              className="pl-7 pr-3 py-1.5 w-36 text-xs bg-sky-950/20 border border-sky-900/25 rounded-lg text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-sky-500/50 transition-colors"
            />
          </div>

          <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} className={cn(SEL, 'w-44')}>
            {ACTION_FILTER_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>

          <select value={String(limit)} onChange={e => setLimit(Number(e.target.value))} className={cn(SEL, 'w-24')}>
            {LIMITS.map(l => <option key={l} value={String(l)}>Son {l}</option>)}
          </select>
        </div>

        {isLoading ? (
          <div className="p-4"><SkeletonTable rows={8} /></div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-700">
            <ClipboardList size={28} className="opacity-20" />
            <p className="text-sm">Kayıt bulunamadı</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-sky-900/15 text-xs text-slate-600 uppercase tracking-wide">
                  <th className="px-4 py-3 text-left w-40">Zaman</th>
                  <th className="px-4 py-3 text-left w-28">Kullanıcı</th>
                  <th className="px-4 py-3 text-left w-44">İşlem</th>
                  <th className="px-4 py-3 text-left w-36">Kaynak</th>
                  <th className="px-4 py-3 text-left">Detay</th>
                  <th className="px-4 py-3 text-left w-28">IP</th>
                  <th className="w-6" />
                </tr>
              </thead>
              <tbody>
                {events.map(ev => <AuditRow key={ev.event_id} ev={ev} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
