'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  ClipboardList, RefreshCw, Search, ShieldCheck, ShieldAlert,
  AlertTriangle, ChevronDown, ChevronUp,
} from 'lucide-react'
import { maintenanceApi } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

// ─── Action meta ───────────────────────────────────────────────────────────────

const ACTION_LABELS: Record<string, string> = {
  'api_key.create':        'API Key Oluşturuldu',
  'api_key.delete':        'API Key Silindi',
  'retention.cleanup':     'Temizlik Çalıştırıldı',
  'auth.logout':           'Oturum Kapatıldı',
  'auth.login':            'Oturum Açıldı',
  'auth.login_failed':     'Giriş Başarısız',
  'auth.mfa_setup':        'MFA Kuruldu',
  'auth.mfa_disabled':     'MFA Devre Dışı',
  'block.create':          'IP Bloklama',
  'block.remove':          'Blok Kaldırıldı',
  'break_glass':           'Break-Glass (Acil)',
  'break_glass.unblock':   'Break-Glass Unblock',
  'incident.create':       'Incident Oluşturuldu',
  'incident.update':       'Incident Güncellendi',
  'incident.resolve':      'Incident Çözüldü',
  'sigma.create':          'Sigma Kuralı Eklendi',
  'sigma.delete':          'Sigma Kuralı Silindi',
  'sigma.toggle':          'Sigma Kuralı Değiştirildi',
  'correlation.create':    'Korelasyon Kuralı Eklendi',
  'correlation.delete':    'Korelasyon Kuralı Silindi',
  'correlation.toggle':    'Korelasyon Kuralı Değiştirildi',
  'fp_rule.create':        'FP Kuralı Oluşturuldu',
  'fp_rule.deactivate':    'FP Kuralı Devre Dışı',
}

const ACTION_COLORS: Record<string, string> = {
  'api_key.create':        'text-emerald-400',
  'api_key.delete':        'text-red-400',
  'retention.cleanup':     'text-blue-400',
  'auth.logout':           'text-zinc-400',
  'auth.login':            'text-emerald-400',
  'auth.login_failed':     'text-red-400',
  'auth.mfa_setup':        'text-indigo-400',
  'auth.mfa_disabled':     'text-orange-400',
  'block.create':          'text-red-400',
  'block.remove':          'text-emerald-400',
  'break_glass':           'text-red-300',
  'break_glass.unblock':   'text-red-300',
  'incident.create':       'text-orange-400',
  'incident.resolve':      'text-emerald-400',
  'sigma.create':          'text-indigo-400',
  'sigma.delete':          'text-red-400',
  'correlation.create':    'text-indigo-400',
  'correlation.delete':    'text-red-400',
  'fp_rule.create':        'text-yellow-400',
  'fp_rule.deactivate':    'text-zinc-400',
}

function isBreakGlass(action: string) {
  return action.includes('break_glass')
}

function isDestructive(action: string) {
  return action.includes('.delete') || action.includes('block.create') || action.includes('login_failed')
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const LIMITS = [50, 100, 250, 500]

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

// ─── Chain Integrity Panel ────────────────────────────────────────────────────

function ChainIntegrityPanel() {
  const [lastVerified, setLastVerified] = useState<number | null>(null)

  const verifyMutation = useMutation({
    mutationFn: () => maintenanceApi.auditVerify(),
    onSuccess:  () => setLastVerified(Date.now()),
  })

  const result = verifyMutation.data

  return (
    <div className="bg-[#13161e] border border-white/[0.06] rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck size={14} className="text-zinc-400" />
          <span className="text-sm font-semibold text-zinc-300">SHA-256 Hash Zinciri Bütünlüğü</span>
          <span className="text-[11px] text-zinc-600">NIST SP 800-92 §3.2</span>
        </div>
        <Button
          size="sm"
          variant="outline"
          disabled={verifyMutation.isPending}
          onClick={() => verifyMutation.mutate()}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 h-7 text-xs"
        >
          {verifyMutation.isPending
            ? <><RefreshCw size={12} className="animate-spin mr-1" />Doğrulanıyor...</>
            : <><ShieldCheck size={12} className="mr-1" />Doğrula</>
          }
        </Button>
      </div>

      {verifyMutation.isError && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-950/30 border border-red-800/50 text-xs text-red-400">
          <AlertTriangle size={13} className="flex-shrink-0" />
          <span>Doğrulama isteği başarısız — rate limit veya yetki hatası</span>
        </div>
      )}

      {result && (
        <div className={cn(
          'rounded-lg border p-3 flex items-start gap-3',
          result.valid
            ? 'bg-emerald-950/30 border-emerald-800/50'
            : 'bg-red-950/30 border-red-800/50',
        )}>
          {result.valid
            ? <ShieldCheck size={18} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            : <ShieldAlert size={18} className="text-red-400 flex-shrink-0 mt-0.5" />
          }
          <div className="flex-1 min-w-0 space-y-1">
            <p className={cn('text-sm font-semibold', result.valid ? 'text-emerald-300' : 'text-red-300')}>
              {result.valid ? 'Zincir Bütün' : 'Zincir Kırık!'}
            </p>
            <p className="text-xs text-zinc-400">{result.message}</p>
            <div className="flex gap-4 mt-1">
              <span className="text-[11px] text-zinc-500">Doğrulanan: <span className="text-zinc-300 font-mono">{result.checked}</span></span>
              {result.skipped > 0 && (
                <span className="text-[11px] text-zinc-500">Atlanan (eski): <span className="text-zinc-300 font-mono">{result.skipped}</span></span>
              )}
              {result.first_broken_at !== null && (
                <span className="text-[11px] text-red-400">İlk kırılma: kayıt #{result.first_broken_at}</span>
              )}
            </div>
          </div>
          {lastVerified && (
            <span className="text-[10px] text-zinc-600 flex-shrink-0">
              {new Date(lastVerified).toLocaleTimeString('tr-TR')}
            </span>
          )}
        </div>
      )}

      {!result && !verifyMutation.isError && (
        <p className="text-[11px] text-zinc-600">
          Tüm audit kayıtlarının SHA-256 hash zinciri doğrulanır.
          Bir kayıt değiştirilmiş veya silinmişse tespit edilir.
          Rate limit: 2/dk (admin only).
        </p>
      )}
    </div>
  )
}

// ─── Row detail expand ────────────────────────────────────────────────────────

function AuditRow({ ev }: { ev: ReturnType<typeof useAuditEvents>[number] }) {
  const [expanded, setExpanded] = useState(false)
  const breakGlass = isBreakGlass(ev.action)
  const destructive = isDestructive(ev.action)

  return (
    <>
      <TableRow
        className={cn(
          'border-zinc-800 cursor-pointer',
          breakGlass  ? 'bg-red-950/20 hover:bg-red-950/30 border-l-2 border-l-red-500' :
          destructive ? 'hover:bg-zinc-800/40' :
          'hover:bg-zinc-800/30',
        )}
        onClick={() => ev.detail ? setExpanded(v => !v) : undefined}
      >
        <TableCell className="text-xs text-zinc-500 font-mono">
          {formatDate(ev.timestamp)}
        </TableCell>
        <TableCell className="text-xs font-medium">
          <span className={cn(breakGlass ? 'text-red-300 font-bold' : 'text-zinc-200')}>
            {ev.actor}
          </span>
          {breakGlass && (
            <span className="ml-1.5 text-[10px] bg-red-900/50 text-red-400 border border-red-800/60 rounded px-1">
              BREAK-GLASS
            </span>
          )}
        </TableCell>
        <TableCell className={cn('text-xs font-medium', ACTION_COLORS[ev.action] ?? 'text-zinc-300')}>
          {ACTION_LABELS[ev.action] ?? ev.action}
        </TableCell>
        <TableCell className="text-xs text-zinc-400 font-mono truncate max-w-[10rem]">
          {ev.resource}
        </TableCell>
        <TableCell className="text-xs text-zinc-500 max-w-xs truncate">
          {ev.detail ?? '—'}
        </TableCell>
        <TableCell className="text-xs text-zinc-500 font-mono">
          {ev.ip_address ?? '—'}
        </TableCell>
        <TableCell className="w-6">
          {ev.detail && (
            expanded
              ? <ChevronUp size={12} className="text-zinc-600" />
              : <ChevronDown size={12} className="text-zinc-600" />
          )}
        </TableCell>
      </TableRow>
      {expanded && ev.detail && (
        <TableRow className={cn('border-zinc-800', breakGlass ? 'bg-red-950/10' : 'bg-zinc-900/50')}>
          <TableCell colSpan={7} className="px-4 py-2">
            <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
              {ev.detail}
            </pre>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

type AuditEventItem = {
  id: number; event_id: string; actor: string; action: string
  resource: string; detail: string | null; ip_address: string | null; timestamp: string
}

function useAuditEvents(events: AuditEventItem[]) {
  return events
}

const LIMITS_ARR = LIMITS

// ─── Main page ────────────────────────────────────────────────────────────────

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

  const events = rawEvents.filter(ev => {
    if (actionFilter !== 'all' && !ev.action.startsWith(actionFilter)) return false
    return true
  })

  const breakGlassCount = rawEvents.filter(ev => isBreakGlass(ev.action)).length

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <ClipboardList size={18} /> Denetim Günlüğü
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {events.length} kayıt
            {breakGlassCount > 0 && (
              <span className="ml-2 text-red-400 font-medium">· {breakGlassCount} break-glass olayı</span>
            )}
          </p>
        </div>
        <Button
          variant="outline" size="sm"
          onClick={() => refetch()}
          disabled={isFetching}
          className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
        >
          <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
          <span className="ml-1.5">Yenile</span>
        </Button>
      </div>

      {/* SHA-256 Chain Integrity */}
      <ChainIntegrityPanel />

      {/* Break-glass uyarısı */}
      {breakGlassCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg border border-red-800/50 bg-red-950/20">
          <AlertTriangle size={15} className="text-red-400 flex-shrink-0" />
          <p className="text-sm text-red-300">
            <span className="font-bold">{breakGlassCount}</span> adet break-glass olayı tespit edildi.
            Bu kayıtlar kırmızı ile vurgulanmıştır. Yetkisiz erişim varsa güvenlik ekibini bilgilendirin.
          </p>
        </div>
      )}

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <CardTitle className="text-sm text-zinc-300 flex-1">Admin Eylem Geçmişi</CardTitle>

            {/* Actor filter */}
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
              <Input
                placeholder="Kullanıcı filtrele..."
                value={actorFilter}
                onChange={(e) => setActorFilter(e.target.value)}
                className="pl-8 w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600"
              />
            </div>

            {/* Action filter */}
            <Select value={actionFilter} onValueChange={(v) => setActionFilter(v ?? 'all')}>
              <SelectTrigger className="w-44 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                {ACTION_FILTER_OPTIONS.map(opt => (
                  <SelectItem key={opt.value} value={opt.value} className="text-zinc-300">
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Limit */}
            <Select value={String(limit)} onValueChange={(v) => setLimit(Number(v))}>
              <SelectTrigger className="w-24 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                {LIMITS_ARR.map((l) => (
                  <SelectItem key={l} value={String(l)} className="text-zinc-300">
                    Son {l}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor...</p>
          ) : events.length === 0 ? (
            <p className="text-zinc-600 text-sm text-center py-10">Kayıt bulunamadı</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-28">Kullanıcı</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-44">İşlem</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-36">Kaynak</TableHead>
                  <TableHead className="text-zinc-500 text-xs">Detay</TableHead>
                  <TableHead className="text-zinc-500 text-xs w-28">IP</TableHead>
                  <TableHead className="w-6" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((ev) => (
                  <AuditRow key={ev.event_id} ev={ev} />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
