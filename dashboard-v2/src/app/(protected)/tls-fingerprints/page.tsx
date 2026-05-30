'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Fingerprint, RefreshCw, Shield, AlertTriangle,
  ShieldAlert, X, Copy, CheckCheck, ExternalLink,
} from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import type { TlsVersionItem, TlsFingerprintItem } from '@/lib/api'
import { SkeletonStatGrid, SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

// ── JA4 parsing ──────────────────────────────────────────────────────────────

interface Ja4Parsed {
  raw:         string
  tls_version: string
  tls_label:   string
  sni_type:    string
  num_ciphers: string
  num_exts:    string
  alpn_first:  string
  risk:        'low' | 'medium' | 'high'
  risk_reasons: string[]
  nist_status: 'compliant' | 'acceptable' | 'deprecated'
}

function parseJa4(hash: string): Ja4Parsed {
  // JA4 format: {type}{tls_ver}{sni}{num_ciphers}{num_exts}{alpn}_...
  // e.g. t13d1301_...  or  t12d1301_...
  const risk_reasons: string[] = []
  let tls_version = 'Unknown'
  let tls_label   = ''
  let sni_type    = ''
  let num_ciphers = ''
  let num_exts    = ''
  let alpn_first  = ''

  try {
    // prefix: t + TLS version code + sni char + cipher count + ext count + alpn
    const prefix = hash.split('_')[0] ?? hash.split(',')[0] ?? hash
    if (prefix.startsWith('t')) {
      const ver = prefix.slice(1, 3)
      if (ver === '10') { tls_version = 'TLS 1.0'; risk_reasons.push('TLS 1.0 kullanımda (NIST SP 800-52r2 uyarınca deprecated)') }
      else if (ver === '11') { tls_version = 'TLS 1.1'; risk_reasons.push('TLS 1.1 kullanımda (deprecated)') }
      else if (ver === '12') { tls_version = 'TLS 1.2' }
      else if (ver === '13') { tls_version = 'TLS 1.3' }
    }
    // legacy JA4 comma format: t13,1301,...
    if (hash.includes(',')) {
      const parts = hash.split(',')
      const p0 = parts[0] ?? ''
      if (p0.includes('13d') || p0.endsWith('13')) tls_version = 'TLS 1.3'
      else if (p0.includes('12d') || p0.endsWith('12')) tls_version = 'TLS 1.2'
      else if (p0.includes('10d') || p0.endsWith('10')) tls_version = 'TLS 1.0'
    }
    tls_label = { 'TLS 1.3': '✓ Güvenli', 'TLS 1.2': '⚠ Kabul Edilebilir', 'TLS 1.0': '✕ Eski', 'TLS 1.1': '✕ Eski' }[tls_version] ?? ''
    sni_type = hash.includes('d') ? 'Domain' : hash.includes('i') ? 'IP' : '—'
    num_ciphers = 'Bkz. ham hash'
    num_exts    = 'Bkz. ham hash'
    alpn_first  = hash.includes('h2') ? 'h2 (HTTP/2)' : hash.includes('h1') ? 'h1 (HTTP/1.1)' : '—'
  } catch { /* ignore */ }

  if (hash.toLowerCase().includes('null') || hash.length < 8) {
    risk_reasons.push('Kısa/geçersiz fingerprint — şüpheli client')
  }

  const nist_status: Ja4Parsed['nist_status'] =
    tls_version === 'TLS 1.3' ? 'compliant' :
    tls_version === 'TLS 1.2' ? 'acceptable' : 'deprecated'

  const risk: Ja4Parsed['risk'] =
    risk_reasons.length > 1 ? 'high' :
    risk_reasons.length === 1 ? 'medium' : 'low'

  return { raw: hash, tls_version, tls_label, sni_type, num_ciphers, num_exts, alpn_first, risk, risk_reasons, nist_status }
}

// ── JA4 Detail Modal ──────────────────────────────────────────────────────────

function Ja4Modal({ fp, onClose }: { fp: TlsFingerprintItem; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const parsed = useMemo(() => parseJa4(fp.fingerprint), [fp.fingerprint])

  function copyHash() {
    navigator.clipboard.writeText(fp.fingerprint).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const riskColors = { low: 'text-emerald-400', medium: 'text-yellow-400', high: 'text-red-400' }
  const nistColors = { compliant: 'text-emerald-400 bg-emerald-950/40 border-emerald-900', acceptable: 'text-yellow-400 bg-yellow-950/40 border-yellow-900', deprecated: 'text-red-400 bg-red-950/40 border-red-900' }
  const nistLabels = { compliant: 'NIST Uyumlu', acceptable: 'Kabul Edilebilir', deprecated: 'Eski — Kaldırılmalı' }

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0a1120] border border-sky-900/30 rounded-xl w-full max-w-lg shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-sky-900/20">
          <div className="flex items-center gap-2">
            <Fingerprint size={16} className="text-sky-400" />
            <h2 className="text-sm font-semibold text-slate-100">JA4 Fingerprint Detayı</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={16} /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Ham Hash */}
          <div className="bg-sky-950/20 rounded-lg px-4 py-3 flex items-start justify-between gap-3">
            <code className="text-xs text-sky-300 break-all font-mono">{fp.fingerprint}</code>
            <button onClick={copyHash} className="shrink-0 text-slate-500 hover:text-slate-200 mt-0.5">
              {copied ? <CheckCheck size={14} className="text-emerald-400" /> : <Copy size={14} />}
            </button>
          </div>

          {/* Durum rozetleri */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('px-2.5 py-1 rounded-full text-xs font-medium border', nistColors[parsed.nist_status])}>
              {nistLabels[parsed.nist_status]}
            </span>
            {fp.is_malicious && (
              <span className="px-2.5 py-1 rounded-full text-xs font-medium border bg-red-950/60 text-red-400 border-red-800">
                ZARARLI
              </span>
            )}
            <span className={cn('px-2.5 py-1 rounded-full text-xs font-medium border border-sky-900/20 bg-sky-950/20', riskColors[parsed.risk])}>
              Risk: {parsed.risk.toUpperCase()}
            </span>
          </div>

          {/* Parse edilen alanlar */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'TLS Versiyonu', value: parsed.tls_version },
              { label: 'Versiyon Değerlendirme', value: parsed.tls_label || '—' },
              { label: 'SNI Tipi', value: parsed.sni_type || '—' },
              { label: 'ALPN', value: parsed.alpn_first || '—' },
              { label: 'Bağlantı Sayısı', value: fp.count.toLocaleString('tr-TR') },
            ].map(({ label, value }) => (
              <div key={label} className="bg-sky-950/20 rounded-lg p-3">
                <p className="text-xs text-slate-500 mb-1">{label}</p>
                <p className="text-sm text-slate-200 font-mono">{value}</p>
              </div>
            ))}
          </div>

          {/* Risk uyarıları */}
          {parsed.risk_reasons.length > 0 && (
            <div className="bg-red-950/30 border border-red-900/50 rounded-lg p-3 space-y-1">
              {parsed.risk_reasons.map((r, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-red-300">
                  <AlertTriangle size={12} className="shrink-0 mt-0.5" />
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}

          {/* Dış bağlantılar */}
          <div className="flex gap-2 flex-wrap">
            <a href={`https://ja4db.com/api/read?ja4=${encodeURIComponent(fp.fingerprint)}`}
              target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1 px-3 py-1.5 rounded text-xs bg-sky-950/20 hover:bg-sky-950/30 text-slate-300 border border-sky-900/20">
              <ExternalLink size={11} /> JA4+ DB
            </a>
            <a href={`https://www.shodan.io/search?query=ja4%3A${encodeURIComponent(fp.fingerprint)}`}
              target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1 px-3 py-1.5 rounded text-xs bg-sky-950/20 hover:bg-sky-950/30 text-slate-300 border border-sky-900/20">
              <ExternalLink size={11} /> Shodan
            </a>
          </div>

          {/* Kaynak notu */}
          <p className="text-xs text-slate-600">
            Kaynak: FoxIO JA4+ Spec · NIST SP 800-52r2 TLS versiyon rehberi · MITRE ATT&CK T1071
          </p>
        </div>
      </div>
    </div>
  )
}

// ── TLS Version Risk Matrix ───────────────────────────────────────────────────

const CIPHER_CLASSES = ['Güçlü (AEAD)', 'Orta (CBC)', 'Zayıf (RC4/NULL)'] as const

// Simüle edilmiş risk matrix: TLS 1.3 sadece güçlü cipher destekler
const MATRIX_DATA: Record<string, Record<string, 'safe' | 'warn' | 'danger' | 'none'>> = {
  'TLS 1.3': { 'Güçlü (AEAD)': 'safe',  'Orta (CBC)': 'none',   'Zayıf (RC4/NULL)': 'none'   },
  'TLS 1.2': { 'Güçlü (AEAD)': 'safe',  'Orta (CBC)': 'warn',   'Zayıf (RC4/NULL)': 'danger' },
  'TLS 1.1': { 'Güçlü (AEAD)': 'none',  'Orta (CBC)': 'danger', 'Zayıf (RC4/NULL)': 'danger' },
  'TLS 1.0': { 'Güçlü (AEAD)': 'none',  'Orta (CBC)': 'danger', 'Zayıf (RC4/NULL)': 'danger' },
}

const MATRIX_STYLES: Record<string, string> = {
  safe:   'bg-emerald-900/40 text-emerald-400 border-emerald-900',
  warn:   'bg-yellow-900/40 text-yellow-400 border-yellow-900',
  danger: 'bg-red-900/40 text-red-400 border-red-900',
  none:   'bg-sky-950/10 text-slate-600 border-sky-900/15',
}
const MATRIX_LABELS: Record<string, string> = { safe: '✓ Güvenli', warn: '⚠ Dikkat', danger: '✕ Risk', none: '—' }

function CipherRiskMatrix({ versions }: { versions: TlsVersionItem[] }) {
  const activeVersions = useMemo(() =>
    ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0'].filter(v =>
      versions.some(item => item.version === v)
    ), [versions])

  if (activeVersions.length === 0) return null

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            <th className="ui-th w-24">Versiyon</th>
            {CIPHER_CLASSES.map(c => (
              <th key={c} className="text-center px-3 py-2 text-slate-500 font-medium">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-sky-900/10">
          {activeVersions.map(ver => {
            const item = versions.find(v => v.version === ver)
            return (
              <tr key={ver}>
                <td className="ui-td">
                  <div className="font-mono text-slate-300">{ver}</div>
                  {item && <div className="text-slate-600">{item.count.toLocaleString()} bağ.</div>}
                </td>
                {CIPHER_CLASSES.map(cls => {
                  const state = MATRIX_DATA[ver]?.[cls] ?? 'none'
                  return (
                    <td key={cls} className="px-3 py-2 text-center">
                      <span className={cn('inline-block px-2 py-0.5 rounded border', MATRIX_STYLES[state])}>
                        {MATRIX_LABELS[state]}
                      </span>
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Version bar ───────────────────────────────────────────────────────────────

function tlsVersionColor(version: string): { bar: string; warning: boolean } {
  const v = version.toLowerCase()
  if (v.includes('1.0') || v.includes('1.1')) return { bar: 'bg-red-500',    warning: true  }
  if (v.includes('1.2'))                       return { bar: 'bg-amber-400',  warning: false }
  if (v.includes('1.3'))                       return { bar: 'bg-emerald-500', warning: false }
  return { bar: 'bg-slate-500', warning: false }
}

function TlsVersionBar({ item, total }: { item: TlsVersionItem; total: number }) {
  const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
  const { bar, warning } = tlsVersionColor(item.version)
  return (
    <div className="flex items-center gap-3">
      <div className="w-28 shrink-0 flex items-center gap-1.5">
        {warning && <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />}
        <span className={cn('text-xs font-mono', warning ? 'text-red-300' : 'text-slate-300')}>
          {item.version}
        </span>
      </div>
      <div className="flex-1 bg-sky-950/30 rounded-full h-2">
        <div className={cn('h-2 rounded-full transition-all', bar)} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-14 text-right text-xs text-zinc-400 shrink-0">
        {item.count.toLocaleString('tr-TR')} <span className="text-slate-600">({pct}%)</span>
      </span>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function TlsFingerprintsPage() {
  const [hours, setHours] = useState(24)
  const [selectedFp, setSelectedFp] = useState<TlsFingerprintItem | null>(null)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['tls-fingerprints', hours],
    queryFn:  () => analyticsApi.tlsFingerprints(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const hasMalicious  = data?.top_fingerprints.some(fp => fp.is_malicious) ?? false
  const versionTotal  = data?.tls_version_dist.reduce((s, v) => s + v.count, 0) ?? 0
  const hasDeprecated = data?.tls_version_dist.some(v => tlsVersionColor(v.version).warning) ?? false

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Fingerprint className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">TLS / JA4 Fingerprint</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-1">
            {HOURS_OPTIONS.map(opt => (
              <button key={opt.value} onClick={() => setHours(opt.value)}
                className={cn('px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors', hours === opt.value
                  ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                  : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40')}>
                {opt.label}
              </button>
            ))}
          </div>
          <button onClick={() => refetch()} className="p-1.5 rounded-lg border border-sky-900/20 text-slate-400 hover:text-slate-100 hover:bg-sky-950/30">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
          Veri yüklenemedi. <button onClick={() => refetch()} className="underline">Tekrar dene</button>
        </div>
      )}

      {/* Uyarı banner */}
      {hasMalicious && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 px-4 py-3 text-sm text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          Tabloda zararlı fingerprint tespit edildi — hemen incelenmeli.
        </div>
      )}
      {hasDeprecated && !hasMalicious && (
        <div className="rounded-lg border border-amber-800 bg-amber-950/30 px-4 py-3 text-sm text-amber-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          Eski TLS versiyonu (1.0/1.1) tespit edildi — NIST SP 800-52r2 uyarınca devre dışı bırakılmalı.
        </div>
      )}

      {/* KPI Kartlar */}
      {isLoading ? (
        <SkeletonStatGrid cols={4} height={96} />
      ) : null}
      <div className={isLoading ? 'hidden' : 'grid grid-cols-2 md:grid-cols-4 gap-4'}>
        {data ? (
          <>
            <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-sky-500/15 text-sky-400"><Shield className="w-5 h-5" /></div>
              <div>
                <p className="text-xs text-slate-500">Toplam Bağlantı</p>
                <p className="text-2xl font-bold text-slate-100">{data.total_connections.toLocaleString('tr-TR')}</p>
              </div>
            </div>
            <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-sky-950/20 text-slate-400"><Fingerprint className="w-5 h-5" /></div>
              <div>
                <p className="text-xs text-slate-500">Benzersiz Fingerprint</p>
                <p className="text-2xl font-bold text-slate-100">{data.unique_count.toLocaleString('tr-TR')}</p>
              </div>
            </div>
            <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-center gap-3">
              <div className={cn('p-2 rounded-lg', data.suspicious_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-sky-950/20 text-slate-400')}>
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <p className="text-xs text-slate-500">Şüpheli / Zararlı</p>
                <p className={cn('text-2xl font-bold', data.suspicious_count > 0 ? 'text-red-400' : 'text-slate-100')}>
                  {data.suspicious_count.toLocaleString('tr-TR')}
                </p>
              </div>
            </div>
            <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-center gap-3">
              <div className={cn('p-2 rounded-lg', data.self_signed_count > 0 ? 'bg-amber-500/15 text-amber-400' : 'bg-sky-950/20 text-slate-400')}>
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <p className="text-xs text-slate-500">Self-Signed Sertifika</p>
                <p className={cn('text-2xl font-bold', data.self_signed_count > 0 ? 'text-amber-400' : 'text-slate-100')}>
                  {data.self_signed_count.toLocaleString('tr-TR')}
                </p>
              </div>
            </div>
          </>
        ) : null}
      </div>

      {/* TLS Versiyon + Cipher Risk Matrix */}
      {data && (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="ui-panel">
            <div className="ui-panel-header">
              <h2 className="text-sm font-semibold text-slate-200">TLS Versiyon Dağılımı</h2>
            </div>
            <div className="p-4 space-y-3">
              {data.tls_version_dist.length === 0 ? (
                <p className="text-sm text-slate-600 py-4 text-center">Versiyon verisi mevcut değil</p>
              ) : (
                data.tls_version_dist.map(item => (
                  <TlsVersionBar key={item.version} item={item} total={versionTotal} />
                ))
              )}
            </div>
          </div>

          <div className="ui-panel">
            <div className="ui-panel-header">
              <h2 className="text-sm font-semibold text-slate-200">Cipher Suite Risk Matrisi</h2>
              <p className="text-xs text-slate-600 mt-0.5">TLS versiyon × cipher gücü (NIST SP 800-52r2)</p>
            </div>
            <div className="p-4">
              {data.tls_version_dist.length === 0 ? (
                <p className="text-sm text-slate-600 py-4 text-center">Veri yok</p>
              ) : (
                <CipherRiskMatrix versions={data.tls_version_dist} />
              )}
            </div>
          </div>
        </div>
      )}

      {/* SNI Tablosu */}
      {data && data.top_sni.length > 0 && (
        <div className="ui-panel">
          <div className="ui-panel-header">
            <h2 className="text-sm font-semibold text-slate-200">Bağlanılan Top Domainler (SNI)</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr >
                  <th className="ui-th">#</th>
                  <th className="ui-th">Domain</th>
                  <th className="ui-th text-right">Bağlantı</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-900/10">
                {data.top_sni.map((item, i) => (
                  <tr key={item.sni} className="hover:bg-sky-950/20">
                    <td className="ui-td text-slate-600 text-xs">{i + 1}</td>
                    <td className="ui-td font-mono text-xs text-slate-300 max-w-xs truncate" title={item.sni}>{item.sni}</td>
                    <td className="ui-td text-right text-slate-300 font-semibold text-xs">{item.count.toLocaleString('tr-TR')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Fingerprint Tablosu */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <h2 className="text-sm font-semibold text-slate-200">Top Fingerprint'ler</h2>
          <p className="text-xs text-slate-600 mt-0.5">Satıra tıkla → JA4 detay modalı</p>
        </div>

        {isLoading ? (
          <div className="p-4"><SkeletonTable rows={4} height={36} /></div>
        ) : !data || data.top_fingerprints.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-600">
            <Fingerprint className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Bu zaman aralığında TLS bağlantısı tespit edilmedi</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr >
                  <th className="ui-th">#</th>
                  <th className="ui-th">Parmak İzi (JA4)</th>
                  <th className="ui-th">TLS Ver.</th>
                  <th className="ui-th text-right">Bağlantı</th>
                  <th className="ui-th">Durum</th>
                  <th className="px-4 py-2.5"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-900/10">
                {data.top_fingerprints.map((fp, idx) => {
                  const parsed = parseJa4(fp.fingerprint)
                  return (
                    <tr key={fp.fingerprint}
                      onClick={() => setSelectedFp(fp)}
                      className={cn('cursor-pointer transition-colors',
                        fp.is_malicious ? 'bg-red-950/20 hover:bg-red-950/30' : 'hover:bg-sky-950/20')}>
                      <td className="ui-td text-slate-600 text-xs">{idx + 1}</td>
                      <td className="ui-td">
                        <span className="font-mono text-xs text-sky-300" title={fp.fingerprint}>
                          {fp.fingerprint.length > 36 ? `${fp.fingerprint.slice(0, 36)}…` : fp.fingerprint}
                        </span>
                      </td>
                      <td className="ui-td">
                        <span className={cn('text-xs font-mono',
                          parsed.tls_version.includes('1.3') ? 'text-emerald-400' :
                          parsed.tls_version.includes('1.2') ? 'text-yellow-400' : 'text-red-400')}>
                          {parsed.tls_version}
                        </span>
                      </td>
                      <td className="ui-td text-right text-slate-300 font-semibold text-sm">
                        {fp.count.toLocaleString('tr-TR')}
                      </td>
                      <td className="ui-td">
                        {fp.is_malicious ? (
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/60 text-red-400 border border-red-800">ZARARLI</span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-900/40 text-emerald-400 border border-emerald-800">Temiz</span>
                        )}
                      </td>
                      <td className="ui-td text-slate-600 text-xs">Detay →</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* JA4 Detay Modal */}
      {selectedFp && <Ja4Modal fp={selectedFp} onClose={() => setSelectedFp(null)} />}
    </div>
  )
}
