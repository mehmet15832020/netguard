'use client'

import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Search, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useCommandPaletteStore } from '@/store/commandPaletteStore'

interface Command {
  section: string
  label:   string
  path:    string
  keywords: string
}

const COMMANDS: Command[] = [
  // OPERASYON
  { section: 'Operasyon', label: 'Genel Bakış',          path: '/overview',               keywords: 'ana sayfa dashboard home' },
  { section: 'Operasyon', label: 'Alertler',              path: '/alerts',                keywords: 'uyarı alarm alert' },
  { section: 'Operasyon', label: 'Incidents',             path: '/incidents',             keywords: 'olay incident güvenlik' },
  { section: 'Operasyon', label: 'Saldırı Timeline',      path: '/timeline',              keywords: 'kill chain attack saldırı zaman' },
  { section: 'Operasyon', label: 'Aktif Bloklar',         path: '/blocks',                keywords: 'ip block engel blok' },
  // AĞ İZLEME
  { section: 'Ağ İzleme', label: 'Cihazlar',             path: '/devices',               keywords: 'device cihaz network ağ' },
  { section: 'Ağ İzleme', label: 'Ağ Topolojisi',        path: '/topology',              keywords: 'topology topoloji network graph' },
  { section: 'Ağ İzleme', label: 'Ağ Keşfi',             path: '/discovery',             keywords: 'discovery keşif scan subnet' },
  { section: 'Ağ İzleme', label: 'SNMP İzleme',          path: '/snmp',                  keywords: 'snmp monitor izleme' },
  { section: 'Ağ İzleme', label: 'Agents',                path: '/agents',                keywords: 'agent host endpoint psutil' },
  // ARAŞTIRMA
  { section: 'Araştırma', label: 'Güvenlik Olayları',    path: '/security',              keywords: 'security event log olay' },
  { section: 'Araştırma', label: 'Normalize Loglar',     path: '/logs',                  keywords: 'log syslog normalized normalize' },
  // TESPİT
  { section: 'Tespit',    label: 'Korelasyon',            path: '/correlation',           keywords: 'correlation rule korelasyon' },
  { section: 'Tespit',    label: 'Korelasyon Kuralları',  path: '/correlation-rules',     keywords: 'rule yönetim korelasyon crud' },
  { section: 'Tespit',    label: 'MITRE ATT&CK',          path: '/mitre',                 keywords: 'mitre attack tactic technique' },
  { section: 'Tespit',    label: 'Anomali Tespiti',       path: '/anomaly',               keywords: 'anomaly ml isolation forest' },
  { section: 'Tespit',    label: 'Network Intelligence',  path: '/network-intelligence',  keywords: 'intel threat network' },
  { section: 'Tespit',    label: 'Sigma Kuralları',       path: '/sigma-rules',           keywords: 'sigma rule detection' },
  { section: 'Tespit',    label: 'Sigma Sihirbazı',       path: '/sigma-wizard',          keywords: 'wizard create rule sigma' },
  { section: 'Tespit',    label: 'YAML Editör',           path: '/sigma-editor',          keywords: 'editor yaml sigma monaco' },
  { section: 'Tespit',    label: 'FP Yönetimi',           path: '/fp-management',         keywords: 'false positive fp suppress' },
  // ANALİTİK
  { section: 'Analitik',  label: 'Top Talkers',           path: '/top-talkers',           keywords: 'traffic ip port top talker' },
  { section: 'Analitik',  label: 'Alert Hacmi',           path: '/alert-volume',          keywords: 'alert volume hacim stacked area' },
  { section: 'Analitik',  label: 'Protokol Dağılımı',    path: '/protocol-distribution', keywords: 'protocol donut dağılım' },
  { section: 'Analitik',  label: 'Trafik Hacmi',          path: '/traffic-volume',        keywords: 'east west traffic hacim volume' },
  { section: 'Analitik',  label: 'Kill Chain',            path: '/kill-chain-timeline',   keywords: 'chain swimlane attack timeline' },
  { section: 'Analitik',  label: 'Threat Intel',          path: '/threat-intel-summary',  keywords: 'threat intel abuseipdb score' },
  { section: 'Analitik',  label: 'Başarısız Auth',        path: '/failed-auth',           keywords: 'auth login brute ssh başarısız' },
  { section: 'Analitik',  label: 'DNS Analiz',            path: '/dns-analysis',          keywords: 'dns tunnel entropy analiz nxdomain' },
  { section: 'Analitik',  label: 'TLS / JA4',             path: '/tls-fingerprints',      keywords: 'tls ssl ja4 fingerprint' },
  { section: 'Analitik',  label: 'Beaconing',             path: '/beaconing',             keywords: 'c2 beacon cobalt strike c&c' },
  { section: 'Analitik',  label: 'E-W Matrix',            path: '/east-west-matrix',      keywords: 'east west heatmap lateral matrix' },
  { section: 'Analitik',  label: 'Asset Risk',            path: '/asset-risk',            keywords: 'asset risk score heatmap' },
  { section: 'Analitik',  label: 'MTTD / MTTR',           path: '/mttd-mttr',             keywords: 'mttd mttr sla metric kpi' },
  // YÖNETİM
  { section: 'Yönetim',   label: 'Uyumluluk',             path: '/compliance',            keywords: 'compliance cis nist uyumluluk' },
  { section: 'Yönetim',   label: 'Raporlar',              path: '/reports',               keywords: 'report pdf export rapor' },
  { section: 'Yönetim',   label: 'Denetim Günlüğü',      path: '/audit',                 keywords: 'audit log tamperproof denetim hash' },
  { section: 'Yönetim',   label: 'Sistem Bakım',          path: '/maintenance',           keywords: 'maintenance cleanup bakım retention' },
  { section: 'Yönetim',   label: 'Ayarlar',               path: '/settings',              keywords: 'settings config mfa totp api key' },
]

const SECTION_ORDER = ['Operasyon', 'Ağ İzleme', 'Araştırma', 'Tespit', 'Analitik', 'Yönetim']

export function CommandPalette() {
  const { isOpen, close } = useCommandPaletteStore()
  const [query, setQuery]             = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const router   = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return COMMANDS
    return COMMANDS.filter(c =>
      c.label.toLowerCase().includes(q) ||
      c.section.toLowerCase().includes(q) ||
      c.keywords.toLowerCase().includes(q),
    )
  }, [query])

  const isFiltering = query.trim().length > 0

  const grouped = useMemo(() =>
    SECTION_ORDER
      .map(section => ({ section, items: COMMANDS.filter(c => c.section === section) }))
      .filter(g => g.items.length > 0),
  [])

  useEffect(() => {
    setSelectedIndex(0)
    itemRefs.current = []
  }, [query])

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [isOpen])

  useEffect(() => {
    itemRefs.current[selectedIndex]?.scrollIntoView({ block: 'nearest' })
  }, [selectedIndex])

  const handleSelect = useCallback((path: string) => {
    close()
    setQuery('')
    router.push(path)
  }, [close, router])

  useEffect(() => {
    if (!isOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        close()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex(i => (i + 1) % Math.max(filtered.length, 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex(i => (i - 1 + Math.max(filtered.length, 1)) % Math.max(filtered.length, 1))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const cmd = filtered[selectedIndex]
        if (cmd) handleSelect(cmd.path)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isOpen, filtered, selectedIndex, handleSelect, close])

  if (!isOpen) return null

  // flatIndex increments sequentially across rendered items — maps selectedIndex to DOM ref
  let flatIndex = 0

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[14vh] bg-[#040911]/80 backdrop-blur-sm"
      onClick={close}
    >
      <div
        className="w-full max-w-xl mx-4 rounded-xl border border-sky-900/30 bg-[#0a1120] shadow-[0_24px_64px_rgba(0,0,0,0.7),0_0_0_1px_rgba(56,189,248,0.04)] overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* ── Search input ───────────────────────────────────────────── */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-sky-900/20">
          <Search size={15} className="text-sky-600 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Sayfa veya komut ara..."
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder:text-slate-600 outline-none"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="text-slate-600 hover:text-slate-400 text-xs transition-colors"
            >
              Temizle
            </button>
          )}
        </div>

        {/* ── Results ────────────────────────────────────────────────── */}
        <div className="max-h-[55vh] overflow-y-auto scrollbar-thin py-1.5">
          {filtered.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-600">
              <Search size={20} className="opacity-30" />
              <p className="text-sm">"{query}" için sonuç bulunamadı</p>
            </div>
          )}

          {isFiltering ? (
            // Filtered flat list with section badge
            filtered.map((cmd) => {
              const i = flatIndex++
              const sel = i === selectedIndex
              return (
                <button
                  key={cmd.path}
                  ref={el => { itemRefs.current[i] = el }}
                  onClick={() => handleSelect(cmd.path)}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-2 text-left transition-colors text-sm border-l-2',
                    sel
                      ? 'bg-sky-500/10 border-sky-400 text-slate-100'
                      : 'border-transparent text-slate-400 hover:bg-sky-950/25 hover:text-slate-200',
                  )}
                >
                  <span className={cn(
                    'w-1.5 h-1.5 rounded-full flex-shrink-0',
                    sel ? 'bg-sky-400 shadow-[0_0_4px_rgba(56,189,248,0.8)]' : 'bg-slate-700',
                  )} />
                  <span className="flex-1">{cmd.label}</span>
                  <span className="text-[10px] text-slate-600 font-mono bg-sky-950/30 px-1.5 py-0.5 rounded border border-sky-900/20">
                    {cmd.section}
                  </span>
                  <ChevronRight size={11} className={cn('flex-shrink-0', sel ? 'text-sky-400' : 'text-slate-700')} />
                </button>
              )
            })
          ) : (
            // Grouped by section
            grouped.map(({ section, items }) => (
              <div key={section} className="mb-1">
                <p className="px-4 pt-2 pb-1 text-[9px] font-bold tracking-[0.18em] text-sky-900 uppercase select-none">
                  {section}
                </p>
                {items.map((cmd) => {
                  const i = flatIndex++
                  const sel = i === selectedIndex
                  return (
                    <button
                      key={cmd.path}
                      ref={el => { itemRefs.current[i] = el }}
                      onClick={() => handleSelect(cmd.path)}
                      className={cn(
                        'w-full flex items-center gap-3 px-4 py-1.5 text-left transition-colors text-sm border-l-2',
                        sel
                          ? 'bg-sky-500/10 border-sky-400 text-slate-100'
                          : 'border-transparent text-slate-400 hover:bg-sky-950/25 hover:text-slate-200',
                      )}
                    >
                      <span className={cn(
                        'w-1.5 h-1.5 rounded-full flex-shrink-0',
                        sel ? 'bg-sky-400 shadow-[0_0_4px_rgba(56,189,248,0.8)]' : 'bg-slate-800',
                      )} />
                      <span className="flex-1">{cmd.label}</span>
                      <ChevronRight size={11} className={cn('flex-shrink-0', sel ? 'text-sky-400' : 'text-slate-800')} />
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>

        {/* ── Footer ─────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 px-4 py-2 border-t border-sky-900/15 bg-sky-950/15">
          {[
            { key: '↑↓', label: 'gezin' },
            { key: '↵',  label: 'aç' },
            { key: 'ESC', label: 'kapat' },
          ].map(({ key, label }) => (
            <span key={key} className="flex items-center gap-1 text-[10px] text-slate-600">
              <kbd className="px-1.5 py-0.5 rounded border border-sky-900/25 font-mono text-[9px] bg-sky-950/30 text-slate-500">
                {key}
              </kbd>
              {label}
            </span>
          ))}
          <span className="ml-auto text-[10px] text-slate-700 tabular-nums">
            {filtered.length} / {COMMANDS.length} sayfa
          </span>
        </div>
      </div>
    </div>
  )
}
