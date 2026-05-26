'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, AlertTriangle, Lock, FileWarning, Mail,
  Network, Wifi, Activity, ChevronRight, Info,
} from 'lucide-react'
import { networkIntelApi, type NetworkIntelEvent } from '@/lib/api'
import { TimeSeriesChart } from '@/components/charts/TimeSeriesChart'
import { cn } from '@/lib/utils'

// ────────────────────────────────────────────────────────────────────────────
// Yardımcı bileşenler
// ────────────────────────────────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, count, accent }: {
  icon: React.ElementType
  title: string
  count: number
  accent: string
}) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <div className={cn('w-7 h-7 rounded-md flex items-center justify-center', accent)}>
        <Icon size={13} />
      </div>
      <span className="text-sm font-semibold text-zinc-300">{title}</span>
      {count > 0 && (
        <span className={cn(
          'ml-auto text-xs font-bold px-2 py-0.5 rounded-full',
          accent.includes('red') ? 'bg-red-500/20 text-red-400' :
          accent.includes('orange') ? 'bg-orange-500/20 text-orange-400' :
          accent.includes('yellow') ? 'bg-yellow-500/20 text-yellow-400' :
          'bg-blue-500/20 text-blue-400',
        )}>
          {count}
        </span>
      )}
    </div>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center py-6 text-zinc-600 text-xs gap-2">
      <Info size={12} />
      <span>{label}</span>
    </div>
  )
}

function EventRow({ ev, badgeText, badgeColor }: {
  ev: NetworkIntelEvent
  badgeText?: string
  badgeColor?: string
}) {
  const ts = ev.timestamp
    ? new Date(ev.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'
  const hash = extractHash(ev.message ?? '')

  return (
    <div className="flex items-start gap-3 px-4 py-2.5 border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
      <div className="flex-1 min-w-0">
        <p className="text-xs text-zinc-300 font-medium truncate">{ev.message}</p>
        <div className="flex items-center gap-2 mt-0.5 flex-wrap">
          {ev.source_ip && (
            <span className="text-[11px] text-zinc-600 font-mono">{ev.source_ip}</span>
          )}
          {ev.destination_ip && ev.destination_ip !== ev.source_ip && (
            <>
              <span className="text-zinc-700">→</span>
              <span className="text-[11px] text-zinc-600 font-mono">{ev.destination_ip}</span>
            </>
          )}
          {hash && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500 border border-zinc-700" title="TLS fingerprint hash">
              {hash}…
            </span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        {badgeText && (
          <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wide', badgeColor)}>
            {badgeText}
          </span>
        )}
        <span className="text-[11px] text-zinc-600 font-mono whitespace-nowrap">{ts}</span>
      </div>
    </div>
  )
}

function Panel({ title, children, className }: {
  title?: string; children: React.ReactNode; className?: string
}) {
  return (
    <div className={cn('bg-[#13161e] border border-white/[0.06] rounded-lg overflow-hidden', className)}>
      {title && (
        <div className="px-4 py-3 border-b border-white/[0.06]">
          <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">{title}</span>
        </div>
      )}
      {children}
    </div>
  )
}

function SummaryCard({
  label, value, sub, accent, icon: Icon, danger,
}: {
  label: string; value: number; sub?: string
  accent: string; icon: React.ElementType; danger?: boolean
}) {
  return (
    <div className={cn(
      'bg-[#13161e] border rounded-lg p-4',
      danger && value > 0 ? 'border-red-500/30' : 'border-white/[0.06]',
    )}>
      <div className="flex items-start justify-between mb-3">
        <div className={cn('w-8 h-8 rounded-md flex items-center justify-center', accent)}>
          <Icon size={15} />
        </div>
        {danger && value > 0 && (
          <span className="text-[10px] text-red-400 font-bold">TEHLİKE</span>
        )}
      </div>
      <p className={cn(
        'text-2xl font-bold tabular-nums',
        danger && value > 0 ? 'text-red-400' : 'text-zinc-100',
      )}>
        {value}
      </p>
      <p className="text-xs text-zinc-500 mt-0.5 font-medium">{label}</p>
      {sub && <p className="text-[11px] text-zinc-600 mt-1">{sub}</p>}
    </div>
  )
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {}
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1
  const n = s.length
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / n
    return acc + p * Math.log2(p)
  }, 0)
}

function extractHash(msg: string): string | null {
  const m = msg.match(/(?:JA4|JA3)=([a-f0-9_]{12,})/i)
  return m ? m[1].slice(0, 16) : null
}

// ────────────────────────────────────────────────────────────────────────────
// Zeek dağılım grafiği
// ────────────────────────────────────────────────────────────────────────────

const ZEEK_COLORS: Record<string, string> = {
  dns_query:                 'bg-blue-500',
  ssl_connection:            'bg-indigo-500',
  network_connection:        'bg-zinc-500',
  ssh_failure:               'bg-red-500',
  ssh_success:               'bg-green-500',
  web_request:               'bg-cyan-500',
  web_client_error:          'bg-orange-500',
  tls_suspicious_fingerprint:'bg-red-600',
  x509_certificate:          'bg-yellow-500',
  ftp_command:               'bg-purple-500',
  smtp_session:              'bg-pink-500',
}

function ZeekDistribution({ data }: { data: Record<string, number> }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0)
  if (total === 0) return <EmptyState label="Zeek verisi yok" />

  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1])

  return (
    <div className="px-4 py-3 space-y-2">
      {sorted.map(([action, count]) => {
        const pct = total > 0 ? (count / total) * 100 : 0
        const color = ZEEK_COLORS[action] ?? 'bg-zinc-600'
        return (
          <div key={action}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-zinc-400 font-mono truncate max-w-[60%]">
                {action.replace(/_/g, ' ')}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-zinc-600">{pct.toFixed(1)}%</span>
                <span className="text-[11px] text-zinc-500 font-mono w-12 text-right">{count.toLocaleString()}</span>
              </div>
            </div>
            <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className={cn('h-full rounded-full', color)}
                style={{ width: `${Math.max(pct, 0.5)}%` }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ────────────────────────────────────────────────────────────────────────────
// Sayfa
// ────────────────────────────────────────────────────────────────────────────

export default function NetworkIntelligencePage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, error } = useQuery({
    queryKey: ['network-intel', hours],
    queryFn: () => networkIntelApi.get(hours),
    refetchInterval: 30_000,
  })

  const summary = data?.summary
  const s = summary ?? {
    ja3_suspicious_count:   0,
    ssl_anomaly_count:      0,
    self_signed_cert_count: 0,
    ftp_sensitive_count:    0,
    smtp_session_count:     0,
    zeek_total_24h:         0,
  }

  return (
    <div className="p-6 space-y-6 max-w-[1600px]">

      {/* Başlık */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
            <Network size={18} className="text-indigo-400" />
            Network Intelligence
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Zeek tabanlı TLS/JA4, x509, FTP, SMTP ve DNS analizi
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          {[1, 6, 24, 48].map(h => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={cn(
                'text-xs px-3 py-1.5 rounded-md font-medium transition-colors',
                hours === h
                  ? 'bg-indigo-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700',
              )}
            >
              {h < 24 ? `${h}s` : `${h / 24}g`}
            </button>
          ))}
        </div>
      </div>

      {/* Özet kartlar */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
        <SummaryCard
          label="TLS Şüpheli Parmak İzi"
          value={s.ja3_suspicious_count}
          sub="Bilinen C2 imzası (JA4/JA3)"
          accent="bg-red-500/20 text-red-400"
          icon={Shield}
          danger
        />
        <SummaryCard
          label="SSL Anomali"
          value={s.ssl_anomaly_count}
          sub="Geçersiz/süresi dolmuş"
          accent="bg-orange-500/20 text-orange-400"
          icon={Lock}
          danger
        />
        <SummaryCard
          label="Self-Signed Sertifika"
          value={s.self_signed_cert_count}
          sub="x509 self-signed"
          accent="bg-yellow-500/20 text-yellow-400"
          icon={FileWarning}
        />
        <SummaryCard
          label="FTP Hassas Komut"
          value={s.ftp_sensitive_count}
          sub="RETR/STOR/DELE"
          accent="bg-purple-500/20 text-purple-400"
          icon={AlertTriangle}
        />
        <SummaryCard
          label="SMTP Oturumu"
          value={s.smtp_session_count}
          sub="Email trafiği"
          accent="bg-pink-500/20 text-pink-400"
          icon={Mail}
        />
        <SummaryCard
          label="Zeek Toplam"
          value={s.zeek_total_24h}
          sub={`Son ${hours} saat`}
          accent="bg-blue-500/20 text-blue-400"
          icon={Activity}
        />
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-16 text-zinc-600 text-sm">
          Yükleniyor…
        </div>
      )}
      {error && (
        <div className="flex items-center justify-center py-8 text-red-500/80 text-sm bg-red-500/5 rounded-lg border border-red-500/20">
          API hatası — backend çalışıyor mu?
        </div>
      )}

      {data && data.summary.zeek_total_24h === 0 && (
        <div className="flex flex-col items-center justify-center py-16 gap-3 rounded-lg border border-white/[0.06] bg-[#13161e]">
          <Wifi size={32} className="text-zinc-700" />
          <p className="text-sm text-zinc-500 font-medium">Zeek veri akışı bekleniyor</p>
          <p className="text-xs text-zinc-600 max-w-sm text-center">
            Son {hours} saatte normalize edilmiş Zeek logu bulunamadı. Zeek collector ve Zeek agent durumunu kontrol edin.
          </p>
        </div>
      )}

      {data && data.summary.zeek_total_24h > 0 && (
        <>
          {/* Zaman serisi + Zeek dağılımı */}
          <div className="grid grid-cols-1 xl:grid-cols-5 gap-3">
            <Panel title={`Zeek Olay Hacmi — Son ${hours} Saat`} className="xl:col-span-3">
              {(data.timeline ?? []).length > 1 ? (
                <div className="px-2 py-3">
                  <TimeSeriesChart
                    data={data.timeline.map(d => ({ t: d.t, v: d.v }))}
                    label="Zeek"
                    color="#6366f1"
                    unit=" olay"
                    height={160}
                  />
                </div>
              ) : (
                <EmptyState label="Zaman serisi verisi yok" />
              )}
            </Panel>

            <Panel title="Zeek Event Dağılımı" className="xl:col-span-2">
              <ZeekDistribution data={data.zeek_distribution ?? {}} />
            </Panel>
          </div>

          {/* TLS Şüpheli Parmak İzleri — kritik panel */}
          <Panel>
            <div className="px-4 py-3">
              <SectionHeader
                icon={Shield}
                title="Şüpheli TLS Parmak İzleri (JA4/JA3)"
                count={data.ja3_suspicious.length}
                accent="bg-red-500/20 text-red-400"
              />
              {data.ja3_suspicious.length === 0 ? (
                <EmptyState label="Şüpheli TLS parmak izi tespit edilmedi" />
              ) : (
                <div className="border border-white/[0.06] rounded-md overflow-hidden">
                  {data.ja3_suspicious.slice(0, 20).map((ev, i) => (
                    <EventRow
                      key={i}
                      ev={ev}
                      badgeText={ev.fingerprint_type === 'ja4' ? 'JA4·C2' : 'JA3·C2'}
                      badgeColor={ev.fingerprint_type === 'ja4'
                        ? 'bg-red-600/30 text-red-300'
                        : 'bg-red-500/20 text-red-400'}
                    />
                  ))}
                </div>
              )}
            </div>
          </Panel>

          {/* İkinci satır: SSL anomalileri + x509 self-signed */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <Panel>
              <div className="px-4 py-3">
                <SectionHeader
                  icon={Lock}
                  title="SSL Sertifika Anomalileri"
                  count={data.ssl_anomalies.length}
                  accent="bg-orange-500/20 text-orange-400"
                />
                {data.ssl_anomalies.length === 0 ? (
                  <EmptyState label="SSL anomalisi yok" />
                ) : (
                  <div className="border border-white/[0.06] rounded-md overflow-hidden">
                    {data.ssl_anomalies.slice(0, 10).map((ev, i) => (
                      <EventRow
                        key={i}
                        ev={ev}
                        badgeText={ev.severity?.toUpperCase()}
                        badgeColor="bg-orange-500/20 text-orange-400"
                      />
                    ))}
                  </div>
                )}
              </div>
            </Panel>

            <Panel>
              <div className="px-4 py-3">
                <SectionHeader
                  icon={FileWarning}
                  title="Self-Signed Sertifikalar"
                  count={data.self_signed_certs.length}
                  accent="bg-yellow-500/20 text-yellow-400"
                />
                {data.self_signed_certs.length === 0 ? (
                  <EmptyState label="Self-signed sertifika yok" />
                ) : (
                  <div className="border border-white/[0.06] rounded-md overflow-hidden">
                    {data.self_signed_certs.slice(0, 10).map((ev, i) => (
                      <EventRow
                        key={i}
                        ev={ev}
                        badgeText="SELF-SIGNED"
                        badgeColor="bg-yellow-500/20 text-yellow-400"
                      />
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          </div>

          {/* Üçüncü satır: FTP + SMTP */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <Panel>
              <div className="px-4 py-3">
                <SectionHeader
                  icon={AlertTriangle}
                  title="FTP Hassas Komutlar"
                  count={data.ftp_sensitive.length}
                  accent="bg-purple-500/20 text-purple-400"
                />
                {data.ftp_sensitive.length === 0 ? (
                  <EmptyState label="FTP hassas komut yok" />
                ) : (
                  <div className="border border-white/[0.06] rounded-md overflow-hidden">
                    {data.ftp_sensitive.slice(0, 10).map((ev, i) => (
                      <EventRow
                        key={i}
                        ev={ev}
                        badgeText="RETR/STOR"
                        badgeColor="bg-purple-500/20 text-purple-400"
                      />
                    ))}
                  </div>
                )}
              </div>
            </Panel>

            <Panel>
              <div className="px-4 py-3">
                <SectionHeader
                  icon={Mail}
                  title="SMTP Oturumları"
                  count={data.smtp_sessions.length}
                  accent="bg-pink-500/20 text-pink-400"
                />
                {data.smtp_sessions.length === 0 ? (
                  <EmptyState label="SMTP trafiği yok" />
                ) : (
                  <div className="border border-white/[0.06] rounded-md overflow-hidden">
                    {data.smtp_sessions.slice(0, 10).map((ev, i) => (
                      <EventRow
                        key={i}
                        ev={ev}
                        badgeText="EMAIL"
                        badgeColor="bg-pink-500/20 text-pink-400"
                      />
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          </div>

          {/* Alt satır: Top kaynaklar + DNS sorgular */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <Panel title="En Aktif Kaynak IP'ler (Zeek)">
              {(data.top_sources ?? []).length === 0 ? (
                <EmptyState label="Zeek kaynak IP verisi yok" />
              ) : (() => {
                const maxCount = Math.max(...data.top_sources.map(s => s.count), 1)
                return (
                  <div className="divide-y divide-white/[0.04]">
                    {data.top_sources.map((src, i) => (
                      <div key={i} className="px-4 py-2.5">
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] text-zinc-600 w-5 text-right">{i + 1}</span>
                            <span className="text-sm text-zinc-300 font-mono">{src.ip}</span>
                          </div>
                          <span className="text-xs font-mono text-indigo-400">{src.count.toLocaleString()}</span>
                        </div>
                        <div className="ml-7 h-1 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-indigo-500/60 rounded-full"
                            style={{ width: `${(src.count / maxCount) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )
              })()}
            </Panel>

            <Panel title="En Çok DNS Sorgusu">
              {(data.dns_top ?? []).length === 0 ? (
                <EmptyState label="DNS sorgu verisi yok" />
              ) : (
                <div className="divide-y divide-white/[0.04]">
                  {data.dns_top.map((d, i) => {
                    const host = d.query.replace(/\.$/, '').split('.').slice(-2).join('.')
                    const entropy = shannonEntropy(host)
                    const isDga = entropy > 3.5
                    return (
                      <div key={i} className="flex items-center justify-between px-4 py-2.5">
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <span className="text-[11px] text-zinc-600 w-5 text-right flex-shrink-0">{i + 1}</span>
                          <span className={cn('text-xs truncate', isDga ? 'text-orange-300' : 'text-zinc-300')}>
                            {d.query}
                          </span>
                          {isDga && (
                            <span
                              className="flex-shrink-0 text-[9px] px-1 py-0.5 rounded bg-orange-900/40 text-orange-400 border border-orange-800/40 font-bold"
                              title={`Shannon entropy: ${entropy.toFixed(2)} — DGA olabilir`}
                            >
                              DGA?
                            </span>
                          )}
                        </div>
                        <span className="text-xs font-mono text-blue-400 ml-2 flex-shrink-0">{d.count.toLocaleString()}</span>
                      </div>
                    )
                  })}
                </div>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  )
}

