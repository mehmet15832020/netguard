'use client'

import dynamic from 'next/dynamic'
import { useRouter, useSearchParams } from 'next/navigation'
import { useState, useEffect, Suspense, useCallback } from 'react'
import { FileCode2, CheckCircle, XCircle, Save, RefreshCw, ChevronDown } from 'lucide-react'
import { sigmaApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const MonacoEditor = dynamic(
  () => import('@monaco-editor/react').then(m => m.default),
  { ssr: false, loading: () => <div className="flex-1 bg-zinc-950 animate-pulse rounded" /> },
)

// ─── Şablonlar ────────────────────────────────────────────────────────────────

const BLANK_YAML = `title: Yeni Kural Başlığı
name: ng_yeni_kural_base
status: test
logsource:
    category: network
detection:
    selection:
        event_action: suspicious_event
    condition: selection
level: medium
---
title: Yeni Kural Korelasyonu
id: 00000000-0000-4000-8000-000000000000
correlation:
    type: event_count
    rules: ng_yeni_kural_base
    group-by:
        - source_ip
    timespan: 5m
    condition:
        gte: 5
level: medium
tags:
    - attack.t1XXX
falsepositives:
    - Normal trafik
`

const TEMPLATES: { label: string; yaml: string }[] = [
  { label: 'Boş Şablon', yaml: BLANK_YAML },
  {
    label: 'SSH Brute Force',
    yaml: `title: SSH Brute Force Base
name: ng_ssh_bf_base
status: stable
logsource:
    category: authentication
detection:
    selection:
        event_action: ssh_failure
    condition: selection
level: low
---
title: SSH Brute Force Korelasyonu
id: 11111111-0000-4000-8000-000000000001
correlation:
    type: event_count
    rules: ng_ssh_bf_base
    group-by:
        - source_ip
    timespan: 5m
    condition:
        gte: 5
level: high
tags:
    - attack.credential_access
    - attack.t1110
falsepositives:
    - Admin SSH otomasyonu
`,
  },
  {
    label: 'Port Tarama',
    yaml: `title: Port Scan Base
name: ng_port_scan_base
status: stable
logsource:
    category: network
detection:
    selection:
        event_action: port_scan
    condition: selection
level: low
---
title: Port Tarama Tespiti
id: 22222222-0000-4000-8000-000000000002
correlation:
    type: event_count
    rules: ng_port_scan_base
    group-by:
        - source_ip
    timespan: 1m
    condition:
        gte: 20
level: medium
tags:
    - attack.reconnaissance
    - attack.t1046
falsepositives:
    - Ağ tarama araçları (nmap)
`,
  },
  {
    label: 'DNS Tünel Tespiti',
    yaml: `title: DNS Tunneling Base
name: ng_dns_tunnel_base
status: test
logsource:
    category: dns
detection:
    selection:
        event_action: dns_tunneling
    condition: selection
level: medium
---
title: DNS Tünel Korelasyonu
id: 33333333-0000-4000-8000-000000000003
correlation:
    type: event_count
    rules: ng_dns_tunnel_base
    group-by:
        - source_ip
    timespan: 10m
    condition:
        gte: 3
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004
falsepositives:
    - Meşru DNS servis trafiği
`,
  },
  {
    label: 'SQL Injection',
    yaml: `title: SQL Injection Attempt Base
name: ng_sqli_base
status: test
logsource:
    category: web
detection:
    selection:
        event_action: sql_injection
    condition: selection
level: medium
---
title: SQL Injection Spike
id: 44444444-0000-4000-8000-000000000004
correlation:
    type: event_count
    rules: ng_sqli_base
    group-by:
        - source_ip
    timespan: 2m
    condition:
        gte: 5
level: high
tags:
    - attack.initial_access
    - attack.t1190
falsepositives:
    - Güvenlik tarama araçları
`,
  },
  {
    label: 'Lateral Movement',
    yaml: `title: Lateral Movement Base
name: ng_lateral_base
status: test
logsource:
    category: network
detection:
    selection:
        event_action: lateral_movement
    condition: selection
level: medium
---
title: Lateral Movement Korelasyonu
id: 55555555-0000-4000-8000-000000000005
correlation:
    type: event_count
    rules: ng_lateral_base
    group-by:
        - source_ip
    timespan: 15m
    condition:
        gte: 3
level: critical
tags:
    - attack.lateral_movement
    - attack.t1021
falsepositives:
    - Sistem yönetimi araçları
`,
  },
]

// ─── Doğrulama sonucu ─────────────────────────────────────────────────────────

interface ValidateResult {
  valid: boolean
  title?: string
  level?: string
  is_correlation?: boolean
  rule_count?: number
  error?: string
}

// ─── Ana içerik (useSearchParams kullanır) ────────────────────────────────────

function EditorContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const ruleId = searchParams.get('rule_id')

  const [yaml, setYaml] = useState(BLANK_YAML)
  const [selectedTemplate, setSelectedTemplate] = useState(0)
  const [loadingRule, setLoadingRule] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [validating, setValidating] = useState(false)
  const [saving, setSaving] = useState(false)
  const [validateResult, setValidateResult] = useState<ValidateResult | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const loadRule = useCallback(async (id: string) => {
    setLoadingRule(true)
    setLoadError(null)
    try {
      const data = await sigmaApi.getRule(id)
      setYaml(data.yaml_content)
      setValidateResult(null)
      setSaved(false)
    } catch {
      setLoadError(`Kural yüklenemedi: ${id}`)
    } finally {
      setLoadingRule(false)
    }
  }, [])

  useEffect(() => {
    if (ruleId) loadRule(ruleId)
  }, [ruleId, loadRule])

  const handleTemplateChange = (idx: number) => {
    setSelectedTemplate(idx)
    setYaml(TEMPLATES[idx].yaml)
    setValidateResult(null)
    setSaved(false)
    setSaveError(null)
  }

  const handleValidate = async () => {
    setValidating(true)
    setValidateResult(null)
    setSaveError(null)
    try {
      const res = await sigmaApi.validateRule(yaml)
      setValidateResult(res)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Doğrulama hatası'
      setValidateResult({ valid: false, error: msg })
    } finally {
      setValidating(false)
    }
  }

  const handleSave = async () => {
    if (!validateResult?.valid) return
    setSaving(true)
    setSaveError(null)
    try {
      await sigmaApi.createRule(yaml)
      setSaved(true)
      setTimeout(() => router.push('/sigma-rules'), 1200)
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Kayıt hatası')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="p-6 flex flex-col h-[calc(100vh-80px)] space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3 flex-shrink-0">
        <div className="flex items-center gap-3">
          <FileCode2 className="h-6 w-6 text-violet-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">Sigma YAML Editör</h1>
            <p className="text-sm text-zinc-400">
              {ruleId ? `Düzenleniyor: ${ruleId}` : 'Yeni kural — pySigma v2 formatı'}
            </p>
          </div>
        </div>

        {/* Template picker */}
        {!ruleId && (
          <div className="relative">
            <div className="flex items-center gap-1.5 px-3 py-2 rounded border border-zinc-700 bg-zinc-800/60 text-sm text-zinc-300 cursor-pointer group">
              <ChevronDown className="h-4 w-4 text-zinc-500" />
              <select
                value={selectedTemplate}
                onChange={e => handleTemplateChange(Number(e.target.value))}
                className="bg-transparent cursor-pointer outline-none text-sm text-zinc-300 pr-1"
              >
                {TEMPLATES.map((t, i) => (
                  <option key={i} value={i} className="bg-zinc-800 text-zinc-200">
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>

      {loadError && (
        <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50 flex-shrink-0">
          {loadError}
        </p>
      )}

      {loadingRule && (
        <div className="flex-shrink-0 h-8 flex items-center gap-2 text-sm text-zinc-400">
          <RefreshCw className="h-4 w-4 animate-spin" />
          Kural yükleniyor…
        </div>
      )}

      {/* Monaco editor */}
      <div className="flex-1 rounded-lg border border-zinc-700 overflow-hidden min-h-0">
        <MonacoEditor
          height="100%"
          language="yaml"
          theme="vs-dark"
          value={yaml}
          onChange={v => {
            setYaml(v ?? '')
            setValidateResult(null)
            setSaved(false)
            setSaveError(null)
          }}
          options={{
            fontSize: 13,
            fontFamily: '"JetBrains Mono", "Fira Code", ui-monospace, monospace',
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            lineNumbers: 'on',
            renderLineHighlight: 'line',
            padding: { top: 12, bottom: 12 },
            tabSize: 4,
            insertSpaces: true,
          }}
        />
      </div>

      {/* Action bar */}
      <div className="flex items-center gap-3 flex-wrap flex-shrink-0">
        <button
          onClick={handleValidate}
          disabled={validating || !yaml.trim()}
          className={cn(
            'flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-colors',
            'bg-zinc-700 hover:bg-zinc-600 text-zinc-100 disabled:opacity-50',
          )}
        >
          {validating
            ? <RefreshCw className="h-4 w-4 animate-spin" />
            : <CheckCircle className="h-4 w-4" />}
          Doğrula
        </button>

        <button
          onClick={handleSave}
          disabled={saving || !validateResult?.valid || saved}
          className={cn(
            'flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-colors',
            validateResult?.valid && !saved
              ? 'bg-violet-600 hover:bg-violet-500 text-white'
              : 'bg-zinc-800 text-zinc-600 cursor-not-allowed',
            'disabled:opacity-60',
          )}
        >
          {saving
            ? <RefreshCw className="h-4 w-4 animate-spin" />
            : <Save className="h-4 w-4" />}
          {saved ? 'Kaydedildi ✓' : 'Kaydet'}
        </button>

        {/* Validation result badge */}
        {validateResult && (
          <div className={cn(
            'flex items-center gap-2 px-3 py-1.5 rounded text-sm',
            validateResult.valid
              ? 'bg-emerald-950/40 border border-emerald-800/50 text-emerald-300'
              : 'bg-red-950/40 border border-red-800/50 text-red-300',
          )}>
            {validateResult.valid
              ? <CheckCircle className="h-4 w-4 text-emerald-400" />
              : <XCircle className="h-4 w-4 text-red-400" />}
            {validateResult.valid
              ? `Geçerli — ${validateResult.title} · ${validateResult.rule_count} kural`
              : validateResult.error}
          </div>
        )}

        {saveError && (
          <p className="text-sm text-red-400">{saveError}</p>
        )}
      </div>

      <p className="text-xs text-zinc-700 flex-shrink-0">
        Kural kaydedildikten sonra correlator otomatik yeniden yüklenir. Aynı UUID ile kayıt mevcut dosyanın üzerine yazar.
      </p>
    </div>
  )
}

// ─── Sayfa wrapper — Suspense zorunlu (useSearchParams) ───────────────────────

export default function SigmaEditorPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64 text-zinc-500 text-sm">
        Yükleniyor…
      </div>
    }>
      <EditorContent />
    </Suspense>
  )
}
