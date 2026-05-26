'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useMutation } from '@tanstack/react-query'
import { Wand2, Plus, X, ChevronLeft, ChevronRight, Check, AlertTriangle } from 'lucide-react'
import { sigmaApi, type SigmaValidateResponse } from '@/lib/api'
import { cn } from '@/lib/utils'

// ─── MITRE ATT&CK v17 (network-relevant subset) ──────────────────────────────

const MITRE_TACTICS = [
  { tag: 'attack.reconnaissance',     label: 'TA0043 — Reconnaissance' },
  { tag: 'attack.initial_access',     label: 'TA0001 — Initial Access' },
  { tag: 'attack.execution',          label: 'TA0002 — Execution' },
  { tag: 'attack.credential_access',  label: 'TA0006 — Credential Access' },
  { tag: 'attack.discovery',          label: 'TA0007 — Discovery' },
  { tag: 'attack.lateral_movement',   label: 'TA0008 — Lateral Movement' },
  { tag: 'attack.collection',         label: 'TA0009 — Collection' },
  { tag: 'attack.command_and_control',label: 'TA0011 — Command & Control' },
  { tag: 'attack.exfiltration',       label: 'TA0010 — Exfiltration' },
  { tag: 'attack.impact',             label: 'TA0040 — Impact' },
]

const MITRE_TECHNIQUES = [
  { tag: 'attack.t1110',     label: 'T1110 — Brute Force' },
  { tag: 'attack.t1110.001', label: 'T1110.001 — Password Guessing' },
  { tag: 'attack.t1110.003', label: 'T1110.003 — Password Spraying' },
  { tag: 'attack.t1046',     label: 'T1046 — Network Service Discovery' },
  { tag: 'attack.t1595',     label: 'T1595 — Active Scanning' },
  { tag: 'attack.t1595.001', label: 'T1595.001 — Scanning IP Blocks' },
  { tag: 'attack.t1595.003', label: 'T1595.003 — Wordlist Scanning' },
  { tag: 'attack.t1078',     label: 'T1078 — Valid Accounts' },
  { tag: 'attack.t1021',     label: 'T1021 — Remote Services' },
  { tag: 'attack.t1021.004', label: 'T1021.004 — SSH' },
  { tag: 'attack.t1071',     label: 'T1071 — App Layer Protocol' },
  { tag: 'attack.t1041',     label: 'T1041 — Exfiltration Over C2' },
  { tag: 'attack.t1190',     label: 'T1190 — Exploit Public-Facing App' },
  { tag: 'attack.t1133',     label: 'T1133 — External Remote Services' },
  { tag: 'attack.t1557',     label: 'T1557 — Adversary-in-the-Middle' },
  { tag: 'attack.t1498',     label: 'T1498 — Network DoS' },
  { tag: 'attack.t1048',     label: 'T1048 — Exfiltration Alt Protocol' },
]

const COMMON_EVENTS = [
  'ssh_failure', 'ssh_success', 'port_scan', 'dns_query', 'dns_anomaly',
  'brute_force', 'lateral_movement', 'c2_beaconing', 'arp_anomaly',
  'windows_logon_failure', 'suricata_alert', 'icmp_flood_attempt',
  'http_error', 'web_request',
]

const ECS_FIELDS = [
  'source_ip', 'destination_ip', 'source_port', 'destination_port',
  'network_protocol', 'observer_hostname', 'username', 'severity',
  'event_category', 'message', 'hostname',
]

const TIMESPANS = ['30s', '1m', '5m', '10m', '30m', '1h', '6h', '24h']

// ─── Types ────────────────────────────────────────────────────────────────────

type MatchModifier = 'exact' | 'startswith' | 'contains'
type SigmaLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical'
type SigmaStatus = 'stable' | 'test' | 'experimental'

interface ExtraFilter {
  id: string
  field: string
  modifier: MatchModifier
  value: string
}

interface WizardForm {
  event_action: string
  match_modifier: MatchModifier
  event_category: string
  extra_filters: ExtraFilter[]
  group_by: string
  timespan: string
  threshold: number
  title: string
  description: string
  level: SigmaLevel
  mitre_tags: string[]
  false_positives: string[]
  status: SigmaStatus
}

const EMPTY: WizardForm = {
  event_action: '',
  match_modifier: 'exact',
  event_category: 'network',
  extra_filters: [],
  group_by: 'source_ip',
  timespan: '5m',
  threshold: 5,
  title: '',
  description: '',
  level: 'high',
  mitre_tags: [],
  false_positives: [''],
  status: 'stable',
}

// ─── YAML Generator ───────────────────────────────────────────────────────────

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 30)
}

function yamlStr(val: string): string {
  if (!val) return '""'
  if (/[:#{}\[\],&*?|<>=!%@`\n\r]/.test(val) || val.includes('"')) {
    return '"' + val.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'
  }
  return val
}

function generateUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

function generateSigmaYaml(form: WizardForm, ruleId: string): string {
  const suffix = Math.random().toString(36).slice(2, 6)
  const baseSlug = slugify(form.event_action || 'event')
  const baseName = `ng_${baseSlug}_base_${suffix}`

  const actionKey = form.match_modifier === 'exact'
    ? 'event_action'
    : `event_action|${form.match_modifier}`

  const selFields: string[] = [`        ${actionKey}: ${yamlStr(form.event_action || 'event')}`]
  for (const f of form.extra_filters) {
    if (f.field && f.value) {
      const fk = f.modifier === 'exact' ? f.field : `${f.field}|${f.modifier}`
      selFields.push(`        ${fk}: ${yamlStr(f.value)}`)
    }
  }

  const fps = form.false_positives.filter(Boolean)
  const tags = form.mitre_tags

  const lines: string[] = [
    `title: ${yamlStr((form.event_action || 'Custom Event') + ' Base')}`,
    `name: ${baseName}`,
    `status: ${form.status}`,
    `logsource:`,
    `    category: ${form.event_category || 'network'}`,
    `detection:`,
    `    selection:`,
    ...selFields,
    `    condition: selection`,
    `level: low`,
    `---`,
    `title: ${yamlStr(form.title || 'Custom Rule')}`,
    `id: ${ruleId}`,
    ...(form.description ? [`description: ${yamlStr(form.description)}`] : []),
    `correlation:`,
    `    type: event_count`,
    `    rules: ${baseName}`,
    `    group-by:`,
    `        - ${form.group_by}`,
    `    timespan: ${form.timespan}`,
    `    condition:`,
    `        gte: ${form.threshold}`,
    `level: ${form.level}`,
    ...(tags.length > 0 ? [`tags:`, ...tags.map(t => `    - ${t}`)] : []),
    ...(fps.length > 0 ? [`falsepositives:`, ...fps.map(f => `    - ${yamlStr(f)}`)] : []),
  ]

  return lines.join('\n')
}

// ─── Sub-components ───────────────────────────────────────────────────────────

const cls = "w-full rounded bg-zinc-800 border border-zinc-700 text-zinc-200 text-sm px-3 py-2 focus:outline-none focus:border-violet-500"

function Label({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return (
    <label className="block text-xs font-medium text-zinc-400 mb-1">
      {children}
      {hint && <span className="text-zinc-600 font-normal ml-1">({hint})</span>}
    </label>
  )
}

function TagToggle({ tag, label, selected, onToggle }: {
  tag: string; label: string; selected: boolean; onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        'px-2.5 py-1 rounded text-xs font-medium transition-colors border',
        selected
          ? 'bg-violet-600/30 text-violet-300 border-violet-500/50'
          : 'bg-zinc-800 text-zinc-500 border-zinc-700 hover:border-zinc-500 hover:text-zinc-300',
      )}
    >
      {label}
    </button>
  )
}

// ─── Step components ──────────────────────────────────────────────────────────

function StepDetection({ form, set }: { form: WizardForm; set: (k: keyof WizardForm, v: unknown) => void }) {
  const addFilter = () => set('extra_filters', [
    ...form.extra_filters,
    { id: Math.random().toString(36).slice(2), field: 'source_ip', modifier: 'exact', value: '' },
  ])

  const updateFilter = (id: string, key: keyof ExtraFilter, val: string) =>
    set('extra_filters', form.extra_filters.map(f => f.id === id ? { ...f, [key]: val } : f))

  const removeFilter = (id: string) =>
    set('extra_filters', form.extra_filters.filter(f => f.id !== id))

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Event Action <span className="text-red-400">*</span></Label>
          <input
            list="event-suggestions"
            className={cls}
            value={form.event_action}
            onChange={e => set('event_action', e.target.value)}
            placeholder="ssh_failure"
          />
          <datalist id="event-suggestions">
            {COMMON_EVENTS.map(e => <option key={e} value={e} />)}
          </datalist>
        </div>
        <div>
          <Label hint="nasıl eşleşsin">Eşleşme Tipi</Label>
          <select className={cls} value={form.match_modifier} onChange={e => set('match_modifier', e.target.value)}>
            <option value="exact">Tam eşleşme</option>
            <option value="startswith">Başlangıç ile (startswith)</option>
            <option value="contains">İçerik (contains)</option>
          </select>
        </div>
      </div>

      <div>
        <Label>Event Kategorisi</Label>
        <select className={cls} value={form.event_category} onChange={e => set('event_category', e.target.value)}>
          <option value="network">network</option>
          <option value="authentication">authentication</option>
          <option value="intrusion">intrusion</option>
          <option value="system">system</option>
          <option value="unknown">unknown</option>
        </select>
      </div>

      {/* Extra filters */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <Label hint="opsiyonel">Ek Alan Filtreleri</Label>
          <button type="button" onClick={addFilter}
            className="flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300">
            <Plus className="h-3 w-3" /> Filtre Ekle
          </button>
        </div>
        {form.extra_filters.map(f => (
          <div key={f.id} className="flex items-center gap-2 mb-2">
            <select className={cn(cls, 'flex-1')} value={f.field}
              onChange={e => updateFilter(f.id, 'field', e.target.value)}>
              {ECS_FIELDS.map(field => <option key={field} value={field}>{field}</option>)}
            </select>
            <select className={cn(cls, 'w-36')} value={f.modifier}
              onChange={e => updateFilter(f.id, 'modifier', e.target.value as MatchModifier)}>
              <option value="exact">tam</option>
              <option value="startswith">başlangıç</option>
              <option value="contains">içerik</option>
            </select>
            <input className={cn(cls, 'flex-1')} value={f.value}
              onChange={e => updateFilter(f.id, 'value', e.target.value)}
              placeholder="değer" />
            <button type="button" onClick={() => removeFilter(f.id)}
              className="text-zinc-600 hover:text-red-400 transition-colors flex-shrink-0">
              <X className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

function StepCorrelation({ form, set }: { form: WizardForm; set: (k: keyof WizardForm, v: unknown) => void }) {
  return (
    <div className="space-y-5">
      <div>
        <Label>Gruplama Alanı</Label>
        <select className={cls} value={form.group_by} onChange={e => set('group_by', e.target.value)}>
          <option value="source_ip">source_ip — kaynak IP başına say</option>
          <option value="destination_ip">destination_ip — hedef IP başına say</option>
          <option value="username">username — kullanıcı başına say</option>
          <option value="observer_hostname">observer_hostname — sensor başına say</option>
          <option value="network_protocol">network_protocol — protokol başına say</option>
          <option value="destination_port">destination_port — hedef port başına say</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Zaman Penceresi</Label>
          <select className={cls} value={form.timespan} onChange={e => set('timespan', e.target.value)}>
            {TIMESPANS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <Label hint="≥ N olay tetiklesin">Eşik</Label>
          <input
            type="number" className={cls} min={1} max={10000}
            value={form.threshold}
            onChange={e => set('threshold', Math.max(1, Number(e.target.value)))}
          />
        </div>
      </div>

      <div className="rounded border border-zinc-800 bg-zinc-800/30 p-4 text-sm text-zinc-400 space-y-1">
        <p className="text-zinc-300 font-medium text-xs">Kural Mantığı</p>
        <p>
          Son <span className="text-violet-300">{form.timespan}</span> içinde&nbsp;
          <span className="text-violet-300">{form.group_by}</span> başına&nbsp;
          <span className="text-violet-300">{form.event_action || '[event]'}</span> olayı&nbsp;
          en az <span className="text-violet-300">{form.threshold}</span> kez tekrarlanırsa uyarı üret.
        </p>
      </div>
    </div>
  )
}

function StepMetadata({ form, set }: { form: WizardForm; set: (k: keyof WizardForm, v: unknown) => void }) {
  const addFP = () => set('false_positives', [...form.false_positives, ''])
  const updateFP = (i: number, val: string) =>
    set('false_positives', form.false_positives.map((f, idx) => idx === i ? val : f))
  const removeFP = (i: number) =>
    set('false_positives', form.false_positives.filter((_, idx) => idx !== i))

  const toggleTag = (tag: string) =>
    set('mitre_tags', form.mitre_tags.includes(tag)
      ? form.mitre_tags.filter(t => t !== tag)
      : [...form.mitre_tags, tag],
    )

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Kural Başlığı <span className="text-red-400">*</span></Label>
          <input className={cls} value={form.title}
            onChange={e => set('title', e.target.value)} placeholder="SSH Brute Force Tespiti" />
        </div>
        <div>
          <Label>Önem Düzeyi</Label>
          <select className={cls} value={form.level} onChange={e => set('level', e.target.value as SigmaLevel)}>
            <option value="informational">informational</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label hint="opsiyonel">Açıklama</Label>
          <textarea className={cn(cls, 'resize-none')} rows={2} value={form.description}
            onChange={e => set('description', e.target.value)} />
        </div>
        <div>
          <Label>Durum</Label>
          <select className={cls} value={form.status} onChange={e => set('status', e.target.value as SigmaStatus)}>
            <option value="stable">stable</option>
            <option value="test">test</option>
            <option value="experimental">experimental</option>
          </select>
        </div>
      </div>

      {/* MITRE Tactics */}
      <div>
        <Label hint="MITRE ATT&CK v17">Taktikler</Label>
        <div className="flex flex-wrap gap-2 mt-1">
          {MITRE_TACTICS.map(({ tag, label }) => (
            <TagToggle key={tag} tag={tag} label={label}
              selected={form.mitre_tags.includes(tag)}
              onToggle={() => toggleTag(tag)} />
          ))}
        </div>
      </div>

      {/* MITRE Techniques */}
      <div>
        <Label hint="MITRE ATT&CK v17">Teknikler</Label>
        <div className="flex flex-wrap gap-2 mt-1">
          {MITRE_TECHNIQUES.map(({ tag, label }) => (
            <TagToggle key={tag} tag={tag} label={label}
              selected={form.mitre_tags.includes(tag)}
              onToggle={() => toggleTag(tag)} />
          ))}
        </div>
      </div>

      {/* False Positives */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <Label hint="opsiyonel">Yanlış Pozitifler</Label>
          <button type="button" onClick={addFP}
            className="flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300">
            <Plus className="h-3 w-3" /> Ekle
          </button>
        </div>
        {form.false_positives.map((fp, i) => (
          <div key={i} className="flex items-center gap-2 mb-2">
            <input className={cn(cls, 'flex-1')} value={fp}
              onChange={e => updateFP(i, e.target.value)}
              placeholder="Örn: Normal yönetici girişleri" />
            {form.false_positives.length > 1 && (
              <button type="button" onClick={() => removeFP(i)}
                className="text-zinc-600 hover:text-red-400 transition-colors">
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function StepPreview({ yaml, validResult, onValidate, onSave, isPending, saveError }: {
  yaml: string
  validResult: SigmaValidateResponse | null
  onValidate: () => void
  onSave: () => void
  isPending: boolean
  saveError: string | null
}) {
  return (
    <div className="space-y-4">
      <div>
        <p className="text-xs text-zinc-500 mb-2">Oluşturulan Sigma YAML — pySigma v2 formatı</p>
        <pre className="w-full rounded bg-zinc-950 border border-zinc-800 text-xs text-emerald-300 p-4 overflow-auto max-h-72 font-mono leading-relaxed">
          {yaml}
        </pre>
      </div>

      {validResult && (
        <div className="flex items-start gap-3 rounded border border-emerald-900/50 bg-emerald-950/20 px-4 py-3">
          <Check className="h-4 w-4 text-emerald-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="text-emerald-400 font-medium">Kural geçerli</p>
            <p className="text-zinc-400 text-xs mt-0.5">
              Başlık: {validResult.title} · Seviye: {validResult.level} · {validResult.rule_count} belge
            </p>
          </div>
        </div>
      )}

      {saveError && (
        <div className="flex items-start gap-3 rounded border border-red-900/50 bg-red-950/20 px-4 py-3">
          <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{saveError}</p>
        </div>
      )}

      <div className="flex gap-3">
        <button
          type="button"
          onClick={onValidate}
          disabled={isPending}
          className="px-4 py-2 rounded text-sm bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors disabled:opacity-50"
        >
          Doğrula
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={isPending || !validResult}
          className="px-4 py-2 rounded text-sm bg-violet-600 hover:bg-violet-500 text-white font-medium transition-colors disabled:opacity-50"
        >
          {isPending ? 'Kaydediliyor…' : 'Kaydet'}
        </button>
        {!validResult && (
          <p className="text-xs text-zinc-500 self-center">Kaydetmeden önce doğrulayın</p>
        )}
      </div>
    </div>
  )
}

// ─── Main Wizard ─────────────────────────────────────────────────────────────

const STEPS = ['Tespit Kuralı', 'Korelasyon', 'Metadata', 'Önizleme & Kaydet']

export default function SigmaWizardPage() {
  const router = useRouter()
  const [step, setStep] = useState(0)
  const [form, setForm] = useState<WizardForm>(EMPTY)
  const [ruleId] = useState(() => generateUUID())
  const [validResult, setValidResult] = useState<SigmaValidateResponse | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  const yaml = generateSigmaYaml(form, ruleId)

  const set = (k: keyof WizardForm, v: unknown) => {
    setForm(f => ({ ...f, [k]: v }))
    setValidResult(null)
  }

  const validateMut = useMutation({
    mutationFn: () => sigmaApi.validateRule(yaml),
    onSuccess: (res) => setValidResult(res),
    onError: (e: Error) => setSaveError(e.message),
  })

  const saveMut = useMutation({
    mutationFn: () => sigmaApi.createRule(yaml),
    onSuccess: () => router.push('/sigma-rules'),
    onError: (e: Error) => setSaveError(e.message),
  })

  const isPending = validateMut.isPending || saveMut.isPending

  const canNext = [
    () => !!form.event_action.trim(),    // step 0
    () => form.threshold >= 1,           // step 1
    () => !!form.title.trim(),           // step 2
    () => true,                          // step 3
  ]

  return (
    <div className="p-6 max-w-3xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Wand2 className="h-6 w-6 text-violet-400" />
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">Sigma Kural Sihirbazı</h1>
          <p className="text-sm text-zinc-400">Formdan Sigma YAML otomatik oluşturulur — YAML bilgisi gerekmez</p>
        </div>
      </div>

      {/* Step indicator */}
      <div className="flex items-center gap-0">
        {STEPS.map((label, i) => (
          <div key={i} className="flex items-center">
            <button
              type="button"
              onClick={() => i < step && setStep(i)}
              className={cn(
                'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-colors',
                i === step
                  ? 'bg-violet-600/20 text-violet-300'
                  : i < step
                    ? 'text-zinc-400 hover:text-zinc-200 cursor-pointer'
                    : 'text-zinc-600 cursor-default',
              )}
            >
              <span className={cn(
                'w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0',
                i === step ? 'bg-violet-600 text-white' : i < step ? 'bg-zinc-600 text-zinc-300' : 'bg-zinc-800 text-zinc-600',
              )}>
                {i < step ? <Check className="h-3 w-3" /> : i + 1}
              </span>
              <span className="hidden sm:inline">{label}</span>
            </button>
            {i < STEPS.length - 1 && (
              <div className={cn('w-6 h-px mx-1', i < step ? 'bg-zinc-600' : 'bg-zinc-800')} />
            )}
          </div>
        ))}
      </div>

      {/* Step content */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        {step === 0 && <StepDetection form={form} set={set} />}
        {step === 1 && <StepCorrelation form={form} set={set} />}
        {step === 2 && <StepMetadata form={form} set={set} />}
        {step === 3 && (
          <StepPreview
            yaml={yaml}
            validResult={validResult}
            onValidate={() => { setSaveError(null); validateMut.mutate() }}
            onSave={() => { setSaveError(null); saveMut.mutate() }}
            isPending={isPending}
            saveError={saveError}
          />
        )}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setStep(s => Math.max(0, s - 1))}
          disabled={step === 0}
          className="flex items-center gap-2 px-4 py-2 rounded text-sm bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          <ChevronLeft className="h-4 w-4" /> Geri
        </button>
        {step < STEPS.length - 1 && (
          <button
            type="button"
            onClick={() => setStep(s => Math.min(STEPS.length - 1, s + 1))}
            disabled={!canNext[step]()}
            className="flex items-center gap-2 px-4 py-2 rounded text-sm bg-violet-600 hover:bg-violet-500 text-white font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            İleri <ChevronRight className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  )
}
