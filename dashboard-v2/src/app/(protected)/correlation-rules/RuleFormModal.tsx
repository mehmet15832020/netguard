'use client'

import { useState, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { correlationApi } from '@/lib/api'
import type { CorrelationRule } from '@/types/models'

const GROUP_COLS = [
  'source_ip', 'destination_ip', 'observer_hostname', 'username',
  'hostname', 'event_action', 'event_category', 'tenant_id',
  'source_type', 'network_protocol', 'source_port', 'destination_port',
]
const SEVERITIES = ['info', 'warning', 'high', 'critical']

interface Props {
  rule: CorrelationRule | null   // null = yeni kural
  onClose: () => void
  onSaved: () => void
}

const EMPTY: CorrelationRule = {
  rule_id: '', name: '', description: '', match_event_action: '',
  group_by: 'source_ip', distinct_by: null, window_seconds: 300,
  threshold: 5, severity: 'high', output_event_action: '',
  enabled: true, match_severity: null, keywords: null, tags: [],
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1">
        {label}
        {hint && <span className="text-slate-600 font-normal ml-1">({hint})</span>}
      </label>
      {children}
    </div>
  )
}

const cls = "ui-input"

export function RuleFormModal({ rule, onClose, onSaved }: Props) {
  const isNew = rule === null
  const [form, setForm] = useState<CorrelationRule>(rule ?? EMPTY)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => { setForm(rule ?? EMPTY) }, [rule])

  const set = (key: keyof CorrelationRule, val: unknown) =>
    setForm(f => ({ ...f, [key]: val }))

  const createMut = useMutation({
    mutationFn: () => correlationApi.createRule(form),
    onSuccess: onSaved,
    onError: (e: Error) => setError(e.message),
  })

  const updateMut = useMutation({
    mutationFn: () => correlationApi.updateRule(rule!.rule_id, form),
    onSuccess: onSaved,
    onError: (e: Error) => setError(e.message),
  })

  const isPending = createMut.isPending || updateMut.isPending

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (isNew) createMut.mutate()
    else updateMut.mutate()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 overflow-y-auto">
      <div className="w-full max-w-2xl rounded-lg border border-sky-900/30 bg-[#0a1120] shadow-2xl my-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-sky-900/20">
          <h2 className="text-base font-semibold text-slate-100">
            {isNew ? 'Yeni Korelasyon Kuralı' : `Düzenle: ${rule.rule_id}`}
          </h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Row 1: rule_id + name */}
          <div className="grid grid-cols-2 gap-4">
            <Field label="Kural ID" hint="2-64 karakter, a-z/0-9/_">
              <input
                className={cls}
                value={form.rule_id}
                onChange={e => set('rule_id', e.target.value.toLowerCase())}
                readOnly={!isNew}
                placeholder="ornek_kural"
                required
              />
            </Field>
            <Field label="Kural Adı">
              <input
                className={cls}
                value={form.name}
                onChange={e => set('name', e.target.value)}
                placeholder="Örnek: SSH Brute Force"
                required
              />
            </Field>
          </div>

          {/* description */}
          <Field label="Açıklama" hint="opsiyonel">
            <textarea
              className={`${cls} resize-none`}
              rows={2}
              value={form.description}
              onChange={e => set('description', e.target.value)}
            />
          </Field>

          {/* Row 2: match_event_action + output_event_action */}
          <div className="grid grid-cols-2 gap-4">
            <Field label="Event Tipi (match)" hint="boş = tümü">
              <input
                className={cls}
                value={form.match_event_action}
                onChange={e => set('match_event_action', e.target.value)}
                placeholder="ssh_failure"
              />
            </Field>
            <Field label="Çıktı Event Tipi">
              <input
                className={cls}
                value={form.output_event_action}
                onChange={e => set('output_event_action', e.target.value)}
                placeholder="ssh_brute_force_detected"
                required
              />
            </Field>
          </div>

          {/* Row 3: group_by + distinct_by */}
          <div className="grid grid-cols-2 gap-4">
            <Field label="Group By">
              <select className={cls} value={form.group_by} onChange={e => set('group_by', e.target.value)}>
                {GROUP_COLS.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Distinct By" hint="opsiyonel — benzersiz say">
              <select
                className={cls}
                value={form.distinct_by ?? ''}
                onChange={e => set('distinct_by', e.target.value || null)}
              >
                <option value="">— yok —</option>
                {GROUP_COLS.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
          </div>

          {/* Row 4: window_seconds + threshold + severity */}
          <div className="grid grid-cols-3 gap-4">
            <Field label="Zaman Penceresi" hint="saniye, 10-86400">
              <input
                type="number" className={cls} min={10} max={86400}
                value={form.window_seconds}
                onChange={e => set('window_seconds', Number(e.target.value))}
                required
              />
            </Field>
            <Field label="Eşik" hint="olay sayısı">
              <input
                type="number" className={cls} min={1} max={10000}
                value={form.threshold}
                onChange={e => set('threshold', Number(e.target.value))}
                required
              />
            </Field>
            <Field label="Önem Düzeyi">
              <select className={cls} value={form.severity} onChange={e => set('severity', e.target.value as CorrelationRule['severity'])}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>

          {/* Row 5: match_severity + tags */}
          <div className="grid grid-cols-2 gap-4">
            <Field label="Severity Filtresi" hint="opsiyonel">
              <select
                className={cls}
                value={form.match_severity ?? ''}
                onChange={e => set('match_severity', e.target.value || null)}
              >
                <option value="">— tümü —</option>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Etiketler" hint="virgülle ayır: attack.t1110,attack.t1595">
              <input
                className={cls}
                value={form.tags.join(', ')}
                onChange={e => set('tags', e.target.value.split(',').map(t => t.trim()).filter(Boolean))}
                placeholder="attack.t1110"
              />
            </Field>
          </div>

          {/* enabled toggle */}
          <label className="flex items-center gap-3 cursor-pointer select-none">
            <div
              onClick={() => set('enabled', !form.enabled)}
              className={`w-10 h-5 rounded-full transition-colors ${form.enabled ? 'bg-violet-600' : 'bg-sky-950/30'}`}
            >
              <div className={`w-5 h-5 rounded-full bg-white shadow transition-transform ${form.enabled ? 'translate-x-5' : 'translate-x-0'}`} />
            </div>
            <span className="text-sm text-slate-300">Kural aktif</span>
          </label>

          {error && (
            <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50">
              {error}
            </p>
          )}

          {/* Footer */}
          <div className="flex justify-end gap-2 pt-2 border-t border-sky-900/20">
            <button
              type="button"
              onClick={onClose}
              className="ui-btn ui-btn-secondary"
            >
              İptal
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="ui-btn ui-btn-primary"
            >
              {isPending ? 'Kaydediliyor…' : isNew ? 'Oluştur' : 'Kaydet'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
