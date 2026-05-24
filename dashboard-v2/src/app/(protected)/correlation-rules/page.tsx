'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { GitMerge, Plus, Pencil, Trash2, Power } from 'lucide-react'
import { correlationApi } from '@/lib/api'
import type { CorrelationRule } from '@/types/models'
import { RuleFormModal } from './RuleFormModal'

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-950/40',
  high:     'text-orange-400 bg-orange-950/40',
  warning:  'text-yellow-400 bg-yellow-950/40',
  info:     'text-blue-400 bg-blue-950/40',
}

function fmtWindow(s: number): string {
  if (s < 60) return `${s}sn`
  if (s < 3600) return `${s / 60}dk`
  return `${s / 3600}s`
}

export default function CorrelationRulesPage() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<CorrelationRule | null | 'new'>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [mutError, setMutError] = useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['correlation', 'rules'],
    queryFn: correlationApi.listRules,
    staleTime: 30_000,
  })

  const toggleMut = useMutation({
    mutationFn: (rule_id: string) => correlationApi.toggleRule(rule_id),
    onSuccess: () => {
      setMutError(null)
      qc.invalidateQueries({ queryKey: ['correlation', 'rules'] })
    },
    onError: (e: Error) => setMutError(e.message),
  })

  const deleteMut = useMutation({
    mutationFn: (rule_id: string) => correlationApi.deleteRule(rule_id),
    onSuccess: () => {
      setConfirmDelete(null)
      setMutError(null)
      qc.invalidateQueries({ queryKey: ['correlation', 'rules'] })
    },
    onError: (e: Error) => setMutError(e.message),
  })

  const rules = data?.rules ?? []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <GitMerge className="h-6 w-6 text-violet-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">Korelasyon Kuralları</h1>
            <p className="text-sm text-zinc-400">Kural tabanlı olay tespiti — hot-reload destekli</p>
          </div>
        </div>
        <button
          onClick={() => setEditing('new')}
          className="flex items-center gap-2 px-4 py-2 rounded bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors"
        >
          <Plus className="h-4 w-4" />
          Yeni Kural
        </button>
      </div>

      {/* Mutation hata mesajı */}
      {mutError && (
        <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50">
          {mutError}
        </p>
      )}

      {/* Stats */}
      {data && (
        <div className="flex gap-6 text-sm text-zinc-400">
          <span><span className="text-zinc-200 font-medium">{data.count}</span> kural</span>
          <span>
            <span className="text-emerald-400 font-medium">
              {rules.filter(r => r.enabled).length}
            </span> aktif
          </span>
          <span>
            <span className="text-zinc-500 font-medium">
              {rules.filter(r => !r.enabled).length}
            </span> pasif
          </span>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 overflow-hidden">
        {isLoading && <div className="h-32 animate-pulse bg-zinc-800 m-4 rounded" />}
        {isError && (
          <div className="h-24 flex items-center justify-center text-red-400 text-sm">
            Kurallar yüklenemedi
          </div>
        )}
        {!isLoading && rules.length === 0 && (
          <div className="h-24 flex flex-col items-center justify-center gap-2 text-zinc-500">
            <GitMerge className="h-7 w-7 text-zinc-700" />
            <p className="text-sm">Henüz kural yok — ilk kuralı ekle</p>
          </div>
        )}
        {rules.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-zinc-500 text-xs">
                <th className="text-left py-3 px-4 font-medium w-8">Aktif</th>
                <th className="text-left py-3 px-4 font-medium">Kural Adı</th>
                <th className="text-left py-3 px-4 font-medium">Event Tipi</th>
                <th className="text-left py-3 px-4 font-medium">Group By</th>
                <th className="text-right py-3 px-4 font-medium">Eşik</th>
                <th className="text-right py-3 px-4 font-medium">Pencere</th>
                <th className="text-center py-3 px-4 font-medium">Önem</th>
                <th className="text-right py-3 px-4 font-medium">İşlem</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr
                  key={rule.rule_id}
                  className={`border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors ${
                    !rule.enabled ? 'opacity-50' : ''
                  }`}
                >
                  <td className="py-3 px-4">
                    <button
                      onClick={() => toggleMut.mutate(rule.rule_id)}
                      disabled={toggleMut.isPending}
                      title={rule.enabled ? 'Devre dışı bırak' : 'Etkinleştir'}
                      className={`p-1 rounded transition-colors ${
                        rule.enabled
                          ? 'text-emerald-400 hover:text-emerald-300'
                          : 'text-zinc-600 hover:text-zinc-400'
                      }`}
                    >
                      <Power className="h-4 w-4" />
                    </button>
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-medium text-zinc-200">{rule.name}</div>
                    <div className="text-xs text-zinc-500 font-mono">{rule.rule_id}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-zinc-400 text-xs">
                    {rule.match_event_action || <span className="text-zinc-600 italic">tümü</span>}
                  </td>
                  <td className="py-3 px-4 text-zinc-400 text-xs">
                    {rule.group_by}
                    {rule.distinct_by && (
                      <span className="text-zinc-600"> / {rule.distinct_by}</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right text-zinc-300">{rule.threshold}</td>
                  <td className="py-3 px-4 text-right text-zinc-400 text-xs">
                    {fmtWindow(rule.window_seconds)}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[rule.severity] ?? 'text-zinc-400'}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1 justify-end">
                      <button
                        onClick={() => setEditing(rule)}
                        className="p-1.5 rounded text-zinc-500 hover:text-zinc-300 hover:bg-zinc-700 transition-colors"
                        title="Düzenle"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setConfirmDelete(rule.rule_id)}
                        className="p-1.5 rounded text-zinc-500 hover:text-red-400 hover:bg-red-950/30 transition-colors"
                        title="Sil"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-zinc-700">
        Kural değişiklikleri anında yüklenir. Correlator her 60 saniyede otomatik kontrol eder.
      </p>

      {/* Form modal */}
      {editing !== null && (
        <RuleFormModal
          rule={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            qc.invalidateQueries({ queryKey: ['correlation', 'rules'] })
          }}
        />
      )}

      {/* Delete confirm dialog */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-lg border border-zinc-700 bg-zinc-900 p-6 space-y-4">
            <h2 className="text-base font-semibold text-zinc-100">Kuralı Sil</h2>
            <p className="text-sm text-zinc-400">
              <span className="font-mono text-zinc-200">{confirmDelete}</span> kuralı kalıcı olarak silinecek.
              Bu işlem geri alınamaz.
            </p>
            {mutError && (
              <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50">
                {mutError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmDelete(null)}
                className="px-4 py-2 rounded text-sm bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors"
              >
                İptal
              </button>
              <button
                onClick={() => deleteMut.mutate(confirmDelete)}
                disabled={deleteMut.isPending}
                className="px-4 py-2 rounded text-sm bg-red-700 hover:bg-red-600 text-white transition-colors disabled:opacity-50"
              >
                {deleteMut.isPending ? 'Siliniyor…' : 'Sil'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
