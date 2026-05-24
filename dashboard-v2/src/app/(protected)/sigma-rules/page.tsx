'use client'

import Link from 'next/link'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, Plus, Trash2, Power, Wand2 } from 'lucide-react'
import { sigmaApi } from '@/lib/api'
import { useState } from 'react'
import { cn } from '@/lib/utils'

const LEVEL_COLORS: Record<string, string> = {
  critical:      'text-red-400 bg-red-950/40',
  high:          'text-orange-400 bg-orange-950/40',
  medium:        'text-yellow-400 bg-yellow-950/40',
  warning:       'text-yellow-400 bg-yellow-950/40',
  low:           'text-blue-400 bg-blue-950/40',
  informational: 'text-zinc-400 bg-zinc-800/40',
}

export default function SigmaRulesPage() {
  const qc = useQueryClient()
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [mutError, setMutError] = useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['sigma', 'rules'],
    queryFn: sigmaApi.listRules,
    staleTime: 30_000,
  })

  const toggleMut = useMutation({
    mutationFn: (rule_id: string) => sigmaApi.toggleRule(rule_id),
    onSuccess: () => {
      setMutError(null)
      qc.invalidateQueries({ queryKey: ['sigma', 'rules'] })
    },
    onError: (e: Error) => setMutError(e.message),
  })

  const deleteMut = useMutation({
    mutationFn: (rule_id: string) => sigmaApi.deleteRule(rule_id),
    onSuccess: () => {
      setConfirmDelete(null)
      setMutError(null)
      qc.invalidateQueries({ queryKey: ['sigma', 'rules'] })
    },
    onError: (e: Error) => setMutError(e.message),
  })

  const rules = data?.rules ?? []
  const activeCount = rules.filter(r => r.enabled).length
  const disabledCount = rules.filter(r => !r.enabled).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-6 w-6 text-violet-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">Sigma Kuralları</h1>
            <p className="text-sm text-zinc-400">pySigma v2 tabanlı tespit kuralları</p>
          </div>
        </div>
        <Link
          href="/sigma-wizard"
          className="flex items-center gap-2 px-4 py-2 rounded bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors"
        >
          <Wand2 className="h-4 w-4" />
          Sihirbazla Oluştur
        </Link>
      </div>

      {mutError && (
        <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50">
          {mutError}
        </p>
      )}

      {/* Stats */}
      {data && (
        <div className="flex gap-6 text-sm text-zinc-400">
          <span><span className="text-zinc-200 font-medium">{data.count}</span> kural</span>
          <span><span className="text-emerald-400 font-medium">{activeCount}</span> aktif</span>
          <span><span className="text-zinc-500 font-medium">{disabledCount}</span> pasif</span>
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
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-zinc-500">
            <ShieldCheck className="h-8 w-8 text-zinc-700" />
            <p className="text-sm">Henüz kural yok</p>
            <Link href="/sigma-wizard" className="text-xs text-violet-400 hover:text-violet-300">
              Sihirbazla ilk kuralı oluştur →
            </Link>
          </div>
        )}
        {rules.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-zinc-500 text-xs">
                <th className="text-left py-3 px-4 font-medium w-8">Aktif</th>
                <th className="text-left py-3 px-4 font-medium">Başlık</th>
                <th className="text-center py-3 px-4 font-medium">Önem</th>
                <th className="text-left py-3 px-4 font-medium">Etiketler</th>
                <th className="text-left py-3 px-4 font-medium hidden lg:table-cell">Dosya</th>
                <th className="text-right py-3 px-4 font-medium">İşlem</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr
                  key={rule.rule_id}
                  className={cn(
                    'border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors',
                    !rule.enabled && 'opacity-50',
                  )}
                >
                  <td className="py-3 px-4">
                    <button
                      onClick={() => toggleMut.mutate(rule.rule_id)}
                      disabled={toggleMut.isPending}
                      title={rule.enabled ? 'Devre dışı bırak' : 'Etkinleştir'}
                      className={cn(
                        'p-1 rounded transition-colors',
                        rule.enabled
                          ? 'text-emerald-400 hover:text-emerald-300'
                          : 'text-zinc-600 hover:text-zinc-400',
                      )}
                    >
                      <Power className="h-4 w-4" />
                    </button>
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-medium text-zinc-200">{rule.title}</div>
                    {rule.description && (
                      <div className="text-xs text-zinc-500 mt-0.5 line-clamp-1">{rule.description}</div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={cn(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      LEVEL_COLORS[rule.level] ?? 'text-zinc-400',
                    )}>
                      {rule.level}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {rule.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="px-1.5 py-0.5 rounded text-[10px] bg-zinc-800 text-zinc-400 font-mono">
                          {tag.replace('attack.', '')}
                        </span>
                      ))}
                      {rule.tags.length > 3 && (
                        <span className="text-[10px] text-zinc-600">+{rule.tags.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 hidden lg:table-cell">
                    <span className="text-xs font-mono text-zinc-500">{rule.filename}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1 justify-end">
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
        Sigma kuralları pySigma v2 ile SQL'e derlenir. Değişiklikler correlator hot-reload ile anında yüklenir.
      </p>

      {/* Delete confirm */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-lg border border-zinc-700 bg-zinc-900 p-6 space-y-4">
            <h2 className="text-base font-semibold text-zinc-100">Kuralı Sil</h2>
            <p className="text-sm text-zinc-400">
              <span className="font-mono text-zinc-200">{confirmDelete}</span> kuralı kalıcı olarak silinecek.
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
