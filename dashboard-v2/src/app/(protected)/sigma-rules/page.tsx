'use client'

import Link from 'next/link'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, Plus, Trash2, Power, Wand2, Pencil } from 'lucide-react'
import { sigmaApi } from '@/lib/api'
import { useState } from 'react'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

const LEVEL_COLORS: Record<string, string> = {
  critical:      'text-red-400 bg-red-950/40',
  high:          'text-orange-400 bg-orange-950/40',
  medium:        'text-yellow-400 bg-yellow-950/40',
  warning:       'text-yellow-400 bg-yellow-950/40',
  low:           'text-blue-400 bg-blue-950/40',
  informational: 'text-slate-400 bg-sky-950/20',
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
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-6 w-6 text-violet-400" />
          <div>
            <h1 className="text-xl font-semibold text-slate-100">Sigma Kuralları</h1>
            <p className="text-sm text-slate-400">pySigma v2 tabanlı tespit kuralları</p>
          </div>
        </div>
        <Link
          href="/sigma-wizard"
          className="ui-btn ui-btn-primary bg-violet-600 hover:bg-violet-500 text-base py-2 px-4"
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
        <div className="flex gap-6 text-sm text-slate-400">
          <span><span className="text-slate-200 font-medium">{data.count}</span> kural</span>
          <span><span className="text-emerald-400 font-medium">{activeCount}</span> aktif</span>
          <span><span className="text-slate-500 font-medium">{disabledCount}</span> pasif</span>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] overflow-hidden">
        {isLoading && <div className="m-4"><SkeletonTable rows={4} height={36} /></div>}
        {isError && (
          <div className="h-24 flex items-center justify-center text-red-400 text-sm">
            Kurallar yüklenemedi
          </div>
        )}
        {!isLoading && rules.length === 0 && (
          <div className="h-32 flex flex-col items-center justify-center gap-2 text-slate-500">
            <ShieldCheck className="h-8 w-8 text-slate-700" />
            <p className="text-sm">Henüz kural yok</p>
            <Link href="/sigma-wizard" className="text-xs text-violet-400 hover:text-violet-300">
              Sihirbazla ilk kuralı oluştur →
            </Link>
          </div>
        )}
        {rules.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr >
                <th className="ui-th">Aktif</th>
                <th className="ui-th">Başlık</th>
                <th className="ui-th text-center">Önem</th>
                <th className="ui-th">Etiketler</th>
                <th className="ui-th">Dosya</th>
                <th className="ui-th text-right">İşlem</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr
                  key={rule.rule_id}
                  className={cn(
                    'border-b border-sky-900/10 hover:bg-sky-950/20 transition-colors',
                    !rule.enabled && 'opacity-50',
                  )}
                >
                  <td className="ui-td">
                    <button
                      onClick={() => toggleMut.mutate(rule.rule_id)}
                      disabled={toggleMut.isPending}
                      title={rule.enabled ? 'Devre dışı bırak' : 'Etkinleştir'}
                      className={cn(
                        'p-1 rounded transition-colors',
                        rule.enabled
                          ? 'text-emerald-400 hover:text-emerald-300'
                          : 'text-slate-600 hover:text-slate-400',
                      )}
                    >
                      <Power className="h-4 w-4" />
                    </button>
                  </td>
                  <td className="ui-td">
                    <div className="font-medium text-slate-200">{rule.title}</div>
                    {rule.description && (
                      <div className="text-xs text-slate-500 mt-0.5 line-clamp-1">{rule.description}</div>
                    )}
                  </td>
                  <td className="ui-td text-center">
                    <span className={cn(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      LEVEL_COLORS[rule.level] ?? 'text-slate-400',
                    )}>
                      {rule.level}
                    </span>
                  </td>
                  <td className="ui-td">
                    <div className="flex flex-wrap gap-1">
                      {rule.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="px-1.5 py-0.5 rounded text-[10px] bg-sky-950/20 text-slate-400 font-mono">
                          {tag.replace('attack.', '')}
                        </span>
                      ))}
                      {rule.tags.length > 3 && (
                        <span className="text-[10px] text-slate-600">+{rule.tags.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="ui-td hidden lg:table-cell">
                    <span className="text-xs font-mono text-slate-500">{rule.filename}</span>
                  </td>
                  <td className="ui-td">
                    <div className="flex items-center gap-1 justify-end">
                      <Link
                        href={`/sigma-editor?rule_id=${rule.rule_id}`}
                        className="p-1.5 rounded text-slate-500 hover:text-violet-400 hover:bg-violet-950/30 transition-colors"
                        title="YAML Editörde Düzenle"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Link>
                      <button
                        onClick={() => setConfirmDelete(rule.rule_id)}
                        className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/30 transition-colors"
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

      <p className="text-xs text-slate-700">
        Sigma kuralları pySigma v2 ile SQL'e derlenir. Değişiklikler correlator hot-reload ile anında yüklenir.
      </p>

      {/* Delete confirm */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-lg border border-sky-900/30 bg-[#0a1120] p-6 space-y-4">
            <h2 className="text-base font-semibold text-slate-100">Kuralı Sil</h2>
            <p className="text-sm text-slate-400">
              <span className="font-mono text-slate-200">{confirmDelete}</span> kuralı kalıcı olarak silinecek.
            </p>
            {mutError && (
              <p className="text-sm text-red-400 bg-red-950/30 rounded px-3 py-2 border border-red-900/50">
                {mutError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmDelete(null)}
                className="ui-btn ui-btn-secondary"
              >
                İptal
              </button>
              <button
                onClick={() => deleteMut.mutate(confirmDelete)}
                disabled={deleteMut.isPending}
                className="ui-btn ui-btn-danger"
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
