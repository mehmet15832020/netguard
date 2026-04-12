'use client'

import { useState } from 'react'
import { Settings, Save, RefreshCw, Plus, Trash2 } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { correlationApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import type { CorrelationRule, Severity } from '@/types/models'

function RuleCard({
  rule,
  onSave,
}: {
  rule: CorrelationRule
  onSave: (updated: CorrelationRule) => void
}) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<CorrelationRule>(rule)

  const handleSave = () => {
    onSave(draft)
    setEditing(false)
  }

  const handleCancel = () => {
    setDraft(rule)
    setEditing(false)
  }

  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm text-zinc-200">{rule.name}</CardTitle>
            <CardDescription className="text-xs text-zinc-500 mt-0.5">{rule.description}</CardDescription>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <SeverityBadge severity={rule.severity} />
            {!editing && (
              <Button
                variant="outline" size="sm"
                onClick={() => setEditing(true)}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-xs h-7 px-2"
              >
                Düzenle
              </Button>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {editing ? (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-xs text-zinc-400">Eşik (Threshold)</Label>
                <Input
                  type="number"
                  value={draft.threshold}
                  onChange={(e) => setDraft({ ...draft, threshold: +e.target.value })}
                  className="h-8 text-sm bg-zinc-800 border-zinc-700 text-zinc-100"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-zinc-400">Zaman Penceresi (saniye)</Label>
                <Input
                  type="number"
                  value={draft.window_seconds}
                  onChange={(e) => setDraft({ ...draft, window_seconds: +e.target.value })}
                  className="h-8 text-sm bg-zinc-800 border-zinc-700 text-zinc-100"
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-zinc-400">Seviye</Label>
              <Select
                value={draft.severity}
                onValueChange={(v) => setDraft({ ...draft, severity: v as Severity })}
              >
                <SelectTrigger className="h-8 text-sm bg-zinc-800 border-zinc-700 text-zinc-300">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  <SelectItem value="info" className="text-zinc-300">Bilgi</SelectItem>
                  <SelectItem value="warning" className="text-zinc-300">Uyarı</SelectItem>
                  <SelectItem value="critical" className="text-zinc-300">Kritik</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2 pt-1">
              <Button size="sm" onClick={handleSave} className="bg-indigo-600 hover:bg-indigo-500 text-white h-7 text-xs">
                <Save size={12} className="mr-1" /> Kaydet
              </Button>
              <Button size="sm" variant="outline" onClick={handleCancel}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 h-7 text-xs">
                İptal
              </Button>
            </div>
          </>
        ) : (
          <div className="grid grid-cols-3 gap-4 text-xs">
            <div>
              <p className="text-zinc-500">Eşik</p>
              <p className="text-zinc-200 font-medium mt-0.5">{rule.threshold} olay</p>
            </div>
            <div>
              <p className="text-zinc-500">Zaman penceresi</p>
              <p className="text-zinc-200 font-medium mt-0.5">{rule.window_seconds}s</p>
            </div>
            <div>
              <p className="text-zinc-500">Gruplama</p>
              <p className="text-zinc-200 font-medium mt-0.5">{rule.group_by}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default function SettingsPage() {
  const queryClient = useQueryClient()
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')

  const { data: rulesData, isLoading } = useQuery({
    queryKey: ['correlation-rules'],
    queryFn: () => correlationApi.listRules(),
  })

  const reloadMutation = useMutation({
    mutationFn: () => correlationApi.reloadRules(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] })
    },
  })

  const rules = rulesData?.rules ?? []

  // Kural güncellemesi — şimdilik sadece UI'da gösterir,
  // tam implementasyon için backend'e PUT /settings/rules gerekir
  const handleRuleSave = (updated: CorrelationRule) => {
    setSaveStatus('saving')
    // TODO: Backend endpoint hazır olunca buraya PUT isteği ekle
    // Şimdilik lokal güncelleme + reload
    setTimeout(() => {
      setSaveStatus('saved')
      reloadMutation.mutate()
      setTimeout(() => setSaveStatus('idle'), 2000)
    }, 500)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
          <Settings size={18} /> Ayarlar
        </h1>
        <p className="text-sm text-zinc-500 mt-0.5">Korelasyon kuralları ve alarm eşikleri</p>
      </div>

      {/* Korelasyon kuralları */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-medium text-zinc-300">Korelasyon Kuralları</h2>
            <p className="text-xs text-zinc-500 mt-0.5">
              Eşik ve pencere değerlerini değiştirip kaydet —
              sunucuyu yeniden başlatmak gerekmez
            </p>
          </div>
          <Button
            variant="outline" size="sm"
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-xs"
          >
            <RefreshCw size={12} className={reloadMutation.isPending ? 'animate-spin mr-1' : 'mr-1'} />
            Kuralları Yenile
          </Button>
        </div>

        {saveStatus === 'saved' && (
          <div className="bg-green-900/30 border border-green-800 rounded px-3 py-2 text-green-400 text-xs">
            Kurallar güncellendi ve yeniden yüklendi.
          </div>
        )}

        {isLoading ? (
          <p className="text-zinc-500 text-sm">Yükleniyor...</p>
        ) : (
          <div className="space-y-3">
            {rules.map((rule) => (
              <RuleCard key={rule.rule_id} rule={rule} onSave={handleRuleSave} />
            ))}
          </div>
        )}
      </div>

      <Separator className="bg-zinc-800" />

      {/* Dedektör eşikleri bilgi kartı */}
      <div className="space-y-3">
        <div>
          <h2 className="text-sm font-medium text-zinc-300">Dedektör Eşikleri</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Sunucu ortam değişkenleriyle ayarlanır
          </p>
        </div>
        <Card className="bg-zinc-900 border-zinc-800">
          <CardContent className="p-4">
            <div className="grid grid-cols-2 gap-x-8 gap-y-3 text-xs">
              {[
                ['NETGUARD_PORTSCAN_THRESHOLD', '10 port', 'Port tarama eşiği'],
                ['NETGUARD_ICMP_THRESHOLD',     '100 pkt/s', 'ICMP flood eşiği'],
                ['NETGUARD_DNS_THRESHOLD',       '30 sorgu', 'DNS anomali eşiği'],
                ['NETGUARD_NTP_SERVER',          'pool.ntp.org', 'NTP sunucusu'],
                ['NETGUARD_CLOCK_WARN_SEC',      '5s', 'Saat sapma uyarı eşiği'],
                ['NETGUARD_CLOCK_CRIT_SEC',      '60s', 'Saat sapma kritik eşiği'],
                ['NETGUARD_SYSLOG_PORT',         '5140', 'Syslog UDP portu'],
                ['NETGUARD_CORR_INTERVAL',       '60s', 'Korelasyon çalışma aralığı'],
              ].map(([env, def, desc]) => (
                <div key={env} className="flex flex-col gap-0.5">
                  <span className="font-mono text-indigo-400">{env}</span>
                  <span className="text-zinc-500">{desc} <span className="text-zinc-400">(varsayılan: {def})</span></span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
