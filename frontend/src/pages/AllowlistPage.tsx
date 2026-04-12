import {
  Check, ChevronLeft, ChevronRight, Clock, Download,
  Plus, RefreshCw, Search, Shield, ShieldCheck, Trash2, Upload, X,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { useToast } from '../components/Toast'
import { usePagePerf } from '../hooks/usePagePerf'

// ── Types ──────────────────────────────────────────────────────────────────────

type Entry = {
  id: number; value: string; reason: string | null; created_by: string | null
  expires_at: string | null; active: boolean; expired: boolean; created_at: string | null
}
type PageData = { total: number; page: number; pages: number; entries: Entry[] }

// ── Helpers ────────────────────────────────────────────────────────────────────

function ExpiryBadge({ entry }: { entry: Entry }) {
  if (entry.expired)
    return <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] text-slate-400 dark:bg-slate-700">Expired</span>
  if (!entry.expires_at)
    return <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">Permanent</span>
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
      <Clock className="h-2.5 w-2.5" />
      {new Date(entry.expires_at).toLocaleDateString()}
    </span>
  )
}

function exportCSV(entries: Entry[]) {
  const header = ['ID', 'Value', 'Reason', 'Created by', 'Expires at', 'Active']
  const rows = entries.map((e) => [e.id, e.value, e.reason ?? '', e.created_by ?? '', e.expires_at ?? '', e.active])
  const csv = [header, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = 'allowlist.csv'; a.click()
  URL.revokeObjectURL(url)
}

const DURATION_OPTIONS = [
  { label: 'Permanent', hours: null },
  { label: '1 hour', hours: 1 },
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 168 },
  { label: '30 days', hours: 720 },
]

// ── Add entry modal ────────────────────────────────────────────────────────────

function AddEntryModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const { addToast } = useToast()
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [expiresHours, setExpiresHours] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSave() {
    if (!value.trim()) return
    setSaving(true)
    try {
      const res = await apiFetch('/api/crowdsec/allowlist', {
        method: 'POST',
        body: JSON.stringify({ value: value.trim(), reason: reason.trim() || null, expires_hours: expiresHours }),
      })
      if (res.ok) {
        addToast(`${value.trim()} added to allowlist`, 'success')
        onAdded()
        onClose()
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Add failed', 'error')
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            <span className="font-semibold text-slate-900 dark:text-white">Add to allowlist</span>
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 p-5">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">IP address or CIDR</label>
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="1.2.3.4 or 10.0.0.0/8"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-mono dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Reason</label>
            <input type="text" value={reason} onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Internal server, trusted partner…"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Duration</label>
            <select value={expiresHours ?? ''} onChange={(e) => setExpiresHours(e.target.value ? Number(e.target.value) : null)}
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
              {DURATION_OPTIONS.map((o) => (
                <option key={o.label} value={o.hours ?? ''}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={onClose}
              className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
              Cancel
            </button>
            <button type="button" onClick={() => void handleSave()} disabled={saving || !value.trim()}
              className="flex-1 rounded-xl bg-emerald-600 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60">
              {saving ? 'Adding…' : 'Add entry'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Bulk import modal ──────────────────────────────────────────────────────────

function BulkImportModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const { addToast } = useToast()
  const [text, setText] = useState('')
  const [reason, setReason] = useState('')
  const [expiresHours, setExpiresHours] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleImport() {
    const entries = text.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
    if (!entries.length) return
    setSaving(true)
    try {
      const res = await apiFetch('/api/crowdsec/allowlist/bulk', {
        method: 'POST',
        body: JSON.stringify({ entries, reason: reason || null, expires_hours: expiresHours }),
      })
      if (res.ok) {
        const data = await res.json() as { added: number; reactivated: number; errors: string[] }
        addToast(`Imported: ${data.added} added, ${data.reactivated} reactivated`, 'success')
        if (data.errors.length) addToast(`${data.errors.length} entries skipped (invalid)`, 'warning')
        onAdded()
        onClose()
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Import failed', 'error')
      }
    } finally {
      setSaving(false)
    }
  }

  const lineCount = text.split(/[\n,]+/).filter((s) => s.trim()).length

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Upload className="h-4 w-4 text-blue-500" />
            <span className="font-semibold text-slate-900 dark:text-white">Bulk import</span>
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 p-5">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
              IPs / CIDRs (one per line or comma-separated)
            </label>
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8}
              placeholder={'1.2.3.4\n10.0.0.0/8\n5.6.7.8'}
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
            {lineCount > 0 && <p className="mt-1 text-[10px] text-slate-400">{lineCount} entries detected</p>}
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Reason (applied to all)</label>
            <input type="text" value={reason} onChange={(e) => setReason(e.target.value)}
              placeholder="Batch import…"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Duration</label>
            <select value={expiresHours ?? ''} onChange={(e) => setExpiresHours(e.target.value ? Number(e.target.value) : null)}
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
              {DURATION_OPTIONS.map((o) => (
                <option key={o.label} value={o.hours ?? ''}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={onClose}
              className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
              Cancel
            </button>
            <button type="button" onClick={() => void handleImport()} disabled={saving || !lineCount}
              className="flex-1 rounded-xl bg-blue-600 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-60">
              {saving ? 'Importing…' : `Import ${lineCount} entries`}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function AllowlistPage() {
  const { me, loading } = useAuth()
  const { addToast } = useToast()
  const [data, setData] = useState<PageData | null>(null)
  const [page, setPage] = useState(1)
  const [showExpired, setShowExpired] = useState(false)
  const [search, setSearch] = useState('')
  const [fetching, setFetching] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [showBulk, setShowBulk] = useState(false)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  usePagePerf('Allowlist', fetching)

  async function load() {
    setFetching(true)
    try {
      const params = new URLSearchParams({ page: String(page), show_expired: String(showExpired) })
      const res = await apiFetch(`/api/crowdsec/allowlist?${params}`)
      if (res.ok) setData(await res.json() as PageData)
    } finally {
      setFetching(false)
    }
  }

  useEffect(() => { void load() }, [page, showExpired]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleDelete(id: number, value: string) {
    setDeletingId(id)
    try {
      const res = await apiFetch(`/api/crowdsec/allowlist/${id}`, { method: 'DELETE' })
      if (res.ok) {
        addToast(`${value} removed from allowlist`, 'success')
        void load()
      } else {
        addToast('Remove failed', 'error')
      }
    } finally {
      setDeletingId(null)
    }
  }

  const filtered = (data?.entries ?? []).filter((e) =>
    !search || e.value.includes(search) || (e.reason ?? '').toLowerCase().includes(search.toLowerCase())
  )

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Allowlist</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            IPs and CIDRs that will never be auto-banned. {data?.total ?? 0} entries.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {me?.is_superuser && (
            <>
              <button type="button" onClick={() => setShowAdd(true)}
                className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700">
                <Plus className="h-4 w-4" /> Add entry
              </button>
              <button type="button" onClick={() => setShowBulk(true)}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
                <Upload className="h-4 w-4" /> Bulk import
              </button>
            </>
          )}
          <button type="button" onClick={() => exportCSV(data?.entries ?? [])}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <Download className="h-4 w-4" /> Export
          </button>
          <button type="button" onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${fetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm dark:border-emerald-500/30 dark:bg-emerald-900/20">
        <Shield className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
        <div className="text-emerald-800 dark:text-emerald-300">
          <p className="font-medium">Local allowlist — Crowdefik only</p>
          <p className="mt-0.5 text-xs">Entries here prevent the auto-ban engine from banning matching IPs during sync. They do NOT modify CrowdSec's own parser whitelists. To whitelist at the CrowdSec level, edit <code className="font-mono">parsers/s02-enrich/</code> files.</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-emerald-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Search IP, CIDR or reason…"
            value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <label className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 cursor-pointer">
          <input type="checkbox" checked={showExpired} onChange={(e) => { setShowExpired(e.target.checked); setPage(1) }}
            className="rounded" />
          Show expired
        </label>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                {['IP / CIDR', 'Reason', 'Added by', 'Expiry', 'Status', ''].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((e) => (
                <tr key={e.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs font-medium text-slate-700 dark:text-slate-200">{e.value}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 max-w-[200px] truncate">{e.reason ?? '—'}</td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{e.created_by ?? '—'}</td>
                  <td className="px-4 py-3"><ExpiryBadge entry={e} /></td>
                  <td className="px-4 py-3">
                    {e.active && !e.expired
                      ? <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400"><Check className="h-2.5 w-2.5" />Active</span>
                      : <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-[10px] text-slate-400 dark:bg-slate-700">Inactive</span>}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {me?.is_superuser && (
                      <button type="button" onClick={() => void handleDelete(e.id, e.value)} disabled={deletingId === e.id}
                        className="rounded-lg border border-red-500/30 bg-red-500/10 p-1.5 text-red-600 hover:bg-red-500/20 disabled:opacity-40 dark:text-red-400">
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {!filtered.length && (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                  {data?.total === 0 ? 'No allowlist entries yet — add IPs or CIDRs that should never be banned.' : 'No entries match filters'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
            <span className="text-xs text-slate-500">{(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total}</span>
            <div className="flex gap-1">
              <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}
                className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)}
                className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {showAdd && <AddEntryModal onClose={() => setShowAdd(false)} onAdded={() => void load()} />}
      {showBulk && <BulkImportModal onClose={() => setShowBulk(false)} onAdded={() => void load()} />}
    </div>
  )
}
