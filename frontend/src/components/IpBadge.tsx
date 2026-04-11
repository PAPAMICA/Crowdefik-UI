import { AlertTriangle, Globe, Info, X } from 'lucide-react'
import { useState } from 'react'
import { apiFetch } from '../api'
import { CountryFlag } from './CountryFlag'

type GeoData = {
  country?: string; countryCode?: string; city?: string; regionName?: string
  isp?: string; org?: string; as?: string; lat?: number; lon?: number
}
type AbuseData = {
  abuseConfidenceScore?: number; countryCode?: string; isp?: string; domain?: string
  totalReports?: number; numDistinctUsers?: number; lastReportedAt?: string; isTor?: boolean
}
type IpInfo = { ip: string; geo: GeoData | null; abuse: AbuseData | null }

function scoreColor(score: number) {
  if (score >= 75) return 'text-red-500 bg-red-500/10'
  if (score >= 30) return 'text-amber-500 bg-amber-500/10'
  if (score > 0) return 'text-yellow-500 bg-yellow-500/10'
  return 'text-emerald-500 bg-emerald-500/10'
}

function Modal({ info, onClose }: { info: IpInfo; onClose: () => void }) {
  const { geo, abuse } = info
  const score = abuse?.abuseConfidenceScore ?? null
  const cc = abuse?.countryCode || geo?.countryCode || ''

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-violet-500" />
            <span className="font-mono text-sm font-medium">{info.ip}</span>
            {cc && <CountryFlag code={cc} size={20} />}
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          {/* Abuse score */}
          {score !== null ? (
            <div className="flex items-center justify-between rounded-xl border border-slate-100 p-3 dark:border-slate-800">
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <AlertTriangle className="h-4 w-4" />
                Abuse confidence score
              </div>
              <span className={`rounded-full px-2.5 py-1 text-xs font-bold ${scoreColor(score)}`}>{score}%</span>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-100 p-3 text-xs text-slate-500 dark:border-slate-800">
              No AbuseIPDB key configured — set it in Settings for abuse scores.
            </div>
          )}

          {/* Geo */}
          {geo && (
            <div className="space-y-2 text-sm">
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">Geolocation</div>
              <div className="grid grid-cols-2 gap-2">
                {geo.country && (
                <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
                  <div className="text-[10px] text-slate-400">Country</div>
                  <div className="mt-0.5 flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-200">
                    {geo.countryCode && <CountryFlag code={geo.countryCode} size={16} />}
                    {geo.country}
                  </div>
                </div>
              )}
                {geo.city && <Row label="City" value={geo.city} />}
                {geo.regionName && <Row label="Region" value={geo.regionName} />}
                {geo.isp && <Row label="ISP" value={geo.isp} />}
                {geo.org && <Row label="Org" value={geo.org} />}
              </div>
            </div>
          )}

          {/* AbuseIPDB extra */}
          {abuse && (
            <div className="space-y-2 text-sm">
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">AbuseIPDB</div>
              <div className="grid grid-cols-2 gap-2">
                {abuse.totalReports != null && <Row label="Reports" value={String(abuse.totalReports)} />}
                {abuse.numDistinctUsers != null && <Row label="Distinct users" value={String(abuse.numDistinctUsers)} />}
                {abuse.isp && <Row label="ISP" value={abuse.isp} />}
                {abuse.domain && <Row label="Domain" value={abuse.domain} />}
                {abuse.isTor && <Row label="Tor exit" value="Yes" className="text-red-500" />}
                {abuse.lastReportedAt && (
                  <Row label="Last report" value={new Date(abuse.lastReportedAt).toLocaleDateString()} />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Row({ label, value, className = '' }: { label: string; value: string; className?: string }) {
  return (
    <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
      <div className="text-[10px] text-slate-400">{label}</div>
      <div className={`mt-0.5 text-xs font-medium ${className || 'text-slate-700 dark:text-slate-200'}`}>{value}</div>
    </div>
  )
}

const cache: Map<string, IpInfo> = new Map()

export function IpBadge({ ip }: { ip: string }) {
  const [open, setOpen] = useState(false)
  const [info, setInfo] = useState<IpInfo | null>(null)
  const [loading, setLoading] = useState(false)

  async function openModal() {
    setOpen(true)
    if (cache.has(ip)) {
      setInfo(cache.get(ip)!)
      return
    }
    setLoading(true)
    const res = await apiFetch(`/api/ip/${encodeURIComponent(ip)}`)
    if (res.ok) {
      const data = (await res.json()) as IpInfo
      cache.set(ip, data)
      setInfo(data)
    }
    setLoading(false)
  }

  return (
    <>
      <button
        type="button"
        onClick={openModal}
        className="group inline-flex items-center gap-1 font-mono text-xs text-slate-700 hover:text-violet-600 dark:text-slate-300 dark:hover:text-violet-400"
      >
        {ip}
        <Info className="h-3 w-3 opacity-0 transition group-hover:opacity-100" />
      </button>
      {open && (
        <Modal
          info={info ?? { ip, geo: null, abuse: null }}
          onClose={() => { setOpen(false); setInfo(null) }}
        />
      )}
      {open && loading && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div className="rounded-xl bg-white px-4 py-3 text-sm shadow-lg dark:bg-slate-800">Loading IP data…</div>
        </div>
      )}
    </>
  )
}
