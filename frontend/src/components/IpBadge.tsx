import { AlertTriangle, ExternalLink, Globe, Info, Loader2, ShieldCheck, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api'
import { CountryFlag } from './CountryFlag'

// ── Allowlist cache ───────────────────────────────────────────
const allowlistCache = new Map<string, boolean>()
const allowlistPending = new Map<string, Promise<boolean>>()

async function fetchIsAllowlisted(ip: string): Promise<boolean> {
  if (allowlistCache.has(ip)) return allowlistCache.get(ip)!
  if (!allowlistPending.has(ip)) {
    const p = apiFetch('/api/crowdsec/allowlist/check', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    })
      .then(async (r) => {
        if (!r.ok) return false
        const d = await r.json() as { protected: boolean }
        allowlistCache.set(ip, d.protected)
        return d.protected
      })
      .catch(() => false)
      .finally(() => allowlistPending.delete(ip))
    allowlistPending.set(ip, p)
  }
  return allowlistPending.get(ip)!
}

type GeoData = {
  country?: string; countryCode?: string; city?: string; regionName?: string
  isp?: string; org?: string; as?: string; lat?: number; lon?: number
}
type AbuseData = {
  abuseConfidenceScore?: number; countryCode?: string; isp?: string; domain?: string
  totalReports?: number; numDistinctUsers?: number; lastReportedAt?: string; isTor?: boolean
}
type IpInfo = { ip: string; geo: GeoData | null; abuse: AbuseData | null }

// ── Score styling ─────────────────────────────────────────────
function scoreClasses(score: number) {
  if (score >= 75) return 'bg-red-500/15 text-red-600 dark:text-red-400'
  if (score >= 30) return 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
  if (score > 0)   return 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400'
  return 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
}

// ── Modal ─────────────────────────────────────────────────────
function Modal({ info, loading, onClose }: { info: IpInfo; loading: boolean; onClose: () => void }) {
  const { geo, abuse } = info
  const score = abuse?.abuseConfidenceScore ?? null
  const cc = abuse?.countryCode || geo?.countryCode || ''

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`IP details for ${info.ip}`}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-violet-500" />
            <Link
              to={`/ip/${encodeURIComponent(info.ip)}`}
              onClick={onClose}
              className="font-mono text-sm font-medium hover:text-violet-600 dark:hover:text-violet-400"
            >
              {info.ip}
            </Link>
            {cc && <CountryFlag code={cc} size={20} />}
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          {/* Abuse score */}
          {loading ? (
            <div className="flex items-center justify-center gap-2 rounded-xl border border-slate-100 p-4 dark:border-slate-800">
              <Loader2 className="h-4 w-4 animate-spin text-slate-400" />
              <span className="text-xs text-slate-400">Loading IP data…</span>
            </div>
          ) : score !== null ? (
            <div className="flex items-center justify-between rounded-xl border border-slate-100 p-3 dark:border-slate-800">
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <AlertTriangle className="h-4 w-4" />
                Abuse confidence score
              </div>
              <span className={`rounded-full px-2.5 py-1 text-xs font-bold ${scoreClasses(score)}`}>{score}%</span>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-100 p-3 text-xs text-slate-500 dark:border-slate-800">
              No abuse score available — AbuseIPDB key may not be configured or the API is unreachable.
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

          {/* Full details link */}
          <Link
            to={`/ip/${encodeURIComponent(info.ip)}`}
            onClick={onClose}
            className="flex items-center justify-center gap-1.5 rounded-xl border border-violet-500/30 bg-violet-500/10 py-2 text-xs font-medium text-violet-700 hover:bg-violet-500/15 dark:text-violet-400"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            View full IP details
          </Link>
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

// ── Shared cache ──────────────────────────────────────────────
// A pending-promise cache avoids firing the same request twice even when
// multiple <IpBadge ip="x.x.x.x" /> components mount at the same time.
const cache = new Map<string, IpInfo>()
const pending = new Map<string, Promise<IpInfo | null>>()

async function fetchIpInfo(ip: string): Promise<IpInfo | null> {
  if (cache.has(ip)) return cache.get(ip)!
  if (!pending.has(ip)) {
    const p = apiFetch(`/api/ip/${encodeURIComponent(ip)}`)
      .then(async (r) => {
        if (!r.ok) return null
        const data = (await r.json()) as IpInfo
        cache.set(ip, data)
        return data
      })
      .catch(() => null)
      .finally(() => pending.delete(ip))
    pending.set(ip, p)
  }
  return pending.get(ip)!
}

// ── IpBadge ───────────────────────────────────────────────────
export function IpBadge({
  ip,
  countryCode: initialCountryCode,
  score: initialScore,
}: {
  ip: string
  /** Pre-populated country code from API data (shown immediately, no hover required) */
  countryCode?: string | null
  /** Pre-populated abuse score from API data */
  score?: number | null
}) {
  const [open, setOpen] = useState(false)
  const [info, setInfo] = useState<IpInfo | null>(() => cache.get(ip) ?? null)
  const [loadingInfo, setLoadingInfo] = useState(false)
  const [protected_, setProtected] = useState<boolean>(() => allowlistCache.get(ip) ?? false)
  const [hovered, setHovered] = useState(false)
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  /** Trigger a fetch if we don't have data yet; sets loadingInfo while in flight. */
  function ensureInfoLoaded() {
    if (info || loadingInfo) return
    setLoadingInfo(true)
    void fetchIpInfo(ip).then((d) => {
      if (d) setInfo(d)
      setLoadingInfo(false)
    })
    if (!allowlistCache.has(ip)) void fetchIsAllowlisted(ip).then(setProtected)
  }

  // Lazy fetch on hover (150 ms debounce)
  useEffect(() => {
    if (!hovered) return
    ensureInfoLoaded()
  }, [hovered, ip]) // eslint-disable-line react-hooks/exhaustive-deps

  // Also fetch immediately when modal opens (covers direct click without hover)
  useEffect(() => {
    if (open) ensureInfoLoaded()
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  function handleMouseEnter() {
    hoverTimer.current = setTimeout(() => setHovered(true), 150)
  }
  function handleMouseLeave() {
    if (hoverTimer.current) clearTimeout(hoverTimer.current)
  }

  // Use fetched data when available, fall back to pre-populated props
  const cc = info?.abuse?.countryCode || info?.geo?.countryCode || initialCountryCode || ''
  const score = info?.abuse?.abuseConfidenceScore ?? initialScore ?? null

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className="group inline-flex items-center gap-1.5 font-mono text-xs text-slate-700 hover:text-violet-600 dark:text-slate-300 dark:hover:text-violet-400"
        title="Click for full IP details"
      >
        {cc && <CountryFlag code={cc} size={16} />}
        <span>{ip}</span>
        {protected_ && (
          <span title="On allowlist — will not be auto-banned">
            <ShieldCheck className="h-3 w-3 text-emerald-500" />
          </span>
        )}
        {score !== null && (
          <span className={`rounded-full px-1.5 py-px text-[10px] font-semibold leading-tight ${scoreClasses(score)}`}>
            {score}%
          </span>
        )}
        <Info className="h-3 w-3 opacity-0 transition group-hover:opacity-60" />
      </button>

      {open && (
        <Modal
          info={info ?? { ip, geo: null, abuse: null }}
          loading={loadingInfo}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  )
}
