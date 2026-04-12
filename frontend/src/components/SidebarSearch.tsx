import { Globe, Search, Shield } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { CountryFlag } from './CountryFlag'

type IpResult = {
  ip: string
  decisions: number
  alerts: number
  is_banned: boolean
  country_code: string | null
  country: string | null
}

type ServiceResult = {
  host: string
  router_name: string
  favicon: string
  crowdsec: boolean
}

type SearchResults = {
  ips: IpResult[]
  services: ServiceResult[]
}

export function SidebarSearch() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResults | null>(null)
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // Debounced search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (!query.trim() || query.length < 2) {
      setResults(null)
      setOpen(false)
      return
    }
    debounceRef.current = setTimeout(() => {
      setLoading(true)
      void apiFetch(`/api/search?q=${encodeURIComponent(query)}&limit=6`)
        .then(async (r) => {
          if (r.ok) {
            const data = await r.json() as SearchResults
            setResults(data)
            setOpen(true)
          }
        })
        .finally(() => setLoading(false))
    }, 280)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query])

  function go(path: string) {
    setOpen(false)
    setQuery('')
    navigate(path)
  }

  const hasResults =
    results && (results.ips.length > 0 || results.services.length > 0)

  return (
    <div ref={containerRef} className="relative px-3 pb-2">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500 pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => {
            if (results && (results.ips.length > 0 || results.services.length > 0)) {
              setOpen(true)
            }
          }}
          placeholder="Search IP or service…"
          className="w-full rounded-xl bg-white/5 py-2 pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 outline-none ring-0 focus:bg-white/10 focus:ring-1 focus:ring-white/20 transition"
        />
        {loading && (
          <div className="absolute right-2.5 top-1/2 -translate-y-1/2">
            <div className="h-3 w-3 animate-spin rounded-full border-2 border-slate-500 border-t-transparent" />
          </div>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-3 right-3 top-full z-[200] mt-1 overflow-hidden rounded-xl border border-slate-700 bg-slate-800 shadow-2xl">
          {!hasResults && !loading && (
            <div className="px-4 py-3 text-xs text-slate-400">No results found</div>
          )}

          {/* Services */}
          {results && results.services.length > 0 && (
            <div>
              <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-700/50">
                Services
              </div>
              {results.services.map((s) => (
                <button
                  key={s.host}
                  type="button"
                  onClick={() => go(`/services/${encodeURIComponent(s.host)}`)}
                  className="flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors"
                >
                  <img
                    src={s.favicon}
                    alt=""
                    width={14}
                    height={14}
                    className="h-3.5 w-3.5 flex-shrink-0 rounded-sm object-contain"
                    onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs text-slate-200">{s.host}</div>
                  </div>
                  {s.crowdsec && (
                    <Shield className="h-3 w-3 shrink-0 text-emerald-400" title="CrowdSec active" />
                  )}
                </button>
              ))}
            </div>
          )}

          {/* IPs */}
          {results && results.ips.length > 0 && (
            <div>
              <div className={`px-3 py-1.5 text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-700/50 ${results.services.length > 0 ? 'border-t border-slate-700/50' : ''}`}>
                IPs
              </div>
              {results.ips.map((ip) => (
                <button
                  key={ip.ip}
                  type="button"
                  onClick={() => go(`/ip/${encodeURIComponent(ip.ip)}`)}
                  className="flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors"
                >
                  {ip.country_code
                    ? <CountryFlag code={ip.country_code} size={14} />
                    : <Globe className="h-3.5 w-3.5 text-slate-500 shrink-0" />
                  }
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-xs text-slate-200">{ip.ip}</div>
                    {ip.country && (
                      <div className="text-[10px] text-slate-500 truncate">{ip.country}</div>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {ip.is_banned && (
                      <span className="rounded-full bg-red-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-red-400">
                        Banned
                      </span>
                    )}
                    {ip.alerts > 0 && (
                      <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-400">
                        {ip.alerts} alert{ip.alerts > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
