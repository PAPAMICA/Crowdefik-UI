import { Globe, Search, Shield, ShieldBan } from 'lucide-react'
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

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

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

  const hasResults = results && (results.ips.length > 0 || results.services.length > 0)

  return (
    <div ref={containerRef} className="relative px-3 pb-3">
      {/* Input */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500 pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => {
            if (hasResults) setOpen(true)
          }}
          placeholder="Search IP or service…"
          className="w-full rounded-lg bg-slate-800 border border-slate-700/60 py-2 pl-8 pr-7 text-xs text-slate-300 placeholder-slate-600 outline-none focus:border-violet-500/60 focus:bg-slate-800 focus:ring-1 focus:ring-violet-500/30 transition"
        />
        {loading && (
          <div className="absolute right-2.5 top-1/2 -translate-y-1/2">
            <div className="h-3 w-3 animate-spin rounded-full border-2 border-slate-600 border-t-violet-400" />
          </div>
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-3 right-3 top-[calc(100%-4px)] z-[200] overflow-hidden rounded-xl border border-slate-700 bg-slate-900 shadow-2xl shadow-black/60">

          {!hasResults && !loading && (
            <div className="flex items-center gap-2 px-4 py-3 text-xs text-slate-500">
              <Search className="h-3.5 w-3.5" />
              No results for <span className="font-mono text-slate-400">"{query}"</span>
            </div>
          )}

          {/* Services section */}
          {results && results.services.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 px-3 pt-2.5 pb-1">
                <Globe className="h-3 w-3 text-blue-400" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Services</span>
              </div>
              <div className="pb-1">
                {results.services.map((s) => (
                  <button
                    key={s.host}
                    type="button"
                    onClick={() => go(`/services/${encodeURIComponent(s.host)}`)}
                    className="group flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors"
                  >
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-800 ring-1 ring-slate-700/60">
                      <img
                        src={s.favicon}
                        alt=""
                        width={12}
                        height={12}
                        className="h-3 w-3 object-contain"
                        onError={(e) => {
                          (e.currentTarget as HTMLImageElement).style.display = 'none'
                          ;(e.currentTarget.parentElement as HTMLElement).innerHTML = '<span style="font-size:9px;color:#64748b">🌐</span>'
                        }}
                      />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-xs font-medium text-slate-300 group-hover:text-white transition-colors">
                        {s.host}
                      </div>
                    </div>
                    {s.crowdsec && (
                      <div className="flex shrink-0 items-center gap-1 rounded-md bg-emerald-500/15 px-1.5 py-0.5">
                        <Shield className="h-2.5 w-2.5 text-emerald-400" />
                        <span className="text-[9px] font-semibold text-emerald-400">WAF</span>
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Divider between sections */}
          {results && results.services.length > 0 && results.ips.length > 0 && (
            <div className="mx-3 border-t border-slate-800" />
          )}

          {/* IPs section */}
          {results && results.ips.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 px-3 pt-2.5 pb-1">
                <ShieldBan className="h-3 w-3 text-red-400" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">IP Addresses</span>
              </div>
              <div className="pb-1">
                {results.ips.map((ip) => (
                  <button
                    key={ip.ip}
                    type="button"
                    onClick={() => go(`/ip/${encodeURIComponent(ip.ip)}`)}
                    className="group flex w-full items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors"
                  >
                    {/* Flag or globe */}
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-800 ring-1 ring-slate-700/60 overflow-hidden">
                      {ip.country_code
                        ? <CountryFlag code={ip.country_code} size={16} />
                        : <Globe className="h-3 w-3 text-slate-500" />
                      }
                    </div>

                    {/* IP + country */}
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-xs font-medium text-slate-300 group-hover:text-white transition-colors">
                        {ip.ip}
                      </div>
                      {ip.country && (
                        <div className="text-[10px] text-slate-600 truncate">{ip.country}</div>
                      )}
                    </div>

                    {/* Status badges */}
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      {ip.is_banned && (
                        <div className="flex items-center gap-1 rounded-md bg-red-500/20 px-1.5 py-0.5 ring-1 ring-red-500/30">
                          <ShieldBan className="h-2.5 w-2.5 text-red-400" />
                          <span className="text-[9px] font-bold text-red-400">Banned</span>
                        </div>
                      )}
                      {ip.alerts > 0 && (
                        <div className="flex items-center gap-1 rounded-md bg-amber-500/15 px-1.5 py-0.5">
                          <span className="text-[9px] font-semibold text-amber-400">{ip.alerts} alert{ip.alerts > 1 ? 's' : ''}</span>
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Footer hint */}
          {hasResults && (
            <div className="border-t border-slate-800 px-3 py-1.5 text-[9px] text-slate-600">
              Press Enter or click to navigate
            </div>
          )}
        </div>
      )}
    </div>
  )
}
