import { useEffect, useRef } from 'react'
import { logPagePerf } from '../perf'

/**
 * Logs a console performance summary for the current page once loading completes.
 *
 * @param pageName  Human-readable label shown in the console group header.
 * @param loading   Aggregate loading flag — true while any data is still fetching.
 *                  When it transitions from true → false the summary is printed.
 *
 * Usage:
 *   usePagePerf('Dashboard', loadingSummary || loadingTimeline || loadingServices)
 */
export function usePagePerf(pageName: string, loading: boolean): void {
  const mountAt = useRef(performance.now())
  const logged = useRef(false)
  const prevLoading = useRef(loading)

  // Reset timer whenever we navigate to a page with a different name
  // (e.g. /services/foo → /services/bar)
  useEffect(() => {
    mountAt.current = performance.now()
    logged.current = false
  }, [pageName])

  useEffect(() => {
    const wasLoading = prevLoading.current
    prevLoading.current = loading

    if (wasLoading && !loading && !logged.current) {
      logged.current = true
      // Small defer so the last state update is fully committed before we read timings
      setTimeout(() => logPagePerf(pageName, mountAt.current), 0)
    }
  }, [loading, pageName])
}
