import { useEffect, useState } from 'react'
import { apiFetch } from '@/lib/api'

interface FetchState<T> {
  data: T | null
  /** true when the request failed (network error or non-2xx) */
  failed: boolean
  loading: boolean
}

/**
 * GET a JSON resource and keep it tied to the URL it came from: when `url`
 * changes, the previous request is aborted and its stale response can never
 * show up under the new URL. A `null` URL fetches nothing. Loading is derived
 * from "the stored response belongs to another URL", so the effect never has to
 * reset state synchronously.
 */
export function useFetchJson<T>(url: string | null): FetchState<T> {
  const [state, setState] = useState<{ url: string | null; data: T | null; failed: boolean }>({
    url: null, data: null, failed: false,
  })

  useEffect(() => {
    if (url == null) return
    const ctrl = new AbortController()
    apiFetch(url, { signal: ctrl.signal })
      .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() as Promise<T> })
      .then(data => setState({ url, data, failed: false }))
      .catch(() => {
        if (!ctrl.signal.aborted) setState({ url, data: null, failed: true })
      })
    return () => ctrl.abort()
  }, [url])

  if (url == null) return { data: null, failed: false, loading: false }
  if (state.url !== url) return { data: null, failed: false, loading: true }
  return { data: state.data, failed: state.failed, loading: false }
}
