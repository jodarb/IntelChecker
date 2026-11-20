// Every backend call goes through apiFetch. The session is an HttpOnly cookie that
// the browser sends on its own (same-origin /api proxy); apiFetch only watches for
// the answers that mean "your session is gone" so the AuthProvider can show the
// login screen again instead of every page failing on its own.

export const API = '/api'

export const AUTH_EXPIRED_EVENT = 'intelchecker:auth-expired'

export interface ApiErrorBody {
  code?: string
  message?: string
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path.startsWith('/api') ? path : `${API}${path}`, {
    credentials: 'same-origin',
    ...init,
  })
  if (res.status === 401 && !path.endsWith('/auth/login') && !path.endsWith('/auth/me')) {
    window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT))
  }
  return res
}

/** `{ code, message }` from a FastAPI error response (`detail` is an object or a string). */
export async function readApiError(res: Response): Promise<ApiErrorBody> {
  const body = await res.json().catch(() => null)
  const detail = body?.detail
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) return detail as ApiErrorBody
  if (typeof detail === 'string') return { message: detail }
  return { code: `HTTP${res.status}`, message: `Backend returned HTTP ${res.status}` }
}

export class ApiError extends Error {
  code?: string
  status: number
  constructor(status: number, body: ApiErrorBody) {
    super(body.message ?? `HTTP ${status}`)
    this.code = body.code
    this.status = status
  }
}

/** JSON request that throws ApiError on a non-2xx answer. */
export async function apiJson<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) throw new ApiError(res.status, await readApiError(res))
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}
