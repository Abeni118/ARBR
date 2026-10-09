const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const baseUrl = configuredBaseUrl.replace(/\/+$/, '')
const apiPrefix = baseUrl.endsWith('/api') ? '' : '/api'
let csrfToken = ''

export function setCsrfToken(value) {
  csrfToken = typeof value === 'string' ? value : ''
}

export class ApiError extends Error {
  constructor(status, message, code = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

export async function request(path, { method = 'GET', body, headers = {}, signal } = {}) {
  const requestHeaders = new Headers(headers)
  requestHeaders.set('Accept', 'application/json')
  if (body !== undefined) requestHeaders.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    if (csrfToken) requestHeaders.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(`${baseUrl}${apiPrefix}${path.startsWith('/') ? path : `/${path}`}`, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
    credentials: 'include',
  })

  if (response.status === 204) return null
  const contentType = response.headers.get('content-type') || ''
  let payload = null
  if (contentType.includes('application/json')) {
    try {
      payload = await response.json()
    } catch {
      throw new ApiError(response.status, 'The API returned an unreadable JSON response.')
    }
  } else if (response.ok) {
    throw new ApiError(response.status, 'The API returned an unexpected response format.')
  }

  if (!response.ok) {
    const detail = payload?.detail
    const code = typeof detail === 'object' && detail !== null ? detail.code : null
    const detailMessage = typeof detail === 'object' && detail !== null ? detail.message : typeof detail === 'string' ? detail : null
    const message = response.status >= 500
      ? 'The service encountered an error. Please try again shortly.'
      : detailMessage || (response.status === 401
        ? 'Your sign-in is required or has expired. Please sign in again.'
        : response.status === 403
          ? 'You do not have permission to perform this operation.'
          : `The API request failed (HTTP ${response.status}).`)
    const error = new ApiError(response.status, message, code)
    if (response.status === 401 && !/^\/auth\/(login|me|logout)$/.test(path) && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('arbr:unauthorized', { detail: error }))
    }
    throw error
  }
  return payload
}

export const api = {
  get: (path, options) => request(path, options),
  post: (path, body, options) => request(path, { ...options, method: 'POST', body }),
  put: (path, body, options) => request(path, { ...options, method: 'PUT', body }),
  patch: (path, body, options) => request(path, { ...options, method: 'PATCH', body }),
  delete: (path, options) => request(path, { ...options, method: 'DELETE' }),
}

export function queryString(values) {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  })
  const query = params.toString()
  return query ? `?${query}` : ''
}
