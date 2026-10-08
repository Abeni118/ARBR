const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const baseUrl = configuredBaseUrl.replace(/\/+$/, '')
const apiPrefix = baseUrl.endsWith('/api') ? '' : '/api'
const bearerToken = import.meta.env.VITE_MVP_BEARER_TOKEN?.trim()

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export async function request(path, { method = 'GET', body, headers = {}, signal } = {}) {
  const requestHeaders = new Headers(headers)
  requestHeaders.set('Accept', 'application/json')
  if (bearerToken) requestHeaders.set('Authorization', `Bearer ${bearerToken}`)
  if (body !== undefined) requestHeaders.set('Content-Type', 'application/json')

  const response = await fetch(`${baseUrl}${apiPrefix}${path.startsWith('/') ? path : `/${path}`}`, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
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
    if (response.status === 401) throw new ApiError(401, 'Authentication is required. Configure the development Bearer token and try again.')
    if (response.status === 403) throw new ApiError(403, 'Permission denied for this operation.')
    throw new ApiError(response.status, `The API request failed (HTTP ${response.status}).`)
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
