import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api, setCsrfToken } from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [status, setStatus] = useState('loading')
  const [sessionNotice, setSessionNotice] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    const handleUnauthorized = () => {
      setUser(null)
      setStatus('anonymous')
      setSessionNotice('Your sign-in session expired or is no longer valid. Please sign in again.')
    }

    window.addEventListener('arbr:unauthorized', handleUnauthorized)
    api.get('/auth/me', { signal: controller.signal })
      .then((currentUser) => {
        setCsrfToken(currentUser.csrf_token)
        const safeUser = { user_id: currentUser.user_id, role: currentUser.role, display_name: currentUser.display_name }
        setUser(safeUser)
        setStatus('authenticated')
        setSessionNotice('')
      })
      .catch((error) => {
        if (error.name === 'AbortError') return
        setUser(null)
        setStatus('anonymous')
        if (error.code === 'session_expired' || error.code === 'invalid_session') {
          setSessionNotice(error.message)
        }
      })

    return () => {
      controller.abort()
      window.removeEventListener('arbr:unauthorized', handleUnauthorized)
    }
  }, [])

  const login = useCallback(async (credentials) => {
    const authenticatedUser = await api.post('/auth/login', credentials)
    setCsrfToken(authenticatedUser.csrf_token)
    const safeUser = { user_id: authenticatedUser.user_id, role: authenticatedUser.role, display_name: authenticatedUser.display_name }
    setUser(safeUser)
    setStatus('authenticated')
    setSessionNotice('')
    return safeUser
  }, [])

  const logout = useCallback(async () => {
    setUser(null)
    setStatus('anonymous')
    try {
      await api.post('/auth/logout', {})
      setCsrfToken('')
      setSessionNotice('')
    } catch {
      setCsrfToken('')
      setSessionNotice('You have been signed out of this view, but the API could not confirm session revocation. The session expires automatically.')
    }
  }, [])

  const changePassword = useCallback(async (credentials) => {
    await api.post('/auth/change-password', credentials)
    setCsrfToken('')
    setUser(null)
    setStatus('anonymous')
    setSessionNotice('Password updated. Sign in again with your new password.')
  }, [])

  const value = useMemo(() => ({ user, status, sessionNotice, login, logout, changePassword }), [user, status, sessionNotice, login, logout, changePassword])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
