import { useState } from 'react'
import { KeyRound, ShieldCheck } from 'lucide-react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'

export default function ChangePasswordPage() {
  const { changePassword, user } = useAuth()
  const navigate = useNavigate()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (!user) return <Navigate to="/login" replace />

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    if (newPassword.length < 12) {
      setError('Choose a password with at least 12 characters.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('The new password and confirmation do not match.')
      return
    }
    if (newPassword === currentPassword) {
      setError('Choose a new password that is different from your current password.')
      return
    }
    if (!window.confirm('Change your password and sign out of all active sessions?')) return
    setBusy(true)
    try {
      await changePassword({ current_password: currentPassword, new_password: newPassword })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      navigate('/login', { replace: true })
    } catch (changeError) {
      setError(changeError.message || 'Password could not be changed. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="dashboard-main">
      <section className="api-page-heading"><div><h1>Change Password</h1><p>Update the password for your authenticated account.</p></div></section>
      <section className="panel password-change-panel">
        <header className="panel-heading"><div><h2><KeyRound size={16} /> Password Update</h2><p>Current password verification is required. All active sessions will be revoked.</p></div></header>
        <form className="password-change-form" onSubmit={submit}>
          <label htmlFor="current-password">Current password</label>
          <input id="current-password" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
          <label htmlFor="new-password">New password</label>
          <input id="new-password" type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
          <span className="password-requirement"><ShieldCheck size={14} /> Use at least 12 characters.</span>
          <label htmlFor="confirm-password">Confirm new password</label>
          <input id="confirm-password" type="password" autoComplete="new-password" minLength={12} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
          {error && <p className="password-change-error" role="alert">{error}</p>}
          <button className="toolbar-button" type="submit" disabled={busy || !currentPassword || !newPassword || !confirmPassword}>{busy ? 'Updating…' : 'Update password and sign out'}</button>
        </form>
      </section>
    </main>
  )
}
