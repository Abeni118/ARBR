import { useState } from 'react'
import { Activity, AlertTriangle, Bell, ChartNoAxesCombined, Database, FileCheck2, LockKeyhole, RotateCcw, Save, Settings as SettingsIcon, Shield, ShieldAlert, X } from 'lucide-react'
import { initialSettings, settingFields, settingsSections } from '../data/settingsData.js'
import './SettingsPage.css'

const sectionIcons = { settings: SettingsIcon, activity: Activity, chart: ChartNoAxesCombined, database: Database, lock: LockKeyhole, rotate: RotateCcw, bell: Bell }

function SettingField({ field, value, onChange }) {
  if (field.type === 'toggle') return <div className="setting-row"><div className="setting-copy"><strong>{field.label}</strong><span>{field.description}</span></div><div className="setting-control"><span className={`setting-value-badge ${value ? 'setting-value-badge--enabled' : 'setting-value-badge--disabled'}`}>{value ? 'Enabled' : 'Disabled'}</span><button type="button" role="switch" aria-checked={value} aria-label={field.label} className={`setting-switch ${value ? 'setting-switch--on' : ''}`} onClick={() => onChange(!value)}><i /></button></div></div>
  if (field.type === 'status') return <div className="setting-row"><div className="setting-copy"><strong>{field.label}</strong><span>{field.description}</span></div><div className="setting-control"><span className="settings-connection"><i className="status-dot status-dot--green" />{value}</span></div></div>
  if (field.type === 'select') return <label className="setting-row setting-row--input"><span className="setting-copy"><strong>{field.label}</strong></span><select value={value} onChange={(event) => onChange(event.target.value)}>{field.options.map((option) => <option key={option} value={option}>{option}</option>)}</select></label>
  if (field.type === 'range') return <label className="setting-row setting-row--input"><span className="setting-copy"><strong>{field.label}</strong></span><span className="setting-number-wrap setting-range-wrap"><small>{field.rangeLabel}</small><input aria-label={field.label} type="number" min="0" max="100" value={value} onChange={(event) => onChange(event.target.value)} /></span></label>
  return <label className="setting-row setting-row--input"><span className="setting-copy"><strong>{field.label}</strong></span><span className="setting-number-wrap"><input type={field.type} min={field.type === 'number' ? 1 : undefined} max={field.type === 'number' ? 100 : undefined} value={value} onChange={(event) => onChange(event.target.value)} /><small>{field.suffix}</small></span></label>
}

export default function SettingsPage({ onToast }) {
  const [activeSection, setActiveSection] = useState('general')
  const [draft, setDraft] = useState(() => structuredClone(initialSettings))
  const [saved, setSaved] = useState(() => structuredClone(initialSettings))
  const [savedAt, setSavedAt] = useState('Configuration synced 2 min ago')
  const [confirmation, setConfirmation] = useState('')
  const currentSection = settingsSections.find((section) => section.id === activeSection)
  const hasChanges = JSON.stringify(draft) !== JSON.stringify(saved)
  const updateSetting = (key, value) => setDraft((current) => ({ ...current, [activeSection]: { ...current[activeSection], [key]: value } }))
  const saveChanges = () => {
    setSaved(structuredClone(draft))
    setSavedAt('Saved just now')
    onToast?.('Settings saved successfully.')
  }
  const resetChanges = () => {
    setDraft(structuredClone(saved))
    onToast?.('Unsaved changes reset')
  }
  const confirmDangerAction = () => {
    if (confirmation === 'disable-isolation') {
      setDraft((current) => ({ ...current, isolation: { ...current.isolation, automaticIsolation: false } }))
      onToast?.('Automatic isolation disabled in the unsaved configuration. Save changes to apply.')
    } else if (confirmation === 'reset-configuration') {
      setDraft(structuredClone(initialSettings))
      onToast?.('Default configuration loaded as unsaved changes.')
    } else {
      onToast?.('Temporary data action is a demo only; no data was removed.')
    }
    setConfirmation('')
  }
  const dangerCopy = {
    'reset-configuration': ['Reset configuration?', 'Load the platform defaults into this unsaved draft? No backend configuration will be changed until Save Changes is selected.'],
    'clear-temporary-data': ['Clear temporary data?', 'This demo action does not remove files or backend data. Continue to acknowledge the action?'],
    'disable-isolation': ['Disable automatic isolation?', 'Automatic containment may stop triggering for critical systems. This change remains unsaved until you select Save Changes.'],
  }
  return <main className="settings-main">
    <section className="settings-page-heading"><div><h1>System Settings</h1><p>Configure security monitoring, risk detection, backup, isolation, and recovery policies.</p></div><div className="settings-page-actions"><span className={hasChanges ? 'settings-unsaved-label' : ''}>{hasChanges ? 'Unsaved changes' : savedAt}</span><button className="toolbar-button" disabled={!hasChanges} onClick={resetChanges}><X size={13} />Reset Changes</button><button className="toolbar-button settings-save-button" disabled={!hasChanges} onClick={saveChanges}><Save size={13} />Save Changes</button></div></section>
    <div className="settings-workspace">
      <nav className="panel settings-nav-panel" aria-label="Settings categories"><span className="settings-nav-label">Configuration</span>{settingsSections.map((section) => {
        const Icon = sectionIcons[section.icon]
        return <button type="button" key={section.id} className={`settings-nav-item ${activeSection === section.id ? 'settings-nav-item--active' : ''}`} onClick={() => setActiveSection(section.id)} aria-current={activeSection === section.id ? 'page' : undefined}><Icon size={14} /><span>{section.label}</span>{activeSection === section.id && <span className="settings-nav-marker" />}</button>
      })}<div className="settings-nav-footer"><i className="status-dot status-dot--green" />Policy engine online</div></nav>
      <section className="panel settings-form-panel" aria-labelledby="settings-section-title"><header className="settings-section-heading"><div><span className="eyebrow">System configuration</span><h2 id="settings-section-title">{currentSection.label}</h2><p>{currentSection.description}</p></div><span className="settings-mock-badge"><FileCheck2 size={12} />LOCAL DEMO</span></header>
        <div className={`settings-fields settings-fields--${activeSection}`}>{settingFields[activeSection].map((field) => <SettingField key={field.key} field={field} value={draft[activeSection][field.key]} onChange={(value) => updateSetting(field.key, value)} />)}</div>
        {activeSection === 'risk' && <div className="settings-safety-note"><Shield size={13} /><span>Automatic recovery is disabled. Restore operations require a verified backup, integrity and security checks, and authorized approval.</span></div>}
        {activeSection === 'isolation' && <div className="settings-warning-note"><AlertTriangle size={13} /><span>Changing isolation thresholds may affect automated threat containment.</span></div>}
        {activeSection === 'recovery' && <div className="settings-safety-note"><Shield size={13} /><span>Recovery is controlled: verified backups and integrity checks are required, and release from isolation remains manual.</span></div>}
        <footer className="settings-form-footer"><span><Shield size={12} />Settings are applied to the local demonstration only.</span><span>Changes will be ready for API persistence.</span></footer>
      </section>
    </div>
    <section className="panel settings-danger-zone" aria-labelledby="settings-danger-title"><header><div><span className="eyebrow">Restricted controls</span><h2 id="settings-danger-title">Danger Zone</h2><p>These actions can affect containment or local demo configuration. Each requires confirmation.</p></div><ShieldAlert size={16} /></header><div className="settings-danger-actions"><div><strong>Reset Configuration</strong><span>Load default policies into the local unsaved draft.</span><button className="settings-danger-button" onClick={() => setConfirmation('reset-configuration')}>Reset Configuration</button></div><div><strong>Clear Temporary Data</strong><span>Demo-only control; no destructive operation is performed.</span><button className="settings-danger-button" onClick={() => setConfirmation('clear-temporary-data')}>Clear Temporary Data</button></div><div><strong>Disable Automatic Isolation</strong><span>Changes the local draft only; saving is still required.</span><button className="settings-danger-button" onClick={() => setConfirmation('disable-isolation')}>Disable Automatic Isolation</button></div></div></section>
    <footer className="settings-page-footer"><span><i className="status-dot status-dot--green" />Configuration service operational</span><span>Policy version: 4.2.6 <span className="footer-divider">|</span> Mock settings source</span></footer>
    {confirmation && <div className="confirmation-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setConfirmation('') }}><section className="confirmation-dialog settings-confirmation" role="alertdialog" aria-modal="true" aria-labelledby="settings-confirm-title"><div className="confirmation-icon"><AlertTriangle size={18} /></div><h3 id="settings-confirm-title">{dangerCopy[confirmation][0]}</h3><p>{dangerCopy[confirmation][1]}</p><div><button className="toolbar-button" onClick={() => setConfirmation('')}>Cancel</button><button className="isolate-event-button" onClick={confirmDangerAction}>Confirm</button></div></section></div>}
  </main>
}
