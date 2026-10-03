import { useState } from 'react'
import { Activity, Bell, ChartNoAxesCombined, Database, FileCheck2, LockKeyhole, RotateCcw, Save, Settings as SettingsIcon, Shield, X } from 'lucide-react'
import { initialSettings, settingFields, settingsSections } from '../data/settingsData.js'
import './SettingsPage.css'

const sectionIcons = { settings: SettingsIcon, activity: Activity, chart: ChartNoAxesCombined, database: Database, lock: LockKeyhole, rotate: RotateCcw, bell: Bell }

function SettingField({ field, value, onChange }) {
  if (field.type === 'toggle') return <div className="setting-row"><div className="setting-copy"><strong>{field.label}</strong><span>{field.description}</span></div><div className="setting-control"><span className={`setting-value-badge ${value ? 'setting-value-badge--enabled' : 'setting-value-badge--disabled'}`}>{value ? 'Enabled' : 'Disabled'}</span><button type="button" role="switch" aria-checked={value} aria-label={field.label} className={`setting-switch ${value ? 'setting-switch--on' : ''}`} onClick={() => onChange(!value)}><i /></button></div></div>
  if (field.type === 'status') return <div className="setting-row"><div className="setting-copy"><strong>{field.label}</strong><span>{field.description}</span></div><div className="setting-control"><span className="settings-connection"><i className="status-dot status-dot--green" />{value}</span></div></div>
  if (field.type === 'select') return <label className="setting-row setting-row--input"><span className="setting-copy"><strong>{field.label}</strong></span><select value={value} onChange={(event) => onChange(event.target.value)}>{field.options.map((option) => <option key={option} value={option}>{option}</option>)}</select></label>
  return <label className="setting-row setting-row--input"><span className="setting-copy"><strong>{field.label}</strong></span><span className="setting-number-wrap"><input type={field.type} min={field.type === 'number' ? 1 : undefined} max={field.type === 'number' ? 100 : undefined} value={value} onChange={(event) => onChange(event.target.value)} /><small>{field.suffix}</small></span></label>
}

export default function SettingsPage({ onToast }) {
  const [activeSection, setActiveSection] = useState('general')
  const [draft, setDraft] = useState(() => structuredClone(initialSettings))
  const [saved, setSaved] = useState(() => structuredClone(initialSettings))
  const [savedAt, setSavedAt] = useState('Configuration synced 2 min ago')
  const currentSection = settingsSections.find((section) => section.id === activeSection)
  const hasChanges = JSON.stringify(draft) !== JSON.stringify(saved)
  const updateSetting = (key, value) => setDraft((current) => ({ ...current, [activeSection]: { ...current[activeSection], [key]: value } }))
  const saveChanges = () => {
    setSaved(structuredClone(draft))
    setSavedAt('Saved just now')
    onToast?.('System settings saved')
  }
  const resetChanges = () => {
    setDraft(structuredClone(saved))
    onToast?.('Unsaved changes reset')
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
        <footer className="settings-form-footer"><span><Shield size={12} />Settings are applied to the local demonstration only.</span><span>Changes will be ready for API persistence.</span></footer>
      </section>
    </div>
    <footer className="settings-page-footer"><span><i className="status-dot status-dot--green" />Configuration service operational</span><span>Policy version: 4.2.6 <span className="footer-divider">|</span> Mock settings source</span></footer>
  </main>
}
