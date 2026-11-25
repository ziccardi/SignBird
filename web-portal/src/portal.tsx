import { ArrowDownToLine, ArrowRight, BadgeCheck, ChevronRight, Feather, KeyRound, LogOut, Plus, RefreshCw, ShieldCheck, Signature } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { Certificate, Key, KeyAlgorithm, KeyCapability, KeyService } from './api'
import { AuthenticatorPanel, CodeField } from './authenticator'
import { DocumentSigningPanel } from './documents'
import { certificateName, date, keyName } from './labels'
import { SigningPanel } from './signing'

const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Operation failed.'

export function Brand() {
  return <div className="brand"><span className="brand-mark"><Feather size={23} aria-hidden="true" /></span><span>SignBird</span></div>
}

function download(name: string, pem: string) {
  const url = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function CertificateEntry({ certificate, onRename, disabled }: { certificate: Certificate; onRename: () => void; disabled: boolean }) {
  const start = new Date(certificate.notBefore).getTime()
  const end = new Date(certificate.notAfter).getTime()
  const label = Date.now() >= end ? 'Expired' : Date.now() < start ? 'Not yet valid' : 'Valid'
  return (
    <li className="certificate">
      <div className="certificate-title"><BadgeCheck size={17} aria-hidden="true" /><strong title={certificate.certificateId}>{certificateName(certificate)}</strong><span className="tag">{label}</span></div>
      <p>Valid from {date(certificate.notBefore)} to {date(certificate.notAfter)}</p>
      <button type="button" className="secondary file-button" disabled={disabled} onClick={onRename}>Edit alias</button>
      {(certificate.certificatePem || certificate.chainPem) && (
        <div className="download-actions">
          {certificate.certificatePem && <button type="button" onClick={() => download(`${certificate.certificateId}.pem`, certificate.certificatePem)}><ArrowDownToLine size={14} /> Certificate</button>}
          {certificate.chainPem && <button type="button" onClick={() => download(`${certificate.certificateId}-chain.pem`, certificate.chainPem)}><ArrowDownToLine size={14} /> Chain</button>}
        </div>
      )}
    </li>
  )
}

export function Dashboard({ service, name, logout, demo = false }: {
  service: KeyService
  name: string
  logout: () => void | Promise<void>
  demo?: boolean
}) {
  const currentSection = () => location.hash.slice(1) || 'keys'
  const [section, setSection] = useState(currentSection)
  useEffect(() => {
    const navigate = () => setSection(currentSection())
    window.addEventListener('hashchange', navigate)
    return () => window.removeEventListener('hashchange', navigate)
  }, [])

  const [keys, setKeys] = useState<Key[]>([])
  const [capabilities, setCapabilities] = useState<KeyCapability[]>([])
  const [algorithm, setAlgorithm] = useState<KeyAlgorithm>()
  const [change, setChange] = useState<
    | { action: 'create'; title: string }
    | { action: 'issue'; title: string; key: Key }
    | { action: 'rename-key'; title: string; key: Key }
    | { action: 'rename-certificate'; title: string; key: Key; certificate: Certificate }
  >()
  const [alias, setAlias] = useState('')
  const aliasInput = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (change) aliasInput.current?.focus()
  }, [change])
  const [code, setCode] = useState('')
  const [detail, setDetail] = useState<Key>()
  const [busy, setBusy] = useState('Loading…')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const requestIds = useRef(new Map<string, string>())
  const running = useRef(false)

  useEffect(() => {
    let active = true
    running.current = true
    async function load() {
      try {
        const [list, profiles] = await Promise.all([service.list(), service.capabilities()])
        if (!active) return
        setKeys(list)
        setCapabilities(profiles)
        const first = list[0]
        if (first) {
          const item = await service.detail(first.keyId)
          if (active) setDetail(item)
        }
      } catch (err) {
        if (active) setError(errorMessage(err))
      } finally {
        if (active) {
          running.current = false
          setBusy('')
        }
      }
    }
    void load()
    return () => { active = false }
  }, [service])

  async function run(label: string, action: () => Promise<void>) {
    if (running.current) return
    running.current = true
    setBusy(label)
    setError('')
    setNotice('')
    try {
      await action()
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      running.current = false
      setBusy('')
    }
  }

  async function mutate<T>(operation: string, action: (id: string) => Promise<T>) {
    const id = requestIds.current.get(operation) ?? crypto.randomUUID()
    requestIds.current.set(operation, id)
    const data = await action(id)
    requestIds.current.delete(operation)
    return data
  }

  function openChange(next: NonNullable<typeof change>) {
    setCode('')
    setError('')
    setNotice('')
    setAlgorithm(capabilities[0]?.algorithm)
    setAlias(next.action === 'rename-key' ? next.key.alias ?? '' :
      next.action === 'rename-certificate' ? next.certificate.alias ?? '' : '')
    setChange(next)
  }

  function createKey(otp: string, selectedAlgorithm: KeyAlgorithm) {
    void run('Generating key…', async () => {
      const created = await mutate(`create:${selectedAlgorithm}`, id => service.create(id, otp, selectedAlgorithm, alias))
      setKeys(list => [created, ...list.filter(item => item.keyId !== created.keyId)])
      setDetail({ ...created, certificates: [] })
      setChange(undefined)
      setNotice('Key generated.')
    })
  }

  function refresh() {
    void run('Refreshing…', async () => {
      const [list, profiles] = await Promise.all([service.list(), service.capabilities()])
      setKeys(list)
      setCapabilities(profiles)
      const id = list.find(item => item.keyId === detail?.keyId)?.keyId ?? list[0]?.keyId
      setDetail(id ? await service.detail(id) : undefined)
    })
  }

  function issueCertificate(key: Key, otp: string) {
    void run('Issuing certificate…', async () => {
      const certificate = await mutate(`issue:${key.keyId}`, id => service.issue(key.keyId, id, otp, alias))
      const history = (key.certificates ?? []).filter(item => item.certificateId !== certificate.certificateId)
      setDetail({ ...key, certificates: [certificate, ...history] })
      setChange(undefined)
      setNotice('Certificate issued.')
    })
  }

  function rename(next: Extract<NonNullable<typeof change>, { action: 'rename-key' | 'rename-certificate' }>, otp: string) {
    void run('Updating alias…', async () => {
      const value = alias.trim()
      if (next.action === 'rename-certificate') {
        const id = next.certificate.certificateId
        await service.renameCertificate(next.key.keyId, id, value, otp)
        setDetail({ ...next.key, certificates: next.key.certificates?.map(cert =>
          cert.certificateId === id ? { ...cert, alias: value } : cert) })
      } else {
        await service.renameKey(next.key.keyId, value, otp)
        setKeys(items => items.map(key => key.keyId === next.key.keyId ? { ...key, alias: value } : key))
        setDetail({ ...next.key, alias: value })
      }
      setChange(undefined)
      setNotice('Alias updated.')
    })
  }

  const history = detail?.certificates ?? []
  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="Main navigation">
          <a className={section === 'keys' ? 'nav-current' : 'nav-link'} href="#keys" aria-current={section === 'keys' ? 'page' : undefined}><KeyRound size={19} /> Keys and certificates <ChevronRight size={16} /></a>
          {service.activation && <a className={section === 'signatures' ? 'nav-current' : 'nav-link'} href="#signatures" aria-current={section === 'signatures' ? 'page' : undefined}><Signature size={19} /> Sign digest <ChevronRight size={16} /></a>}
          {service.documents && <a className={section === 'documents' ? 'nav-current' : 'nav-link'} href="#documents" aria-current={section === 'documents' ? 'page' : undefined}><Signature size={19} /> P7M signing <ChevronRight size={16} /></a>}
          {service.activation && <a className={section === 'authenticator' ? 'nav-current' : 'nav-link'} href="#authenticator" aria-current={section === 'authenticator' ? 'page' : undefined}><ShieldCheck size={19} /> Authenticator <ChevronRight size={16} /></a>}
        </nav>
        <div className="profile">
          <div className="avatar" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</div>
          <span title={name}>{name}</span>
          <button className="icon-button" aria-label={demo ? 'Exit demo' : 'Sign out'} title={demo ? 'Exit demo' : 'Sign out'} disabled={!!busy} onClick={() => void run('Signing out…', async () => { await logout() })}><LogOut size={18} /></button>
        </div>
      </aside>
      <main className="workspace" id="keys">
        <header className="topbar">
          <span>Signing Portal</span>
          <span className="environment"><span />{demo ? 'Local demo' : 'Test environment'}</span>
        </header>
        <div className="content">
          {section === 'documents' && service.documents ? <DocumentSigningPanel documents={service.documents} keys={keys} loadKey={service.detail} /> : section === 'authenticator' && service.activation ? <AuthenticatorPanel activation={service.activation} account={name} /> : section === 'signatures' && service.activation ? <SigningPanel activation={service.activation} keys={keys} capabilities={capabilities} loadKey={service.detail} /> : <>
          <section className="intro">
            <div>
              <h1>Keys and certificates</h1>
              <p>Generate test keys and manage their certificates.</p>
            </div>
            <button className="primary" disabled={!!busy || !capabilities.length} onClick={() => openChange({ action: 'create', title: 'Generate key' })}><Plus size={19} /> Generate key</button>
          </section>
          {demo && <p className="demo-banner"><ShieldCheck size={17} /> Demo changes are simulated and reset when you reload.</p>}
          {busy && <p className="feedback" role="status">{busy}</p>}
          {notice && <p className="feedback success" role="status">{notice}</p>}
          {error && <p className="feedback error" role="alert">{error}</p>}
          {change && <section className="panel signing-panel change-panel">
            <h2>{change.title}</h2>
            {'key' in change && <p>Key <strong>{keyName(change.key)}</strong></p>}
            {change.action === 'rename-certificate' && <p>Certificate <strong>{certificateName(change.certificate)}</strong></p>}
            <form className="signing-form" onSubmit={event => {
              event.preventDefault()
              if (change.action === 'create') {
                if (algorithm) createKey(code, algorithm)
              } else if (change.action === 'issue') issueCertificate(change.key, code)
              else rename(change, code)
              setCode('')
            }}>
              {change.action === 'create' && <label>Key algorithm
                <select value={algorithm} required onChange={event => {
                  setAlgorithm(capabilities.find(profile => profile.algorithm === event.target.value)?.algorithm)
                }}>
                  {capabilities.map(({ algorithm: option }) => <option key={option}>{option}</option>)}
                </select>
              </label>}
              <label>Alias (optional)
                <input ref={aliasInput} value={alias} onChange={event => setAlias(event.target.value)}  />
              </label>
              {service.activation && <>
                <CodeField id="change-code" code={code} setCode={setCode} />
                <p>For first-time use, <a href="#authenticator" onClick={() => { setChange(undefined); setCode('') }}>set up your authenticator</a>.</p>
              </>}
              <div className="change-actions">
                <button className="primary" disabled={!!busy}>Confirm operation</button>
                <button type="button" className="secondary" disabled={!!busy} onClick={() => { setChange(undefined); setCode('') }}>Cancel</button>
              </div>
            </form>
          </section>}
          <div className="panels">
            <section className="panel inventory" aria-labelledby="inventory-title">
              <header className="panel-heading">
                <div><h2 id="inventory-title">My keys <span className="count">{keys.length}</span></h2></div>
                <button className="icon-button refresh" aria-label="Refresh list" title="Refresh list" disabled={!!busy} onClick={refresh}><RefreshCw size={17} /></button>
              </header>
              {keys.length ? (
                <div className="table-scroll">
                  <table>
                    <thead><tr><th>Key</th><th>Created on</th><th>Status</th></tr></thead>
                    <tbody>{keys.map(key => (
                      <tr key={key.keyId} className={detail?.keyId === key.keyId ? 'selected' : ''}>
                        <td><button className="key-link" title={key.keyId} disabled={!!busy} aria-pressed={detail?.keyId === key.keyId} onClick={() => void run('Loading key details…', async () => { setDetail(await service.detail(key.keyId)) })}><span className="key-icon"><KeyRound size={16} /></span><span><strong>{keyName(key)}</strong><small>{key.algorithm}</small></span></button></td>
                        <td>{date(key.createdAt)}</td>
                        <td><span className="status"><span />Active</span></td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              ) : <p className="empty">{busy ? 'Loading keys…' : 'No keys to display.'}</p>}
            </section>
            <section className="panel detail" aria-labelledby="detail-title">
              <header className="panel-heading"><h2 id="detail-title">Key details</h2><KeyRound size={18} aria-hidden="true" /></header>
              {detail ? (
                <div className="detail-body">
                  <dl>
                    <div><dt>Alias</dt><dd>{detail.alias || '—'}</dd></div>
                    <div><dt>Identifier</dt><dd><code>{detail.keyId}</code></dd></div>
                    <div><dt>Algorithm</dt><dd>{detail.algorithm}</dd></div>
                    <div><dt>Keystore</dt><dd>{detail.keystoreId}</dd></div>
                  </dl>
                  {detail.publicKey && <button className="secondary file-button" onClick={() => download(`${detail.keyId}-public.pem`, detail.publicKey)}><ArrowDownToLine size={16} /> Public key</button>}
                  <button type="button" className="secondary file-button" disabled={!!busy} onClick={() =>
                    openChange({ action: 'rename-key', title: 'Edit key alias', key: detail })}>Edit key alias</button>
                  <div className="history">
                    <h3>Certificates <span className="count">{history.length}</span></h3>
                    {history.length ? <ul>{history.map(certificate => <CertificateEntry key={certificate.certificateId} certificate={certificate}
                      disabled={!!busy} onRename={() => openChange({
                        action: 'rename-certificate', title: 'Edit certificate alias', key: detail, certificate,
                      })} />)}</ul> : <p>No certificates have been issued for this key.</p>}
                    <button className="secondary issue" disabled={!!busy} onClick={() => openChange({ action: 'issue', title: history.length ? 'Renew certificate' : 'Issue certificate', key: detail })}>{history.length ? 'Renew certificate' : 'Issue certificate'} <ArrowRight size={16} /></button>
                  </div>
                </div>
              ) : <p className="empty">Select a key to view its details.</p>}
            </section>
          </div>
          </>}
        </div>
      </main>
    </div>
  )
}
