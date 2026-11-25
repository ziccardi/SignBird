import { RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { certificateOption, keyOption } from './labels'
import { CodeField } from './authenticator'
import type { ActivationService, Certificate, Key, KeyCapability, DigestInput, SignatureRequest } from './api'

function digestToBase64(hex: string, digestBytes: number) {
  if (hex.length !== digestBytes * 2 || !/^[a-f0-9]+$/i.test(hex)) {
    throw new Error(`Inserisci un digest di ${digestBytes * 2} caratteri esadecimali.`)
  }
  const pairs = hex.match(/../g)!
  return btoa(String.fromCharCode(...pairs.map(pair => Number.parseInt(pair, 16))))
}

function digestToHex(base64: string) {
  return Array.from(atob(base64), byte => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

const statuses = { PENDING: 'In attesa', SIGNED: 'Firmata', EXPIRED: 'Scaduta' }

export function SigningPanel({ activation, keys, capabilities, loadKey }: {
  activation: ActivationService
  keys: Key[]
  capabilities: KeyCapability[]
  loadKey: (keyId: string) => Promise<Key>
}) {
  const [enabled, setEnabled] = useState<boolean>()
  const [code, setCode] = useState('')
  const [approvalCode, setApprovalCode] = useState('')
  const [keyId, setKeyId] = useState('')
  const [hashAlgorithm, setHashAlgorithm] = useState<DigestInput['hashAlgorithm']>()
  const profile = capabilities.find(item => item.algorithm === keys.find(key => key.keyId === keyId)?.algorithm)
  const hash = profile?.hashAlgorithms.find(item => item.algorithm === hashAlgorithm)
  const [credential, setCredential] = useState('')
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [digest, setDigest] = useState('')
  const [requests, setRequests] = useState<SignatureRequest[]>([])
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const request = requests.find(item => item.requestId === selected)

  const run = useCallback(async (action: () => Promise<void>) => {
    setBusy(true)
    setError('')
    try {
      await action()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Operazione non riuscita.')
    } finally {
      setBusy(false)
    }
  }, [])

  const refresh = useCallback(async () => {
    const status = await activation.status()
    setEnabled(status.enabled)
    if (status.enabled) setRequests(await activation.list())
  }, [activation])

  useEffect(() => { void run(refresh) }, [refresh, run])

  function show(item: SignatureRequest) {
    setRequests(items => [item, ...items.filter(existing => existing.requestId !== item.requestId)])
    setSelected(item.requestId)
    setCode('')
    setApprovalCode('')
  }

  return (
    <section className="signing">
      <header className="intro">
        <div><h1>Firma digest</h1><p>Firma subito un digest con un codice dell’app di autenticazione.</p></div>
        <button className="secondary" disabled={busy} onClick={() => void run(refresh)}><RefreshCw size={15} /> Aggiorna richieste</button>
      </header>
      {error && <p className="feedback error" role="alert">{error}</p>}
      {busy && <p className="feedback" role="status">Operazione in corso…</p>}
      {enabled === false && <p className="feedback">Prima di firmare, <a href="#authenticator">configura l’autenticatore</a>.</p>}
      {enabled && <div className="panels">
        <div className="signing-column">
          <section className="panel signing-panel">
            <h2>Nuova richiesta</h2>
            <form className="signing-form" onSubmit={event => {
              event.preventDefault()
              if (!profile || !hash) return
              void run(async () => show(await activation.create({
                credentialId: credential,
                digest: digestToBase64(digest.trim(), hash.digestBytes),
                hashAlgorithm: hash.algorithm,
                signatureScheme: profile.signatureScheme,
              }, code)))
              setCode('')
            }}>
              <label htmlFor="signing-key">Chiave
                <select id="signing-key" defaultValue="" disabled={busy} onChange={event => {
                  const id = event.target.value
                  setKeyId(id)
                  const selected = keys.find(key => key.keyId === id)
                  setHashAlgorithm(capabilities.find(item => item.algorithm === selected?.algorithm)?.hashAlgorithms[0]?.algorithm)
                  setCredential('')
                  setCertificates([])
                  if (!id) return
                  void run(async () => {
                    const now = Date.now()
                    const detail = await loadKey(id)
                    setCertificates((detail.certificates ?? []).filter(item =>
                      Date.parse(item.notBefore) <= now && now < Date.parse(item.notAfter)))
                  })
                }}>
                  <option value="">Seleziona una chiave</option>
                  {keys.map(key => <option key={key.keyId} value={key.keyId}>{keyOption(key, keys)}</option>)}
                </select>
              </label>
              <label htmlFor="signing-credential">Credenziale
                <select id="signing-credential" value={credential} onChange={event => setCredential(event.target.value)} required disabled={busy || !certificates.length}>
                  <option value="">{certificates.length ? 'Seleziona un certificato' : 'Nessun certificato disponibile'}</option>
                  {certificates.map(cert => <option key={cert.credentialId} value={cert.credentialId}>{certificateOption(cert)}</option>)}
                </select>
              </label>
              <label>Algoritmo di hash
                <select value={hash?.algorithm ?? ''} disabled={!profile || busy} onChange={event => {
                  setHashAlgorithm(profile?.hashAlgorithms.find(item => item.algorithm === event.target.value)?.algorithm)
                }}>
                  {!profile && <option value="">Seleziona prima una chiave</option>}
                  {profile?.hashAlgorithms.map(item => <option key={item.algorithm}>{item.algorithm}</option>)}
                </select>
              </label>
              <label>Digest esadecimale{hash ? ` (${hash.digestBytes * 2} caratteri)` : ''}
                <input value={digest} onChange={event => setDigest(event.target.value)} required disabled={!hash}
                  pattern={hash ? `[a-fA-F0-9]{${hash.digestBytes * 2}}` : undefined} spellCheck={false} />
              </label>
              <CodeField id="signing-code" code={code} setCode={setCode} />
              <button className="primary" disabled={busy || !credential || !hash}>Firma digest</button>
            </form>
          </section>
          <section className="panel signing-panel">
            <h2>Richieste di firma</h2>
            {requests.length ? <ul className="signature-list">{requests.map(item => <li key={item.requestId}>
              <button className="secondary" aria-pressed={selected === item.requestId} disabled={busy} onClick={() => {
                setSelected(item.requestId)
                setApprovalCode('')
                setError('')
              }}><code>{item.requestId}</code><span>{statuses[item.status]}</span></button>
            </li>)}</ul> : <p>Nessuna richiesta.</p>}
          </section>
        </div>
        <section className="panel signing-panel">
          <h2>Dettaglio richiesta</h2>
          {!request ? <p>Seleziona una richiesta.</p> : <>
            <dl className="signature-details">
              <div><dt>Chiave</dt><dd><code>{request.keyId}</code></dd></div>
              <div><dt>Credenziale</dt><dd><code>{request.credentialId}</code></dd></div>
              <div><dt>Digest</dt><dd><code>{digestToHex(request.digest)}</code></dd></div>
              <div><dt>Schema</dt><dd>{request.signatureScheme} · {request.hashAlgorithm}</dd></div>
              {request.status !== 'SIGNED' && <div><dt>Scadenza</dt><dd>{new Date(request.expiresAt).toLocaleString('it-IT')}</dd></div>}
              <div><dt>Stato</dt><dd>{statuses[request.status]}</dd></div>
            </dl>
            {request.status === 'PENDING' && <form className="signing-form" onSubmit={event => {
              event.preventDefault()
              void run(async () => show(await activation.approve(request.requestId, approvalCode)))
            }}>
              <p>Usa un codice nuovo dopo la configurazione o un’altra approvazione.</p>
              <CodeField id="approval-code" code={approvalCode} setCode={setApprovalCode} />
              <button className="primary" disabled={busy}>Approva e firma</button>
            </form>}
            {request.signature && <label className="signature-result">Firma Base64<textarea value={request.signature} readOnly rows={5} /></label>}
          </>}
        </section>
      </div>}
    </section>
  )
}
