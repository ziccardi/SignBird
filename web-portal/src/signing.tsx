import { RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { certificateOption, keyOption } from './labels'
import { CodeField } from './authenticator'
import type { ActivationService, Certificate, Key, KeyCapability, DigestInput, SignatureRequest } from './api'

function digestToBase64(hex: string, digestBytes: number) {
  if (hex.length !== digestBytes * 2 || !/^[a-f0-9]+$/i.test(hex)) {
    throw new Error(`Enter a ${digestBytes * 2}-character hexadecimal digest.`)
  }
  const pairs = hex.match(/../g)!
  return btoa(String.fromCharCode(...pairs.map(pair => Number.parseInt(pair, 16))))
}

function digestToHex(base64: string) {
  return Array.from(atob(base64), byte => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

const statuses = { PENDING: 'Pending', SIGNED: 'Signed', EXPIRED: 'Expired' }

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
      setError(err instanceof Error ? err.message : 'Operation failed.')
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
        <div><h1>Sign digest</h1><p>Sign a digest using a code from your authenticator app.</p></div>
        <button className="secondary" disabled={busy} onClick={() => void run(refresh)}><RefreshCw size={15} /> Refresh requests</button>
      </header>
      {error && <p className="feedback error" role="alert">{error}</p>}
      {busy && <p className="feedback" role="status">Working…</p>}
      {enabled === false && <p className="feedback">Before signing, <a href="#authenticator">set up your authenticator</a>.</p>}
      {enabled && <div className="panels">
        <div className="signing-column">
          <section className="panel signing-panel">
            <h2>New request</h2>
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
              <label htmlFor="signing-key">Key
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
                  <option value="">Select a key</option>
                  {keys.map(key => <option key={key.keyId} value={key.keyId}>{keyOption(key, keys)}</option>)}
                </select>
              </label>
              <label htmlFor="signing-credential">Credential
                <select id="signing-credential" value={credential} onChange={event => setCredential(event.target.value)} required disabled={busy || !certificates.length}>
                  <option value="">{certificates.length ? 'Select a certificate' : 'No certificates available'}</option>
                  {certificates.map(cert => <option key={cert.credentialId} value={cert.credentialId}>{certificateOption(cert)}</option>)}
                </select>
              </label>
              <label>Hash algorithm
                <select value={hash?.algorithm ?? ''} disabled={!profile || busy} onChange={event => {
                  setHashAlgorithm(profile?.hashAlgorithms.find(item => item.algorithm === event.target.value)?.algorithm)
                }}>
                  {!profile && <option value="">Select a key first</option>}
                  {profile?.hashAlgorithms.map(item => <option key={item.algorithm}>{item.algorithm}</option>)}
                </select>
              </label>
              <label>Hexadecimal digest{hash ? ` (${hash.digestBytes * 2} characters)` : ''}
                <input value={digest} onChange={event => setDigest(event.target.value)} required disabled={!hash}
                  pattern={hash ? `[a-fA-F0-9]{${hash.digestBytes * 2}}` : undefined} spellCheck={false} />
              </label>
              <CodeField id="signing-code" code={code} setCode={setCode} />
              <button className="primary" disabled={busy || !credential || !hash}>Sign digest</button>
            </form>
          </section>
          <section className="panel signing-panel">
            <h2>Signing requests</h2>
            {requests.length ? <ul className="signature-list">{requests.map(item => <li key={item.requestId}>
              <button className="secondary" aria-pressed={selected === item.requestId} disabled={busy} onClick={() => {
                setSelected(item.requestId)
                setApprovalCode('')
                setError('')
              }}><code>{item.requestId}</code><span>{statuses[item.status]}</span></button>
            </li>)}</ul> : <p>No requests.</p>}
          </section>
        </div>
        <section className="panel signing-panel">
          <h2>Request details</h2>
          {!request ? <p>Select a request.</p> : <>
            <dl className="signature-details">
              <div><dt>Key</dt><dd><code>{request.keyId}</code></dd></div>
              <div><dt>Credential</dt><dd><code>{request.credentialId}</code></dd></div>
              <div><dt>Digest</dt><dd><code>{digestToHex(request.digest)}</code></dd></div>
              <div><dt>Scheme</dt><dd>{request.signatureScheme} · {request.hashAlgorithm}</dd></div>
              {request.status !== 'SIGNED' && <div><dt>Expires</dt><dd>{new Date(request.expiresAt).toLocaleString('en-GB')}</dd></div>}
              <div><dt>Status</dt><dd>{statuses[request.status]}</dd></div>
            </dl>
            {request.status === 'PENDING' && <form className="signing-form" onSubmit={event => {
              event.preventDefault()
              void run(async () => show(await activation.approve(request.requestId, approvalCode)))
            }}>
              <p>Use a fresh code after setup or another approval.</p>
              <CodeField id="approval-code" code={approvalCode} setCode={setApprovalCode} />
              <button className="primary" disabled={busy}>Approve and sign</button>
            </form>}
            {request.signature && <label className="signature-result">Base64 signature<textarea value={request.signature} readOnly rows={5} /></label>}
          </>}
        </section>
      </div>}
    </section>
  )
}
