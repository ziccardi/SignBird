import { toDataURL } from 'qrcode'
import { useEffect, useState } from 'react'
import type { ActivationService } from './api'

export function CodeField({ id, code, setCode }: { id: string; code: string; setCode: (value: string) => void }) {
  return <label htmlFor={id}>Six-digit code
    <input id={id} value={code} onChange={event => setCode(event.target.value)} inputMode="numeric"
      autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required />
  </label>
}

function SetupQrCode({ secret, account }: { secret: string; account: string }) {
  const [image, setImage] = useState('')
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let active = true
    const issuer = 'SignBird'
    const label = `${issuer}:${encodeURIComponent(account.replaceAll(':', ' '))}`
    const parameters = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' })

    void toDataURL(`otpauth://totp/${label}?${parameters}`, { width: 220, margin: 4 }).then(
      url => { if (active) setImage(url) },
      () => { if (active) setFailed(true) },
    )
    return () => { active = false }
  }, [secret, account])

  if (failed) return <p role="status">The QR code is unavailable. Use the setup key below.</p>
  if (!image) return <p role="status">Generating QR code…</p>
  return <img className="authenticator-qr" src={image} width={220} height={220}
    alt="QR code to scan with your authenticator app" />
}

export function AuthenticatorPanel({ activation, account }: { activation: ActivationService; account: string }) {
  const [enabled, setEnabled] = useState<boolean>()
  const [secret, setSecret] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    try {
      await action()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Operation failed.')
    } finally {
      setBusy(false)
    }
  }

  function loadStatus() {
    return run(async () => setEnabled((await activation.status()).enabled))
  }

  useEffect(() => { void loadStatus() }, [activation])

  return <section>
    <header className="intro">
      <div><h1>Authenticator</h1><p>Use a one-time code for key, certificate, and signing operations.</p></div>
    </header>
    <div className="panel signing-panel">
      <h2>Setup</h2>
      {error && <p className="feedback error" role="alert">{error}</p>}
      {busy && <p role="status">Working…</p>}
      {enabled === true && <p role="status">Authenticator enabled.</p>}
      {enabled === undefined && !busy && <button className="secondary" onClick={loadStatus}>Try again</button>}
      {enabled === false && (secret ? <form className="signing-form" onSubmit={event => {
        event.preventDefault()
        void run(async () => {
          const status = await activation.confirm(code)
          setEnabled(status.enabled)
          setSecret('')
          setCode('')
        })
      }}>
        <p>In Google Authenticator, tap <strong>+</strong> and scan the QR code.</p>
        <SetupQrCode secret={secret} account={account} />
        <p>To enter the key manually, select the time-based option.</p>
        <p><strong>Account name</strong> SignBird ({account})</p>
        <p><strong>Setup key</strong> <code className="break-value">{secret}</code></p>
        <CodeField id="enrollment-code" code={code} setCode={setCode} />
        <button className="primary" disabled={busy}>Confirm setup</button>
      </form> : <button className="primary" disabled={busy} onClick={() => void run(async () => setSecret((await activation.enroll()).secret))}>Set up authenticator</button>)}
    </div>
  </section>
}
