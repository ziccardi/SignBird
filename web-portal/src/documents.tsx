import { ArrowDownToLine, RefreshCw } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { certificateOption, keyOption } from './labels'
import { CodeField } from './authenticator'
import type { Certificate, DocumentService, Key, P7mJob } from './api'

const statuses: Record<P7mJob['status'], string> = {
  QUEUED: 'In coda',
  AWAITING_APPROVAL: 'In attesa di conferma',
  SIGNING_QUEUED: 'Firma in coda',
  READY: 'Pronto',
  FAILED: 'Errore di elaborazione',
  EXPIRED: 'Scaduto',
}

export function DocumentSigningPanel({ documents, keys, loadKey }: {
  documents: DocumentService
  keys: Key[]
  loadKey: (keyId: string) => Promise<Key>
}) {
  const [jobs, setJobs] = useState<P7mJob[]>([])
  const [selected, setSelected] = useState('')
  const [key, setKey] = useState('')
  const [credential, setCredential] = useState('')
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [file, setFile] = useState<File>()
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)
  const job = jobs.find(item => item.jobId === selected)

  useEffect(() => {
    let active = true
    let timer: number | undefined
    async function refresh() {
      try {
        const list = await documents.list()
        if (active) setJobs(list)
      } catch (error) {
        if (active) setProblem(error instanceof Error ? error.message : 'Aggiornamento non riuscito.')
      } finally {
        if (active) timer = window.setTimeout(refresh, 3000)
      }
    }
    if (!busy) void refresh()
    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [documents, busy])

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setProblem('')
    try {
      await action()
    } catch (error) {
      setProblem(error instanceof Error ? error.message : 'Operazione non riuscita.')
    } finally {
      setBusy(false)
    }
  }

  function show(item: P7mJob) {
    setJobs(previous => [item, ...previous.filter(existing => existing.jobId !== item.jobId)])
    setSelected(item.jobId)
  }

  return <section>
    <header className="intro">
      <div><h1>Firma P7M</h1><p>Carica un file, approva la firma e scarica il risultato quando è pronto.</p></div>
      <button className="secondary" disabled={busy} onClick={() => void run(async () => setJobs(await documents.list()))}><RefreshCw size={15} /> Aggiorna</button>
    </header>
    {problem && <p role="alert" className="feedback error">{problem}</p>}
    {busy && <p role="status" className="feedback">Operazione in corso…</p>}
    <div className="panels">
      <div className="signing-column">
        <section className="panel signing-panel">
          <h2>Carica un file</h2>
          <form className="signing-form" onSubmit={event => {
            event.preventDefault()
            if (!file || !credential) return
            void run(async () => {
              if (file.size > 10 * 1024 * 1024 || file.size === 0) throw new Error('Carica un file non vuoto di massimo 10 MB.')
              show(await documents.upload(key, credential, file))
              setFile(undefined)
              if (fileInput.current) fileInput.current.value = ''
            })
          }}>
            <label>File da firmare (max 10 MB)
              <input ref={fileInput} type="file" required onChange={event => setFile(event.target.files?.[0])} />
            </label>
            <label>Chiave
              <select value={key} required disabled={busy} onChange={event => {
                const id = event.target.value
                setKey(id)
                setCredential('')
                setCertificates([])
                if (id) void run(async () => {
                  const now = Date.now()
                  setCertificates(((await loadKey(id)).certificates ?? []).filter(cert =>
                    Date.parse(cert.notBefore) <= now && now < Date.parse(cert.notAfter)))
                })
              }}>
                <option value="">Seleziona una chiave</option>
                {keys.map(item => <option key={item.keyId} value={item.keyId}>{keyOption(item, keys)}</option>)}
              </select>
            </label>
            <label>Credenziale
              <select value={credential} required disabled={busy || !certificates.length} onChange={event => setCredential(event.target.value)}>
                <option value="">Seleziona un certificato</option>
                {certificates.map(cert => <option key={cert.credentialId} value={cert.credentialId}>{certificateOption(cert)}</option>)}
              </select>
            </label>
            <button className="primary" disabled={busy || !credential || !file}>Accoda file</button>
          </form>
        </section>
        <section className="panel signing-panel">
          <h2>Operazioni</h2>
          {jobs.length ? <ul className="signature-list">{jobs.map(item => <li key={item.jobId}>
            <button className="secondary" aria-pressed={selected === item.jobId} disabled={busy}
              onClick={() => { setSelected(item.jobId); setCode('') }}><span className="break-value">{item.filename}</span><small>{statuses[item.status]}</small></button>
          </li>)}</ul> : <p>Nessuna operazione.</p>}
        </section>
      </div>
      <section className="panel signing-panel">
        <h2>Dettaglio operazione</h2>
        {job ? <>
          <dl className="signature-details">
            <div><dt>File</dt><dd>{job.filename}</dd></div>
            <div><dt>Chiave</dt><dd><code>{job.keyId}</code></dd></div>
            <div><dt>Credenziale</dt><dd><code>{job.credentialId}</code></dd></div>
            <div><dt>Algoritmo</dt><dd>{job.signatureScheme} · SHA-256</dd></div>
            <div><dt>Stato</dt><dd role="status">{statuses[job.status]}</dd></div>
            <div><dt>Scadenza</dt><dd>{new Date(job.expiresAt).toLocaleString('it-IT')}</dd></div>
          </dl>
          {job.status === 'AWAITING_APPROVAL' && <form className="signing-form" onSubmit={event => {
            event.preventDefault()
            const submitted = code
            setCode('')
            void run(async () => show(await documents.approve(job.jobId, submitted)))
          }}>
            <CodeField id="document-code" code={code} setCode={setCode} />
            <button className="primary" disabled={busy}>Approva firma</button>
            <p>Al primo utilizzo, <a href="#authenticator">configura l’autenticatore</a>.</p>
          </form>}
          {job.status === 'READY' && <button className="primary" disabled={busy} onClick={() => void run(async () => {
            const url = URL.createObjectURL(await documents.download(job.jobId))
            const link = document.createElement('a')
            link.href = url
            link.download = job.filename + '.p7m'
            link.click()
            setTimeout(() => URL.revokeObjectURL(url), 1000)
          })}><ArrowDownToLine size={16} /> Scarica P7M</button>}
        </> : <p>Seleziona un’operazione.</p>}
      </section>
    </div>
  </section>
}
