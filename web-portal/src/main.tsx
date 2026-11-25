import Keycloak from 'keycloak-js'
import { createRoot } from 'react-dom/client'
import { LogIn } from 'lucide-react'
import { connectApi } from './api'
import { Brand, Dashboard } from './portal'
import './style.css'

const root = createRoot(document.getElementById('root')!)
const redirectUri = new URL(import.meta.env.BASE_URL, window.location.origin).href

function welcome(message?: string, login?: () => void) {
  root.render(
    <main className="welcome">
      <Brand />
      <section className="welcome-card">
        <h1>Portale di firma</h1>
        <p>Accedi per gestire le tue chiavi e i tuoi certificati.</p>
        {message && <p role="status">{message}</p>}
        {login && <button className="primary" onClick={login}><LogIn size={17} /> Accedi con Keycloak</button>}
        {import.meta.env.DEV && <a className="secondary" href="?demo=1">Apri la demo locale</a>}
      </section>
    </main>,
  )
}

async function start() {
  if (import.meta.env.DEV && new URLSearchParams(location.search).get('demo') === '1') {
    const { demoApi } = await import('./demo')
    root.render(<Dashboard service={demoApi()} name="Utente demo" demo logout={() => location.assign(redirectUri)} />)
    return
  }
  const { VITE_KEYCLOAK_URL: url, VITE_KEYCLOAK_REALM: realm, VITE_KEYCLOAK_CLIENT_ID: clientId } = import.meta.env
  if (!url || !realm || !clientId) {
    welcome('Configura Keycloak per collegare il portale ai servizi SignBird.')
    return
  }

  const auth = new Keycloak({ url, realm, clientId })
  welcome('Connessione a Keycloak…')
  try {
    const authenticated = await auth.init({ flow: 'standard', pkceMethod: 'S256', checkLoginIframe: false, redirectUri })
    if (!authenticated) {
      const login = () => {
        void auth.login({ redirectUri }).catch(() => welcome('Accesso non riuscito. Riprova.', login))
      }
      welcome(undefined, login)
      return
    }
    const service = connectApi(async () => {
      try {
        await auth.updateToken(30)
        if (auth.token) return auth.token
      } catch {
        auth.clearToken()
      }
      throw new Error('Sessione scaduta. Ricarica la pagina e accedi di nuovo.')
    })
    const name = auth.idTokenParsed?.preferred_username ?? auth.idTokenParsed?.name ?? 'Utente'
    root.render(<Dashboard service={service} name={name} logout={() => auth.logout({ redirectUri })} />)
  } catch {
    welcome('Connessione a Keycloak non riuscita. Verifica la configurazione e ricarica la pagina.')
  }
}

void start()
