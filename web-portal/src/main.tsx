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
        <h1>Signing Portal</h1>
        <p>Sign in to manage your keys and certificates.</p>
        {message && <p role="status">{message}</p>}
        {login && <button className="primary" onClick={login}><LogIn size={17} /> Sign in with Keycloak</button>}
        {import.meta.env.DEV && <a className="secondary" href="?demo=1">Open local demo</a>}
      </section>
    </main>,
  )
}

async function start() {
  if (import.meta.env.DEV && new URLSearchParams(location.search).get('demo') === '1') {
    const { demoApi } = await import('./demo')
    root.render(<Dashboard service={demoApi()} name="Demo user" demo logout={() => location.assign(redirectUri)} />)
    return
  }
  const { VITE_KEYCLOAK_URL: url, VITE_KEYCLOAK_REALM: realm, VITE_KEYCLOAK_CLIENT_ID: clientId } = import.meta.env
  if (!url || !realm || !clientId) {
    welcome('Configure Keycloak to connect the portal to the SignBird services.')
    return
  }

  const auth = new Keycloak({ url, realm, clientId })
  welcome('Connecting to Keycloak…')
  try {
    const authenticated = await auth.init({ flow: 'standard', pkceMethod: 'S256', checkLoginIframe: false, redirectUri })
    if (!authenticated) {
      const login = () => {
        void auth.login({ redirectUri, locale: 'en' }).catch(() => welcome('Sign-in failed. Try again.', login))
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
      throw new Error('Your session expired. Reload the page and sign in again.')
    })
    const name = auth.idTokenParsed?.preferred_username ?? auth.idTokenParsed?.name ?? 'User'
    root.render(<Dashboard service={service} name={name} logout={() => auth.logout({ redirectUri })} />)
  } catch {
    welcome('Could not connect to Keycloak. Check the configuration and reload the page.')
  }
}

void start()
