import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/bebas-neue/latin-400.css'
import './index.css'
import App from './App.tsx'
import { EnginesProvider } from './EnginesContext'
import { I18nProvider } from './i18n/I18nProvider'
import { AuthProvider } from './auth/AuthProvider'
import { AuthGate } from './auth/AuthGate'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <AuthProvider>
        <AuthGate>
          <EnginesProvider>
            <App />
          </EnginesProvider>
        </AuthGate>
      </AuthProvider>
    </I18nProvider>
  </StrictMode>,
)
