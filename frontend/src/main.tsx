import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/bebas-neue/latin-400.css'
import './index.css'
import App from './App.tsx'
import { EnginesProvider } from './EnginesContext'
import { I18nProvider } from './i18n/I18nProvider'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <EnginesProvider>
        <App />
      </EnginesProvider>
    </I18nProvider>
  </StrictMode>,
)
