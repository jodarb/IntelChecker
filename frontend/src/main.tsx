import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/bebas-neue/latin-400.css'
import './index.css'
import App from './App.tsx'
import { EnginesProvider } from './EnginesContext'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <EnginesProvider>
      <App />
    </EnginesProvider>
  </StrictMode>,
)
