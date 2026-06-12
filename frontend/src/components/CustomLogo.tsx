import { useState, useEffect } from 'react'

export default function CustomLogo() {
  const [visible, setVisible] = useState(true)
  const [enabled, setEnabled] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/config.json')
      .then(r => r.json())
      .then(cfg => setEnabled(cfg.showLogo ?? true))
      .catch(() => setEnabled(true))
  }, [])

  if (enabled === null || !enabled || !visible) return null

  return (
    <img
      src="/logo.svg"
      alt="Organization logo"
      className="h-12 mx-auto object-contain"
      onError={() => setVisible(false)}
    />
  )
}
