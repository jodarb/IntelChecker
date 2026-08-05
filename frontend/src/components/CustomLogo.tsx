import { useState, useEffect } from 'react'

export default function CustomLogo() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [lightVisible, setLightVisible] = useState(true)
  const [darkVisible, setDarkVisible] = useState(true)

  useEffect(() => {
    fetch('/config.json')
      .then(r => r.json())
      .then(cfg => setEnabled(cfg.showLogo ?? true))
      .catch(() => setEnabled(true))
  }, [])

  if (enabled === null || !enabled || (!lightVisible && !darkVisible)) return null

  // Two logos, swapped purely via the same `dark` class the theme toggle applies
  // to <html> — no need to duplicate theme state here, it just tracks Tailwind's
  // existing dark-mode variant.
  return (
    <>
      {lightVisible && (
        <img
          src="/logo/light.png"
          alt="Organization logo"
          className="h-12 mx-auto object-contain dark:hidden"
          onError={() => setLightVisible(false)}
        />
      )}
      {darkVisible && (
        <img
          src="/logo/dark.png"
          alt="Organization logo"
          className="h-12 mx-auto object-contain hidden dark:block"
          onError={() => setDarkVisible(false)}
        />
      )}
    </>
  )
}
