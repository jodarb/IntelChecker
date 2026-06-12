import { useEffect, useState } from 'react'
import { X, Download, Copy, Check } from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism'

interface Props {
  open: boolean
  onClose: () => void
  data: unknown
  title: string
}

function useDark() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const observer = new MutationObserver(() => {
      setDark(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])
  return dark
}

export default function RawJsonModal({ open, onClose, data, title }: Props) {
  const [copied, setCopied] = useState(false)
  const dark = useDark()
  const json = JSON.stringify(data, null, 2)

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  const handleCopy = async () => {
    await navigator.clipboard.writeText(json)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${title.toLowerCase().replace(/[\s·]+/g, '_')}_response.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-3xl mx-4 rounded-lg border border-border bg-background shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 shrink-0">
          <span className="text-sm font-semibold text-foreground font-mono">{title} · Raw JSON</span>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border border-border hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              {copied
                ? <><Check className="h-3.5 w-3.5 text-green-400" />Copied!</>
                : <><Copy className="h-3.5 w-3.5" />Copy</>
              }
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border border-border hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <Download className="h-3.5 w-3.5" />
              Download
            </button>
            <button
              onClick={onClose}
              className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        <div className="overflow-auto flex-1 text-xs">
          <SyntaxHighlighter
            language="json"
            style={dark ? vscDarkPlus : vs}
            customStyle={{
              margin: 0,
              borderRadius: 0,
              fontSize: '0.75rem',
              lineHeight: '1.5',
              background: 'transparent',
            }}
            wrapLongLines={false}
          >
            {json}
          </SyntaxHighlighter>
        </div>
      </div>
    </div>
  )
}
