import { Fragment, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

// Tiny inline markup for translated strings, so dictionaries stay plain text:
//   **bold**   `code`   *italic*   [label](/route | #anchor | https://…)
const TOKEN = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*|\[[^\]]+\]\([^)]+\))/g

export function rich(text: string): ReactNode {
  return text.split(TOKEN).map((part, i) => {
    if (!part) return null
    if (part.startsWith('**') && part.endsWith('**')) {
      return <span key={i} className="text-foreground font-medium">{part.slice(2, -2)}</span>
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="text-xs bg-muted px-1 py-0.5 rounded font-mono text-foreground">{part.slice(1, -1)}</code>
    }
    const link = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/)
    if (link) {
      const [, label, href] = link
      const cls = 'text-primary hover:underline'
      if (href.startsWith('/')) return <Link key={i} to={href} className={cls}>{label}</Link>
      const external = href.startsWith('http')
      return <a key={i} href={href} className={cls} {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}>{label}</a>
    }
    if (part.length > 2 && part.startsWith('*') && part.endsWith('*')) return <em key={i}>{part.slice(1, -1)}</em>
    return <Fragment key={i}>{part}</Fragment>
  })
}
