import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, BookOpen, PowerOff, ShieldCheck, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import { useEngines } from '@/EnginesContext'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import { QUADRANT_META, OUTCOME_META, outcomeLabel, quadrantLabel } from '@/quadrants'
import { INDICATOR_TYPES as TYPES } from '@/registry'
import { DEFAULT_SCORING, type EngineOutcome, type Quadrant } from '@/verdictEngine'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'
import { docsEn, type DocsContent } from '@/i18n/docs/en'
import { docsEs } from '@/i18n/docs/es'

// In-app documentation for analysts and admins. The text lives in i18n/docs/{en,es}.ts;
// the weights, thresholds and coverage tables are read live from the backend.

const DOCS: Record<'en' | 'es', DocsContent> = { en: docsEn, es: docsEs }

const OUTCOMES: EngineOutcome[] = ['hit', 'clean', 'context', 'no_data', 'excluded']
const QUADRANTS: Quadrant[] = ['confirmed_malicious', 'isolated_signal', 'known_benign', 'known_low_signals', 'known_no_verdict', 'unknown']

type TocKey = keyof DocsContent['toc']
const ANALYST_SECTIONS: TocKey[] = ['lookup', 'results', 'outcomes', 'knowledge', 'risk', 'quadrants', 'summary', 'matrix', 'history']
const ADMIN_SECTIONS: TocKey[] = ['adminPage', 'weights', 'subscores', 'depth', 'config']

// ── Building blocks ──────────────────────────────────────────────────────────

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-6 flex flex-col gap-3">
      <h3 className="text-lg font-semibold text-foreground">{title}</h3>
      {children}
    </section>
  )
}

function Part({ icon, title, intro }: { icon: React.ReactNode; title: string; intro: string }) {
  return (
    <div className="flex items-start gap-3 pt-4 border-t border-border">
      <span className="mt-0.5 text-primary">{icon}</span>
      <div>
        <h2 className="text-xl font-semibold text-foreground">{title}</h2>
        <p className="text-sm text-muted-foreground mt-1">{intro}</p>
      </div>
    </div>
  )
}

function P({ children }: { children: string }) {
  return <p className="text-sm text-muted-foreground leading-relaxed">{rich(children)}</p>
}

function Formula({ children }: { children: string }) {
  return (
    <pre className="text-xs sm:text-sm bg-muted/60 border border-border rounded-md px-4 py-3 overflow-x-auto font-mono text-foreground">
      {children}
    </pre>
  )
}

function Note({ children }: { children: string }) {
  return (
    <div className="text-sm text-muted-foreground border-l-2 border-primary/60 bg-primary/5 rounded-r-md px-4 py-2.5 leading-relaxed">
      {rich(children)}
    </div>
  )
}

function List({ items }: { items: string[] }) {
  return (
    <ul className="text-sm text-muted-foreground list-disc pl-5 flex flex-col gap-1.5 leading-relaxed">
      {items.map((it, i) => <li key={i}>{rich(it)}</li>)}
    </ul>
  )
}

type Cell = React.ReactNode
const cell = (c: Cell) => (typeof c === 'string' ? rich(c) : c)

function Table({ head, rows, center = [] }: { head: Cell[]; rows: Cell[][]; center?: number[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full text-sm">
        <thead className="bg-muted/40">
          <tr>
            {head.map((h, i) => (
              <th
                key={i}
                className={`px-3 py-2 text-xs uppercase tracking-wide font-medium text-muted-foreground ${center.includes(i) ? 'text-center' : 'text-left'}`}
              >
                {cell(h)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-border align-top">
              {r.map((c, j) => (
                <td key={j} className={`px-3 py-2 text-muted-foreground ${center.includes(j) ? 'text-center' : ''} ${j === 0 ? 'text-foreground font-medium' : ''}`}>
                  {cell(c)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function QuadrantChip({ q }: { q: Quadrant }) {
  const { t } = useI18n()
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full border text-xs font-semibold whitespace-nowrap ${QUADRANT_META[q].className}`}>
      {quadrantLabel(q, t)}
    </span>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DocsPage() {
  const { engines, status } = useEngines()
  const config = useVerdictWeights()
  const { t, lang } = useI18n()
  const d = DOCS[lang]
  const tk = config?.thresholds.knowledge ?? 4
  const tr = config?.thresholds.risk ?? 5
  const fa = config?.scoring?.knowledge_full_at ?? DEFAULT_SCORING.knowledge_full_at
  const th = (s: string) => s.replaceAll('{tk}', String(tk)).replaceAll('{tr}', String(tr)).replaceAll('{fa}', String(fa))

  const weightRows = useMemo(() => {
    if (!config) return []
    return engines
      .filter(e => config.engines[e.id])
      .map(e => ({ engine: e, w: config.engines[e.id] }))
      .sort((a, b) => (b.w.risk - a.w.risk) || (b.w.knowledge - a.w.knowledge) || a.engine.label.localeCompare(b.engine.label))
  }, [engines, config])

  const toc = [
    { group: d.toc.analysts, items: ANALYST_SECTIONS },
    { group: d.toc.admins, items: ADMIN_SECTIONS },
  ]

  return (
    <Layout>
      <main className="flex-1 px-4 sm:px-6 py-6 w-full max-w-6xl mx-auto flex gap-8">
        {/* Table of contents */}
        <nav className="hidden lg:block w-52 shrink-0">
          <div className="sticky top-6 flex flex-col gap-4 text-sm">
            {toc.map(g => (
              <div key={g.group} className="flex flex-col gap-1">
                <span className="text-xs uppercase tracking-wide font-medium text-muted-foreground mb-1">{g.group}</span>
                {g.items.map(id => (
                  <a key={id} href={`#${id}`} className="text-muted-foreground hover:text-foreground transition-colors py-0.5">
                    {d.toc[id]}
                  </a>
                ))}
              </div>
            ))}
          </div>
        </nav>

        <article className="flex-1 min-w-0 flex flex-col gap-8 pb-16">
          <div className="flex items-start gap-4">
            <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
              <Link to="/"><ArrowLeft className="h-4 w-4 mr-1" /> {t('common.back')}</Link>
            </Button>
            <div>
              <h1 className="text-2xl font-semibold text-foreground flex items-center gap-2">
                <BookOpen className="h-5 w-5 text-primary" /> {d.title}
              </h1>
              <p className="text-sm text-muted-foreground mt-1">{rich(d.intro)}</p>
            </div>
          </div>

          {/* ═════════════════════════════ ANALYSTS ═════════════════════════════ */}
          <Part icon={<Users className="h-5 w-5" />} title={d.partAnalysts.title} intro={d.partAnalysts.intro} />

          <Section id="lookup" title={d.lookup.title}>
            <P>{d.lookup.p1}</P>
            <Table head={d.lookup.head} rows={d.lookup.types} />
            <List items={d.lookup.list} />
          </Section>

          <Section id="results" title={d.results.title}>
            <P>{d.results.p1}</P>
            <List items={d.results.list.map(th)} />
            <P>{d.results.p2}</P>
            <Table
              head={d.results.head}
              rows={[
                [<span className="inline-flex px-2 py-0.5 rounded-full text-xs font-bold text-white bg-red-600">8/10</span>, d.results.badges.score],
                [<span className="inline-flex px-2 py-0.5 rounded-full border text-xs font-medium text-yellow-400 bg-yellow-500/10 border-yellow-500/30 whitespace-nowrap">{t('badge.noResults')}</span>, d.results.badges.noResults],
                [<span className="inline-flex px-2 py-0.5 rounded-full border text-xs font-medium text-yellow-400 bg-yellow-500/10 border-yellow-500/30 whitespace-nowrap">{t('badge.noScore')}</span>, d.results.badges.noScore],
                [<span className="inline-flex px-2 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">{t('badge.error')}</span>, d.results.badges.error],
                [<span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 whitespace-nowrap"><PowerOff className="h-3 w-3" />{t('disconnected.missingKey')}</span>, d.results.badges.off],
              ]}
            />
          </Section>

          <Section id="outcomes" title={d.outcomes.title}>
            <P>{d.outcomes.p1}</P>
            <Table
              head={d.outcomes.head}
              center={[3, 4]}
              rows={OUTCOMES.map(o => [
                <span className={OUTCOME_META[o].className}>{outcomeLabel(o, t)}</span>,
                ...d.outcomes.rows[o],
              ])}
            />
            <Note>{d.outcomes.note}</Note>
          </Section>

          <Section id="knowledge" title={d.knowledge.title}>
            <P>{d.knowledge.p1}</P>
            <Formula>{th(d.knowledge.formula)}</Formula>
            <List items={d.knowledge.list.map(th)} />
            <P>{d.knowledge.example}</P>
            <Formula>{d.knowledge.exampleFormula}</Formula>
          </Section>

          <Section id="risk" title={d.risk.title}>
            <P>{d.risk.p1}</P>
            <Formula>{d.risk.formula}</Formula>
            <List items={d.risk.list} />
            <P>{d.risk.example}</P>
            <Formula>{d.risk.exampleFormula}</Formula>
          </Section>

          <Section id="quadrants" title={d.quadrants.title}>
            <P>{th(d.quadrants.p1)}</P>
            <Table
              head={['', th(d.quadrants.riskBelow), th(d.quadrants.riskAbove)]}
              rows={[
                [th(d.quadrants.knowledgeAbove), <div className="flex flex-wrap gap-1"><QuadrantChip q="known_benign" /><QuadrantChip q="known_low_signals" /><QuadrantChip q="known_no_verdict" /></div>, <QuadrantChip q="confirmed_malicious" />],
                [th(d.quadrants.knowledgeBelow), <QuadrantChip q="unknown" />, <QuadrantChip q="isolated_signal" />],
              ]}
            />
            <Table
              head={d.quadrants.head}
              rows={QUADRANTS.map(q => [<QuadrantChip q={q} />, ...d.quadrants.rows[q].map(th)])}
            />
            <P>{d.quadrants.cve}</P>
          </Section>

          <Section id="summary" title={d.summary.title}>
            <P>{d.summary.p1}</P>
            <Table head={d.summary.head} rows={d.summary.rows} />
            <Note>{d.summary.note}</Note>
          </Section>

          <Section id="matrix" title={d.matrix.title}>
            <List items={d.matrix.list} />
          </Section>

          <Section id="history" title={d.history.title}>
            <P>{d.history.p1}</P>
            <P>{d.history.p2}</P>
            <Table
              head={d.history.head}
              center={[1, 2, 3]}
              rows={[
                [d.history.levels[0], '0', '0', '0'],
                [d.history.levels[1], '—', '—', '1–3'],
                [d.history.levels[2], '1', '1–4', '4–8'],
                [d.history.levels[3], '2–4', '5–7', '9–15'],
                [d.history.levels[4], '5+', '8+', '16+'],
              ]}
            />
            <P>{d.history.p3}</P>
          </Section>

          {/* ═════════════════════════════ ADMINS ═════════════════════════════ */}
          <Part icon={<ShieldCheck className="h-5 w-5" />} title={d.partAdmins.title} intro={d.partAdmins.intro} />

          <Section id="adminPage" title={d.adminPage.title}>
            <P>{d.adminPage.p1}</P>
            <Table head={d.adminPage.head} rows={d.adminPage.rows.map(r => r.map(th))} />
            <List items={d.adminPage.list} />
            <Table head={d.adminPage.buttonsHead} rows={d.adminPage.buttons} />
            <Note>{d.adminPage.note}</Note>
          </Section>

          <Section id="weights" title={d.weights.title}>
            <P>{d.weights.p1}</P>
            {!config ? (
              <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
            ) : (
              <Table
                head={[d.weights.sourceCol, 'R', 'K', ...TYPES.map(type => t(`typeShort.${type}`))]}
                center={[1, 2, 3, 4, 5, 6, 7, 8]}
                rows={weightRows.map(({ engine, w }) => {
                  const connected = status?.[engine.id]?.connected ?? true
                  return [
                    <span className={connected ? '' : 'opacity-50'}>
                      {engine.label}
                      {!connected && <span className="ml-1 text-xs text-muted-foreground font-normal">{d.weights.notConfigured}</span>}
                    </span>,
                    String(w.risk),
                    String(w.knowledge),
                    ...TYPES.map(type => engine.supports.includes(type)
                      ? (w.knowledge_by_type?.[type] != null
                        ? <span className="text-primary font-medium" title={d.weights.overrideTitle}>K {w.knowledge_by_type[type]}</span>
                        : '✓')
                      : ''),
                  ]
                })}
              />
            )}
          </Section>

          <Section id="subscores" title={d.subscores.title}>
            <P>{d.subscores.p1}</P>
            <Table head={d.subscores.head} rows={d.subscores.rows} />
          </Section>

          <Section id="depth" title={d.depth.title}>
            <Table head={d.depth.head} rows={d.depth.rows} />
          </Section>

          <Section id="config" title={d.config.title}>
            <Table head={d.config.head} rows={d.config.rows} />
            <Note>{d.config.note}</Note>
          </Section>
        </article>
      </main>
    </Layout>
  )
}
