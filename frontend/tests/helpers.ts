// Shared helpers for the frontend unit tests (`npm test`, Node's built-in runner).
import { readFileSync } from 'node:fs'
import type { EngineConfig, QueryResult } from '@/registry'

export const LABELS: Record<string, string> = {
  alienvault: 'AlienVault OTX',
  mitreattack: 'MITRE ATT&CK',
  recordedfuture: 'Recorded Future',
  malpedia: 'Malpedia',
  ransomwarelive: 'ransomware.live',
  opencti_1: 'OpenCTI',
}

/** Minimal engine configs: the actor modules only read `id` and `label`. */
export const engines = (...ids: string[]): EngineConfig[] =>
  ids.map(id => ({ id, label: LABELS[id] ?? id, supports: ['threat-actor'], logo: '' })) as unknown as EngineConfig[]

export const ok = (data: unknown): QueryResult => ({ loading: false, data, error: null })
export const failed = (code: string): QueryResult => ({ loading: false, data: { error: { code, message: code } }, error: null })
export const loading = (): QueryResult => ({ loading: true, data: null, error: null })

export interface HistoryFixture {
  id: number
  indicator: string
  timestamp: string
  results: Record<string, { data: unknown; error: string | null }>
}

/** A history entry saved from a real lookup (backend/data/history.db). */
export function historyFixture(id: number) {
  const e = JSON.parse(readFileSync(new URL(`./fixtures/history-${id}.json`, import.meta.url), 'utf8')) as HistoryFixture
  const results: Record<string, QueryResult> = Object.fromEntries(
    Object.entries(e.results).map(([k, r]) => [k, { loading: false, data: r.data, error: r.error }]),
  )
  return {
    indicator: e.indicator,
    asOf: new Date(e.timestamp.replace(' ', 'T') + 'Z'),
    engineIds: Object.keys(e.results),
    results,
  }
}
