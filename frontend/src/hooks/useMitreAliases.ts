import { useFetchJson } from '@/hooks/useFetchJson'
import type { MitreAliases } from '@/intelAggregates'

/**
 * MITRE ATT&CK group and software aliases for the Summary (actor detection in
 * tags, malware family merging). Best-effort: if the backend can't reach the
 * dataset it returns empty lists and the Summary falls back to its built-in table.
 */
export function useMitreAliases(): MitreAliases | null {
  const { data } = useFetchJson<MitreAliases>('/api/mitre/aliases')
  return data
}
