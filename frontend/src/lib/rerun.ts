import type { IndicatorType } from '@/registry'
import { companyReportUrl } from '@/lib/company'

/**
 * A live lookup of a history entry, as if it were searched again. The saved indicator
 * is already resolved (actor name picked, company pinned with its domain / Q-id / LEI),
 * so it skips the candidate pickers.
 */
export const rerunUrl = (type: IndicatorType | string, indicator: string) =>
  type === 'company'
    ? companyReportUrl(indicator)
    : `/results?indicator=${encodeURIComponent(indicator)}&type=${encodeURIComponent(type)}`
