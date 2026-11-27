import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { SUMMARY_REGISTRY, type SummaryField } from '@/summaryRegistry'
import type { IndicatorType } from '@/registry'

const get = (engine: string, type: IndicatorType, field: SummaryField, data: unknown) =>
  SUMMARY_REGISTRY[engine]?.[type]?.find(e => e.field === field)?.extract(data)

describe('summary extractors (IP)', () => {
  it('VirusTotal', () => {
    const d = { data: { attributes: { country: 'US', asn: 15169, as_owner: 'GOOGLE' } } }
    assert.equal(get('virustotal', 'ip', 'country', d), 'US')
    assert.equal(get('virustotal', 'ip', 'asn', d), 'AS15169')
    assert.equal(get('virustotal', 'ip', 'isp', d), 'GOOGLE')
    assert.equal(get('virustotal', 'ip', 'asn', {}), null)
  })
  it('IPinfo splits "AS15169 Google LLC"', () => {
    const d = { country: 'US', org: 'AS15169 Google LLC' }
    assert.equal(get('ipinfo', 'ip', 'asn', d), 'AS15169')
    assert.equal(get('ipinfo', 'ip', 'isp', d), 'Google LLC')
    assert.equal(get('ipinfo', 'ip', 'isp', { org: 'AS15169' }), null)
  })
  it('OTX keeps the leading ASN', () => {
    assert.equal(get('alienvault', 'ip', 'asn', { asn: 'AS15169 GOOGLE - Google LLC, US' }), 'AS15169')
  })
  it('AbuseIPDB and Tor exit flags', () => {
    assert.equal(get('abuseipdb', 'ip', 'torExit', { data: { isTor: true } }), 'Yes')
    assert.equal(get('abuseipdb', 'ip', 'torExit', { data: { isTor: false } }), null)
    assert.equal(get('torexitlist', 'ip', 'torExit', { is_tor_exit: true }), 'Yes')
    assert.equal(get('abuseipdb', 'ip', 'country', { data: { countryCode: 'ES' } }), 'ES')
  })
  it('Shodan sorts open ports', () => {
    assert.equal(get('shodan', 'ip', 'openPorts', { ports: [443, 22, 80] }), '22, 80, 443')
    assert.equal(get('shodan', 'ip', 'openPorts', { ports: [] }), null)
  })
  it('TweetFeed, RIPEstat, CrowdSec, Any.run', () => {
    assert.equal(get('tweetfeed', 'ip', 'asn', { net: { org: 'AS13335 Cloudflare' } }), 'AS13335')
    assert.equal(get('tweetfeed', 'ip', 'isp', { net: { org: 'AS13335 Cloudflare' } }), 'Cloudflare')
    assert.equal(get('ripestat', 'ip', 'asn', { network_info: { asns: ['3352'] } }), 'AS3352')
    assert.equal(get('crowdsec', 'ip', 'asn', { as_num: 3352 }), 'AS3352')
    assert.equal(get('anyrun', 'ip', 'country', { destinationIPgeo: ['de'] }), 'de')
    assert.equal(get('anyrun', 'ip', 'asn', { destinationIpAsn: [{ asn: 'AS1' }] }), 'AS1')
  })
  it('missing or malformed data gives null', () => {
    for (const d of [null, undefined, 'x', 3, { data: null }]) {
      assert.equal(get('virustotal', 'ip', 'country', d), null)
      assert.equal(get('shodan', 'ip', 'openPorts', d), null)
    }
  })
})
