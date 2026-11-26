import type React from 'react'
import type { CardWeight } from '@/components/results/WeightBadge'
import AbuseIPDBCard from '@/components/results/AbuseIPDBCard'
import VirusTotalCard from '@/components/results/VirusTotalCard'
import AbuseCHCard from '@/components/results/AbuseCHCard'
import AlienVaultCard from '@/components/results/AlienVaultCard'
import IPInfoCard from '@/components/results/IPInfoCard'
import ShodanCard from '@/components/results/ShodanCard'
import TorExitNodeCard from '@/components/results/TorExitNodeCard'
import URLHausCard from '@/components/results/URLHausCard'
import MitreAttackCard from '@/components/results/MitreAttackCard'
import RIPEstatCard from '@/components/results/RIPEstatCard'
import URLScanCard from '@/components/results/URLScanCard'
import MalwareBazaarCard from '@/components/results/MalwareBazaarCard'
import PhishTankCard from '@/components/results/PhishTankCard'
import RecordedFutureCard from '@/components/results/RecordedFutureCard'
import AnyRunCard from '@/components/results/AnyRunCard'
import GreyNoiseCard from '@/components/results/GreyNoiseCard'
import HybridAnalysisCard from '@/components/results/HybridAnalysisCard'
import SafeBrowsingCard from '@/components/results/SafeBrowsingCard'
import TweetFeedCard from '@/components/results/TweetFeedCard'
import CrowdSecCard from '@/components/results/CrowdSecCard'
import HashlookupCard from '@/components/results/HashlookupCard'
import RdapCard from '@/components/results/RdapCard'
import TrancoCard from '@/components/results/TrancoCard'
import MalpediaCard from '@/components/results/MalpediaCard'
import SpamhausCard from '@/components/results/SpamhausCard'
import OpenPhishCard from '@/components/results/OpenPhishCard'
import YaraifyCard from '@/components/results/YaraifyCard'
import SslblCard from '@/components/results/SslblCard'
import CirclPdnsCard from '@/components/results/CirclPdnsCard'
import NvdCard from '@/components/results/NvdCard'
import CisaKevCard from '@/components/results/CisaKevCard'
import EpssCard from '@/components/results/EpssCard'
import OpenTipCard from '@/components/results/OpenTipCard'
import VulnCheckKevCard from '@/components/results/VulnCheckKevCard'
import WikidataCard from '@/components/results/WikidataCard'
import GleifCard from '@/components/results/GleifCard'
import RansomwareLiveCard from '@/components/results/RansomwareLiveCard'
import HudsonRockCard from '@/components/results/HudsonRockCard'
import HibpCard from '@/components/results/HibpCard'
import GdeltCard from '@/components/results/GdeltCard'

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'asn' | 'threat-actor' | 'cve' | 'company'

/** Every indicator type, in the order of the search box and the Docs coverage table. */
export const INDICATOR_TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'hash', 'asn', 'threat-actor', 'cve', 'company']

/** Types of the artifact search (companies have their own search tab). */
export const ARTIFACT_TYPES: IndicatorType[] = INDICATOR_TYPES.filter(t => t !== 'company')

export interface CardProps {
  loading: boolean
  error: string | null
  data: unknown
  label?: string
  score?: number | null
  weight?: CardWeight | null
  indicator?: string
  type?: IndicatorType
}

export interface QueryResult {
  loading: boolean
  data: unknown
  error: string | null
}

export interface EngineConfig {
  id: string
  label: string
  supports: IndicatorType[]
  component: React.ComponentType<CardProps>
  logo: string
}

// Static engines, known at build time. MISP instances are discovered at runtime
// from the backend (any number of them, user-named) — see EnginesContext.tsx,
// which merges these with the dynamic ones into the list the rest of the app uses.
export const STATIC_ENGINES: EngineConfig[] = [
  {
    id: 'abuseipdb',
    label: 'AbuseIPDB',
    supports: ['ip'],
    component: AbuseIPDBCard as React.ComponentType<CardProps>,
    logo: '/logos/abuseipdb.ico',
  },
  {
    id: 'virustotal',
    label: 'VirusTotal',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: VirusTotalCard as React.ComponentType<CardProps>,
    logo: '/logos/virustotal.ico',
  },
  {
    id: 'abusech',
    label: 'ThreatFox · abuse.ch',
    supports: ['ip', 'hash'],
    component: AbuseCHCard as React.ComponentType<CardProps>,
    logo: '/logos/abusech.png',
  },
  {
    id: 'alienvault',
    label: 'AlienVault OTX',
    supports: ['ip', 'domain', 'url', 'hash', 'threat-actor', 'cve'],
    component: AlienVaultCard as React.ComponentType<CardProps>,
    logo: '/logos/alienvault.png',
  },
  {
    id: 'ipinfo',
    label: 'IPinfo',
    supports: ['ip'],
    component: IPInfoCard as React.ComponentType<CardProps>,
    logo: '/logos/ipinfo.ico',
  },
  {
    id: 'shodan',
    label: 'Shodan',
    supports: ['ip', 'asn'],
    component: ShodanCard as React.ComponentType<CardProps>,
    logo: '/logos/shodan.png',
  },
  {
    id: 'torexitlist',
    label: 'Tor Exit Nodes (dan.me.uk)',
    supports: ['ip'],
    component: TorExitNodeCard as React.ComponentType<CardProps>,
    logo: '/logos/torexitlist.ico',
  },
  {
    id: 'urlhaus',
    label: 'URLhaus · abuse.ch',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: URLHausCard as React.ComponentType<CardProps>,
    logo: '/logos/urlhaus.png',
  },
  {
    id: 'mitreattack',
    label: 'MITRE ATT&CK',
    supports: ['threat-actor'],
    component: MitreAttackCard as React.ComponentType<CardProps>,
    logo: '/logos/mitreattack.ico',
  },
  {
    id: 'ripestat',
    label: 'RIPEstat',
    supports: ['ip', 'asn'],
    component: RIPEstatCard as React.ComponentType<CardProps>,
    logo: '/logos/ripestat.png',
  },
  {
    id: 'urlscan',
    label: 'urlscan.io',
    supports: ['url', 'domain'],
    component: URLScanCard as React.ComponentType<CardProps>,
    logo: '/logos/urlscan.png',
  },
  {
    id: 'malwarebazaar',
    label: 'MalwareBazaar · abuse.ch',
    supports: ['hash'],
    component: MalwareBazaarCard as React.ComponentType<CardProps>,
    logo: '/logos/malwarebazaar.png',
  },
  {
    id: 'phishtank',
    label: 'PhishTank',
    supports: ['url'],
    component: PhishTankCard as React.ComponentType<CardProps>,
    logo: '/logos/phishtank.ico',
  },
  {
    id: 'recordedfuture',
    label: 'Recorded Future',
    supports: ['ip', 'domain', 'url', 'hash', 'threat-actor'],
    component: RecordedFutureCard as React.ComponentType<CardProps>,
    logo: '/logos/recordedfuture.ico',
  },
  {
    id: 'anyrun',
    label: 'ANY.RUN',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: AnyRunCard as React.ComponentType<CardProps>,
    logo: '/logos/anyrun.png',
  },
  {
    id: 'greynoise',
    label: 'GreyNoise',
    supports: ['ip'],
    component: GreyNoiseCard as React.ComponentType<CardProps>,
    logo: '/logos/greynoise.png',
  },
  {
    id: 'hybridanalysis',
    label: 'Hybrid Analysis',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: HybridAnalysisCard as React.ComponentType<CardProps>,
    logo: '/logos/hybridanalysis.ico',
  },
  {
    id: 'safebrowsing',
    label: 'Google Safe Browsing',
    supports: ['url'],
    component: SafeBrowsingCard as React.ComponentType<CardProps>,
    logo: '/logos/safebrowsing.ico',
  },
  {
    id: 'tweetfeed',
    label: 'TweetFeed',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: TweetFeedCard as React.ComponentType<CardProps>,
    logo: '/logos/tweetfeed.png',
  },
  {
    id: 'crowdsec',
    label: 'CrowdSec CTI',
    supports: ['ip'],
    component: CrowdSecCard as React.ComponentType<CardProps>,
    logo: '/logos/crowdsec.ico',
  },
  {
    id: 'hashlookup',
    label: 'CIRCL hashlookup',
    supports: ['hash'],
    component: HashlookupCard as React.ComponentType<CardProps>,
    logo: '/logos/hashlookup.ico',
  },
  {
    id: 'rdap',
    label: 'RDAP (domain registration)',
    supports: ['domain', 'url'],
    component: RdapCard as React.ComponentType<CardProps>,
    logo: '/logos/rdap.ico',
  },
  {
    id: 'tranco',
    label: 'Tranco (top domains)',
    supports: ['domain'],
    component: TrancoCard as React.ComponentType<CardProps>,
    logo: '/logos/tranco.svg',
  },
  {
    id: 'malpedia',
    label: 'Malpedia',
    supports: ['threat-actor'],
    component: MalpediaCard as React.ComponentType<CardProps>,
    logo: '/logos/malpedia.png',
  },
  {
    id: 'spamhaus',
    label: 'Spamhaus',
    supports: ['ip', 'domain', 'url', 'asn'],
    component: SpamhausCard as React.ComponentType<CardProps>,
    logo: '/logos/spamhaus.ico',
  },
  {
    id: 'openphish',
    label: 'OpenPhish',
    supports: ['ip', 'domain', 'url'],
    component: OpenPhishCard as React.ComponentType<CardProps>,
    logo: '/logos/openphish.svg',
  },
  {
    id: 'yaraify',
    label: 'YARAify · abuse.ch',
    supports: ['hash'],
    component: YaraifyCard as React.ComponentType<CardProps>,
    logo: '/logos/yaraify.png',
  },
  {
    id: 'sslbl',
    label: 'SSLBL · abuse.ch',
    supports: ['hash'],
    component: SslblCard as React.ComponentType<CardProps>,
    logo: '/logos/sslbl.png',
  },
  {
    id: 'circlpdns',
    label: 'CIRCL Passive DNS',
    supports: ['ip', 'domain'],
    component: CirclPdnsCard as React.ComponentType<CardProps>,
    logo: '/logos/circlpdns.ico',
  },
  {
    id: 'nvd',
    label: 'NVD (NIST)',
    supports: ['cve'],
    component: NvdCard as React.ComponentType<CardProps>,
    logo: '/logos/nvd.png',
  },
  {
    id: 'cisakev',
    label: 'CISA KEV',
    supports: ['cve'],
    component: CisaKevCard as React.ComponentType<CardProps>,
    logo: '/logos/cisakev.png',
  },
  {
    id: 'epss',
    label: 'EPSS · FIRST',
    supports: ['cve'],
    component: EpssCard as React.ComponentType<CardProps>,
    logo: '/logos/epss.png',
  },
  {
    id: 'opentip',
    label: 'Kaspersky OpenTIP',
    supports: ['ip', 'domain', 'url', 'hash'],
    component: OpenTipCard as React.ComponentType<CardProps>,
    logo: '/logos/opentip.ico',
  },
  {
    id: 'vulncheckkev',
    label: 'VulnCheck KEV',
    supports: ['cve'],
    component: VulnCheckKevCard as React.ComponentType<CardProps>,
    logo: '/logos/vulncheckkev.png',
  },
  // Companies
  {
    id: 'wikidata',
    label: 'Wikidata',
    supports: ['company'],
    component: WikidataCard as React.ComponentType<CardProps>,
    logo: '/logos/wikidata.png',
  },
  {
    id: 'gleif',
    label: 'GLEIF (LEI)',
    supports: ['company'],
    component: GleifCard as React.ComponentType<CardProps>,
    logo: '/logos/gleif.png',
  },
  {
    id: 'ransomwarelive',
    label: 'ransomware.live',
    supports: ['company'],
    component: RansomwareLiveCard as React.ComponentType<CardProps>,
    logo: '/logos/ransomwarelive.png',
  },
  {
    id: 'hudsonrock',
    label: 'Hudson Rock (infostealers)',
    supports: ['company'],
    component: HudsonRockCard as React.ComponentType<CardProps>,
    logo: '/logos/hudsonrock.png',
  },
  {
    id: 'hibp',
    label: 'Have I Been Pwned',
    supports: ['company'],
    component: HibpCard as React.ComponentType<CardProps>,
    logo: '/logos/hibp.png',
  },
  {
    id: 'gdelt',
    label: 'GDELT (news)',
    supports: ['company'],
    component: GdeltCard as React.ComponentType<CardProps>,
    logo: '/logos/gdelt.png',
  },
]

export function getEnginesForType(engines: EngineConfig[], type: IndicatorType): EngineConfig[] {
  return engines.filter(e => e.supports.includes(type))
}
