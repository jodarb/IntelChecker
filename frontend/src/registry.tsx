import type React from 'react'
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

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'asn' | 'threat-actor'

export interface CardProps {
  loading: boolean
  error: string | null
  data: unknown
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

export const ENGINES: EngineConfig[] = [
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
    supports: ['ip', 'domain', 'url', 'hash'],
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
]

export function getEnginesForType(type: IndicatorType): EngineConfig[] {
  return ENGINES.filter(e => e.supports.includes(type))
}
