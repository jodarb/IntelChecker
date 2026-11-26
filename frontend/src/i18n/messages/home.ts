const en = {
  'home.title': 'Threat Intelligence Lookup',
  'home.subtitle': 'Analyze IPs, domains, URLs, hashes, ASNs, threat actors and CVEs across multiple CTI sources.',
  'home.placeholder': 'Enter an IP, domain, URL, hash, ASN, threat actor or CVE...',
  'home.analyze': 'Analyze',
  'home.connected': 'Connected sources ({n})',
  'home.notConfiguredLink': '{n} more sources are not configured — set them up on [Connectors](/connectors).',
  'home.disableSource': 'Disable this source for the next search',
  'home.enableSource': 'Enable this source',
}
const es: Record<keyof typeof en, string> = {
  'home.title': 'Consulta de inteligencia de amenazas',
  'home.subtitle': 'Analiza IPs, dominios, URLs, hashes, ASNs, actores de amenaza y CVEs en múltiples fuentes CTI.',
  'home.placeholder': 'Introduce una IP, dominio, URL, hash, ASN, actor de amenaza o CVE...',
  'home.analyze': 'Analizar',
  'home.connected': 'Fuentes conectadas ({n})',
  'home.notConfiguredLink': 'Hay {n} fuentes más sin configurar — configúralas en [Conectores](/connectors).',
  'home.disableSource': 'Desactivar esta fuente para la próxima búsqueda',
  'home.enableSource': 'Activar esta fuente',
}
export default { en, es }
