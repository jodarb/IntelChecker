// Threat actor search tab (/actors)
const en = {
  'tabs.actors': 'Actors',
  'actors.title': 'Threat Actor Intelligence',
  'actors.subtitle': 'Profile of an adversary group across CTI sources: aliases, techniques, malware and related reports.',
  'actors.placeholder': 'Actor name or alias, e.g. APT28, Fancy Bear or Kimsuky',
  'actors.search': 'Search actor',
  'actorPick.searching': 'Looking for matching actors…',
  'actorPick.pick': 'Pick the actor to look up:',
  'actorPick.none': 'No known actor matches “{q}”.',
  'actorPick.error': 'Could not list candidate actors. You can still search as typed.',
  'actorPick.aka': 'Also known as',
  'actorPick.exact': 'exact match',
  'actorPick.ransomware': 'ransomware group',
  'actorPick.ransomwareVictims': 'ransomware · {n} victims',
  'actorPick.minor': 'Other Recorded Future names: individuals, forum handles… ({n})',
  'actorPick.asTyped': 'Search “{q}” as typed',
  'actorPick.asTypedHint': 'Every source matches it against its own names and aliases.',
}

const es: typeof en = {
  'tabs.actors': 'Actores',
  'actors.title': 'Inteligencia de actores',
  'actors.subtitle': 'Perfil de un grupo adversario en las fuentes CTI: alias, técnicas, malware e informes relacionados.',
  'actors.placeholder': 'Nombre o alias del actor, p. ej. APT28, Fancy Bear o Kimsuky',
  'actors.search': 'Buscar actor',
  'actorPick.searching': 'Buscando actores que coincidan…',
  'actorPick.pick': 'Elige el actor que quieres consultar:',
  'actorPick.none': 'Ningún actor conocido coincide con «{q}».',
  'actorPick.error': 'No se ha podido obtener la lista de actores. Puedes buscar tal cual.',
  'actorPick.aka': 'También conocido como',
  'actorPick.exact': 'coincidencia exacta',
  'actorPick.ransomware': 'grupo de ransomware',
  'actorPick.ransomwareVictims': 'ransomware · {n} víctimas',
  'actorPick.minor': 'Otros nombres en Recorded Future: personas, alias de foros… ({n})',
  'actorPick.asTyped': 'Buscar «{q}» tal cual',
  'actorPick.asTypedHint': 'Cada fuente lo compara con sus propios nombres y alias.',
}

export default { en, es }
