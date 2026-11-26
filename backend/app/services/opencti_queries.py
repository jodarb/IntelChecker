"""GraphQL documents sent to OpenCTI, kept apart from the service so they can be
validated against the platform schema (see backend/tests/opencti_schema_check.py).

Each lookup has two variants. `FULL` uses fields added in OpenCTI 6.x/7.x (CVSS v4,
EPSS, CISA KEV and SSVC on vulnerabilities, threat actor groups / individuals);
`COMPAT` sticks to fields every 5.12+ release has. The service sends FULL first and
falls back to COMPAT when the server rejects the document (GRAPHQL_VALIDATION_FAILED),
so older instances keep working with less detail.
"""

COMMON = """
fragment IcCommon on StixCoreObject {
  id
  entity_type
  created_at
  updated_at
  createdBy { name }
  objectLabel { value color }
  objectMarking { definition x_opencti_color }
}
"""

INDICATOR = """
fragment IcIndicator on Indicator {
  id
  name
  pattern
  pattern_type
  x_opencti_score
  x_opencti_detection
  valid_from
  valid_until
  revoked
  indicator_types
  created
  createdBy { name }
  objectLabel { value color }
}
"""

OBSERVABLES = COMMON + INDICATOR + """
query IcObservables($types: [String], $filters: FilterGroup) {
  stixCyberObservables(types: $types, filters: $filters, first: 5) {
    edges {
      node {
        ...IcCommon
        observable_value
        x_opencti_score
        x_opencti_description
        indicators(first: 25) { edges { node { ...IcIndicator } } }
      }
    }
  }
}
"""

# Indicators whose pattern mentions the value but with no observable (feeds imported
# without "create observables"). Full-text search, filtered on the pattern by the service.
INDICATORS = INDICATOR + """
query IcIndicators($search: String) {
  indicators(search: $search, first: 25) {
    edges { node { ...IcIndicator } }
  }
}
"""

_VULN_FIELDS_COMPAT = """
        name
        description
        x_opencti_aliases
        x_opencti_cvss_base_score
        x_opencti_cvss_base_severity
"""

_VULN_FIELDS_FULL = _VULN_FIELDS_COMPAT + """
        x_opencti_cvss_vector_string
        x_opencti_cvss_v4_base_score
        x_opencti_cvss_v4_base_severity
        x_opencti_cisa_kev
        x_opencti_epss_score
        x_opencti_epss_percentile
        x_opencti_cwe
        x_opencti_ssvc_exploitation
        x_opencti_score
"""


def _vulnerabilities(fields: str) -> str:
    return COMMON + """
query IcVulnerabilities($filters: FilterGroup) {
  vulnerabilities(filters: $filters, first: 3) {
    edges { node { ...IcCommon """ + fields + """ } }
  }
}
"""


VULNERABILITIES = {"full": _vulnerabilities(_VULN_FIELDS_FULL), "compat": _vulnerabilities(_VULN_FIELDS_COMPAT)}

_ACTOR_FIELDS = "name aliases description first_seen last_seen primary_motivation resource_level goals"

ACTORS = {
    "full": COMMON + """
query IcActors($search: String) {
  stixDomainObjects(types: ["Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual"], search: $search, first: 10) {
    edges {
      node {
        ...IcCommon
        ... on IntrusionSet { """ + _ACTOR_FIELDS + """ }
        ... on ThreatActorGroup { """ + _ACTOR_FIELDS + """ threat_actor_types sophistication }
        ... on ThreatActorIndividual { """ + _ACTOR_FIELDS + """ threat_actor_types sophistication }
      }
    }
  }
}
""",
    "compat": COMMON + """
query IcActors($search: String) {
  stixDomainObjects(types: ["Intrusion-Set", "Threat-Actor"], search: $search, first: 10) {
    edges {
      node {
        ...IcCommon
        ... on IntrusionSet { """ + _ACTOR_FIELDS + """ }
        ... on ThreatActor { """ + _ACTOR_FIELDS + """ }
      }
    }
  }
}
""",
}

# Reports and relationships of the matched entity: what OpenCTI knows *around* it
# (malware it's tied to, actors, campaigns, reports that mention it).
_RELATED = """
  ... on BasicObject { id entity_type }
  ... on StixObject { representative { main } }
"""

# Threat actors relate to far more (techniques, CVEs, targets, indicators…): the actor
# lookup asks for more relationships, and the extra fragments give each one the
# details the actor Summary needs (ATT&CK id, observable value, indicator pattern).
_RELATED_ACTOR = _RELATED + """
  ... on AttackPattern { x_mitre_id }
  ... on StixCyberObservable { observable_value }
  ... on Indicator { pattern x_opencti_main_observable_type }
"""

CONTEXT = """
query IcContext($id: String!) {
  stixCoreObject(id: $id) {
    reports(first: 10) {
      pageInfo { globalCount }
      edges { node { id name published report_types createdBy { name } } }
    }
    stixCoreRelationships(first: 50) {
      edges {
        node {
          relationship_type
          fromId
          toId
          from { """ + _RELATED + """ }
          to { """ + _RELATED + """ }
        }
      }
    }
  }
}
"""

ACTOR_CONTEXT = """
query IcActorContext($id: String!) {
  stixCoreObject(id: $id) {
    reports(first: 25) {
      pageInfo { globalCount }
      edges { node { id name published report_types createdBy { name } } }
    }
    stixCoreRelationships(first: 300) {
      edges {
        node {
          relationship_type
          fromId
          toId
          from { """ + _RELATED_ACTOR + """ }
          to { """ + _RELATED_ACTOR + """ }
        }
      }
    }
  }
}
"""

ALL = {
    "observables": OBSERVABLES,
    "indicators": INDICATORS,
    "vulnerabilities.full": VULNERABILITIES["full"],
    "vulnerabilities.compat": VULNERABILITIES["compat"],
    "actors.full": ACTORS["full"],
    "actors.compat": ACTORS["compat"],
    "context": CONTEXT,
    "actor_context": ACTOR_CONTEXT,
}
