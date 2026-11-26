"""OpenCTI — any number of instances (Connectors page or OPENCTI_<N>_* in .env), each
its own source, like MISP. Queried through the GraphQL API (`<url>/graphql`, Bearer
token), OpenCTI 6.0 or newer.

What is looked up per type:
  * ip / domain / url / hash — the observable (exact value, or any of its hashes)
    with its indicators, plus indicators whose STIX pattern names the value but that
    have no observable (feeds imported without "create observables").
  * cve — the Vulnerability entity (CVSS, and on 6.x+/7.x EPSS, CISA KEV, SSVC).
  * threat-actor — intrusion sets and threat actors, matched on name or alias.
Then, for the matched entity, its reports and relationships (malware, actors,
campaigns, vulnerabilities…), which feed the card and the Summary.

The answer is normalised into IntelChecker's own shape (below), so the card and the
verdict don't depend on the OpenCTI version. Whether an indicator is still active
(not revoked, `valid_until` in the future) is decided here, at lookup time, and frozen
in the history like RDAP's domain age.
"""
import os
import ssl
from datetime import datetime, timezone

import httpx

from app.core import config, connectors
from app.core.cve import normalize_cve
from app.services import opencti_queries as Q

_TIMEOUT = 20
_MAX_RELATIONS = 30
_THREAT_TYPES = {"Intrusion-Set", "Threat-Actor-Group", "Threat-Actor-Individual", "Threat-Actor", "Malware", "Campaign"}
_OBSERVABLE_TYPES = {
    "ip": ["IPv4-Addr", "IPv6-Addr"],
    "domain": ["Domain-Name", "Hostname"],
    "url": ["Url"],
    "hash": ["StixFile", "Artifact"],
}
_HASH_KEYS = ("hashes.MD5", "hashes.SHA-1", "hashes.SHA-256", "hashes.SHA-512")
SUPPORTED_TYPES = ("ip", "domain", "url", "hash", "cve", "threat-actor")


class _GraphQLError(Exception):
    def __init__(self, error: dict, schema_mismatch: bool = False):
        super().__init__(error.get("message"))
        self.error = error
        # The document uses fields this OpenCTI version doesn't have.
        self.schema_mismatch = schema_mismatch


def _filter(key: str, values: list[str]) -> dict:
    return {"key": [key], "values": values, "operator": "eq", "mode": "or"}


def _group(filters: list[dict], mode: str = "and") -> dict:
    return {"mode": mode, "filters": filters, "filterGroups": []}


def _edges(conn) -> list[dict]:
    if not isinstance(conn, dict):
        return []
    return [e["node"] for e in conn.get("edges") or [] if isinstance(e, dict) and isinstance(e.get("node"), dict)]


def _labels(node: dict) -> list[dict]:
    return [{"value": label.get("value"), "color": label.get("color")}
            for label in node.get("objectLabel") or [] if isinstance(label, dict) and label.get("value")]


def _markings(node: dict) -> list[dict]:
    return [{"definition": m.get("definition"), "color": m.get("x_opencti_color")}
            for m in node.get("objectMarking") or [] if isinstance(m, dict) and m.get("definition")]


def _author(node: dict) -> str | None:
    by = node.get("createdBy")
    return by.get("name") if isinstance(by, dict) else None


def _is_active(ind: dict, now: datetime) -> bool:
    if ind.get("revoked") is True:
        return False
    until = ind.get("valid_until")
    if not until:
        return True
    try:
        return datetime.fromisoformat(str(until).replace("Z", "+00:00")) > now
    except ValueError:
        return True


class OpenCTIEngine:
    """Dispatch bound to one configured OpenCTI instance (see MispEngine)."""

    def __init__(self, instance: dict):
        self._inst = instance
        self._name = instance["name"]
        self._url = instance["url"]

    def _link(self, entity_id: str | None) -> str | None:
        return f"{self._url}/dashboard/id/{entity_id}" if entity_id else None

    def _client_cert(self):
        cert = config.cert_path(self._inst.get("client_cert", ""))
        key = config.cert_path(self._inst.get("client_key", ""))
        if not cert:
            return None
        for path, label in ((cert, "client certificate"), (key, "client key")):
            if path and not os.path.isfile(path):
                return {"error": {"code": "MissingCertificate", "message": f"{self._name}'s {label} file was not found at {path}. Drop it in backend/certs/ and select it again on the Connectors page."}}
        return (cert, key) if key else cert

    async def _query(self, client: httpx.AsyncClient, document: str, variables: dict) -> dict:
        r = await client.post(f"{self._url}/graphql", json={"query": document, "variables": variables})
        if r.status_code in (401, 403):
            raise _GraphQLError({"code": "Unauthorized", "message": f"Invalid API token for {self._name}."})
        if r.status_code == 429:
            raise _GraphQLError({"code": "RateLimitExceeded", "message": f"{self._name} rate limit exceeded."})
        if r.status_code >= 500:
            raise _GraphQLError({"code": "ServiceUnavailable", "message": f"{self._name} is unavailable (HTTP {r.status_code})."})
        try:
            payload = r.json()
        except ValueError:
            raise _GraphQLError({"code": "ApiError", "message": f"{self._name} returned a non-JSON response (is {self._url} an OpenCTI URL?)."})
        if not r.is_success and not payload.get("errors"):
            raise _GraphQLError({"code": "HttpError", "message": f"{self._name} returned HTTP {r.status_code}."})
        errors = payload.get("errors") or []
        if errors:
            first = errors[0] if isinstance(errors[0], dict) else {}
            code = str((first.get("extensions") or {}).get("code") or "")
            if code in ("AUTH_REQUIRED", "UNAUTHENTICATED", "FORBIDDEN_ACCESS", "FORBIDDEN"):
                raise _GraphQLError({"code": "Unauthorized", "message": f"{self._name} rejected the API token ({code})."})
            raise _GraphQLError({"code": "ApiError", "message": f"{self._name}: {first.get('message') or code or 'GraphQL error'}"},
                                schema_mismatch=code == "GRAPHQL_VALIDATION_FAILED")
        return payload.get("data") or {}

    async def _query_versions(self, client: httpx.AsyncClient, variants: dict, variables: dict) -> dict:
        """The FULL document, or COMPAT if the server is too old for it."""
        try:
            return await self._query(client, variants["full"], variables)
        except _GraphQLError as e:
            if not e.schema_mismatch:
                raise
        return await self._query(client, variants["compat"], variables)

    # ── Normalisation ────────────────────────────────────────────────────────

    def _indicator(self, ind: dict, now: datetime) -> dict:
        return {
            "id": ind.get("id"),
            "name": ind.get("name"),
            "pattern": ind.get("pattern"),
            "pattern_type": ind.get("pattern_type"),
            "score": ind.get("x_opencti_score"),
            "detection": ind.get("x_opencti_detection"),
            "valid_until": ind.get("valid_until"),
            "revoked": ind.get("revoked") is True,
            "active": _is_active(ind, now),
            "types": [t for t in ind.get("indicator_types") or [] if isinstance(t, str)],
            "author": _author(ind),
            "labels": _labels(ind),
            "link": self._link(ind.get("id")),
        }

    def _entity(self, node: dict, value: str | None, description: str | None, score=None) -> dict:
        return {
            "id": node.get("id"),
            "type": node.get("entity_type"),
            "value": value,
            "description": description or "",
            "score": score,
            "created_at": node.get("created_at"),
            "updated_at": node.get("updated_at"),
            "author": _author(node),
            "labels": _labels(node),
            "markings": _markings(node),
            "link": self._link(node.get("id")),
        }

    def _context(self, data: dict, own_id: str, max_relations: int = _MAX_RELATIONS) -> dict:
        obj = data.get("stixCoreObject") if isinstance(data.get("stixCoreObject"), dict) else {}
        reports_conn = obj.get("reports") if isinstance(obj.get("reports"), dict) else {}
        reports = [{
            "name": r.get("name"),
            "published": r.get("published"),
            "types": [t for t in r.get("report_types") or [] if isinstance(t, str)],
            "author": _author(r),
            "link": self._link(r.get("id")),
        } for r in _edges(reports_conn)]
        total = (reports_conn.get("pageInfo") or {}).get("globalCount")
        relations, seen = [], set()
        for rel in _edges(obj.get("stixCoreRelationships")):
            outgoing = rel.get("fromId") == own_id
            other = rel.get("to") if outgoing else rel.get("from")
            if not isinstance(other, dict) or other.get("id") == own_id:
                continue
            name = (other.get("representative") or {}).get("main")
            key = (rel.get("relationship_type"), other.get("id"))
            if key in seen:
                continue
            seen.add(key)
            item = {
                "type": rel.get("relationship_type"),
                "direction": "out" if outgoing else "in",
                "entity_type": other.get("entity_type"),
                "name": name,
                "link": self._link(other.get("id")),
            }
            # Only in the actor context: ATT&CK id, observable value, indicator pattern.
            for k in ("x_mitre_id", "observable_value", "pattern", "x_opencti_main_observable_type"):
                if isinstance(other.get(k), str) and other[k]:
                    item[k] = other[k][:300]
            relations.append(item)
        return {
            "reports": reports,
            "reports_total": total if isinstance(total, int) else len(reports),
            "relations": relations[:max_relations],
            "relations_total": len(relations),
            "threat_links": sum(1 for r in relations if r["entity_type"] in _THREAT_TYPES),
        }

    # ── Lookups ──────────────────────────────────────────────────────────────

    async def _observable(self, client: httpx.AsyncClient, value: str, type: str) -> dict:
        now = datetime.now(timezone.utc)
        if type == "hash":
            h = value.lower()
            filters = _group([_filter(k, [h, value.upper()]) for k in _HASH_KEYS], mode="or")
        else:
            filters = _group([_filter("value", [value.lower() if type == "domain" else value])])
        data = await self._query(client, Q.OBSERVABLES, {"types": _OBSERVABLE_TYPES[type], "filters": filters})
        observables = _edges(data.get("stixCyberObservables"))
        obs = observables[0] if observables else None

        indicators: dict[str, dict] = {}
        for o in observables:
            for ind in _edges(o.get("indicators")):
                indicators[ind["id"]] = self._indicator(ind, now)
        # Indicators naming the value in their pattern, with or without an observable.
        needle = f"'{value.lower()}'"
        found = await self._query(client, Q.INDICATORS, {"search": value})
        for ind in _edges(found.get("indicators")):
            if needle in str(ind.get("pattern") or "").lower() and ind.get("id") not in indicators:
                indicators[ind["id"]] = self._indicator(ind, now)

        if not obs and not indicators:
            return {"found": False, "kind": "observable"}
        out = {
            "found": True,
            "kind": "observable" if obs else "indicator",
            "entity": self._entity(obs, obs.get("observable_value"), obs.get("x_opencti_description"),
                                   obs.get("x_opencti_score")) if obs else None,
            "indicators": sorted(indicators.values(), key=lambda i: (not i["active"], -(i["score"] or 0))),
        }
        out["indicators_active"] = sum(1 for i in out["indicators"] if i["active"])
        own_id = obs["id"] if obs else next(iter(indicators))
        out.update(self._context(await self._query(client, Q.CONTEXT, {"id": own_id}), own_id))
        return out

    async def _vulnerability(self, client: httpx.AsyncClient, value: str) -> dict:
        cve_id = normalize_cve(value)
        if not cve_id:
            return {"error": {"code": "BadRequest", "message": f"'{value}' is not a CVE identifier (expected CVE-YYYY-NNNN)."}}
        data = await self._query_versions(client, Q.VULNERABILITIES, {"filters": _group([_filter("name", [cve_id])])})
        vulns = _edges(data.get("vulnerabilities"))
        if not vulns:
            return {"found": False, "kind": "vulnerability"}
        v = vulns[0]
        out = {
            "found": True,
            "kind": "vulnerability",
            "entity": self._entity(v, v.get("name"), v.get("description"), v.get("x_opencti_score")),
            "indicators": [],
            "indicators_active": 0,
            "vulnerability": {
                "cvss_score": v.get("x_opencti_cvss_v4_base_score") or v.get("x_opencti_cvss_base_score"),
                "cvss_severity": v.get("x_opencti_cvss_v4_base_severity") or v.get("x_opencti_cvss_base_severity"),
                "cvss_version": "4.0" if v.get("x_opencti_cvss_v4_base_score") else "3.x",
                "cvss_vector": v.get("x_opencti_cvss_vector_string"),
                "kev": v.get("x_opencti_cisa_kev"),
                "epss": v.get("x_opencti_epss_score"),
                "epss_percentile": v.get("x_opencti_epss_percentile"),
                "cwe": [c for c in v.get("x_opencti_cwe") or [] if isinstance(c, str)],
                "ssvc_exploitation": v.get("x_opencti_ssvc_exploitation"),
                "aliases": [a for a in v.get("x_opencti_aliases") or [] if isinstance(a, str)],
            },
        }
        out.update(self._context(await self._query(client, Q.CONTEXT, {"id": v["id"]}), v["id"]))
        return out

    async def _actor(self, client: httpx.AsyncClient, value: str) -> dict:
        needle = value.strip()
        data = await self._query_versions(client, Q.ACTORS, {"search": needle})
        candidates = [n for n in _edges(data.get("stixDomainObjects")) if n.get("name")]
        norm = needle.casefold()
        exact = next((c for c in candidates
                      if norm in {str(x).casefold() for x in [c.get("name"), *(c.get("aliases") or [])]}), None)
        match = exact or (candidates[0] if candidates else None)
        if not match:
            return {"found": False, "kind": "actor"}
        out = {
            "found": True,
            "kind": "actor",
            "exact": exact is not None,
            "entity": self._entity(match, match.get("name"), match.get("description")),
            "indicators": [],
            "indicators_active": 0,
            "actor": {
                "aliases": [a for a in match.get("aliases") or [] if isinstance(a, str)],
                "first_seen": match.get("first_seen"),
                "last_seen": match.get("last_seen"),
                "motivation": match.get("primary_motivation"),
                "resource_level": match.get("resource_level"),
                "goals": [g for g in match.get("goals") or [] if isinstance(g, str)],
                "types": [t for t in match.get("threat_actor_types") or [] if isinstance(t, str)],
                "sophistication": match.get("sophistication"),
            },
        }
        out.update(self._context(await self._query(client, Q.ACTOR_CONTEXT, {"id": match["id"]}), match["id"], 300))
        return out

    async def dispatch(self, indicator: str, type: str) -> dict:
        if type not in SUPPORTED_TYPES:
            return {"error": {"code": "UnsupportedType", "message": f"{self._name} does not support type '{type}'."}}
        if not self._url or not self._inst["key"]:
            missing = "URL" if not self._url else "API token"
            return {"error": {"code": "MissingApiKey", "message": f"{self._name} is not fully configured (missing {missing})."}}
        cert = self._client_cert()
        if isinstance(cert, dict):
            return cert
        value = indicator.strip()
        headers = {"Authorization": f"Bearer {self._inst['key']}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self._inst["verify_ssl"], cert=cert,
                                         headers=headers) as client:
                if type == "cve":
                    out = await self._vulnerability(client, value)
                elif type == "threat-actor":
                    out = await self._actor(client, value)
                else:
                    out = await self._observable(client, value, type)
        except _GraphQLError as e:
            return {"error": e.error}
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": f"{self._name} request timed out after {_TIMEOUT} s."}}
        except ssl.SSLError as e:
            return {"error": {"code": "SSLError", "message": f"TLS error connecting to {self._name}: {e.reason or e}."}}
        except httpx.ConnectError:
            return {"error": {"code": "NetworkError", "message": f"Could not reach {self._name} ({self._url})."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": f"Could not reach {self._name}."}}
        return out


def engine_for(instance_id: str) -> OpenCTIEngine | None:
    """Engine bound to the instance's current settings (they can change at runtime)."""
    inst = connectors.get_instance("opencti", instance_id) if instance_id.startswith("opencti_") else None
    return OpenCTIEngine(inst) if inst else None
