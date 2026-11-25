import asyncio
import os
import ssl
import httpx

from app.core import config, connectors

_SUPPORTED_TYPES = ("ip", "domain", "url", "hash")


class MispEngine:
    """Dispatch bound to one configured MISP instance.

    Unlike the other services (one module = one fixed API), MISP can have any
    number of user-defined instances, so each instance gets its own MispEngine
    at startup instead of its own module.
    """

    def __init__(self, instance: dict):
        self._instance = instance

    def _build_client_cert(self):
        """Returns an httpx `cert=` value, None, or an error dict if a configured
        cert file is missing. Some MISP instances (mTLS) reject the connection
        with an SSL alert unless the client presents a certificate on connect."""
        name = self._instance["name"]
        client_cert = config.cert_path(self._instance.get("client_cert", ""))
        client_key = config.cert_path(self._instance.get("client_key", ""))

        if not client_cert:
            return None

        files_to_check = [(client_cert, "client certificate")]
        if client_key:
            files_to_check.append((client_key, "client key"))

        for path, label in files_to_check:
            if not os.path.isfile(path):
                return {"error": {"code": "MissingCertificate", "message": f"{name}'s {label} file was not found at {path}. Drop it in backend/certs/ and select it again on the Connectors page."}}

        return (client_cert, client_key) if client_key else client_cert

    async def _fetch_event(self, client: httpx.AsyncClient, base_url: str, key: str, event_id: str) -> dict | None:
        """Fetches the full event an attribute belongs to, so we can show its
        own info and tags (e.g. TLP, threat-actor galaxy clusters) — data the
        lightweight `Event` object nested in an attributes/restSearch hit doesn't
        carry. Returns None on any failure (missing read access to the event's
        sharing group, deleted event, etc.) so a single bad event doesn't fail
        the whole lookup — the attribute-level info is still shown either way.
        """
        try:
            r = await client.get(
                f"{base_url}/events/view/{event_id}",
                headers={"Authorization": key, "Accept": "application/json"},
            )
        except httpx.RequestError:
            return None
        if not r.is_success:
            return None
        try:
            event = r.json().get("Event")
        except ValueError:
            return None
        if not isinstance(event, dict):
            return None

        tags = event.get("Tag", [])
        if not isinstance(tags, list):
            tags = []

        return {
            "id": event.get("id"),
            "info": event.get("info"),
            "date": event.get("date"),
            "threat_level_id": event.get("threat_level_id"),
            "analysis": event.get("analysis"),
            "published": event.get("published"),
            "org": (event.get("Orgc") or {}).get("name"),
            "Tag": [
                {"name": t.get("name"), "colour": t.get("colour")}
                for t in tags if isinstance(t, dict) and t.get("name")
            ],
        }

    async def dispatch(self, indicator: str, type: str) -> dict:
        name = self._instance["name"]

        if type not in _SUPPORTED_TYPES:
            return {"error": {"code": "UnsupportedType", "message": f"{name} does not support type '{type}'."}}

        url = self._instance["url"]
        key = self._instance["key"]
        if not url or not key:
            missing = "URL" if not url else "API key"
            return {"error": {"code": "MissingApiKey", "message": f"{name} is not fully configured (missing {missing})."}}

        cert = self._build_client_cert()
        if isinstance(cert, dict):  # error
            return cert

        async with httpx.AsyncClient(timeout=20, verify=self._instance["verify_ssl"], cert=cert) as client:
            try:
                r = await client.post(
                    f"{url}/attributes/restSearch",
                    json={"returnFormat": "json", "value": indicator},
                    headers={
                        "Authorization": key,
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                )
            except httpx.TimeoutException:
                return {"error": {"code": "Timeout", "message": f"{name} request timed out after 20 s."}}
            except httpx.ConnectError:
                return {"error": {"code": "NetworkError", "message": f"Could not reach {name} ({url})."}}
            except ssl.SSLError as e:
                # Not always wrapped into an httpx exception — e.g. a mid-handshake
                # "certificate required" alert from a server expecting mTLS surfaces
                # as a raw ssl.SSLError instead of httpx.ConnectError.
                return {"error": {"code": "SSLError", "message": f"TLS error connecting to {name}: {e.reason or e}."}}
            except httpx.RequestError:
                return {"error": {"code": "NetworkError", "message": f"Could not reach {name}."}}

        if r.status_code in (401, 403):
            return {"error": {"code": "Unauthorized", "message": f"Invalid API key for {name}."}}
        if r.status_code == 429:
            return {"error": {"code": "RateLimitExceeded", "message": f"{name} rate limit exceeded."}}
        if not r.is_success:
            return {"error": {"code": "HttpError", "message": f"{name} returned HTTP {r.status_code}."}}

        try:
            payload = r.json()
        except ValueError:
            return {"error": {"code": "ApiError", "message": f"{name} returned a non-JSON response."}}

        attributes = payload.get("response", {}).get("Attribute", [])
        if not isinstance(attributes, list):
            attributes = []

        # Embed a ready-to-click event link per attribute — the frontend doesn't
        # know each instance's base URL, only this service does.
        for attr in attributes:
            event_id = attr.get("event_id")
            if event_id:
                attr["event_url"] = f"{url}/events/view/{event_id}"

        # Fetch each distinct parent event once (several attributes commonly share
        # the same event) to surface its own info and tags — e.g. TLP marking or
        # threat-actor galaxy clusters — not just the attribute-level ones.
        event_ids = sorted({a.get("event_id") for a in attributes if a.get("event_id")})
        events: dict[str, dict] = {}
        if event_ids:
            async with httpx.AsyncClient(timeout=20, verify=self._instance["verify_ssl"], cert=cert) as client:
                fetched = await asyncio.gather(
                    *(self._fetch_event(client, url, key, eid) for eid in event_ids)
                )
            events = {eid: ev for eid, ev in zip(event_ids, fetched) if ev is not None}

        return {"Attribute": attributes, "Events": events}


def engine_for(instance_id: str) -> MispEngine | None:
    """Engine bound to the instance's current settings (they can change at runtime)."""
    inst = connectors.get_misp(instance_id)
    return MispEngine(inst) if inst else None
