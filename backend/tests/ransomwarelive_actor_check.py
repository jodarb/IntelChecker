"""ransomware.live group lookup for threat actors (app/services/ransomwarelive.py):
by name, by version ("LockBit 3.0"), and by the actor's MITRE ATT&CK aliases.

Offline: both catalogues come from tests/fixtures/actor_catalog.json.
Run from backend/:  .venv/bin/python -m unittest tests/ransomwarelive_actor_check.py
"""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import mitreattack, ransomwarelive as rl  # noqa: E402

CATALOG = json.loads((Path(__file__).parent / "fixtures" / "actor_catalog.json").read_text())
FRESH = 10 ** 12   # "fetched" far in the future: the caches never refresh in the test


def mitre_index() -> dict:
    index = {}
    for g in CATALOG["mitre"]:
        group = {"name": g["name"], "aliases": g["aliases"], "attack_id": g["attack_id"]}
        for n in [g["name"], *g["aliases"]]:
            index.setdefault(n.lower(), group)
    return index


class GroupLookupTest(unittest.TestCase):
    def setUp(self):
        groups = [{"name": g["name"], "altname": g.get("altname")} for g in CATALOG["ransomwarelive"]]
        for target, attrs in ((rl._groups, {"data": groups, "fetched_at": FRESH}),
                              (rl._feed, {"data": [], "fetched_at": FRESH})):
            for k, v in attrs.items():
                p = mock.patch.object(target, k, v)
                p.start()
                self.addCleanup(p.stop)
        for k, v in (("_index", mitre_index()), ("_fetched_at", FRESH)):
            p = mock.patch.object(mitreattack, k, v)
            p.start()
            self.addCleanup(p.stop)

    def lookup(self, q: str) -> dict:
        return asyncio.run(rl.lookup_group(q))

    def test_by_name(self):
        r = self.lookup("Akira")
        self.assertTrue(r["found"])
        self.assertEqual(r["groups"][0]["name"], "akira")
        self.assertNotIn("matched_alias", r)

    def test_by_mitre_alias(self):
        r = self.lookup("GOLD SAHARA")   # MITRE alias of Akira; no ransomware.live group has it
        self.assertTrue(r["found"])
        self.assertEqual(r["groups"][0]["name"], "akira")
        self.assertEqual(r["matched_alias"], {"alias": "Akira", "source": "MITRE ATT&CK"})
        self.assertEqual(r["query"], "GOLD SAHARA")

    def test_version_suffix(self):
        self.assertEqual(self.lookup("LockBit 3.0")["groups"][0]["name"], "lockbit3")

    def test_apt_without_leak_site_is_not_found(self):
        r = self.lookup("APT28")   # MITRE knows it, but none of its names is a ransomware group
        self.assertFalse(r["found"])

    def test_unknown_name(self):
        self.assertFalse(self.lookup("Zorblaxian Kettle")["found"])


if __name__ == "__main__":
    unittest.main()
