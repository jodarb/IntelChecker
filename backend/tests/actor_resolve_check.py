"""Pinned candidates for GET /actor/resolve (app/core/actor.py), so that changes to the
scoring or the merging don't make the Actors search box worse.

Offline: the MITRE ATT&CK and ransomware.live catalogues come from a snapshot of their
names and aliases (tests/fixtures/actor_catalog.json) and Malpedia / Recorded Future
answer from canned rows shaped like their search APIs.

Run from backend/:  .venv/bin/python -m unittest tests/actor_resolve_check.py
"""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import actor  # noqa: E402

CATALOG = json.loads((Path(__file__).parent / "fixtures" / "actor_catalog.json").read_text())


async def _mitre(q: str) -> list[dict]:
    out = []
    for g in CATALOG["mitre"]:
        names = list(dict.fromkeys([g["name"], *g["aliases"]]))
        if (s := actor.score(q, names)):
            out.append({"source": "MITRE ATT&CK", "name": g["name"], "names": names, "score": s,
                        "description": None, "mitre_id": g["attack_id"]})
    return out


async def _ransomwarelive(q: str) -> list[dict]:
    out = []
    for g in CATALOG["ransomwarelive"]:
        names = [n.strip() for n in [g["name"], *actor.re.split(r"[/,;|]", g.get("altname") or "")] if n and n.strip()]
        if (s := actor.score(q, names)):
            out.append({"source": "ransomware.live", "name": g["name"], "names": names, "score": s,
                        "description": None, "ransomware": True, "victims": None})
    return out


# What Malpedia's /find/actor and RF's /threat/actor/search return for a term (as typed).
MALPEDIA = {
    "thegentlemen": [{"common_name": "The Gentlemen", "synonyms": ["GOLD SHERWOOD", "Storm-2697"]}],
    "apt28": [{"common_name": "APT28", "synonyms": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"]}],
    "fancybear": [{"common_name": "APT28", "synonyms": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"]}],
    "akira": [{"common_name": "Storm-1567", "synonyms": ["Akira", "PUNK SPIDER"]}],
    "play": [{"common_name": "PLAY", "synonyms": ["Balloonfly", "PlayCrypt"]}],
    "scatteredspider": [{"common_name": "Scattered Spider", "synonyms": ["Octo Tempest", "UNC3944", "0ktapus"]}],
}
RF = {
    "gentleman": [
        {"name": "Gentleman", "categories": ["Underground Forum Member", "Financially Motivated"]},
        {"name": "gentleman07", "categories": []},
    ],
    "thegentlemen": [{"name": "The Gentlemen Ransomware Group", "common_names": ["The Gentlemen"],
                      "categories": ["Ransomware and Extortion Groups"]}],
    "apt28": [{"name": "APT28", "alias": ["Fancy Bear", "APT 28", "Sofacy"], "categories": ["Nation State Sponsored Threat Groups"]}],
    "akira": [{"name": "Akira Ransomware Group", "common_names": ["Akira"], "categories": ["Ransomware and Extortion Groups"]}],
    "lockbit": [{"name": "LockBit Gang", "common_names": ["LockBit", "LockBit 3.0"], "categories": ["Ransomware and Extortion Groups"]}],
}


async def _malpedia(_client, q: str) -> list[dict]:
    return [{"source": "Malpedia", "name": a["common_name"], "names": [a["common_name"], *a["synonyms"]],
             "score": max(actor.score(q, [a["common_name"], *a["synonyms"]]), 50)} for a in MALPEDIA.get(actor.key(q), [])]


async def _recordedfuture(_client, q: str) -> list[dict]:
    out = []
    for a in RF.get(actor.key(q), []):
        names = [a["name"], *a.get("common_names", []), *a.get("alias", [])]
        cats = a["categories"]
        out.append({"source": "Recorded Future", "name": a["name"], "names": names, "score": max(actor.score(q, names), 50),
                    "categories": cats, "persona": any("Forum Member" in c or "Community Member" in c for c in cats)})
    return out


def resolve(q: str) -> list[dict]:
    with mock.patch.multiple(actor, _mitre=_mitre, _ransomwarelive=_ransomwarelive,
                             _malpedia=_malpedia, _recordedfuture=_recordedfuture):
        return asyncio.run(actor.resolve(q))["candidates"]


def actors(cands: list[dict]) -> list[dict]:
    """The candidates listed as actors (not the minor RF-only handles listed after)."""
    return [c for c in cands if not c["minor"]]


class ResolveTest(unittest.TestCase):
    def test_gentleman_finds_the_gentlemen_and_lists_the_rf_persona_apart(self):
        cands = resolve("Gentleman")
        top = cands[0]
        self.assertEqual(top["name"], "The Gentlemen")
        self.assertFalse(top["minor"])
        self.assertEqual(top["sources"], ["MITRE ATT&CK", "Malpedia", "Recorded Future", "ransomware.live"])
        self.assertTrue(top["ransomware"])
        self.assertIn("Storm-2697", top["aliases"])
        persona = next(c for c in cands if c["name"] == "Gentleman")
        self.assertTrue(persona["persona"] and persona["minor"])
        self.assertEqual(persona["sources"], ["Recorded Future"])
        # RF handles without a group category go after the actors, never merged with them.
        self.assertEqual([c["name"] for c in actors(cands)], ["The Gentlemen"])

    def test_alias_fancy_bear_resolves_to_apt28(self):
        cands = resolve("fancy bear")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["name"], "APT28")
        self.assertEqual(cands[0]["mitre_id"], "G0007")
        self.assertEqual(cands[0]["sources"], ["MITRE ATT&CK", "Malpedia", "Recorded Future"])
        self.assertNotIn("APT28", cands[0]["aliases"])

    def test_typo_akria_finds_akira(self):
        cands = resolve("akria")
        self.assertEqual(cands[0]["name"], "Akira")
        self.assertEqual(cands[0]["sources"], ["MITRE ATT&CK", "Malpedia", "Recorded Future", "ransomware.live"])
        self.assertEqual(len(actors(cands)), 1)

    def test_short_common_name_play_puts_the_group_first(self):
        cands = resolve("Play")
        self.assertEqual(cands[0]["name"], "Play")
        self.assertEqual(cands[0]["score"], 100)
        self.assertEqual(cands[0]["sources"], ["MITRE ATT&CK", "Malpedia", "ransomware.live"])
        # "Playful Dragon" (Ke3chang) is a weaker, separate candidate, not merged into Play.
        others = {c["name"]: c for c in cands[1:]}
        self.assertIn("Ke3chang", others)
        self.assertLess(others["Ke3chang"]["score"], 100)

    def test_partial_name_scattered_finds_scattered_spider(self):
        cands = resolve("scattered")
        self.assertEqual([c["name"] for c in cands], ["Scattered Spider"])
        self.assertIn("UNC3944", cands[0]["aliases"])

    def test_lockbit_puts_the_brand_first_then_its_versions(self):
        cands = resolve("lockbit")
        self.assertEqual(cands[0]["name"], "LockBit")
        self.assertEqual(cands[0]["score"], 100)
        self.assertIn("ransomware.live", cands[0]["sources"])
        self.assertTrue({"lockbit3", "lockbit5"} <= {c["name"] for c in cands[1:]})

    def test_lockbit_3_0_finds_lockbit3(self):
        self.assertEqual(resolve("LockBit 3.0")[0]["name"], "lockbit3")

    def test_unknown_name_has_no_candidates(self):
        self.assertEqual(resolve("Zorblaxian Kettle"), [])


class ScoreTest(unittest.TestCase):
    def test_score_levels(self):
        self.assertEqual(actor.score("APT 28", ["APT28"]), 100)
        self.assertGreaterEqual(actor.score("scattered", ["Scattered Spider"]), 70)
        self.assertEqual(actor.score("akria", ["Akira"]), 50)          # swapped letters: one edit
        self.assertEqual(actor.score("gentleman", ["thegentlemen"]), 50)
        self.assertEqual(actor.score("apt", ["APT28"]), 78)            # contained (3+ letters)
        self.assertEqual(actor.score("ap", ["APT28"]), 0)              # shorter: exact only
        # A short query with a typo is compared with whole words, not inside longer names.
        self.assertEqual(actor.score("akria", ["Akira Group"]), 50)
        self.assertEqual(actor.score("akria", ["makiradomains"]), 0)


if __name__ == "__main__" and "--show" in sys.argv:
    for q in sys.argv[sys.argv.index("--show") + 1:]:
        print(f"== {q}")
        for c in resolve(q):
            print(f"   {c['score']:3} {'minor ' if c['minor'] else ''}{'persona ' if c['persona'] else ''}{c['name']!r} {c['sources']} {c['aliases'][:5]}")
    sys.exit()

if __name__ == "__main__":
    unittest.main()
