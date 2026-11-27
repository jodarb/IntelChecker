"""Companies are not scored (app/core/verdict.py and the history endpoints in app/main.py).

Run from backend/:  .venv/bin/python -m unittest tests/company_unscored_check.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.verdict import compute_verdict  # noqa: E402
from app.core.weights import get_weights  # noqa: E402
from app.main import _unscored_company  # noqa: E402


class CompanyUnscoredTest(unittest.TestCase):
    def test_verdict_is_empty_for_companies(self):
        results = {"hudsonrock": {"data": {"found": True, "employees": 12}, "error": None}}
        v = compute_verdict(get_weights(), [{"id": "hudsonrock", "label": "Hudson Rock"}], results, "company")
        self.assertEqual((v["risk"], v["knowledge"], v["quadrant"]), (None, None, None))
        self.assertEqual(v["contributions"], {"risk": [], "knowledge": []})

    def test_old_company_entries_lose_their_stored_score(self):
        old = {"id": 9, "type": "company", "score": 9, "knowledge_score": 9, "quadrant": "confirmed_malicious",
               "contributions": {"risk": [{"engineId": "x"}], "knowledge": []}}
        e = _unscored_company(old)
        self.assertEqual((e["score"], e["knowledge_score"], e["quadrant"]), (None, None, None))
        self.assertEqual(e["contributions"], {"risk": [], "knowledge": []})
        self.assertEqual(old["score"], 9)   # the stored entry itself is not modified

    def test_other_types_keep_their_scores(self):
        ip = {"id": 1, "type": "ip", "score": 8, "knowledge_score": 7, "quadrant": "confirmed_malicious"}
        self.assertIs(_unscored_company(ip), ip)


if __name__ == "__main__":
    unittest.main()
