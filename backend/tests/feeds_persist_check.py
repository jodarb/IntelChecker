"""CachedFeed `persist`: the last good download survives a restart (app/core/feeds.py).

Offline: downloads are answered by an httpx.MockTransport.
Run from backend/:  .venv/bin/python -m unittest tests/feeds_persist_check.py
"""
import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import feeds  # noqa: E402

_RealClient = httpx.AsyncClient


def serve(status: int, body: str = "", calls: list | None = None):
    """Patch feeds' httpx.AsyncClient so every download gets this response."""
    def handler(request):
        if calls is not None:
            calls.append(str(request.url))
        return httpx.Response(status, text=body)
    return mock.patch.object(feeds.httpx, "AsyncClient",
                             lambda **kw: _RealClient(transport=httpx.MockTransport(handler), **kw))


def feed(ttl: int = 3600) -> feeds.CachedFeed:
    return feeds.CachedFeed("test", "https://example.invalid/list.json", ttl, json.loads, persist="test-list", retry_after=1800)


class PersistTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(feeds, "_DIR", Path(self.dir.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.dir.cleanup)

    def test_saves_and_restarts_without_downloading(self):
        with serve(200, '[1, 2, 3]'):
            f = feed()
            self.assertIsNone(asyncio.run(f.get()))
        self.assertTrue((Path(self.dir.name) / "test-list.gz").exists())
        calls = []
        with serve(500, calls=calls):   # "restart": a new instance, the copy is still fresh
            g = feed()
            self.assertIsNone(asyncio.run(g.get()))
        self.assertEqual(g.data, [1, 2, 3])
        self.assertEqual(g.size, 3)
        self.assertEqual(calls, [])
        self.assertAlmostEqual(g.fetched_at, f.fetched_at, delta=1)

    def test_stale_copy_is_served_when_the_refresh_is_rate_limited(self):
        with serve(200, '["old"]'):
            asyncio.run(feed().get())
        calls = []
        with serve(429, calls=calls):
            g = feed(ttl=0)   # the saved copy is past its TTL: refresh, which fails
            self.assertIsNone(asyncio.run(g.get()))
        self.assertEqual(len(calls), 1)
        self.assertEqual(g.data, ["old"])

    def test_stale_copy_is_replaced_by_a_new_download(self):
        with serve(200, '["old"]'):
            asyncio.run(feed().get())
        with serve(200, '["new"]'):
            g = feed(ttl=0)
            asyncio.run(g.get())
        self.assertEqual(g.data, ["new"])
        with serve(500):
            self.assertEqual((asyncio.run(_load(feed()))), ["new"])

    def test_no_copy_and_no_download_reports_the_error(self):
        with serve(429):
            err = asyncio.run(feed().get())
        self.assertEqual(err["error"]["code"], "RateLimitExceeded")

    def test_corrupt_copy_is_ignored(self):
        (Path(self.dir.name) / "test-list.gz").write_bytes(b"not gzip")
        with serve(200, '[9]'):
            g = feed()
            self.assertIsNone(asyncio.run(g.get()))
        self.assertEqual(g.data, [9])

    def test_feeds_without_persist_write_nothing(self):
        with serve(200, '[1]'):
            asyncio.run(feeds.CachedFeed("plain", "https://example.invalid/x", 3600, json.loads).get())
        self.assertEqual(list(Path(self.dir.name).iterdir()), [])


async def _load(f: feeds.CachedFeed):
    await f.get()
    return f.data


if __name__ == "__main__":
    unittest.main()
