"""Regression tests for concurrent GitHub feed archival."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("merge_feed", ROOT / "scripts" / "merge_feed.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def item(i, p=30, exploitation="unconfirmed", s="Vendor", date="2026-10-27T10:00:00Z"):
    return dict(id=i, title=i, summary="text", category="CVE", source=s, sources=[s], url="https://example.com/"+i,
                links=[{"source":s,"url":"https://example.com/"+i}], published=date,
                first_seen=date, last_seen=date, priority=p, exploitation=exploitation,
                severity="Critical", severity_detail="CVSS 9.8", exploitation_note="", cve=i, epss="", soc_actions=[])


def feed(records, date="2026-10-27T10:00:00Z"):
    return dict(schema=1, generated_at=date, source_status={"NVD":{"ok":True,"count":len(records)}},
                failed_sources=[], last_collection_candidates=len(records), items=records)


class MergeFeedTests(unittest.TestCase):
    def test_unions_additions_from_two_runs(self):
        result=m.merge(feed([item("CVE-2026-0001")]),feed([item("CVE-2026-0002")]))
        self.assertEqual({x["id"] for x in result["items"]},{"CVE-2026-0001","CVE-2026-0002"})

    def test_same_cve_kept_once_and_kev_priority(self):
        a=item("cve:2026-1")
        b=item("cve:2026-1", 120, "confirmed", "CISA")
        result=m.merge(feed([a]), feed([b]))
        self.assertEqual(len(result["items"]),1)
        self.assertEqual(result["items"][0]["exploitation"],"confirmed")
        self.assertEqual(result["items"][0]["severity"],"Exploited")
        self.assertEqual(result["items"][0]["sources"],["CISA","Vendor"])

    def test_newer_status_wins(self):
        old=feed([item("a")], "2026-10-27T09:00:00Z")
        new=feed([item("b")], "2026-10-27T11:00:00Z")
        self.assertEqual(m.merge(old,new)["generated_at"],new["generated_at"])

    def test_corrupted_or_missing_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"feed.json"
            p.write_text('{bad json',encoding='utf8')
            with self.assertRaises(json.JSONDecodeError):
                m.load(p)
            p.unlink()
            with self.assertRaises(FileNotFoundError):
                m.load(p)

    def test_roundtrip_cli_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            existing=d/"feed.json"
            incoming=d/"incoming.json"
            existing.write_text(json.dumps(feed([item("a")])),encoding='utf8')
            incoming.write_text(json.dumps(feed([item("a"),item("b")])),encoding='utf8')
            completed=subprocess.run([sys.executable,str(ROOT/'scripts'/'merge_feed.py'),'--existing',str(existing),'--incoming',str(incoming),'--output',str(existing)],capture_output=True,text=True)
            self.assertEqual(completed.returncode,0, completed.stderr)
            self.assertEqual(len(m.load(existing)["items"]),2)

    def test_recent_items_kept_old_items_expire(self):
        old=item("old", date="2026-07-01T10:00:00Z")
        recent=item("recent")
        self.assertEqual([x["id"] for x in m.merge(feed([old,recent]),feed([]))["items"]],["recent"])


if __name__ == '__main__':
    unittest.main()
