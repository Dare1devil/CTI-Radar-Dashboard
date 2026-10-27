import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import collect
import sources

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def alert(cve="CVE-2026-12345", source="NIST NVD", category="NEW_CVE", priority=70, key="cve:CVE-2026-12345", severity="CVSS 9.8 / CRITICAL", url=None):
    return sources.Alert(key, category, source, "Important security flaw " + cve,
                         "Remote code execution in a sample software product", url or f"https://example.org/{cve}",
                         NOW - timedelta(hours=1), severity, "not confirmed", "check assets", priority, cve)


def empty_feed():
    return {"schema": 1, "items": [], "generated_at": None, "failed_sources": [], "source_status": {}}


class ModelTests(unittest.TestCase):
    def test_nvd_and_kev_merge_one_record(self):
        nvd=alert()
        kev=alert(source="CISA KEV", category="CONFIRMED_EXPLOITED", priority=100, key="kev:CVE-2026-12345",severity="Confirmed Exploited / CVSS unknown")
        feed=collect.build_feed(empty_feed(), {"NVD": [nvd], "CISA KEV": [kev]}, [], NOW)
        self.assertEqual(len(feed["items"]), 1)
        row=feed["items"][0]
        self.assertEqual(row["exploitation"], "confirmed")
        self.assertEqual(row["severity"], "Exploited")
        self.assertEqual(row["severity_detail"], "CVSS 9.8 / CRITICAL")
        self.assertEqual(set(row["sources"]), {"NIST NVD","CISA KEV"})

    def test_repeated_collection_does_not_duplicate(self):
        one=collect.build_feed(empty_feed(), {"NVD": [alert()]}, [], NOW)
        later=collect.build_feed(one, {"NVD": [alert()]}, [], NOW + timedelta(hours=1))
        self.assertEqual(len(later["items"]), 1)
        self.assertEqual(one["items"][0]["first_seen"], later["items"][0]["first_seen"])

    def test_different_cves_remain_distinct(self):
        feed=collect.build_feed(empty_feed(), {"NVD":[alert(), alert(cve="CVE-2026-88888",key="cve:CVE-2026-88888")]}, [], NOW)
        self.assertEqual(len(feed["items"]),2)

    def test_previously_seen_records_survive_source_failure(self):
        one=collect.build_feed(empty_feed(), {"NVD": [alert()]}, [], NOW)
        later=collect.build_feed(one, {"NVD": []}, ["NVD"], NOW+timedelta(hours=2))
        self.assertEqual(len(later["items"]),1)
        self.assertEqual(later["failed_sources"],["NVD"])

    def test_older_than_thirty_days_expires(self):
        old=collect.build_feed(empty_feed(), {"NVD": [alert()]}, [], NOW)
        result=collect.build_feed(old, {"NVD": []}, [], NOW+timedelta(days=32))
        self.assertEqual(result["items"],[])

    def test_https_only_links(self):
        self.assertEqual(collect.valid_url('javascript:alert(1)'), '')
        self.assertEqual(collect.valid_url('https://example.com/a'), 'https://example.com/a')
        self.assertEqual(collect.valid_url('https://a@b.com'), '')
        self.assertEqual(collect.valid_url('http://example.com/a'), '')

    def test_broken_feed_does_not_reset_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'feed.json'
            path.write_text('not json', encoding='utf-8')
            with self.assertRaises(json.JSONDecodeError):
                collect.read_feed(path)
            self.assertEqual(path.read_text(), 'not json')

    def test_lost_feed_not_silently_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                collect.read_feed(Path(directory)/'nonexistent.json')

    def test_source_html_xss_is_safe_plain_text(self):
        a=alert()
        a=sources.replace(a, title='<script>alert(1)</script>Important CVE')
        record=collect.record_from(a, collect.iso(NOW))
        self.assertNotIn('<script>',record['title'])

    def test_news_only_not_claimed_confirmed(self):
        item=alert(cve="",source="The Hacker News",category="BREAKING_SECURITY_NEWS",key="news:abc",priority=58, severity="News / research")
        record=collect.record_from(item, collect.iso(NOW))
        self.assertEqual(record["exploitation"],"unconfirmed")
        self.assertEqual(record["category"],"News")

    def test_same_news_title_with_different_urls_merges(self):
        title='Hackers exploit dangerous flaw in business VPN infrastructure'
        a=sources.replace(alert(cve="",key="news:a"),category="CYBER_NEWS",title=title,url="https://example.org/a")
        b=sources.replace(alert(cve="",key="news:b"),category="CYBER_NEWS",title=title,url="https://example.org/b")
        feed=collect.build_feed(empty_feed(),{"RSS":[a,b]},[],NOW)
        self.assertEqual(len(feed["items"]),1)
        self.assertEqual(len(feed["items"][0]["links"]),2)

    def test_partial_failure_keeps_all_successes(self):
        feed=collect.build_feed(empty_feed(),{"NVD":[alert()], "KEV":[]},["KEV"],NOW)
        self.assertEqual(feed['source_status']['NVD']['ok'],True)
        self.assertEqual(feed['source_status']['KEV']['ok'],False)

    def test_failed_sources_do_not_raise_in_collector_if_any_success(self):
        # All source fetchers mocked. Source failure must never empty archived results.
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'feed.json'
            previous=collect.build_feed(empty_feed(),{"NVD":[alert()]},[],NOW)
            path.write_text(json.dumps(previous),encoding='utf-8')
            with patch.object(collect,'DATA',path), patch.object(collect,'COLLECTORS',(("NVD",lambda now: (_ for _ in ()).throw(OSError("no network"))),("KEV",lambda now: []))), patch.object(collect.src,'fetch_news',return_value=([],[])), patch.object(collect.src,'add_epss',side_effect=lambda x:x):
                feed=collect.collect(NOW+timedelta(hours=1))
            self.assertEqual(len(feed['items']),1)

    def test_all_sources_down_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'feed.json'
            original=json.dumps(empty_feed())
            path.write_text(original)
            with patch.object(collect,'DATA',path), patch.object(collect,'COLLECTORS',(("NVD",lambda now: (_ for _ in ()).throw(OSError("no network"))),)), patch.object(collect.src,'fetch_news', side_effect=OSError('offline')):
                with self.assertRaises(RuntimeError):collect.collect(NOW)
            self.assertEqual(path.read_text(),original)

    def test_site_has_no_secrets(self):
        site=collect.ROOT/'site'
        contents=''.join(f.read_text(errors='ignore') for f in site.rglob('*') if f.is_file())
        for secret in ('TELEGRAM_BOT_TOKEN','TELEGRAM_CHAT_ID','NVD_API_KEY','OPENCVE_TOKEN'):
            self.assertNotIn(secret,contents)

    def test_frontend_avoids_innerhtml_injection(self):
        js=(collect.ROOT/'site/assets/app.js').read_text()
        self.assertNotIn('innerHTML', js)
        self.assertIn('textContent',js)

    def test_source_bounded_timeouts(self):
        self.assertLessEqual(max(sources.GET_TIMEOUT),12)
        self.assertLessEqual(sources.GET_MAX_ATTEMPTS,2)


if __name__=='__main__':unittest.main()
