#!/usr/bin/env python3
"""Collect security advisories into a durable, deduplicated static dashboard feed."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import sources as src

LOG = logging.getLogger("cti-dashboard")
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "site" / "data" / "feed.json"
ITEM_LIMIT = 2500
RETENTION_DAYS = 30
COLLECTORS = (
    ("CISA KEV", src.fetch_cisa_kev),
    ("NIST NVD", src.fetch_nvd),
    ("Apple Security Releases", src.fetch_apple),
    ("Saudi CERT", src.fetch_saudi_cert),
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def valid_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password else ""
    except ValueError:
        return ""


def severity_from_alert(a: src.Alert) -> str:
    if a.category == "CONFIRMED_EXPLOITED":
        return "Exploited"
    cvss = re.search(r"CVSS\s+(\d+(?:\.\d+)?)", a.severity, re.I)
    if cvss:
        val = float(cvss.group(1))
        if val >= 9.0:
            return "Critical"
        if val >= 7.0:
            return "High"
        if val >= 4.0:
            return "Medium"
        return "Low"
    if "critical" in a.severity.casefold():
        return "Critical"
    if "high" in a.severity.casefold():
        return "High"
    return "Unrated"


def canonical_id(a: src.Alert) -> str:
    if a.cve and src.CVE_RE.fullmatch(a.cve):
        # Multiple intelligence sources for the same CVE => one card.
        return "cve:" + a.cve.upper()
    if a.key.startswith("news:"):
        norm = re.sub(r"\W+", " ", a.title.casefold()).strip()
        if len(norm) >= 28 and len(norm.split()) >= 5:
            return "story:" + hashlib.sha256(norm.encode("utf-8")).hexdigest()[:24]
    return a.key


def display_group(a: src.Alert) -> str:
    if a.category == "CONFIRMED_EXPLOITED":
        return "KEV"
    if a.category in {"NEW_CVE", "REPORTED_EXPLOITATION"}:
        return "CVE"
    if a.category == "VENDOR_ADVISORY":
        return "Advisory"
    if a.category == "EXPLOIT_RESEARCH":
        return "Research"
    return "News"


def record_from(a: src.Alert, timestamp: str) -> dict:
    return {
        "id": canonical_id(a),
        "title": src.clean(a.title, 210),
        "summary": src.clean(a.detail, 900),
        "category": display_group(a),
        "source": a.source,
        "sources": [a.source],
        "url": valid_url(a.url),
        "links": ([{"source": a.source, "url": valid_url(a.url)}] if valid_url(a.url) else []),
        "published": iso(a.published),
        "first_seen": timestamp,
        "last_seen": timestamp,
        "severity": severity_from_alert(a),
        "severity_detail": src.clean(a.severity, 110),
        "exploitation": "confirmed" if a.category == "CONFIRMED_EXPLOITED" else "reported" if a.category == "REPORTED_EXPLOITATION" else "unconfirmed",
        "exploitation_note": src.clean(a.exploitation, 250),
        "cve": a.cve.upper() if a.cve and src.CVE_RE.fullmatch(a.cve) else "",
        "priority": a.priority,
        "epss": src.clean(a.epss, 30),
        "soc_actions": src.soc_recommendations(a),
    }


def merge_record(previous: dict, incoming: dict) -> dict:
    """Do not degrade KEV to NVD, or lose original first_seen or sources."""
    result = dict(previous)
    result["last_seen"] = incoming["last_seen"]
    result["sources"] = sorted(set(previous.get("sources", []) + incoming.get("sources", [])))
    links = previous.get("links", []) + incoming.get("links", [])
    dedup = {}
    for link in links:
        url = valid_url(link.get("url", ""))
        if url:
            dedup[url] = {"source": str(link.get("source", "Reference"))[:70], "url": url}
    result["links"] = list(dedup.values())[:8]
    higher = incoming["priority"] > previous.get("priority", 0)
    # Preserve more informative vendor/NVD data when KEV includes only generic text.
    for field in ("title", "summary", "source", "url", "category", "exploitation_note", "soc_actions"):
        if higher and incoming.get(field):
            result[field] = incoming[field]
    if incoming["exploitation"] == "confirmed":
        result["exploitation"] = "confirmed"
        result["category"] = "KEV"
        result["severity"] = "Exploited"
        result["exploitation_note"] = incoming["exploitation_note"]
        result["priority"] = max(100, result.get("priority", 0))
        result["soc_actions"] = incoming["soc_actions"]
    elif result.get("exploitation") != "confirmed" and incoming["exploitation"] == "reported":
        result["exploitation"] = "reported"
    if result.get("severity") not in {"Exploited", "Critical", "High", "Medium", "Low"} and incoming["severity"] != "Unrated":
        result["severity"] = incoming["severity"]
    if incoming.get("severity_detail", "").startswith("CVSS"):
        result["severity_detail"] = incoming["severity_detail"]
    if incoming.get("epss"):
        result["epss"] = incoming["epss"]
    result["priority"] = max(previous.get("priority", 0), incoming["priority"])
    if incoming.get("cve") and not result.get("cve"):
        result["cve"] = incoming["cve"]
    return result


def read_feed(path: Path | None = None) -> dict:
    path = path or DATA
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}; preserve the previous dashboard data")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or obj.get("schema") != 1 or not isinstance(obj.get("items"), list):
        raise ValueError("Invalid feed schema; refusing to overwrite existing data")
    ids = [r.get("id") for r in obj["items"] if isinstance(r, dict)]
    if len(set(ids)) != len(ids) or len(ids) != len(obj["items"]):
        raise ValueError("Invalid/duplicate feed records; refusing to overwrite")
    return obj


def build_feed(previous: dict, groups: dict[str, list[src.Alert]], failures: list[str], timestamp: datetime) -> dict:
    """Pure data merge. Keeps previous records when a source fails."""
    ts = iso(timestamp)
    keep_since = timestamp - timedelta(days=RETENTION_DAYS)
    existing: dict[str, dict] = {}
    for entry in previous["items"]:
        published = src.parse_date(entry.get("published"))
        if published is not None and published >= keep_since:
            existing[entry["id"]] = dict(entry)
    total = 0
    for name, alerts in groups.items():
        for a in alerts:
            if not a.title or not valid_url(a.url):
                continue
            item = record_from(a, ts)
            key = item["id"]
            existing[key] = merge_record(existing[key], item) if key in existing else item
            total += 1
    # No ranking truncation until after all sources have been merged.
    rows = sorted(existing.values(), key=lambda r: (r.get("priority", 0), r.get("published", "")), reverse=True)[:ITEM_LIMIT]
    return {
        "schema": 1,
        "generated_at": ts,
        "source_status": {k: {"ok": k not in failures, "count": len(v)} for k, v in groups.items()},
        "failed_sources": list(dict.fromkeys(failures)),
        "last_collection_candidates": total,
        "items": rows,
    }


def collect(timestamp: datetime | None = None) -> dict:
    timestamp = timestamp or now_utc()
    previous = read_feed()
    groups: dict[str, list[src.Alert]] = {}
    failed: list[str] = []
    for label, fn in COLLECTORS:
        try:
            rows = fn(timestamp)
            groups[label] = rows
            LOG.info("%s => %d records", label, len(rows))
        except Exception as exc:
            groups[label] = []
            failed.append(label)
            LOG.warning("%s unavailable: %s", label, type(exc).__name__)
    # Feeds are isolated within the source module. Do not infer success from zero items.
    try:
        rows, news_errors = src.fetch_news(timestamp)
        groups["Security News & Research"] = rows
        failed.extend(news_errors)
        if len(news_errors) >= len(src.RSS_FEEDS) + len(src.read_opml()):
            failed.append("Security News & Research")
        LOG.info("News/research => %d, failed feeds => %d", len(rows), len(news_errors))
    except Exception as exc:
        groups["Security News & Research"] = []
        failed.append("Security News & Research")
        LOG.warning("News/research unavailable: %s", type(exc).__name__)
    try:
        if os.getenv("OPENCVE_TOKEN"):
            groups["OpenCVE"] = src.fetch_opencve(timestamp)
        if os.getenv("VULNCHECK_API_TOKEN"):
            groups["VulnCheck"] = src.fetch_vulncheck(timestamp)
    except Exception as exc:
        LOG.warning("Optional intelligence source unavailable: %s", type(exc).__name__)
        failed.append("Optional Intelligence")
    success_count = sum(k not in failed for k in groups)
    if success_count == 0:
        raise RuntimeError("All sources failed. Previous feed preserved (fail closed).")
    # Avoid extra dependency for EPSS; optional enrichment failures are ignored.
    all_alerts = [a for batch in groups.values() for a in batch]
    enriched = src.add_epss(all_alerts)
    if len(enriched) == len(all_alerts):
        positions = 0
        for k, rows in groups.items():
            groups[k] = enriched[positions:positions + len(rows)]
            positions += len(rows)
    next_feed = build_feed(previous, groups, failed, timestamp)
    DATA.parent.mkdir(parents=True, exist_ok=True)
    tmp = DATA.with_suffix(".tmp")
    tmp.write_text(json.dumps(next_feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(DATA)
    LOG.info("Wrote %d deduplicated items; %d source failures", len(next_feed["items"]), len(failed))
    return next_feed


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect CTI sources and build static dashboard feed")
    parser.add_argument("--check", action="store_true", help="Validate existing JSON without fetching")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.check:
        obj = read_feed()
        print(f"Validated: {len(obj['items'])} items; last run={obj.get('generated_at')}")
    else:
        collect()


if __name__ == "__main__":
    main()
