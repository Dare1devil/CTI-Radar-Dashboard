#!/usr/bin/env python3
"""Safely reconcile a collected CTI snapshot with the current GitHub archive.

This operates on local JSON files; it does not fetch sources or send alerts.
It merges rather than rebases the generated feed, preventing conflict in feed.json.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_ITEMS = 2500
RETENTION_DAYS = 30


def stamp(value: str | None) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Expected ISO timestamp, got: {value!r}")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("Timestamp must include a UTC offset")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Bad timestamp: {value!r}") from exc


def load(path: Path) -> dict:
    """Fail closed on missing, corrupt, or duplicate-ID archives."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or obj.get("schema") != 1 or not isinstance(obj.get("items"), list):
        raise ValueError(f"Invalid feed schema: {path}")
    ids = set()
    for item in obj["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError(f"Invalid record in {path}")
        if item["id"] in ids:
            raise ValueError(f"Duplicate feed ID: {item['id']}")
        ids.add(item["id"])
    if obj.get("generated_at") is not None:
        stamp(obj["generated_at"])
    return obj


def safe_https(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
    except (ValueError, TypeError):
        return False


def rank(item: dict) -> tuple[float, int, str]:
    return (
        float(item.get("priority") or 0),
        int(item.get("exploitation") == "confirmed"),
        str(item.get("last_seen") or ""),
    )


def merge_item(a: dict, b: dict) -> dict:
    """Preserve the highest-priority finding and union its evidence."""
    winner, loser = (a, b) if rank(a) >= rank(b) else (b, a)
    result = dict(winner)
    for key, value in loser.items():
        if key not in result or result[key] in (None, "", []):
            result[key] = value

    for field, default in (("first_seen", ""), ("last_seen", "")):
        stamps = [x.get(field) for x in (a, b) if x.get(field)]
        if stamps:
            values = sorted(stamps, key=stamp)
            result[field] = values[0] if field == "first_seen" else values[-1]

    result["priority"] = max(float(a.get("priority") or 0), float(b.get("priority") or 0))
    result["sources"] = sorted(set(str(x) for x in (a.get("sources") or []) + (b.get("sources") or []) if x))
    links = {}
    for item in (a, b):
        for link in item.get("links") or []:
            if isinstance(link, dict) and safe_https(link.get("url", "")):
                links[link["url"]] = {"source": str(link.get("source") or "Reference")[:70], "url": link["url"]}
        if safe_https(item.get("url", "")):
            links.setdefault(item["url"], {"source": str(item.get("source") or "Reference")[:70], "url": item["url"]})
    result["links"] = list(links.values())[:8]

    if a.get("exploitation") == "confirmed" or b.get("exploitation") == "confirmed":
        result["exploitation"] = "confirmed"
        result["category"] = "KEV"
        result["severity"] = "Exploited"
        result["priority"] = max(100, result["priority"])
    elif a.get("exploitation") == "reported" or b.get("exploitation") == "reported":
        result["exploitation"] = "reported"
    return result


def merge(existing: dict, incoming: dict) -> dict:
    current_stamp = stamp(existing["generated_at"]) if existing.get("generated_at") else datetime.min.replace(tzinfo=timezone.utc)
    incoming_stamp = stamp(incoming["generated_at"]) if incoming.get("generated_at") else datetime.min.replace(tzinfo=timezone.utc)
    latest = incoming if incoming_stamp >= current_stamp else existing
    archive = {}
    for record in existing["items"] + incoming["items"]:
        item_id = record["id"]
        archive[item_id] = merge_item(archive[item_id], record) if item_id in archive else dict(record)

    newest = max(current_stamp, incoming_stamp)
    cutoff = newest - timedelta(days=RETENTION_DAYS)
    retained = []
    for record in archive.values():
        try:
            published = stamp(record.get("published"))
        except ValueError:
            # Preserve undated records instead of silently deleting them.
            published = newest
        if published >= cutoff:
            retained.append(record)
    retained.sort(key=lambda item: (float(item.get("priority") or 0), item.get("published") or "", item["id"]), reverse=True)

    return {
        "schema": 1,
        "generated_at": latest.get("generated_at"),
        "source_status": latest.get("source_status", {}),
        "failed_sources": latest.get("failed_sources", []),
        "last_collection_candidates": latest.get("last_collection_candidates", 0),
        "items": retained[:MAX_ITEMS],
    }


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(payload, out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        Path(tmp_name).replace(path)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--existing", required=True, type=Path)
    ap.add_argument("--incoming", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    previous = load(args.existing)
    collected = load(args.incoming)
    output = merge(previous, collected)
    atomic_write(args.output, output)
    print(f"Feed merged: {len(previous['items'])} stored + {len(collected['items'])} collected => {len(output['items'])} unique records")


if __name__ == "__main__":
    main()
