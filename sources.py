#!/usr/bin/env python3
"""Source ingestion for the CTI Threat Dashboard (no Telegram required)."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, replace
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from defusedxml import ElementTree as ET

LOG = logging.getLogger("cti-dashboard")
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
APPLE_URL = "https://support.apple.com/en-us/100100"
SAUDI_URL = "https://nca.gov.sa/ar/cert/"
VULNCHECK_API = "https://api.vulncheck.com/v3/index/vulncheck-kev"
OPENCVE_API = "https://app.opencve.io/api/v2/cves"
STATE_PATH = Path("data/state.json")
OPML_PATH = Path("sources.opml")
MAX_ALERTS_PER_RUN = min(40, max(1, int(os.getenv("MAX_ALERTS_PER_RUN", "24"))))
MAX_RSS_FEEDS = 30
GET_TIMEOUT = (4, 12)   # connect/read seconds; no unbounded request
POST_TIMEOUT = (4, 12)
GET_MAX_ATTEMPTS = 2
LOOKBACK_HOURS = min(168, max(12, int(os.getenv("LOOKBACK_HOURS", "72"))))
NEWS_MODE = os.getenv("NEWS_MODE", "all").lower()

# Feedly / Inoreader are feed READER services; import their exported OPML via sources.opml.
RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Citizen Lab": "https://citizenlab.ca/feed/",
    "Google Project Zero": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
    "VulnCheck Research": "https://www.vulncheck.com/feed/blog/atom.xml",
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CISA Official News": "https://www.cisa.gov/news.xml",
    "The Hacker News": "https://thehackernews.com/feeds/posts/default?alt=rss",
}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.I)
SIGNALS = re.compile(
    r"zero[ -]?day|zero[ -]?click|0[ -]?day|0[ -]?click|actively exploit|"
    r"exploited in the wild|remote code execution|\bRCE\b|"
    r"unauthenticated|critical vulnerabilit|ransomware|phishing|"
    r"data breach|breached|spyware|APT\b|malware|exploit chain|"
    r"\bCVE-\d{4}-\d+\b|command injection|privilege escalation|"
    r"threat actor|cyberattack|supply chain attack", re.I,
)
HIGH_PRIORITY = re.compile(
    r"zero[ -]?day|zero[ -]?click|0[ -]?day|0[ -]?click|"
    r"actively exploit|exploited in the wild|unauthenticated.*RCE|"
    r"critical.*RCE|emergency patch|ransomware attack", re.I,
)
TARGETS = (
    "apple", "iphone", "ios", "imessage", "microsoft", "windows", "fortinet",
    "fortios", "citrix", "vmware", "broadcom", "exchange", "sharepoint",
    "palo alto", "cisco", "ivanti", "sonicwall", "php", "oracle",
    "chrome", "apache", "linux", "elastic", "splunk", "sentinel",
)


@dataclass(frozen=True)
class Alert:
    key: str
    category: str
    source: str
    title: str
    detail: str
    url: str
    published: datetime
    severity: str
    exploitation: str
    action: str
    priority: int = 10
    cve: str = ""
    epss: str = ""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        try:
            d = parsedate_to_datetime(str(value))
        except (ValueError, TypeError, IndexError):
            for fmt in ("%d %b %Y", "%d %B %Y", "%d/%m/%Y", "%Y-%m-%d"):
                try:
                    d = datetime.strptime(str(value), fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def is_recent(date: datetime | None, now: datetime, hours: int | None = None) -> bool:
    return bool(date and now - timedelta(hours=hours or LOOKBACK_HOURS) <= date <= now + timedelta(hours=2))


def http_get(url: str, *, params: dict | None = None, headers: dict | None = None) -> requests.Response:
    """Bounded retries for safe source retrieval."""
    request_headers = {"User-Agent": "CTIThreatDashboard/1.0 (+public-security-feed-monitor)", **(headers or {})}
    for attempt in range(GET_MAX_ATTEMPTS):
        try:
            response = requests.get(url, params=params, headers=request_headers, timeout=GET_TIMEOUT)
            if response.status_code in (429, 500, 502, 503, 504) and attempt + 1 < GET_MAX_ATTEMPTS:
                response.close()
                time.sleep(1 + attempt)
                continue
            response.raise_for_status()
            return response
        except (requests.Timeout, requests.ConnectionError):
            if attempt + 1 == GET_MAX_ATTEMPTS:
                raise
            time.sleep(1 + attempt)
    raise RuntimeError("HTTP GET retry exhausted")


def get_json(url: str, *, params: dict | None = None, headers: dict | None = None) -> dict:
    data = http_get(url, params=params, headers=headers).json()
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data


def get_html(url: str) -> BeautifulSoup:
    return BeautifulSoup(http_get(url).text, "html.parser")


def canonical_article_url(link: str) -> str:
    """Normalize tracking variants and URLs syndicated into multiple RSS subscriptions."""
    u = urlsplit(link.strip())
    if u.scheme not in ("https", "http") or not u.hostname:
        return ""
    host = u.hostname.lower().removeprefix("www.")
    # Whitelist only site-relevant query strings; strip common ad/tracking parameters.
    tracking = ("utm_", "fbclid", "gclid", "mc_", "ref_", "igshid", "_ga")
    params = sorted((k, v) for k, v in parse_qsl(u.query, keep_blank_values=True)
                    if not any(k.lower().startswith(prefix) for prefix in tracking))
    return urlunsplit(("https", host, u.path.rstrip("/") or "/", urlencode(params), ""))


def clean(text: str, length: int = 650) -> str:
    value = BeautifulSoup(html.unescape(str(text or "")), "html.parser").get_text(" ", strip=True)
    value = re.sub(r"\s+", " ", value)
    return value[:length]


def cvss_score(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for group_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(group_name) or []
        if items:
            row = next((r for r in items if r.get("type") == "Primary"), items[0])
            data = row.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), str(data.get("baseSeverity") or row.get("baseSeverity") or "Unrated")
    return None, "Unrated"


def cve_description(cve: dict) -> str:
    return next((x.get("value", "") for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")


def interesting_nvd(score: float | None, desc: str) -> bool:
    text = desc.lower()
    target = any(word in text for word in TARGETS)
    signal = bool(SIGNALS.search(desc))
    return bool((score is not None and score >= 9.0) or
                (score is not None and score >= 7.0 and (target or signal)) or
                (target and signal))


def fetch_cisa_kev(now: datetime) -> list[Alert]:
    items = get_json(KEV_URL).get("vulnerabilities", [])
    alerts = []
    for x in items:
        d = parse_date(x.get("dateAdded"))
        if not is_recent(d, now, 168):
            continue
        cve = x.get("cveID", "")
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            continue
        cve = cve.upper()
        label = f"{cve} — {x.get('vendorProject', '')} {x.get('product', '')}"
        alerts.append(Alert(
            f"kev:{cve}", "CONFIRMED_EXPLOITED", "CISA KEV", clean(label),
            clean(x.get("shortDescription", "")), "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            d, "Confirmed Exploited / CVSS unknown", "مؤكد ضمن CISA KEV (استغلال فعلي)",
            clean(x.get("requiredAction") or "راجع إرشادات الشركة المصنّعة وطبّق التحديثات"),
            100, cve,
        ))
    return alerts


def fetch_nvd(now: datetime) -> list[Alert]:
    begin = now - timedelta(hours=LOOKBACK_HOURS)
    key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": key} if key else {}
    params = {"pubStartDate": begin.isoformat(timespec="milliseconds"),
              "pubEndDate": now.isoformat(timespec="milliseconds"), "resultsPerPage": 2000}
    result, offset = [], 0
    for _ in range(4):
        obj = get_json(NVD_URL, params={**params, "startIndex": offset}, headers=headers)
        batch = obj.get("vulnerabilities", [])
        for wrapper in batch:
            cve = wrapper.get("cve", {})
            if str(cve.get("vulnStatus", "")).lower() == "rejected":
                continue
            cve_id = cve.get("id", "")
            if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
                continue
            cve_id = cve_id.upper()
            description = cve_description(cve)
            score, label = cvss_score(cve)
            if not interesting_nvd(score, description):
                continue
            d = parse_date(cve.get("published"))
            if not is_recent(d, now):
                continue
            result.append(Alert(
                f"cve:{cve_id}", "NEW_CVE", "NIST NVD", cve_id,
                clean(description), f"https://nvd.nist.gov/vuln/detail/{cve_id}", d,
                (f"CVSS {score:g} / {label}" if score is not None else "Unrated"),
                "غير مؤكد الاستغلال؛ وجود CVE لا يعني وجود Exploit فعلي",
                "تحقق من الإصدارات المتأثرة والـ Vendor Advisory والـ Patch، وابحث عن IOCs",
                70 if score is not None and score >= 9 else 50, cve_id,
            ))
        offset += len(batch)
        if not batch or offset >= int(obj.get("totalResults", 0)):
            break
    return result


def xml_text(node: ET.Element, *tags: str) -> str:
    for tag in tags:
        child = node.find(tag)
        if child is not None:
            value = "".join(child.itertext()).strip()
            if value:
                return value
    return ""


def parse_rss_or_atom(content: bytes) -> list[dict[str, str]]:
    root = ET.fromstring(content)
    atom = "{http://www.w3.org/2005/Atom}"
    entries = []
    for node in root.findall(".//item"):
        entries.append({
            "title": xml_text(node, "title"),
            "summary": xml_text(node, "description", "{http://purl.org/rss/1.0/modules/content/}encoded"),
            "link": xml_text(node, "link"),
            "published": xml_text(node, "pubDate", "{http://purl.org/dc/elements/1.1/}date"),
        })
    for node in root.findall(f".//{atom}entry"):
        links = node.findall(f"{atom}link")
        alternate = next((x for x in links if x.get("rel", "alternate") == "alternate"), links[0] if links else None)
        entries.append({
            "title": xml_text(node, f"{atom}title"),
            "summary": xml_text(node, f"{atom}summary", f"{atom}content"),
            "link": alternate.get("href", "") if alternate is not None else "",
            "published": xml_text(node, f"{atom}published", f"{atom}updated"),
        })
    return entries


def read_opml(path: Path = OPML_PATH) -> dict[str, str]:
    if not path.exists():
        return {}
    root = ET.fromstring(path.read_bytes())
    feeds = {}
    for outline in root.findall(".//outline"):
        url = outline.get("xmlUrl", "")
        if urlsplit(url).scheme == "https" and urlsplit(url).hostname:
            feeds[(outline.get("title") or outline.get("text") or url)[:64]] = url
    return feeds


def interesting_news(title: str, summary: str) -> bool:
    # used when NEWS_MODE=filtered; default all delivers all articles from chosen publishers
    return bool(SIGNALS.search(f"{title} {summary}"))


def categorise_news(title: str, source: str) -> tuple[str, int]:
    if source in ("Citizen Lab", "Google Project Zero", "VulnCheck Research", "Exploit-DB"):
        return "EXPLOIT_RESEARCH", 45 if HIGH_PRIORITY.search(title) else 32
    if HIGH_PRIORITY.search(title):
        return "BREAKING_SECURITY_NEWS", 58
    return "CYBER_NEWS", 25


def fetch_single_feed(source: str, url: str, now: datetime) -> list[Alert]:
    response = http_get(url)
    entries = parse_rss_or_atom(response.content)
    if not entries:
        raise ValueError("RSS/Atom feed returned no items")
    result = []
    for item in entries[:80]:
        published = parse_date(item.get("published"))
        if not is_recent(published, now):
            continue
        title = clean(item.get("title", ""), 180)
        detail = clean(item.get("summary", ""), 570)
        link = item.get("link", "")
        canonical = canonical_article_url(link)
        if not title or not canonical:
            continue
        if source in {"CISA Advisories", "CISA Official News"} and re.search(
            r"CISA Adds? .*Known Exploited Vulnerabilit(?:y|ies).*Catalog", title, re.I
        ):
            # Deduplicated via the authoritative CISA KEV JSON source.
            continue
        if NEWS_MODE == "filtered" and not interesting_news(title, detail):
            continue
        category, priority = categorise_news(title, source)
        matches = CVE_RE.findall(f"{title} {detail}")
        cve = matches[0].upper() if matches else ""
        ident = hashlib.sha256(canonical.encode()).hexdigest()[:24]
        result.append(Alert(
            f"news:{ident}", category, source, title, detail, link, published,
            "خبر / بحث (ليس تصنيف CVSS)",
            "خبر أو تحليل بحثي؛ لا يُعد تأكيداً للاستغلال في الواقع بمفرده",
            "راجع المقال الأصلي وحدد التأثر والـ Detection والـ Mitigation عند الحاجة",
            priority, cve,
        ))
    return result


# CISA's .gov RSS service can reject automated GitHub runners with HTTP 403.
# The agency's official cisagov/CSAF repository provides a PARTIAL fallback:
# machine-readable IT/OT advisories (not every CISA news item or KEV notice).
CISA_ADVISORY_RSS = (
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
)
CISA_NEWS_RSS = (
    "https://www.cisa.gov/news.xml",
    "https://www.cisa.gov/rss.xml",
)
CSAF_COMMITS_API = "https://api.github.com/repos/cisagov/CSAF/commits"
CSAF_DOC_PREFIX = "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
CSAF_ALLOWED_PATH = re.compile(r"csaf_files/(?:IT|OT)/(?:white|clear)/[0-9]{4}/[a-zA-Z0-9_.-]+\.json", re.I)


def cisa_github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_API_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_cisa_csaf(now: datetime) -> list[Alert]:
    """Bounded official CISA IT/OT CSAF fallback, using only recently modified files.

    This is *not* a substitute for all CISA RSS alerts/news. No third-party mirrors.
    """
    params = {
        "sha": "develop", "path": "csaf_files",
        "since": (now - timedelta(hours=LOOKBACK_HOURS)).isoformat(timespec="seconds"),
        "per_page": 12,
    }
    response = http_get(CSAF_COMMITS_API, params=params, headers=cisa_github_headers())
    commits = response.json()
    if not isinstance(commits, list):
        raise ValueError("CISA CSAF commits endpoint returned unexpected data")
    paths: set[str] = set()
    for row in commits[:12]:
        sha = str(row.get("sha", ""))
        if not re.fullmatch(r"[a-fA-F0-9]{40}", sha):
            continue
        detail = get_json(f"{CSAF_COMMITS_API}/{sha}", headers=cisa_github_headers())
        for file in detail.get("files", []):
            name = str(file.get("filename", ""))
            if CSAF_ALLOWED_PATH.fullmatch(name) and file.get("status") in ("added", "modified"):
                paths.add(name)
    if len(paths) > 20:
        LOG.warning("CISA CSAF changes truncated to 20 documents this run")
    results = []
    doc_failures = 0
    for name in sorted(paths)[:20]:
        try:
            data = get_json(CSAF_DOC_PREFIX + name)
            doc = data.get("document") or {}
            tracking = doc.get("tracking") or {}
            advisory_id = str(tracking.get("id", ""))
            version = str(tracking.get("version", "1"))
            published = parse_date(tracking.get("current_release_date"))
            if not advisory_id or not is_recent(published, now):
                continue
            summary = next((n.get("text", "") for n in doc.get("notes", [])
                            if n.get("category") == "summary"), "")
            title = clean(str(doc.get("title") or advisory_id), 180)
            cves = [v.get("cve", "") for v in data.get("vulnerabilities", [])]
            cve = next((c.upper() for c in cves if isinstance(c, str) and CVE_RE.fullmatch(c)), "")
            results.append(Alert(
                f"cisa-csaf:{advisory_id}:v{version}", "VENDOR_ADVISORY",
                "CISA CSAF (IT/OT)", title, clean(summary, 650),
                f"https://github.com/cisagov/CSAF/blob/develop/{name}", published,
                "Official IT/OT advisory — check CVSS in source",
                "CISA advisory; exploitation not confirmed unless explicitly stated",
                "Verify affected products/versions and mitigation in original CISA advisory",
                72, cve,
            ))
        except (requests.RequestException, ValueError, TypeError, KeyError, AttributeError) as exc:
            LOG.warning("CISA CSAF document unavailable %s: %s", name, type(exc).__name__)
            doc_failures += 1
    if paths and doc_failures == min(20, len(paths)):
        raise RuntimeError("No changed CISA CSAF documents could be read")
    return results


def fetch_cisa_advisories(now: datetime) -> list[Alert]:
    for url in CISA_ADVISORY_RSS:
        try:
            result = fetch_single_feed("CISA Advisories", url, now)
            LOG.info("CISA Advisories: direct RSS operational")
            return result
        except (requests.RequestException, ValueError, ET.ParseError):
            pass
    result = fetch_cisa_csaf(now)
    LOG.warning("CISA .gov Advisories RSS inaccessible: using official CISA CSAF IT/OT subset (%d items)", len(result))
    return result


def fetch_cisa_news(now: datetime) -> list[Alert]:
    for url in CISA_NEWS_RSS:
        try:
            return fetch_single_feed("CISA Official News", url, now)
        except (requests.RequestException, ValueError, ET.ParseError):
            pass
    raise RuntimeError("CISA News RSS unavailable (agency .gov feeds may block automated requests)")


def fetch_news(now: datetime) -> tuple[list[Alert], list[str]]:
    feeds = dict(list({**RSS_FEEDS, **read_opml()}.items())[:MAX_RSS_FEEDS])
    alerts, failures = [], []
    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = {}
        for source, url in feeds.items():
            if source == "CISA Advisories":
                future = pool.submit(fetch_cisa_advisories, now)
            elif source == "CISA Official News":
                future = pool.submit(fetch_cisa_news, now)
            else:
                future = pool.submit(fetch_single_feed, source, url, now)
            jobs[future] = source
        for future in as_completed(jobs):
            source = jobs[future]
            try:
                alerts.extend(future.result())
            except Exception as exc:
                # Isolate third-party feed failures, including unexpected parser changes.
                LOG.warning("RSS source unavailable %s: %s", source, type(exc).__name__)
                failures.append(source)
    return alerts, failures


def fetch_apple(now: datetime) -> list[Alert]:
    soup = get_html(APPLE_URL)
    results = []
    for tr in soup.select("tr"):
        cells = tr.find_all("td")
        if len(cells) < 3:
            continue
        title = clean(cells[0].get_text(" ", strip=True), 130)
        release = clean(cells[-1].get_text(" ", strip=True), 55)
        d = parse_date(release)
        if not is_recent(d, now, 168):
            continue
        if not any(x in title.lower() for x in ("ios", "ipados", "safari", "macos", "security improvement")):
            continue
        href = cells[0].find("a", href=True)
        url = urljoin(APPLE_URL, href["href"]) if href else APPLE_URL
        ident = hashlib.sha256(f"{title}|{release}".encode()).hexdigest()[:20]
        results.append(Alert(
            f"apple:{ident}", "VENDOR_ADVISORY", "Apple Security Releases", title,
            clean(cells[1].get_text(" ", strip=True), 450), url, d,
            "Vendor Advisory — راجع تفاصيل CVEs", "تحديث أمني رسمي؛ لا يعني وجود Zero-Day مؤكدة",
            "تحقق من إصلاحات CVE والـ iOS/iPadOS versions ثم حدّث الأجهزة المتأثرة",
            64,
        ))
    return results


def fetch_saudi_cert(now: datetime) -> list[Alert]:
    soup = get_html(SAUDI_URL)
    result, urls = [], set()
    for a in soup.find_all("a", href=True):
        url = urljoin(SAUDI_URL, a["href"])
        if not re.search(r"nca\.gov\.sa/(?:ar|en)/cert/\d+/?", url) or url in urls:
            continue
        urls.add(url)
        container = a
        for ancestor in list(a.parents)[:4]:
            if re.search(r"\d{2}/\d{2}/\d{4}", ancestor.get_text(" ", strip=True)):
                container = ancestor
                break
        content = clean(container.get_text(" ", strip=True), 600)
        date_match = re.search(r"\b\d{2}/\d{2}/\d{4}\b", content)
        d = parse_date(date_match.group(0)) if date_match else None
        if not is_recent(d, now, 168):
            continue
        title = clean(a.get_text(" ", strip=True), 120)
        if not title or title.isdigit():
            title = clean(content[:120])
        severity = "Critical" if "عالٍ جداً" in content or "حرج" in content else "High / See advisory"
        result.append(Alert(
            f"saudicert:{hashlib.sha256(url.encode()).hexdigest()[:20]}", "VENDOR_ADVISORY",
            "Saudi CERT (NCA)", title, content, url, d, severity,
            "تنبيه رسمي؛ راجع المرجع للتأكد من حالة الاستغلال",
            "راجع توصيات المركز الوطني الإرشادي ونسق مع فرق إدارة الثغرات",
            68,
        ))
    return result


def fetch_opencve(now: datetime) -> list[Alert]:
    token = os.getenv("OPENCVE_TOKEN", "")
    if not token:
        return []
    payload = get_json(OPENCVE_API, params={"page_size": 100}, headers={"Authorization": f"Bearer {token}"})
    alerts = []
    for row in payload.get("results", []):
        ident = row.get("cve_id") or row.get("id") or row.get("cve")
        if isinstance(ident, dict):
            ident = ident.get("id")
        if not isinstance(ident, str) or not CVE_RE.fullmatch(ident):
            continue
        ident = ident.upper()
        published = parse_date(row.get("published_at") or row.get("published") or row.get("created_at"))
        if not is_recent(published, now):
            continue
        desc = row.get("description") or row.get("summary") or ""
        if isinstance(desc, dict):
            desc = desc.get("en") or next(iter(desc.values()), "")
        desc = str(desc)
        if not interesting_nvd(None, desc):
            continue
        alerts.append(Alert(
            f"cve:{ident}", "NEW_CVE", "OpenCVE API", ident, clean(desc),
            f"https://nvd.nist.gov/vuln/detail/{ident}", published,
            "Severity: refer to vendor", "OpenCVE لا يثبت وحده الاستغلال الفعلي",
            "راجع تفاصيل CVE والإصدارات المتأثرة", 45, ident,
        ))
    return alerts


def fetch_vulncheck(now: datetime) -> list[Alert]:
    token = os.getenv("VULNCHECK_API_TOKEN", "")
    if not token:
        return []
    obj = get_json(VULNCHECK_API, params={"sort": "date_added", "order": "desc", "limit": 200},
                   headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    result = []
    for row in obj.get("data", []):
        d = parse_date(row.get("date_added"))
        if not is_recent(d, now, 168):
            continue
        cves = row.get("cve", [])
        if isinstance(cves, str):
            cves = [cves]
        for cve in cves:
            if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
                continue
            cve = cve.upper()
            reported = bool(row.get("vulncheck_reported_exploitation") or row.get("reported_exploited_by_vulncheck_canaries"))
            result.append(Alert(
                f"vulncheck:{cve}", "REPORTED_EXPLOITATION", "VulnCheck KEV",
                f"{cve} — {row.get('vendorProject', '')} {row.get('product', '')}",
                clean(row.get("shortDescription", "")),
                f"https://nvd.nist.gov/vuln/detail/{cve}", d,
                "Exploitation intelligence", "VulnCheck: مؤشرات/تقارير استغلال" if reported else "VulnCheck KEV: راجع أدلة المصدر",
                clean(row.get("required_action") or "راجع دلائل الاستغلال وإرشادات الشركة"),
                89, cve,
            ))
    return result


def add_epss(alerts: list[Alert]) -> list[Alert]:
    cves = list(dict.fromkeys(a.cve for a in alerts if a.cve and a.category in
                              ("NEW_CVE", "CONFIRMED_EXPLOITED", "REPORTED_EXPLOITATION")))[:75]
    if not cves:
        return alerts
    try:
        response = get_json(EPSS_URL, params={"cve": ",".join(cves)})
        scores = {row["cve"]: f"{float(row['epss'])*100:.1f}% (30-day estimate)" for row in response.get("data", [])}
        return [replace(a, epss=scores.get(a.cve, "")) for a in alerts]
    except (requests.RequestException, ValueError, KeyError) as exc:
        LOG.warning("EPSS enrichment unavailable: %s", type(exc).__name__)
        return alerts


def soc_recommendations(a: Alert) -> list[str]:
    """Deterministic, evidence-neutral playbooks; never imply a patch/IOC exists.

    Messages cite primary records. These are triage suggestions, not findings or
    claims that the specific vendor release fixes an affected installation.
    """
    body = f"{a.title} {a.detail}".lower()
    if a.category in {"CYBER_NEWS", "BREAKING_SECURITY_NEWS", "EXPLOIT_RESEARCH"}:
        if "ransomware" in body:
            return ["اربط الحملة ببيئتك، وافحص EDR وعمليات التشفير غير المعتادة.",
                    "راجع الـ IOCs المنشورة قبل إضافتها إلى Detection Rules."]
        if "data breach" in body or "leak" in body or "expos" in body:
            return ["تحقق مما إذا كان الخبر يخص جهة أو مورّداً تتعامل معه.",
                    "إن كان مرتبطاً ببيئتك، راجع Access Logs وإشارات تسريب البيانات."]
        if "phishing" in body:
            return ["ابحث عن النطاقات والروابط ذات الصلة في Email Gateway وProxy Logs.",
                    "تحقق من حسابات المستخدمين المتأثرين قبل تنفيذ Containment."]
        if any(t in body for t in ("zero-click", "zero click", "spyware", "imessage", "iphone", "ios")):
            return ["راجع الأجهزة والإصدارات المستهدفة والمعلومات المنشورة من الباحثين.",
                    "تحقق من تحديثات Vendor والـ IOCs المؤكدة قبل البدء بالـ Hunting."]
        if any(t in body for t in ("exploited", "exploit", "rce", "vulnerability", "cve-")):
            return ["راجع المصدر لتحديد التأثر الفعلي، وتحقق من Asset Inventory.",
                    "اربط المعلومات الجديدة بـ SIEM/EDR حسب الـ TTPs المدعومة بالأدلة."]
        return ["تحقق من صلة الخبر بأصول المؤسسة أو مورّديها قبل فتح Incident."]

    if any(t in body for t in ("iphone", "imessage", "ipados", "ios ", "imageio", "appleexr")):
        investigation = ["راجع موديلات الأجهزة وإصدارات iOS المتأثرة.",
                         "طبّق تحديثات Apple الرسمية بعد التحقق من وجودها."]
    elif any(t in body for t in ("sql injection", "sqli")):
        investigation = ["تحقق من الأنظمة المكشوفة وراجع Web/WAF Logs لأنماط SQLi.",
                         "راجع محاولات تعديل الحسابات أو رفع الصلاحيات غير المعتادة."]
    elif any(t in body for t in ("remote code execution", "command injection", "arbitrary code", "rce")):
        investigation = ["حدد الأصول المتأثرة وافحص Web/WAF Logs وProcess Telemetry.",
                         "ابحث عن أوامر Shell غير معتادة واتصالات Outbound لاحقة."]
    elif any(t in body for t in ("authentication bypass", "auth bypass", "unauthorized access", "privilege escalation")):
        investigation = ["راجع Authentication Logs ومحاولات استخدام صلاحيات غير معتادة.",
                         "تحقق من حسابات الإدارة والتغييرات الحساسة على الأنظمة المتأثرة."]
    elif any(t in body for t in ("vpn", "firewall", "fortios", "netscaler", "citrix")):
        investigation = ["تحقق من الأجهزة المعرضة للإنترنت وإصداراتها.",
                         "افحص VPN/Firewall Logs لجلسات الإدارة واتصالات غير مألوفة."]
    else:
        investigation = ["طابق المنتجات والإصدارات المتأثرة مع Asset Inventory.",
                         "راجع Vendor Advisory وأدلة الاستغلال قبل إنشاء Detection جديدة."]

    if a.category == "CONFIRMED_EXPLOITED":
        investigation.append("أعطِ الأولوية للتصحيح أو Mitigation المعتمد؛ CISA KEV تؤكد الاستغلال.")
    else:
        investigation.append("تحقق من توفر Patch أو Mitigation رسمي قبل تطبيقه.")
    return investigation


