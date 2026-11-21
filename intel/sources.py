"""Fetchers for CISA KEV, NVD, FIRST EPSS and security news. Each one retries, records
failures in `errors`, and never raises, so one bad source can't stop the digest."""
from __future__ import annotations

import datetime as dt
import re
import time
from email.utils import parsedate_to_datetime

import requests

from . import config

UA = {"User-Agent": "cyber-watch-bot/1.0 (+https://github.com/sihlangu-mthembu/cyber-watch-bot)"}
UTC = dt.timezone.utc


def get(url, params=None, tries=4, timeout=40, pause=2.0):
    last = None
    for i in range(tries):
        try:
            r = requests.get(url, params=params, headers=UA, timeout=timeout)
            if r.status_code == 200:
                return r
            last = f"HTTP {r.status_code}"
            if r.status_code in (403, 429, 503):  # NVD rate limit: back off harder
                time.sleep(pause * 4 * (i + 1))
                continue
        except requests.RequestException as e:
            last = type(e).__name__
        time.sleep(pause * (i + 1))
    raise RuntimeError(f"{url.split('?')[0]}: {last}")


# ------------------------------------------------------------------ CISA KEV
def fetch_kev(errors):
    for url in (config.KEV_URL, config.KEV_MIRROR):
        try:
            data = get(url).json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return {"version": data.get("catalogVersion"), "released": data.get("dateReleased"),
                        "count": len(vulns), "items": vulns}
        except Exception as e:
            errors.append(f"KEV ({'CISA' if url == config.KEV_URL else 'GitHub mirror'}): {e}")
    return {"version": None, "released": None, "count": 0, "items": []}


def compact_kev(items):
    out = []
    for v in items:
        out.append({
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "added": v.get("dateAdded", ""),
            "due": v.get("dueDate", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "desc": (v.get("shortDescription") or "")[:240],
        })
    out.sort(key=lambda x: x["added"], reverse=True)
    return out


# ------------------------------------------------------------------ NVD
def _cvss(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []) or []:
            d = m.get("cvssData", {})
            if d.get("baseScore") is not None:
                return {"score": d["baseScore"], "severity": d.get("baseSeverity") or m.get("baseSeverity"),
                        "version": d.get("version"), "vector": d.get("vectorString")}
    return None


def _vendor_product(cve):
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    return parts[3].replace("_", " "), parts[4].replace("_", " ")
    return "", ""


def parse_nvd(cve):
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    vendor, product = _vendor_product(cve)
    cwe = [d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", []) if d["value"].startswith("CWE-")]
    return {"cve": cve["id"], "published": cve.get("published", "")[:10], "status": cve.get("vulnStatus"),
            "desc": desc[:400], "cvss": _cvss(cve.get("metrics", {})), "vendor": vendor, "product": product,
            "cwe": sorted(set(cwe))[:3], "refs": [r["url"] for r in cve.get("references", [])[:3]]}


def fetch_nvd_recent(now, errors, hours=config.NVD_HOURS):
    start = (now - dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    found = {}
    for sev_key in ("cvssV3Severity", "cvssV4Severity"):
        try:
            r = get(config.NVD_URL, params={"pubStartDate": start, "pubEndDate": end, sev_key: "CRITICAL",
                                            "resultsPerPage": 200}, pause=6)
            for v in r.json().get("vulnerabilities", []):
                c = parse_nvd(v["cve"])
                found[c["cve"]] = c
        except Exception as e:
            errors.append(f"NVD {sev_key}: {e}")
        time.sleep(6.5)  # public rate limit: 5 requests per 30 seconds
    return list(found.values())


# ------------------------------------------------------------------ EPSS
def fetch_epss(cves, errors):
    scores = {}
    ids = sorted(set(c for c in cves if c))
    for i in range(0, len(ids), 100):
        try:
            r = get(config.EPSS_URL, params={"cve": ",".join(ids[i:i + 100])})
            for d in r.json().get("data", []):
                scores[d["cve"]] = {"epss": float(d["epss"]), "percentile": float(d["percentile"]), "date": d.get("date")}
        except Exception as e:
            errors.append(f"EPSS: {e}")
    return scores


# ------------------------------------------------------------------ news
def tag(text):
    t = text.lower()
    tags = [k for k, words in config.NEWS_TAGS.items()
            if any(re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", t) for w in words)]
    vendors = [v for v in config.WATCHLIST if re.search(rf"(?<![a-z]){re.escape(v.lower())}(?![a-z])", t)]
    return tags, vendors


def fetch_news(now, errors, hours=config.NEWS_HOURS):
    import feedparser

    seen, out = set(), []
    for source, url in config.NEWS_FEEDS:
        try:
            feed = feedparser.parse(get(url, tries=3).content)
        except Exception as e:
            errors.append(f"News {source}: {e}")
            continue
        for e in feed.entries[:50]:
            title = re.sub(r"\s+", " ", e.get("title", "")).strip()
            src = source
            if source.startswith("Google News") and " - " in title:
                title, src = title.rsplit(" - ", 1)
            try:
                ts = parsedate_to_datetime(e.get("published") or e.get("updated"))
                ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
            except Exception:
                continue
            if (now - ts).total_seconds() > hours * 3600 or not title:
                continue
            key = re.sub(r"[^a-z0-9]", "", title.lower())[:60]
            if key in seen:
                continue
            seen.add(key)
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", ""))
            tags, vendors = tag(title + " " + summary[:300])
            if source.startswith("Google News") and "South Africa" not in tags:
                tags.append("South Africa")
            out.append({"title": title, "source": src, "link": e.get("link", ""), "published": ts.isoformat(),
                        "tags": tags, "vendors": vendors, "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", title + " " + summary)))})
    weight = {"Exploited": 3, "Ransomware": 3, "South Africa": 3, "Breach": 2, "Nation-state": 2, "Advisory": 1}
    out.sort(key=lambda n: (-(sum(weight.get(t, 0) for t in n["tags"]) + 2 * len(n["vendors"])),
                            -dt.datetime.fromisoformat(n["published"]).timestamp()))
    return out[:30]
