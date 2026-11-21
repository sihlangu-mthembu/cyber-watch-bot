"""Daily Cyber Watch run:  python -m intel.build            (live)
                         python -m intel.build --offline  (sample data, no network)

1. Pull CISA KEV, NVD critical CVEs (last 48h), FIRST EPSS scores and security news.
2. Rank what to patch first with transparent rules (KEV > EPSS > CVSS > watchlist vendor).
3. Ask an AI analyst for a short summary, then fact-check it in code.
4. Write data/ files the chat bot reads, and push the digest to Telegram via the Worker."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import time

import requests

from . import config, sources

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAST = dt.timezone(dt.timedelta(hours=2))


# ------------------------------------------------------------------ ranking
def is_watch(vendor: str, product: str = "") -> bool:
    t = f"{vendor} {product}".lower()
    return any(w.lower() in t for w in config.WATCHLIST)


def priority(item, epss, in_kev):
    """0-100 score: exploited-in-the-wild dominates, then exploit probability, severity, relevance."""
    e = epss.get(item["cve"], {}).get("epss", 0.0)
    cv = (item.get("cvss") or {}).get("score") or 0
    s = 50 if in_kev else 0
    s += round(25 * e)
    s += round(15 * cv / 10)
    s += 10 if is_watch(item.get("vendor", ""), item.get("product", "")) else 0
    s += 5 if item.get("ransomware") else 0
    return min(100, s)


# ------------------------------------------------------------------ AI analyst
SYSTEM = ("You are a threat-intelligence analyst writing a morning brief for a South African security team "
          "and its executives. Use ONLY the facts provided. Never invent CVE IDs, scores, vendors, victims or "
          "dates. Only call something exploited if it is on CISA KEV or a headline says so. Plain English, "
          "no hype. Reply with JSON only.")
SCHEMA = """Return exactly:
{"headline": "max 16 words, the single most important thing today",
 "patch_first": [{"cve": "CVE id from the facts", "why": "max 22 words"}],   (up to 3, most urgent first)
 "threats": ["2-3 bullets, max 25 words each, from the headlines"],
 "sa_angle": ["0-2 bullets on South African relevance, only if South African headlines exist"],
 "exec_note": "one sentence a non-technical executive can act on"}"""


def facts_text(kev_recent, critical, news, epss):
    L = ["NEW ON CISA KEV (actively exploited), last 7 days:"]
    for k in kev_recent[:15]:
        e = epss.get(k["cve"], {})
        L.append(f"- {k['cve']} | {k['vendor']} {k['product']} | {k['name']} | added {k['added']} | due {k['due']}"
                 f" | ransomware: {'known' if k['ransomware'] else 'unknown'} | EPSS {e.get('epss', 0):.3f}")
    L.append("\nNEW CRITICAL CVEs (NVD, last 48h), top by priority:")
    for c in critical[:12]:
        e = epss.get(c["cve"], {})
        cv = c.get("cvss") or {}
        L.append(f"- {c['cve']} | {c['vendor']} {c['product']} | CVSS {cv.get('score')} | EPSS {e.get('epss', 0):.3f}"
                 f" | {c['desc'][:180]}")
    L.append("\nHEADLINES (last 36h):")
    for n in news[:15]:
        L.append(f"- {n['title']} ({n['source']}) [tags: {', '.join(n['tags'])}]")
    return "\n".join(L)


def fact_check(ai, facts):
    known_cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", facts))
    nums = [float(x) for x in re.findall(r"\d+(?:\.\d+)?", facts)]
    removed = 0

    def ok(text):
        for c in re.findall(r"CVE-\d{4}-\d{4,7}", text):
            if c not in known_cves:
                return False
        for x in re.findall(r"(?<![\w-])\d+(?:\.\d+)?(?![\w-])", re.sub(r"CVE-\d{4}-\d{4,7}", "", text)):
            v = float(x)
            if v <= 12 or any(abs(v - k) < 0.051 or abs(v - k * 100) < 0.6 for k in nums):
                continue
            return False
        return True

    pf = []
    for p in ai.get("patch_first", [])[:3]:
        if isinstance(p, dict) and p.get("cve") in known_cves and ok(p.get("why", "")):
            pf.append({"cve": p["cve"], "why": p.get("why", "")})
        else:
            removed += 1
    ai["patch_first"] = pf
    for key in ("threats", "sa_angle"):
        keep = [b for b in ai.get(key, []) if isinstance(b, str) and ok(b)]
        removed += len(ai.get(key, [])) - len(keep)
        ai[key] = keep
    for key in ("headline", "exec_note"):
        if ai.get(key) and not ok(ai[key]):
            ai[key] = ""
            removed += 1
    ai["fact_check_removed"] = removed
    return ai


def ai_brief(facts, errors):
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        errors.append("AI: GROQ_API_KEY not set, digest built by rules only")
        return None
    body = {"model": os.environ.get("AI_MODEL", config.AI_MODEL), "temperature": 0.1, "max_tokens": 4000,
            "reasoning_effort": "low", "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": facts + "\n\n" + SCHEMA}]}
    last = None
    for i in range(3):
        try:
            r = requests.post(config.GROQ_URL, json=body, timeout=90,
                              headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            if r.status_code != 200:
                last = f"HTTP {r.status_code}: {r.text[:150]}"
                time.sleep(4 * (i + 1))
                continue
            content = r.json()["choices"][0]["message"].get("content") or ""
            m = re.search(r"\{.*\}", content, re.S)
            return fact_check(json.loads(m.group(0)), facts)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"[:160]
            time.sleep(4 * (i + 1))
    errors.append(f"AI: {last}; digest built by rules only")
    return None


# ------------------------------------------------------------------ digest
def esc(s):
    return html.escape(str(s or ""), quote=False)


def short_desc(d, n=70):
    d = re.sub(r"\s+", " ", d or "").strip()
    return d if len(d) <= n else d[:n].rsplit(" ", 1)[0] + "…"


def pct(x):
    return f"{x * 100:.0f}%" if x >= 0.01 else "<1%"


def digest_html(now, kev, kev_recent, critical, news, epss, ai, errors):
    by_cve = {k["cve"]: k for k in kev_recent} | {c["cve"]: c for c in critical}
    L = [f"🛡 <b>Cyber Watch · {now:%a %d %b %Y}</b>"]
    if ai and ai.get("headline"):
        L.append(f"<b>{esc(ai['headline'])}</b>")
    L.append("")
    # patch first: AI choice if it survived fact-check, else top rule-ranked
    pf = (ai or {}).get("patch_first") or [{"cve": x["cve"], "why": ""} for x in (kev_recent + critical)[:3]]
    if pf:
        L.append("<b>🔧 Patch first</b>")
        for i, p in enumerate(pf, 1):
            x = by_cve.get(p["cve"], {})
            e = epss.get(p["cve"], {}).get("epss")
            bits = []
            if p["cve"] in kev["ids"]:
                bits.append("on KEV")
            if e is not None:
                bits.append(f"EPSS {pct(e)}")
            if (x.get("cvss") or {}).get("score"):
                bits.append(f"CVSS {x['cvss']['score']}")
            if x.get("ransomware"):
                bits.append("ransomware")
            name = f"{x.get('vendor', '')} {x.get('product', '')}".strip()
            L.append(f"{i}. <code>{esc(p['cve'])}</code> {esc(name)} · {' · '.join(bits)}")
            if p.get("why"):
                L.append(f"   {esc(p['why'])}")
        L.append("")
    L.append(f"<b>🚨 New on CISA KEV (7 days): {len(kev_recent)}</b>")
    for k in kev_recent[:5]:
        flag = " ⚠️ ransomware" if k["ransomware"] else ""
        star = " ⭐" if is_watch(k["vendor"], k["product"]) else ""
        L.append(f"• <code>{esc(k['cve'])}</code> {esc(k['vendor'])} {esc(k['product'])} · added {dt.date.fromisoformat(k['added']):%d %b}{flag}{star}")
    if len(kev_recent) > 5:
        L.append(f"  …and {len(kev_recent) - 5} more (/kev)")
    L.append("")
    L.append(f"<b>🆕 New critical CVEs (48h): {len(critical)}</b>")
    for c in critical[:3]:
        e = epss.get(c["cve"], {}).get("epss", 0)
        what = f"{c['vendor']} {c['product']}".strip() or short_desc(c["desc"])
        L.append(f"• <code>{esc(c['cve'])}</code> {esc(what)} · CVSS {(c.get('cvss') or {}).get('score')} · EPSS {pct(e)}")
    L.append("")
    if ai and ai.get("threats"):
        L.append("<b>📰 Threat picture</b>")
        L += [f"• {esc(t)}" for t in ai["threats"]]
        L.append("")
    top_news = [n for n in news if "South Africa" not in n["tags"]][:4]
    if top_news:
        L.append("<b>🔗 Read</b>")
        L += [f"• <a href=\"{esc(n['link'])}\">{esc(n['title'])}</a> ({esc(n['source'])})" for n in top_news]
        L.append("")
    incident = {"Breach", "Ransomware", "Exploited", "Nation-state"}
    sa = [n for n in news if "South Africa" in n["tags"] and incident & set(n["tags"])][:3]
    if sa or (ai and ai.get("sa_angle")):
        L.append("<b>🇿🇦 South Africa</b>")
        L += [f"• {esc(t)}" for t in (ai or {}).get("sa_angle", [])]
        L += [f"• <a href=\"{esc(n['link'])}\">{esc(n['title'])}</a> ({esc(n['source'])})" for n in sa]
        L.append("")
    if ai and ai.get("exec_note"):
        L.append(f"<i>For leadership:</i> {esc(ai['exec_note'])}")
        L.append("")
    note = "AI summary fact-checked against the data" if ai else "Rule-based digest"
    if ai and ai.get("fact_check_removed"):
        note += f" ({ai['fact_check_removed']} unsupported line(s) removed)"
    L.append(f"<i>{note}. Sources: CISA KEV v{esc(kev.get('version'))}, NVD, FIRST EPSS, security news. "
             f"⭐ = on your vendor watchlist.</i>")
    if errors:
        L.append(f"<i>Data issues: {esc('; '.join(errors))[:300]}</i>")
    L.append("Ask me: /cve CVE-ID · /vendor fortinet · /kev · /news, or any question.")
    # each line is self-contained HTML, so the bot can split long digests on line breaks safely
    return "\n".join(L)


# ------------------------------------------------------------------ sample data
def sample(now):
    d = lambda n: (now - dt.timedelta(days=n)).strftime("%Y-%m-%d")
    items = [
        {"cveID": "CVE-2026-11111", "vendorProject": "Fortinet", "product": "FortiOS", "vulnerabilityName": "Fortinet FortiOS Heap Overflow",
         "dateAdded": d(1), "dueDate": d(-20), "knownRansomwareCampaignUse": "Known", "shortDescription": "Heap overflow in SSL-VPN allows RCE."},
        {"cveID": "CVE-2026-22222", "vendorProject": "Microsoft", "product": "Windows", "vulnerabilityName": "Windows Kernel EoP",
         "dateAdded": d(3), "dueDate": d(-18), "knownRansomwareCampaignUse": "Unknown", "shortDescription": "Elevation of privilege."},
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "shortDescription": "JNDI RCE."},
    ]
    kev = {"version": "2026.11.20", "released": now.isoformat(), "count": 3, "items": items}
    critical = [{"cve": "CVE-2026-33333", "published": d(1), "status": "Received", "desc": "Auth bypass in Ivanti Connect Secure.",
                 "cvss": {"score": 9.8, "severity": "CRITICAL", "version": "3.1"}, "vendor": "ivanti", "product": "connect secure", "cwe": ["CWE-287"], "refs": []}]
    epss = {"CVE-2026-11111": {"epss": 0.94, "percentile": 0.99}, "CVE-2026-22222": {"epss": 0.12, "percentile": 0.9},
            "CVE-2026-33333": {"epss": 0.41, "percentile": 0.97}}
    news = [{"title": "Fortinet warns of FortiOS zero-day exploited in attacks", "source": "BleepingComputer", "link": "https://example.com/1",
             "published": now.isoformat(), "tags": ["Exploited"], "vendors": ["Fortinet"], "cves": ["CVE-2026-11111"]},
            {"title": "South African municipality hit by ransomware attack", "source": "MyBroadband", "link": "https://example.com/2",
             "published": now.isoformat(), "tags": ["Ransomware", "South Africa"], "vendors": [], "cves": []}]
    return kev, critical, epss, news


# ------------------------------------------------------------------ broadcast
def broadcast(text, errors):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    try:
        worker = json.load(open(os.path.join(ROOT, "data", "worker.json"))).get("url")
    except Exception:
        worker = None
    if not (token and worker):
        errors.append("Broadcast skipped: worker not deployed yet or TELEGRAM_BOT_TOKEN missing")
        return 0
    auth = hashlib.sha256(f"broadcast:{token}".encode()).hexdigest()
    try:
        r = requests.post(f"{worker}/broadcast", json={"html": text}, timeout=60,
                          headers={"Authorization": f"Bearer {auth}"})
        res = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.status_code != 200:
            errors.append(f"Broadcast: HTTP {r.status_code} {r.text[:100]}")
        return res.get("sent", 0)
    except Exception as e:
        errors.append(f"Broadcast: {type(e).__name__}")
        return 0


def run(offline=False, send=True):
    now_utc = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now = now_utc.astimezone(SAST)
    errors = []
    if offline:
        kev, critical, epss_pre, news = sample(now_utc)
    else:
        kev = sources.fetch_kev(errors)
        critical = sources.fetch_nvd_recent(now_utc, errors)
        news = sources.fetch_news(now_utc, errors)
        epss_pre = None
    kev_items = sources.compact_kev(kev["items"])
    kev["ids"] = {k["cve"] for k in kev_items}
    cutoff = (now_utc - dt.timedelta(days=config.KEV_RECENT_DAYS)).strftime("%Y-%m-%d")
    kev_recent = [k for k in kev_items if k["added"] >= cutoff]
    epss = epss_pre if offline else sources.fetch_epss([k["cve"] for k in kev_recent] + [c["cve"] for c in critical], errors)

    for k in kev_recent:
        k["priority"] = priority(k, epss, True)
    for c in critical:
        c["in_kev"] = c["cve"] in kev["ids"]
        c["priority"] = priority(c, epss, c["in_kev"])
    kev_recent.sort(key=lambda x: (-x["priority"], x["added"]))
    critical.sort(key=lambda x: -x["priority"])

    facts = facts_text(kev_recent, critical, news, epss)
    ai = None if offline else ai_brief(facts, errors)
    text = digest_html(now, kev, kev_recent, critical, news, epss, ai, errors)

    data = os.path.join(ROOT, "data" if not offline else "data/offline")
    os.makedirs(data, exist_ok=True)
    with open(os.path.join(data, "kev.json"), "w") as f:  # compact index the bot searches
        slim = [{k: v for k, v in x.items() if k != "desc"} for x in kev_items]  # small enough for the Worker's CPU budget
        json.dump({"version": kev["version"], "count": len(slim), "items": slim}, f, separators=(",", ":"))
    intel = {"generated": now.isoformat(), "kev_version": kev["version"], "kev_count": len(kev_items),
             "kev_recent": kev_recent, "critical": critical[:40], "epss": epss, "news": news,
             "ai": ai, "errors": errors, "digest_html": text}
    with open(os.path.join(data, "intel.json"), "w") as f:
        json.dump(intel, f, indent=1)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    if not offline:
        with open(os.path.join(ROOT, "reports", f"{now:%Y-%m-%d}.html.txt"), "w") as f:
            f.write(text)
    sent = broadcast(text, errors) if (send and not offline) else 0
    print(f"KEV {len(kev_items)} (v{kev['version']}), {len(kev_recent)} new in {config.KEV_RECENT_DAYS}d; "
          f"{len(critical)} critical CVEs in {config.NVD_HOURS}h; {len(news)} news; AI={'yes' if ai else 'no'}; "
          f"sent to {sent} chat(s); issues={len(errors)}")
    for e in errors:
        print("  issue:", e)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("```\n" + re.sub(r"<[^>]+>", "", text) + "\n```\n")
    return intel


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-send", action="store_true")
    a = ap.parse_args()
    run(a.offline, not a.no_send)
