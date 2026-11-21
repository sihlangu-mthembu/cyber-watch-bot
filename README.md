# Cyber Watch Bot 🛡

**A Telegram threat-intelligence agent. Every morning it tells you which vulnerabilities are being exploited right now and what to patch first. Ask it anything, like *"is CVE-2024-3400 being exploited?"*, *"anything new on Fortinet?"* or *"explain this for my CEO"*, and it answers from CISA, NIST and FIRST data, not from memory.**

Python · GitHub Actions · Cloudflare Workers (JavaScript) · Telegram Bot API · Groq (free LLM) · **R0 a month to run**

---

## Why
Security teams and the executives they report to drown in CVEs. Thousands are published each year, but only a small share is ever exploited in the wild. The useful question is *"which of these are being used against organisations like us, and what do we do today?"* This bot answers that every morning, and on demand.

## What it does
| | |
|---|---|
| **06:30 daily digest** | Newly exploited vulnerabilities (CISA KEV), new critical CVEs (NVD, last 48h) with exploit probability (EPSS), the threat headlines, a 🇿🇦 South Africa section, a "patch first" list and one line for leadership |
| `/cve CVE-ID` | Live card: CVSS severity, EPSS exploit probability, KEV status, ransomware use, US federal patch deadline, description |
| `/vendor fortinet` | Every exploited vulnerability for a vendor, plus new critical CVEs that match it |
| `/kev 14` | What CISA added to its exploited list in the last N days |
| `/news ransomware` | Filtered security headlines |
| **Any question** | A tool-using AI agent looks up the facts first, then answers in plain English with next steps and sources |

## How it works
```
 GitHub Actions · Python · 06:30 daily                Cloudflare Worker · JavaScript · always on
 ┌─────────────────────────────────────────┐          ┌────────────────────────────────────────────┐
 │ CISA KEV (1,600+ exploited CVEs)        │          │ Telegram webhook (secret-token checked)    │
 │ NVD critical CVEs, last 48h             │          │ owner lock: first /start owns the bot,     │
 │ FIRST EPSS exploit probabilities        │──data/──▶│   others need /allow                       │
 │ BleepingComputer, Hacker News,          │  (JSON)  │ commands: /cve /vendor /kev /news /digest  │
 │   SecurityWeek, CISA, SA news           │          │ AI agent with 4 tools:                     │
 │ rule-based priority score               │          │   lookup_cve (NVD + EPSS live, KEV index)  │
 │ AI summary → fact-checked in code       │──push───▶│   search_kev · recent_news · todays_digest │
 │ digest → /broadcast to subscribers      │          │ guardrail: flags any CVE no tool returned  │
 └─────────────────────────────────────────┘          └────────────────────────────────────────────┘
```

### Priority score (transparent, 0–100)
`50 if on CISA KEV` + `25 × EPSS probability` + `15 × CVSS / 10` + `10 if vendor on the SA watchlist` + `5 if used by ransomware`

Exploitation in the wild dominates, because that is what attackers are actually using. Severity alone is a poor guide.

## Guardrails (the part that matters for security work)
- **AI never supplies facts.** The digest AI only sees data the code fetched. A code fact-check then removes any CVE ID or number that isn't in that data, and the digest says how many lines it removed.
- **The chat agent must use tools.** Any CVE it mentions that no tool returned is flagged as *not verified* in the reply.
- **"Exploited" means exploited.** It only says this when the CVE is on CISA KEV or a headline reports it.
- **Private by default.** The first person to send `/start` becomes the owner, and anyone else needs `/allow`. Webhook calls must carry Telegram's secret token, and the broadcast and setup endpoints need a key derived from the bot token. No extra secrets to manage.
- **No silent failures.** Every source is retried separately. Anything that fails is listed in the digest, and if the AI is unavailable the digest is built by rules instead.

## Engineering notes
- **Split by cost profile.** Cloudflare's free Workers plan allows 10 ms of CPU per request, so the heavy parsing (the full KEV catalogue, NVD pages, news) runs in GitHub Actions. The Worker only reads a small pre-built index and makes single-CVE lookups.
- **Instant webhook replies.** The Worker answers Telegram with 200 straight away and does the work in `waitUntil`, so Telegram never retries and duplicates a message.
- **Tested offline.** `worker/test/run.mjs` stubs Telegram, NVD, EPSS and Groq and runs 15 end-to-end checks on every deploy.
- **One-click deploy.** The workflow creates the storage, deploys, sets secrets, registers the webhook and bot commands, and health-checks the bot.

## Set it up yourself (about 15 minutes, all free)
1. Create a bot with **@BotFather** (`/newbot`) and keep the token.
2. Create a free **Cloudflare** account, open *Workers & Pages* once, then create an API token from the *Edit Cloudflare Workers* template. Note your Account ID.
3. Get a free **Groq** API key at console.groq.com.
4. Fork this repo, then add the secrets `TELEGRAM_BOT_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and `GROQ_API_KEY`.
5. Run **Actions → Deploy bot**, send your bot `/start`, then run **Actions → Daily digest**.

Customise the vendor watchlist, news feeds and tags in [`intel/config.py`](intel/config.py).

## Files
| Path | What |
|---|---|
| `intel/sources.py` | CISA KEV, NVD, EPSS and RSS fetchers with retries |
| `intel/build.py` | Ranking, AI summary + fact-check, digest, broadcast |
| `worker/src/index.js` | Webhook, access control, commands, broadcast/setup/health endpoints |
| `worker/src/agent.js` | Tool-using AI agent and its guardrail |
| `worker/src/tools.js` | Live CVE lookup, KEV search, news |
| `worker/test/run.mjs` | Offline end-to-end tests |
| `.github/workflows/` | `deploy.yml` (bot) and `digest.yml` (daily) |

---
Data: CISA Known Exploited Vulnerabilities Catalog · NIST National Vulnerability Database (this product uses the NVD API but is not endorsed or certified by the NVD) · FIRST EPSS · publishers' RSS feeds. For awareness only; verify before acting.

Built by **Sihlangu Mthembu** · Agentic workflows & automation · MIT licence
