"""Sources and settings for the daily Cyber Watch pipeline."""

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# Vendors common in South African enterprise and government estates. Matches are flagged in the digest.
WATCHLIST = [
    "Microsoft", "Fortinet", "Cisco", "Palo Alto Networks", "Citrix", "Ivanti", "VMware", "Broadcom",
    "SAP", "Oracle", "Atlassian", "SonicWall", "Check Point", "Juniper", "F5", "Apple", "Google",
    "Veeam", "Sophos", "WatchGuard", "Zyxel", "MOVEit", "Progress", "ConnectWise", "Adobe",
]

NEWS_FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Google News (SA)", "https://news.google.com/rss/search?q=%22South+Africa%22+(cyberattack+OR+ransomware+OR+%22data+breach%22+OR+hackers+OR+cybersecurity)+when:3d&hl=en-ZA&gl=ZA&ceid=ZA:en"),
]

NEWS_TAGS = {
    "Ransomware": ["ransomware", "lockbit", "akira", "qilin", "extortion"],
    "Exploited": ["zero-day", "0-day", "actively exploited", "exploited in the wild", "exploitation", "kev"],
    "Breach": ["breach", "leak", "leaked", "stolen data", "data exposure", "compromised"],
    "Advisory": ["advisory", "patch", "update", "fixes", "vulnerability", "vulnerabilities", "cve"],
    "South Africa": ["south africa", "south african", "sars", "transnet", "eskom", "popia", "information regulator", "johannesburg", "cape town", "pretoria", "durban"],
    "Nation-state": ["apt", "nation-state", "state-sponsored", "espionage", "china", "russia", "iran", "north korea"],
}

KEV_RECENT_DAYS = 7
NVD_HOURS = 48
NEWS_HOURS = 36
AI_MODEL = "openai/gpt-oss-120b"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
