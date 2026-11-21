import { esc } from "./telegram.js";

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS = "https://api.first.org/data/v1/epss";
const UA = { "user-agent": "cyber-watch-bot/1.0 (+https://github.com/sihlangu-mthembu/cyber-watch-bot)" };

// Daily data published by the GitHub Actions pipeline; cached in memory for 10 minutes per isolate.
const cache = {};
async function data(env, name) {
  const c = cache[name];
  if (c && Date.now() - c.at < 600_000) return c.data;
  const r = await fetch(`${env.DATA_BASE}/${name}`, { cf: { cacheTtl: 600, cacheEverything: true } });
  if (!r.ok) throw new Error(`could not load ${name} (HTTP ${r.status})`);
  const d = await r.json();
  cache[name] = { at: Date.now(), data: d };
  return d;
}
export const latestIntel = (env) => data(env, "intel.json");
export const kevIndex = (env) => data(env, "kev.json");

function cvssFrom(metrics = {}) {
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    for (const m of metrics[key] || []) {
      const d = m.cvssData || {};
      if (d.baseScore != null) return { score: d.baseScore, severity: d.baseSeverity || m.baseSeverity, version: d.version };
    }
  }
  return null;
}

export async function lookupCve(env, rawId) {
  const id = rawId.toUpperCase();
  const [nvd, epss, kev] = await Promise.allSettled([
    fetch(`${NVD}?cveId=${id}`, { headers: UA }).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`NVD HTTP ${r.status}`)))),
    fetch(`${EPSS}?cve=${id}`, { headers: UA }).then((r) => (r.ok ? r.json() : Promise.reject(new Error(`EPSS HTTP ${r.status}`)))),
    kevIndex(env),
  ]);
  const out = { cve: id, found: false, notes: [] };
  if (nvd.status === "fulfilled") {
    const c = nvd.value.vulnerabilities?.[0]?.cve;
    if (c) {
      out.found = true;
      out.description = (c.descriptions || []).find((d) => d.lang === "en")?.value?.slice(0, 600);
      out.published = c.published?.slice(0, 10);
      out.status = c.vulnStatus;
      out.cvss = cvssFrom(c.metrics);
      out.cwe = [...new Set((c.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)).filter((v) => v.startsWith("CWE-")))].slice(0, 3);
      out.references = (c.references || []).slice(0, 3).map((r) => r.url);
    }
  } else out.notes.push(`NVD unavailable: ${nvd.reason?.message}`);
  if (epss.status === "fulfilled") {
    const d = epss.value.data?.[0];
    if (d) out.epss = { probability: Number(d.epss), percentile: Number(d.percentile), date: d.date };
  } else out.notes.push(`EPSS unavailable: ${epss.reason?.message}`);
  if (kev.status === "fulfilled") {
    const k = kev.value.items.find((x) => x.cve === id);
    out.kev = k ? { added: k.added, due: k.due, ransomware: k.ransomware, vendor: k.vendor, product: k.product, name: k.name } : null;
    if (k) out.found = true;
  } else out.notes.push("KEV index unavailable");
  return out;
}

const pct = (x) => (x >= 0.01 ? `${(x * 100).toFixed(0)}%` : "<1%");

export function cveCard(c) {
  if (!c.found) return `I couldn't find <code>${esc(c.cve)}</code> in NVD or CISA KEV.${c.notes.length ? `\n<i>${esc(c.notes.join("; "))}</i>` : ""}`;
  const L = [`🔎 <b>${esc(c.cve)}</b>${c.kev ? ` · ${esc(c.kev.vendor)} ${esc(c.kev.product)}` : ""}`];
  if (c.kev) L.push(`🚨 <b>Actively exploited</b>: on CISA KEV since ${c.kev.added}${c.kev.ransomware ? ", used in ransomware campaigns" : ""}. US federal patch deadline: ${c.kev.due}.`);
  else L.push("✅ Not on CISA's Known Exploited Vulnerabilities list.");
  if (c.cvss) L.push(`Severity: <b>${c.cvss.score} ${esc(c.cvss.severity || "")}</b> (CVSS ${esc(c.cvss.version)})`);
  if (c.epss) L.push(`Exploit probability (next 30 days, EPSS): <b>${pct(c.epss.probability)}</b>, higher than ${(c.epss.percentile * 100).toFixed(0)}% of all CVEs`);
  if (c.published) L.push(`Published: ${c.published}${c.status ? ` · NVD status: ${esc(c.status)}` : ""}`);
  if (c.cwe?.length) L.push(`Weakness: ${c.cwe.map(esc).join(", ")}`);
  if (c.description) L.push("", esc(c.description));
  L.push("", `<a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}">NVD record</a>`);
  if (c.notes.length) L.push(`<i>${esc(c.notes.join("; "))}</i>`);
  L.push("<i>Ask \"explain this for my CEO\" or \"what should we do?\" for advice.</i>");
  return L.join("\n");
}

export async function searchKev(env, { query = "", days = 0, limit = 10 } = {}) {
  const kev = await kevIndex(env);
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const cutoff = days ? new Date(Date.now() - days * 864e5).toISOString().slice(0, 10) : "";
  const hits = kev.items.filter((k) => {
    if (cutoff && k.added < cutoff) return false;
    const hay = `${k.vendor} ${k.product} ${k.name} ${k.cve}`.toLowerCase();
    return terms.every((t) => hay.includes(t));
  });
  let recentCritical = [];
  if (terms.length) {
    try {
      const intel = await latestIntel(env);
      recentCritical = intel.critical
        .filter((c) => terms.every((t) => `${c.vendor} ${c.product} ${c.desc}`.toLowerCase().includes(t)))
        .slice(0, 5)
        .map((c) => ({ cve: c.cve, cvss: c.cvss?.score, product: c.product || c.vendor, published: c.published }));
    } catch {}
  }
  return {
    total: hits.length,
    ransomware: hits.filter((k) => k.ransomware).length,
    kev_version: kev.version,
    items: hits.slice(0, limit).map(({ cve, vendor, product, name, added, due, ransomware }) => ({ cve, vendor, product, name, added, due, ransomware })),
    recentCritical,
  };
}

export async function recentNews(env, { query = "", limit = 8 } = {}) {
  const intel = await latestIntel(env);
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const items = intel.news.filter((n) => terms.every((t) => `${n.title} ${n.tags.join(" ")} ${n.vendors.join(" ")}`.toLowerCase().includes(t)));
  return { generated: intel.generated, items: items.slice(0, limit).map(({ title, source, link, published, tags }) => ({ title, source, link, published, tags })) };
}
