// Free-text questions: a small tool-using agent (Groq, OpenAI-compatible function calling).
// The model must fetch facts through tools; its answer is then checked so it can't cite CVEs it never saw.
import { esc } from "./telegram.js";
import { latestIntel, lookupCve, recentNews, searchKev } from "./tools.js";

const GROQ = "https://api.groq.com/openai/v1/chat/completions";

const TOOLS = [
  { type: "function", function: { name: "lookup_cve", description: "Get one CVE's description, CVSS severity, EPSS exploit probability and whether it is on CISA's Known Exploited Vulnerabilities list.",
    parameters: { type: "object", properties: { cve_id: { type: "string", description: "e.g. CVE-2024-3400" } }, required: ["cve_id"] } } },
  { type: "function", function: { name: "search_kev", description: "Search CISA's Known Exploited Vulnerabilities catalog by vendor/product/keyword and/or recency. Also returns new critical CVEs from the last 48 hours that match.",
    parameters: { type: "object", properties: { query: { type: "string", description: "vendor or product, e.g. 'citrix netscaler'" }, days: { type: "integer", description: "only entries added in the last N days" } } } } },
  { type: "function", function: { name: "recent_news", description: "Security headlines from the last 36 hours (BleepingComputer, The Hacker News, SecurityWeek, CISA, South African news), optionally filtered by keyword.",
    parameters: { type: "object", properties: { query: { type: "string" } } } } },
  { type: "function", function: { name: "todays_digest", description: "Today's prioritised digest: new KEV entries, new critical CVEs, AI summary.", parameters: { type: "object", properties: {} } } },
];

async function runTool(env, name, args) {
  switch (name) {
    case "lookup_cve": return lookupCve(env, String(args.cve_id || ""));
    case "search_kev": return searchKev(env, { query: args.query || "", days: args.days || 0, limit: 12 });
    case "recent_news": return recentNews(env, { query: args.query || "", limit: 8 });
    case "todays_digest": {
      const i = await latestIntel(env);
      return { generated: i.generated, ai: i.ai, kev_recent: i.kev_recent.slice(0, 10), critical: i.critical.slice(0, 8).map(({ cve, vendor, product, cvss, desc }) => ({ cve, vendor, product, cvss: cvss?.score, desc })) };
    }
    default: return { error: `unknown tool ${name}` };
  }
}

const SYSTEM = (today) => `You are Cyber Watch, a threat-intelligence assistant for a South African security team. Today is ${today}.
Rules:
- Get facts with the tools before answering. Never invent CVE IDs, scores, dates, vendors or exploitation status.
- "Actively exploited" only if the CVE is on CISA KEV (kev not null) or a headline says so.
- If the tools return nothing useful, say so plainly.
- Be brief: under 170 words, short bullets, then concrete next steps (patch, mitigate, detect, who to tell).
- For executives: no jargon, focus on business risk.
- Plain text only; you may use **bold** and \`code\`.`;

function toHtml(s) {
  return esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/^#+\s*(.+)$/gm, "<b>$1</b>");
}

export async function answerWithAgent(env, question) {
  if (!env.GROQ_API_KEY) return "AI answers aren't configured yet. Try /cve, /vendor, /kev or /news.";
  const messages = [{ role: "system", content: SYSTEM(new Date().toISOString().slice(0, 10)) }, { role: "user", content: question }];
  const seen = new Set((question.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((x) => x.toUpperCase()));
  const used = new Set();
  for (let step = 0; step < 5; step++) {
    const r = await fetch(GROQ, {
      method: "POST",
      headers: { authorization: `Bearer ${env.GROQ_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ model: env.AI_MODEL, messages, tools: TOOLS, tool_choice: "auto", temperature: 0.1, max_tokens: 2500, reasoning_effort: "low" }),
    });
    if (!r.ok) return `⚠️ The AI service returned an error (HTTP ${r.status}). Try a command instead: /cve, /vendor, /kev, /news.`;
    const msg = (await r.json()).choices?.[0]?.message;
    if (!msg) return "⚠️ No answer from the AI service.";
    if (msg.tool_calls?.length) {
      messages.push({ role: "assistant", content: msg.content || "", tool_calls: msg.tool_calls });
      for (const call of msg.tool_calls) {
        let args = {};
        try { args = JSON.parse(call.function.arguments || "{}"); } catch {}
        let result;
        try { result = await runTool(env, call.function.name, args); } catch (e) { result = { error: String(e.message || e) }; }
        used.add(call.function.name);
        const json = JSON.stringify(result);
        for (const c of json.match(/CVE-\d{4}-\d{4,7}/g) || []) seen.add(c);
        messages.push({ role: "tool", tool_call_id: call.id, content: json.slice(0, 6000) });
      }
      continue;
    }
    let answer = (msg.content || "").trim();
    // guardrail: flag any CVE the model mentions that no tool returned
    const unverified = [...new Set((answer.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((x) => x.toUpperCase()))].filter((c) => !seen.has(c));
    let html = toHtml(answer);
    if (unverified.length) html += `\n\n⚠️ <i>Not verified against the data: ${unverified.map(esc).join(", ")}. Check with /cve.</i>`;
    const src = { lookup_cve: "NVD · EPSS · CISA KEV", search_kev: "CISA KEV", recent_news: "security news", todays_digest: "today's digest" };
    if (used.size) html += `\n\n<i>Sources: ${[...used].map((u) => src[u]).join(" · ")}</i>`;
    return html;
  }
  return "⚠️ That took too many steps. Try a narrower question, or /cve, /vendor, /kev.";
}
