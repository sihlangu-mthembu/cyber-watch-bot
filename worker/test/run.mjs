// Offline end-to-end test: stubs Telegram, NVD, EPSS, Groq and the data files, then drives the Worker.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker, { sha256hex } from "../src/index.js";

const TOKEN = "123:TEST";
const dataDir = new URL("./fixtures/", import.meta.url);
const sent = [];
let groqStep = 0;

globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? input : input.url;
  const body = init.body ? JSON.parse(init.body) : null;
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (url.startsWith("https://api.telegram.org/")) {
    const method = url.split("/").pop();
    sent.push({ method, body });
    return json({ ok: true, result: method === "getMe" ? { username: "test_bot" } : {} });
  }
  if (url.startsWith("https://data.test/")) return new Response(readFileSync(new URL(url.split("/").pop(), dataDir)));
  if (url.startsWith("https://services.nvd.nist.gov/")) {
    return json({ vulnerabilities: [{ cve: { id: "CVE-2026-11111", published: "2026-11-19T10:00:00", vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "Heap overflow in FortiOS SSL-VPN allows remote code execution." }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", version: "3.1" } }] },
      weaknesses: [{ description: [{ value: "CWE-122" }] }], references: [{ url: "https://fortiguard.example/psirt" }] } }] });
  }
  if (url.startsWith("https://api.first.org/")) return json({ data: [{ cve: "CVE-2026-11111", epss: "0.94", percentile: "0.998", date: "2026-11-21" }] });
  if (url.startsWith("https://api.groq.com/")) {
    groqStep++;
    if (groqStep === 1) return json({ choices: [{ message: { content: "", tool_calls: [{ id: "c1", type: "function", function: { name: "lookup_cve", arguments: '{"cve_id":"CVE-2026-11111"}' } }] } }] });
    return json({ choices: [{ message: { content: "**Yes, patch now.** CVE-2026-11111 is on CISA KEV and used by ransomware. Also see CVE-2099-0001." } }] });
  }
  throw new Error(`unexpected fetch ${url}`);
};

const kv = new Map();
const env = { TELEGRAM_BOT_TOKEN: TOKEN, GROQ_API_KEY: "k", AI_MODEL: "m", DATA_BASE: "https://data.test",
  STATE: { get: async (k) => kv.get(k) ?? null, put: async (k, v) => void kv.set(k, v) } };
const waits = [];
const ctx = { waitUntil: (p) => waits.push(p) };
const secret = await sha256hex(`webhook:${TOKEN}`);

async function say(chatId, text) {
  sent.length = 0;
  const req = new Request("https://bot.test/telegram", { method: "POST", headers: { "x-telegram-bot-api-secret-token": secret, "content-type": "application/json" },
    body: JSON.stringify({ message: { chat: { id: chatId }, text } }) });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 200);
  await Promise.all(waits.splice(0));
  return sent.filter((s) => s.method === "sendMessage").map((s) => s.body.text).join("\n");
}

// 1. bad webhook secret is rejected
const bad = await worker.fetch(new Request("https://bot.test/telegram", { method: "POST", body: "{}" }), env, ctx);
assert.equal(bad.status, 403); console.log("✓ rejects requests without the webhook secret");
// 2. first /start claims ownership; strangers are locked out
assert.match(await say(111, "/start"), /now the owner/); console.log("✓ first /start becomes owner");
assert.match(await say(222, "/help"), /private bot/); console.log("✓ strangers are locked out");
// 3. commands
assert.match(await say(111, "/cve cve-2026-11111"), /Actively exploited.*ransomware/s); console.log("✓ /cve card with KEV + EPSS + CVSS");
const v = await say(111, "/vendor fortinet"); assert.match(v, /1 vulnerabilities on CISA's exploited list/); console.log("✓ /vendor search");
assert.match(await say(111, "/kev 30"), /CVE-2026-22222/); console.log("✓ /kev recent list");
assert.match(await say(111, "/news ransomware"), /municipality/); console.log("✓ /news filter");
assert.match(await say(111, "/digest"), /Patch first/); console.log("✓ /digest");
// 4. agent: uses a tool, flags the CVE it never saw
const a = await say(111, "Should we worry about the Fortinet bug?");
assert.match(a, /<b>Yes, patch now.<\/b>/); assert.match(a, /Not verified.*CVE-2099-0001/); assert.doesNotMatch(a, /Not verified.*CVE-2026-11111/);
assert.match(a, /Sources: NVD · EPSS · CISA KEV/); console.log("✓ agent calls tools, cites sources, flags unverified CVEs");
// 5. owner can allow another user, broadcast reaches both
assert.match(await say(111, "/allow 222"), /Allowed users: 222/);
assert.doesNotMatch(await say(222, "/help"), /private bot/); console.log("✓ /allow grants access");
sent.length = 0;
const auth = await sha256hex(`broadcast:${TOKEN}`);
const b = await worker.fetch(new Request("https://bot.test/broadcast", { method: "POST", headers: { authorization: `Bearer ${auth}` }, body: JSON.stringify({ html: "<b>hi</b>" }) }), env, ctx);
assert.deepEqual(await b.json(), { sent: 2, owner: true }); console.log("✓ broadcast to owner + allowed users");
const nob = await worker.fetch(new Request("https://bot.test/broadcast", { method: "POST", body: "{}" }), env, ctx);
assert.equal(nob.status, 403); console.log("✓ broadcast needs the derived key");
// 6. setup + health
const s = await worker.fetch(new Request("https://bot.test/setup", { method: "POST", headers: { authorization: `Bearer ${await sha256hex(`setup:${TOKEN}`)}` } }), env, ctx);
const sj = await s.json(); assert.equal(sj.webhook, true); assert.equal(sj.bot, "test_bot");
const hook = sent.find((x) => x.method === "setWebhook").body; assert.equal(hook.url, "https://bot.test/telegram"); assert.equal(hook.secret_token, secret);
console.log("✓ /setup registers webhook with secret and commands");
const h = await (await worker.fetch(new Request("https://bot.test/health"), env, ctx)).json();
assert.equal(h.owner_set, true); assert.equal(h.data_ok, true); console.log("✓ /health");
// 7. long messages are split under Telegram's limit
const { chunks } = await import("../src/telegram.js");
assert.ok(chunks("x".repeat(100) + "\n" + "y\n".repeat(3000)).every((c) => c.length <= 3900)); console.log("✓ long messages split");
console.log("\nAll worker tests passed.");
