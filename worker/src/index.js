// Cyber Watch Bot: Telegram threat-intel agent on Cloudflare Workers (free plan).
// The heavy lifting (CISA KEV, NVD, EPSS, news) runs daily in GitHub Actions and is published
// as small JSON files; this Worker answers chats, looks up single CVEs live and calls the AI.
import { answerWithAgent } from "./agent.js";
import { esc, sendHtml, tg } from "./telegram.js";
import { cveCard, latestIntel, lookupCve, recentNews, searchKev } from "./tools.js";

const enc = new TextEncoder();
export async function sha256hex(s) {
  const b = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const COMMANDS = [
  ["digest", "Today's threat digest"],
  ["cve", "Look up a CVE: /cve CVE-2024-3400"],
  ["vendor", "Exploited bugs for a vendor: /vendor fortinet"],
  ["kev", "Newly exploited vulnerabilities: /kev 14"],
  ["news", "Security headlines: /news ransomware"],
  ["help", "What I can do"],
];

const HELP = `🛡 <b>Cyber Watch</b> tracks actively exploited vulnerabilities and security news for you.

<b>Commands</b>
/digest: today's briefing (also sent every morning at 06:30)
/cve CVE-ID: severity, exploit probability, CISA KEV status
/vendor name: exploited bugs for a vendor (e.g. /vendor fortinet)
/kev [days]: newly added to CISA's exploited list
/news [topic]: latest security headlines

Or just ask, e.g. <i>"Should we worry about the new Citrix bug?"</i> or <i>"Explain CVE-2024-3400 for my CEO"</i>.

<i>Sources: CISA KEV, NIST NVD, FIRST EPSS, security news. Answers are AI-assisted and checked against the data.</i>`;

async function getAccess(env) {
  const owner = await env.STATE.get("owner");
  const allowed = JSON.parse((await env.STATE.get("allowed")) || "[]");
  return { owner, allowed };
}

async function handleMessage(env, msg) {
  const chatId = String(msg.chat.id);
  const text = (msg.text || "").trim();
  if (!text) return;
  const [rawCmd, ...rest] = text.split(/\s+/);
  const cmd = rawCmd.startsWith("/") ? rawCmd.slice(1).split("@")[0].toLowerCase() : null;
  const arg = rest.join(" ").trim();
  let { owner, allowed } = await getAccess(env);

  // first person to /start becomes the owner; everyone else needs the owner's /allow
  if (!owner && cmd === "start") {
    await env.STATE.put("owner", chatId);
    owner = chatId;
    await sendHtml(env, chatId, `✅ You're now the owner of this bot.\n\n${HELP}`);
    return;
  }
  const isOwner = chatId === owner;
  if (!isOwner && !allowed.includes(chatId)) {
    await sendHtml(env, chatId, `🔒 This is a private bot. Ask the owner to run <code>/allow ${esc(chatId)}</code>.`);
    return;
  }

  await tg(env, "sendChatAction", { chat_id: chatId, action: "typing" });
  switch (cmd) {
    case "start":
    case "help":
      return sendHtml(env, chatId, HELP);
    case "digest": {
      const intel = await latestIntel(env);
      return sendHtml(env, chatId, intel.digest_html || "No digest yet.");
    }
    case "cve": {
      const id = (arg.match(/CVE-\d{4}-\d{4,7}/i) || [])[0];
      if (!id) return sendHtml(env, chatId, "Send it like: <code>/cve CVE-2024-3400</code>");
      return sendHtml(env, chatId, cveCard(await lookupCve(env, id)));
    }
    case "vendor": {
      if (!arg) return sendHtml(env, chatId, "Send it like: <code>/vendor fortinet</code>");
      const r = await searchKev(env, { query: arg, limit: 8 });
      const lines = [`🏷 <b>${esc(arg)}</b>: ${r.total} vulnerabilities on CISA's exploited list${r.ransomware ? `, ${r.ransomware} used by ransomware` : ""}`];
      for (const k of r.items) lines.push(`• <code>${k.cve}</code> ${esc(k.product)} · added ${k.added}${k.ransomware ? " ⚠️" : ""}\n   ${esc(k.name)}`);
      if (r.recentCritical.length) {
        lines.push("", "<b>New critical CVEs (48h)</b>");
        for (const c of r.recentCritical) lines.push(`• <code>${c.cve}</code> CVSS ${c.cvss ?? "n/a"} · ${esc(c.product)}`);
      }
      if (!r.total && !r.recentCritical.length) lines.push("Nothing found. Try a shorter name, e.g. <code>/vendor cisco</code>.");
      return sendHtml(env, chatId, lines.join("\n"));
    }
    case "kev": {
      const days = Math.min(Math.max(parseInt(arg) || 7, 1), 90);
      const r = await searchKev(env, { days, limit: 15 });
      const lines = [`🚨 <b>Added to CISA KEV in the last ${days} days: ${r.total}</b>`];
      for (const k of r.items) lines.push(`• <code>${k.cve}</code> ${esc(k.vendor)} ${esc(k.product)} · ${k.added}${k.ransomware ? " ⚠️ ransomware" : ""}`);
      return sendHtml(env, chatId, lines.join("\n"));
    }
    case "news": {
      const r = await recentNews(env, { query: arg, limit: 8 });
      const lines = [`📰 <b>${arg ? `Headlines: ${esc(arg)}` : "Latest security headlines"}</b>`];
      for (const n of r.items) lines.push(`• <a href="${esc(n.link)}">${esc(n.title)}</a> (${esc(n.source)})`);
      if (!r.items.length) lines.push("No matching headlines in the last 36 hours.");
      return sendHtml(env, chatId, lines.join("\n"));
    }
    case "allow":
    case "revoke": {
      if (!isOwner) return sendHtml(env, chatId, "Only the owner can do that.");
      const id = arg.replace(/[^\d-]/g, "");
      if (!id) return sendHtml(env, chatId, `Send it like: <code>/${cmd} 123456789</code>`);
      allowed = cmd === "allow" ? [...new Set([...allowed, id])] : allowed.filter((x) => x !== id);
      await env.STATE.put("allowed", JSON.stringify(allowed));
      return sendHtml(env, chatId, `Done. Allowed users: ${allowed.length ? allowed.map(esc).join(", ") : "none"}`);
    }
    case "whoami":
      return sendHtml(env, chatId, `Your chat ID: <code>${esc(chatId)}</code>${isOwner ? " (owner)" : ""}`);
    default:
      return sendHtml(env, chatId, await answerWithAgent(env, text));
  }
}

async function authorised(request, env, purpose) {
  const want = await sha256hex(`${purpose}:${env.TELEGRAM_BOT_TOKEN}`);
  return (request.headers.get("authorization") || "") === `Bearer ${want}`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (request.method === "POST" && url.pathname === "/telegram") {
        const secret = await sha256hex(`webhook:${env.TELEGRAM_BOT_TOKEN}`);
        if (request.headers.get("x-telegram-bot-api-secret-token") !== secret) return new Response("forbidden", { status: 403 });
        const update = await request.json();
        const msg = update.message || update.edited_message;
        if (msg) {
          // reply in the background so Telegram gets its 200 at once and never retries
          ctx.waitUntil(handleMessage(env, msg).catch((e) =>
            sendHtml(env, String(msg.chat.id), `⚠️ Something went wrong: <code>${esc(String(e.message || e)).slice(0, 200)}</code>`)));
        }
        return new Response("ok");
      }
      if (request.method === "POST" && url.pathname === "/broadcast") {
        if (!(await authorised(request, env, "broadcast"))) return new Response("forbidden", { status: 403 });
        const { html } = await request.json();
        const { owner, allowed } = await getAccess(env);
        const to = [owner, ...allowed].filter(Boolean);
        for (const id of to) await sendHtml(env, id, html);
        return Response.json({ sent: to.length, owner: Boolean(owner) });
      }
      if (request.method === "POST" && url.pathname === "/setup") {
        if (!(await authorised(request, env, "setup"))) return new Response("forbidden", { status: 403 });
        const secret = await sha256hex(`webhook:${env.TELEGRAM_BOT_TOKEN}`);
        const hook = await tg(env, "setWebhook", {
          url: `${url.origin}/telegram`, secret_token: secret, allowed_updates: ["message", "edited_message"], drop_pending_updates: true,
        });
        const cmds = await tg(env, "setMyCommands", { commands: COMMANDS.map(([command, description]) => ({ command, description })) });
        const desc = await tg(env, "setMyDescription", { description: "Threat-intel assistant: actively exploited vulnerabilities (CISA KEV), CVE severity and exploit probability (NVD, EPSS) and security news, with a daily digest." });
        const me = await tg(env, "getMe", {});
        return Response.json({ webhook: hook.ok, commands: cmds.ok, description: desc.ok, bot: me.result?.username || null });
      }
      if (url.pathname === "/health") {
        let generated = null, dataOk = false;
        try { generated = (await latestIntel(env)).generated; dataOk = true; } catch {}
        const { owner, allowed } = await getAccess(env);
        return Response.json({ ok: true, owner_set: Boolean(owner), allowed: allowed.length, data_ok: dataOk, data_generated: generated });
      }
      return new Response("Cyber Watch Bot is running. Talk to it on Telegram.", { status: 200 });
    } catch (e) {
      return Response.json({ ok: false, error: String(e.message || e) }, { status: 500 });
    }
  },
};
