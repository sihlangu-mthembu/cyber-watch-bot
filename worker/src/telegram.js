export const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export async function tg(env, method, payload) {
  const r = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  return r.json().catch(() => ({ ok: false }));
}

// Telegram caps messages at 4096 characters: split on line breaks.
export function chunks(text, max = 3900) {
  const out = [];
  let cur = "";
  for (const line of text.split("\n")) {
    if ((cur + "\n" + line).length > max && cur) {
      out.push(cur);
      cur = line;
    } else cur = cur ? `${cur}\n${line}` : line;
  }
  if (cur) out.push(cur);
  return out;
}

export async function sendHtml(env, chatId, html) {
  for (const part of chunks(html)) {
    const r = await tg(env, "sendMessage", { chat_id: chatId, text: part, parse_mode: "HTML", disable_web_page_preview: true });
    if (!r.ok) {
      // malformed HTML from upstream text: fall back to plain text rather than failing silently
      await tg(env, "sendMessage", { chat_id: chatId, text: part.replace(/<[^>]+>/g, ""), disable_web_page_preview: true });
    }
  }
}
