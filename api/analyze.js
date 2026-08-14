// Vercel Serverless Function - runs on Vercel's servers, never in the browser.
// Keeps your Google Gemini API key secret while letting the app make real AI requests.
// Vercel auto-detects any file inside /api as a serverless endpoint - no extra
// configuration needed. This becomes reachable at: https://DEINE-APP.vercel.app/api/analyze
//
// Get a free API key (no credit card required) at: https://aistudio.google.com/apikey

// Google renames/retires its free "Flash" model every few months. Instead of relying on
// a single hardcoded name, we try a short list in order and use whichever one responds
// successfully - this survives Google quietly retiring one of them ahead of schedule.
const GEMINI_MODELS = ["gemini-3.5-flash", "gemini-3.6-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite"];

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: "Server not configured: GEMINI_API_KEY environment variable is missing." });
    return;
  }

  const { contents } = req.body || {};
  if (!contents) {
    res.status(400).json({ error: "Missing 'contents' in request body." });
    return;
  }

  let lastError = null;
  for (const model of GEMINI_MODELS) {
    try {
      const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({ contents }),
      });
      const data = await geminiRes.json();
      if (geminiRes.ok) {
        res.status(200).json(data);
        return;
      }
      lastError = data;
    } catch (err) {
      lastError = { error: err.message || "Unknown server error" };
    }
  }
  res.status(502).json(lastError || { error: "All Gemini models failed" });
}
