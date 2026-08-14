// Vercel Serverless Function - runs on Vercel's servers, never in the browser.
// Keeps your Google Gemini API key secret while letting the app make real AI requests.
// Vercel auto-detects any file inside /api as a serverless endpoint - no extra
// configuration needed. This becomes reachable at: https://DEINE-APP.vercel.app/api/analyze
//
// Get a free API key (no credit card required) at: https://aistudio.google.com/apikey

const GEMINI_MODEL = "gemini-2.5-flash";

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

  try {
    const { contents } = req.body || {};
    if (!contents) {
      res.status(400).json({ error: "Missing 'contents' in request body." });
      return;
    }

    const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({ contents }),
    });

    const data = await geminiRes.json();
    res.status(geminiRes.status).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message || "Unknown server error" });
  }
}
