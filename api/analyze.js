// Vercel Serverless Function - runs on Vercel's servers, never in the browser.
// Keeps your Google Gemini API key secret while letting the app make real AI requests.
// Vercel auto-detects any file inside /api as a serverless endpoint - no extra
// configuration needed. This becomes reachable at: https://DEINE-APP.vercel.app/api/analyze
//
// Get a free API key (no credit card required) at: https://aistudio.google.com/apikey
//
// DIAGNOSTIC VERSION: every failure mode returns a distinct, explicit message
// (rather than a generic one) so the exact cause is visible directly in the app's
// error banner - no need to dig through Vercel's dashboard.

const GEMINI_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest"];

export default async function handler(req, res) {
  // Wrap literally everything - so even an unexpected crash returns a readable
  // JSON error instead of a bare 500 with no body.
  try {
    if (req.method !== "POST") {
      res.status(405).json({ error: `DIAG: wrong method "${req.method}", expected POST` });
      return;
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(500).json({ error: "DIAG: GEMINI_API_KEY is missing or empty in this deployment's environment." });
      return;
    }

    // Defensive body parsing: normally Vercel auto-parses JSON bodies, but if it
    // ever arrives as a raw string for any reason, handle that too.
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch (e) {
        res.status(400).json({ error: "DIAG: request body was a string and not valid JSON.", raw: body.slice(0, 200) });
        return;
      }
    }
    if (!body || typeof body !== "object") {
      res.status(400).json({ error: `DIAG: request body missing or not an object (got ${typeof body}).` });
      return;
    }

    const { contents } = body;
    if (!contents) {
      res.status(400).json({ error: "DIAG: 'contents' field missing from parsed request body.", bodyKeys: Object.keys(body) });
      return;
    }

    const attempts = [];
    const modelsToTry = [...GEMINI_MODELS, GEMINI_MODELS[0]]; // retry the primary once more at the end, in case the 503 was momentary
    for (let i = 0; i < modelsToTry.length; i++) {
      const model = modelsToTry[i];
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
        attempts.push({ model, status: geminiRes.status, error: data?.error?.message || JSON.stringify(data).slice(0, 200) });
        // brief pause before the next attempt - "high demand" (503) errors are often gone within a second or two
        if (i < modelsToTry.length - 1) await new Promise((r) => setTimeout(r, 1200));
      } catch (err) {
        attempts.push({ model, error: `fetch threw: ${err.message}` });
      }
    }

    res.status(502).json({ error: "DIAG: all Gemini models failed.", attempts });
  } catch (outerErr) {
    res.status(500).json({ error: `DIAG: unexpected crash in handler: ${outerErr.message}`, stack: (outerErr.stack || "").slice(0, 500) });
  }
}
