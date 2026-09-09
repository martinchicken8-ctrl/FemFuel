// Vercel Serverless Function - manages a SHARED, server-side cache of German recipe
// translations, stored in Vercel Blob. This is the key piece that makes translation
// happen only ONCE, system-wide, rather than separately for every visitor's browser:
//
// - GET  /api/translations  -> returns whatever has been translated so far (fast, free)
// - POST /api/translations  -> translates the next small batch of untranslated recipes
//                               (using Gemini) and saves the updated result back to Blob
//
// The app calls GET on every load to show cached translations immediately, and fires a
// background POST if the library isn't fully translated yet - contributing a small batch
// of progress. Because progress is shared centrally, the app converges to "fully
// translated for everyone" after a handful of total visits, not per visitor.

import { put, head } from "@vercel/blob";

const BLOB_PATH = "nicinsync-recipe-translations.json";
const BATCH_SIZE = 6; // small enough to safely finish within a serverless function's time limit
const GEMINI_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest"];

async function readTranslations() {
  try {
    const info = await head(BLOB_PATH).catch(() => null);
    if (!info) return {};
    const res = await fetch(info.url);
    if (!res.ok) return {};
    return await res.json();
  } catch (err) {
    return {};
  }
}

async function writeTranslations(data) {
  await put(BLOB_PATH, JSON.stringify(data), {
    access: "public",
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: "application/json",
  });
}

async function callGemini(apiKey, prompt) {
  let lastErr = null;
  for (const model of GEMINI_MODELS) {
    try {
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }] }),
      });
      const data = await res.json();
      if (res.ok) {
        const text = data?.candidates?.[0]?.content?.parts?.find((p) => typeof p.text === "string")?.text;
        if (text) return text;
      }
      lastErr = data;
    } catch (err) {
      lastErr = { error: err.message };
    }
  }
  throw new Error(`All Gemini models failed: ${JSON.stringify(lastErr).slice(0, 200)}`);
}

async function translateOne(apiKey, recipe) {
  const prompt = `Translate this recipe from English to natural, appetizing German. Respond with ONLY a JSON object, no markdown, in exactly this shape:
{"title":"...","ingredients":["...","..."],"steps":["...","..."]}

Title: ${recipe.title}
Ingredients:
${recipe.ingredients.map((i) => `- ${i}`).join("\n")}
Steps:
${recipe.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`;
  const text = await callGemini(apiKey, prompt);
  const cleaned = text.replace(/```json|```/g, "").trim();
  const parsed = JSON.parse(cleaned);
  if (!parsed.title || !Array.isArray(parsed.ingredients) || !Array.isArray(parsed.steps)) {
    throw new Error("Unexpected translation shape");
  }
  return parsed;
}

export default async function handler(req, res) {
  try {
    if (req.method === "GET") {
      const translations = await readTranslations();
      res.status(200).json({ translations, count: Object.keys(translations).length });
      return;
    }

    if (req.method === "POST") {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(500).json({ error: "GEMINI_API_KEY missing" });
        return;
      }
      const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      const allRecipes = body?.recipes;
      if (!Array.isArray(allRecipes)) {
        res.status(400).json({ error: "Missing 'recipes' array in request body" });
        return;
      }

      const translations = await readTranslations();
      const remaining = allRecipes.filter((r) => !translations[r.id]);
      const batch = remaining.slice(0, BATCH_SIZE);

      for (const recipe of batch) {
        try {
          translations[recipe.id] = await translateOne(apiKey, recipe);
        } catch (err) {
          console.warn(`Translation failed for ${recipe.id}:`, err.message);
        }
      }

      if (batch.length > 0) await writeTranslations(translations);

      res.status(200).json({
        translations,
        count: Object.keys(translations).length,
        total: allRecipes.length,
        done: Object.keys(translations).length >= allRecipes.length,
      });
      return;
    }

    res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    res.status(500).json({ error: err.message || "Unknown server error" });
  }
}
