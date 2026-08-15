import React, { useState, useMemo, useEffect, useRef, useCallback, createContext, useContext } from "react";
import {
  Home,
  Salad,
  BookOpen,
  Activity,
  Droplet,
  Sprout,
  Sun,
  Moon,
  Camera,
  Sparkles,
  Search,
  Clock,
  Flame,
  ChevronRight,
  ChevronLeft,
  Check,
  X,
  Wheat,
  Beef,
  Nut,
  Frown,
  Zap,
  Wind,
  HeartCrack,
  Brain,
  Smile,
  Meh,
  CircleDot,
  Settings,
  AlertTriangle,
  Leaf,
  ArrowRight,
  Pencil,
  Trash2,
  CalendarDays,
  Wand2,
  ListChecks,
  ChefHat,
  ImagePlus,
  ShoppingCart,
  Gauge,
  TrendingUp,
  Refrigerator,
  Plus,
  Mic,
  MicOff,
  Award,
  Trophy,
  Bookmark,
  Heart,
  BookmarkCheck,
} from "lucide-react";

/* ------------------------------- Security utilities ------------------------------- */

// --- 1. Cryptographically secure ID generation (replaces Math.random()-based ids) ---
function secureId(prefix) {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      const uuid = crypto.randomUUID();
      return prefix ? `${prefix}-${uuid}` : uuid;
    }
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
      bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
      const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      return prefix ? `${prefix}-${uuid}` : uuid;
    }
  } catch (e) {
    /* fall through to last-resort below */
  }
  // Extremely unlikely fallback (very old / insecure-context browser only). Not used for
  // anything security-relevant elsewhere - this only ever backs list keys/local item ids.
  console.warn("secureId(): Web Crypto unavailable, using a non-cryptographic fallback id.");
  const rand = Date.now().toString(36) + Math.random().toString(36).slice(2);
  return prefix ? `${prefix}-${rand}` : rand;
}

// --- 2. Input sanitization for all free-text user entry (defense in depth on top of
//        React's default JSX escaping - guards against control characters, keeps stored
//        data safe even if it is later rendered somewhere that doesn't auto-escape, e.g.
//        an export/print view, and caps length to stop localStorage/UI abuse). ---
function sanitizeText(input, maxLen = 200) {
  if (typeof input !== "string") return "";
  const withoutControlChars = input.replace(/[\u0000-\u001F\u007F]/g, "");
  const withoutMarkup = withoutControlChars.replace(/[<>]/g, "");
  return withoutMarkup.trim().slice(0, maxLen);
}
// Same protections as sanitizeText but without trimming, so it's safe to run on every
// keystroke of a live search/filter field without eating a trailing space the user just typed.
function sanitizeLiveInput(input, maxLen = 200) {
  if (typeof input !== "string") return "";
  const withoutControlChars = input.replace(/[\u0000-\u001F\u007F]/g, "");
  return withoutControlChars.replace(/[<>]/g, "").slice(0, maxLen);
}

// --- 3. Prototype-pollution-safe JSON parsing ---
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function safeJSONParse(text, fallback) {
  try {
    return JSON.parse(text, (key, value) => (DANGEROUS_KEYS.has(key) ? undefined : value));
  } catch (e) {
    console.warn("safeJSONParse(): invalid or corrupted JSON, using fallback value.", e);
    return fallback;
  }
}

// --- 4. Lightweight schema validation for every persisted key, so a tampered or
//        corrupted localStorage entry can never crash the app or inject unexpected
//        shapes into state - it just falls back to a safe default instead. ---
function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
const STORAGE_VALIDATORS = {
  nicinsync_lang: (v) => v === "de" || v === "en",
  nicinsync_cycle_start: (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v),
  nicinsync_profile: (v) =>
    isPlainObject(v) &&
    typeof v.height === "number" && v.height > 0 && v.height < 300 &&
    typeof v.weight === "number" && v.weight > 0 && v.weight < 400 &&
    typeof v.age === "number" && v.age > 0 && v.age < 120 &&
    Array.isArray(v.diets),
  nicinsync_recipes: (v) => Array.isArray(v),
  nicinsync_logs: (v) => isPlainObject(v),
  nicinsync_mood_log: (v) => isPlainObject(v),
  nicinsync_shopping: (v) => Array.isArray(v),
  nicinsync_favorites: (v) => Array.isArray(v),
  nicinsync_shortcuts: (v) => Array.isArray(v),
};
function isValidForKey(key, value) {
  const validator = STORAGE_VALIDATORS[key];
  return validator ? validator(value) : true;
}

// --- 5. Encrypted at-rest storage (AES-GCM, 256-bit, non-extractable per-device key).
//
//        Honest scope of this protection: the key is generated with crypto.subtle
//        (extractable: false) and kept in IndexedDB, so the raw key material can never
//        be exported or exfiltrated - copying the encrypted blob out of localStorage
//        alone is useless without this specific browser profile's key. This stops
//        passive/offline snooping (devtools on a shared device, a browser extension that
//        only reads storage, a backup of the localStorage file, etc.).
//        It does NOT protect against an active XSS payload running on this origin, since
//        such a payload could call the same decrypt function our own code uses. Encryption
//        is defense-in-depth here, not a substitute for XSS prevention. ---
const SECURE_DB_NAME = "nicinsync_secure";
const SECURE_STORE = "keys";
const DEVICE_KEY_ID = "device-key";

function openKeyDB() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB unavailable"));
      return;
    }
    const req = indexedDB.open(SECURE_DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(SECURE_STORE)) req.result.createObjectStore(SECURE_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getDeviceKey() {
  const db = await openKeyDB();
  const existing = await new Promise((resolve, reject) => {
    const tx = db.transaction(SECURE_STORE, "readonly");
    const req = tx.objectStore(SECURE_STORE).get(DEVICE_KEY_ID);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
  if (existing) return existing;

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await new Promise((resolve, reject) => {
    const tx = db.transaction(SECURE_STORE, "readwrite");
    tx.objectStore(SECURE_STORE).put(key, DEVICE_KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return key;
}

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function encryptJSON(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { v: 1, iv: bufToBase64(iv), data: bufToBase64(ciphertext) };
}
async function decryptJSON(key, payload) {
  const iv = base64ToBuf(payload.iv);
  const data = base64ToBuf(payload.data);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return safeJSONParse(new TextDecoder().decode(plaintext), undefined);
}
function isEncryptedPayload(v) {
  return isPlainObject(v) && v.v === 1 && typeof v.iv === "string" && typeof v.data === "string";
}

/**
 * Encrypted, validated, corruption-safe replacement for a plain useLocalStorage hook.
 * - Reads are synchronous on first render (using any previously-decrypted/legacy plaintext
 *   value so the UI has no loading flicker), then upgraded to the decrypted value shortly
 *   after mount once the device key is available.
 * - Every value - on read AND on write - is checked against STORAGE_VALIDATORS[key] before
 *   it is trusted, so a manipulated or corrupted entry can never crash the app.
 * - Writes are always encrypted going forward, transparently migrating any old plaintext
 *   entries the first time they're saved again.
 */
function useLocalStorage(key, initialValue) {
  const [storedValue, setStoredValue] = useState(() => {
    try {
      if (typeof window === "undefined") return initialValue;
      const raw = window.localStorage.getItem(key);
      if (!raw) return initialValue;
      const parsed = safeJSONParse(raw, undefined);
      if (isEncryptedPayload(parsed)) return initialValue; // will be decrypted async below
      return isValidForKey(key, parsed) ? parsed : initialValue;
    } catch (error) {
      console.error(`[useLocalStorage] Error reading key "${key}":`, error);
      return initialValue;
    }
  });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const raw = window.localStorage.getItem(key);
        if (!raw) return;
        const parsed = safeJSONParse(raw, undefined);
        if (!isEncryptedPayload(parsed)) return; // already handled synchronously above
        const deviceKey = await getDeviceKey();
        const decrypted = await decryptJSON(deviceKey, parsed);
        if (!cancelled && isValidForKey(key, decrypted)) setStoredValue(decrypted);
      } catch (error) {
        console.warn(`[useLocalStorage] Could not decrypt key "${key}", keeping default value.`, error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [key]);

  const setValue = useCallback(
    (value) => {
      setStoredValue((prev) => {
        const valueToStore = value instanceof Function ? value(prev) : value;
        if (!isValidForKey(key, valueToStore)) {
          console.error(`[useLocalStorage] Refused to persist invalid value for key "${key}".`);
          return prev;
        }
        (async () => {
          try {
            const deviceKey = await getDeviceKey();
            const payload = await encryptJSON(deviceKey, valueToStore);
            window.localStorage.setItem(key, JSON.stringify(payload));
          } catch (error) {
            // Web Crypto/IndexedDB unavailable (very old browser, private-mode restrictions, etc.)
            // - fall back to plain storage rather than silently losing the write.
            console.error(`[useLocalStorage] Encrypted write failed for "${key}", falling back to plain storage.`, error);
            try {
              window.localStorage.setItem(key, JSON.stringify(valueToStore));
            } catch (_) {
              /* localStorage unavailable/full - nothing more we can do */
            }
          }
        })();
        return valueToStore;
      });
    },
    [key]
  );

  return [storedValue, setValue];
}

function clearAllLocalData() {
  const keys = [
    "nicinsync_lang",
    "nicinsync_cycle_start",
    "nicinsync_profile",
    "nicinsync_recipes",
    "nicinsync_logs",
    "nicinsync_mood_log",
    "nicinsync_shopping",
    "nicinsync_favorites",
    "nicinsync_shortcuts",
  ];
  keys.forEach((k) => {
    try {
      window.localStorage.removeItem(k);
    } catch (e) {
      /* ignore */
    }
  });
  try {
    indexedDB.deleteDatabase(SECURE_DB_NAME);
  } catch (e) {
    /* ignore */
  }
}


/* ------------------------------- Language / i18n ------------------------------- */
const LangContext = createContext({ lang: "de", t: (k) => k });
function useLang() {
  return useContext(LangContext);
}

const UI_TEXT = {
  de: {
    nav_dashboard: "Dashboard",
    cycle_day: "Zyklustag",
    drag_dial_hint: "Gedrückt halten, dann ziehen, um den Zyklustag zu ändern",
    nav_tracker: "Tracker",
    nav_recipes: "Rezepte",
    nav_shopping: "Einkauf",
    nav_symptoms: "Symptome",
    greeting: "Guten Tag",
    hello: "Hallo",
    hormone_score: "Hormone-Balance-Score",
    rewards_title: "Belohnungen",
    rewards_points: "Punkte",
    rewards_streak_active: "Tag(e) in Folge gut ernährt",
    rewards_streak_empty: "Logge heute deine erste Mahlzeit, um deine Streak zu starten!",
    rewards_no_badges: "Erreiche an einem Tag einen Score ab 60%, um dein erstes Abzeichen freizuschalten.",
    recommended_for: "Empfohlen für deine",
    todays_recipe_picks: "Rezeptvorschläge für heute",
    prep_time: "Vorbereitung",
    cook_time: "Kochzeit",
    total_time: "Gesamt",
    focus_label: "Fokus",
    to_recipe: "Zum Rezept",
    nutrient_focus: "Nährstoff-Fokus",
    tracker_title: "Kalorien & Nährstoffe",
    today: "Heute",
    calorie_bonus: "kcal Bonus",
    history_search: "Verlauf durchsuchen",
    protein: "Protein",
    carbs: "Kohlenhydrate",
    fat: "Fett",
    remaining_kcal: "Noch",
    remaining_kcal_suffix: "kcal übrig",
    eaten_label: "Gegessen",
    meal_breakfast: "Frühstück",
    meal_lunch: "Mittagessen",
    meal_dinner: "Abendessen",
    meal_snack: "Snacks",
    add_meal_aria: "Mahlzeit hinzufügen",
    choose_meal_type: "Zu welcher Mahlzeit hinzufügen?",
    logging_to: "Wird protokolliert unter",
    goal_label: "Ziel",
    remaining_label: "Übrig",
    goal_from_profile: "Individuelles Ziel aus deinem Profil",
    scanner_title: "KI-Food-Scanner",
    scanner_placeholder: "z. B. 1 Schüssel Haferflocken mit Beeren und Mandeln… oder 'Pommes'",
    listening: "Höre zu… sag, was du gegessen hast",
    photo_change: "Foto ändern",
    photo_take: "Foto",
    analyzing: "Analysiere…",
    analyze_button: "Analysieren & eintragen",
    your_shortcuts: "Deine Shortcuts",
    no_shortcuts_yet: "Noch keine Shortcuts – lege dir welche für Mahlzeiten an, die du oft isst.",
    new_shortcut: "Neuer Shortcut",
    shortcut_name_label: "Name",
    logged_today: "Heute geloggt",
    logged_on: "Geloggt am",
    no_meals_day: "Für diesen Tag wurden noch keine Mahlzeiten geloggt.",
    match: "Match",
    edit: "Bearbeiten",
    delete: "Löschen",
    cancel: "Abbrechen",
    back: "Zurück",
    save: "Speichern",
    close: "Schließen",
    close_recipe_aria: "Rezept schließen",
    shortcut_saved: "Als Shortcut gespeichert",
    added_label: "Hinzugefügt",
    ai_generated_tag: "KI-Generiert",
    leftover_tag: "Resteverwertung",
    filter_all: "Alle",
    clear_all_recipes: "Alle löschen",
    privacy_title: "Datenschutz",
    privacy_hint: "Deine Daten werden ausschließlich verschlüsselt auf diesem Gerät gespeichert - nichts wird an einen Server gesendet. Du kannst sie jederzeit vollständig löschen.",
    delete_my_data: "Meine Daten löschen",
    confirm_delete: "Wirklich löschen",
    recipes_title: "Rezepte für dich",
    curated_for: "Kuratiert für deine",
    recipes_count: "Rezepte",
    search_results_all_phases: "Suchergebnisse über alle Phasen",
    filtered_by: "Gefiltert nach",
    show_saved_only: "Nur gespeicherte anzeigen",
    show_all_recipes: "Alle Rezepte anzeigen",
    discover_tab: "Entdecken",
    my_favorites_tab: "Meine Favoriten",
    popular_categories: "Beliebte Kategorien",
    recipes_by_kcal: "Rezepte nach Kalorien",
    by_cuisine: "Nach Küchenstil",
    by_diet: "Nach Ernährungsart",
    category_filter_active: "Alle zurücksetzen",
    search_recipes: "Rezepte durchsuchen…",
    ai_generate_button: "Neues KI-Rezept für deine Phase generieren",
    ai_generating: "KI generiert Rezept…",
    pantry_title: "Was hast du zu Hause?",
    pantry_placeholder: "z. B. Brokkoli, Eier, Feta",
    pantry_button: "3 neue Rezeptideen aus Resten",
    pantry_generating: "Erstelle 3 Rezeptideen…",
    pantry_generate_cta: "3 neue Rezeptideen aus Resten",
    newly_generated: "Neu für dich generiert",
    min: "Min",
    pantry_new_for_you: "Neu für dich generiert",
    library_matches: "Passende Rezepte aus der Bibliothek",
    ingredients_present: "von",
    ingredients_available: "Zutaten vorhanden",
    no_recipes_found: "Keine Rezepte gefunden. Versuch einen anderen Filter oder Suchbegriff.",
    generating_ai_recipe: "KI generiert Rezept…",
    generate_ai_cta: "Neues KI-Rezept generieren",
    save_recipe_aria: "Rezept speichern",
    recipe_fallback: "Rezept",
    view_ingredients: "Zutaten & Zubereitung ansehen",
    ingredients_for_one: "Zutaten (für 1 Portion)",
    preparation: "Zubereitung",
    cycle_benefit: "Zyklus-Nutzen",
    fits_diet: "Passt zu",
    add_to_shopping: "Zur Einkaufsliste hinzufügen",
    added_to_shopping: "Zur Einkaufsliste hinzugefügt",
    save_as_shortcut: "Als Shortcut für schnelles Loggen speichern",
    save_as_favorite_recipe: "Als Rezept-Favorit speichern",
    edit_meal: "Mahlzeit bearbeiten",
    delete_meal: "Mahlzeit löschen",
    cravings_swap: "Cravings-Swap",
    log_swap_instead: "Swap stattdessen loggen",
    saved_as_shortcut: "Als Shortcut gespeichert",
    ai_generated: "KI-Generiert",
    leftovers: "Resteverwertung",
    shopping_title: "Einkaufsliste",
    shopping_empty: "Noch keine Zutaten hinzugefügt.",
    shopping_done_of: "von",
    shopping_done: "erledigt",
    shopping_clear_list: "Liste leeren",
    shopping_add_placeholder: "Eigenes Lebensmittel hinzufügen…",
    shopping_empty_hint: "Füge oben eigene Artikel hinzu oder öffne ein Rezept und tippe auf \"Zur Einkaufsliste\".",
    for_recipe: "für",
    symptoms_title: "Symptome & Stimmung",
    symptoms_subtitle: "Tracke, wie du dich heute fühlst",
    mood_trend_title: "Stimmungsverlauf (14 Tage)",
    no_entry: "kein Eintrag",
    mood_today: "Stimmung heute",
    select_symptoms: "Symptome auswählen",
    why_happens: "Warum passiert das?",
    helpful_ingredients: "Hilfreiche Zutaten",
    view: "Ansehen",
    select_symptoms_hint: "Wähle Symptome aus, um personalisierte KI-Tipps & Kochempfehlungen zu erhalten.",
    ai_insight_label: "KI-Insight:",
    profile_title: "Dein Profil",
    your_name: "Dein Name",
    name_placeholder: "z. B. Nic",
    height_cm: "Größe (cm)",
    weight_kg: "Gewicht (kg)",
    age_years: "Alter (Jahre)",
    activity_level: "Aktivitätslevel",
    diet_style: "Ernährungsstil",
    diet_multiselect: "(Mehrfachauswahl möglich)",
    language: "Sprache",
    daily_goal: "Berechnetes Tagesziel (Mifflin-St Jeor)",
    luteal_bonus: "kcal Zyklus-Bonus (Lutealphase)",
    shortcut_name: "Name",
    shortcut_name_placeholder: "z. B. Mein Frühstück",
    shortcut_hint: "Für Mahlzeiten, die du oft isst – z. B. dein tägliches Frühstück. Ein Tap loggt sie sofort.",
    add_ingredient: "Zutat hinzufügen",
    portion_size: "Portionsgröße",
    portion_hint: "Bezogen auf {base} bei 100%",
    ingredients_label: "Zutaten & Mengen",
    no_ingredients_hint: "Keine Zutaten – füge unten welche hinzu.",
    remove_ingredient: "Zutat entfernen",
    add: "Hinzufügen",
    remove: "Entfernen",
    undo: "Rückgängig",
    add_extra_placeholder: "z. B. 1 EL Olivenöl",
    remove_placeholder: "z. B. Sauce",
    badge_streak3: "3 Tage in Folge",
    badge_streak7: "7 Tage in Folge",
    badge_streak14: "14 Tage in Folge",
    badge_perfect: "Perfekter Tag",
    badge_pro: "Ernährungs-Profi",
  },
  en: {
    nav_dashboard: "Dashboard",
    cycle_day: "Cycle day",
    drag_dial_hint: "Press and hold, then drag to change your cycle day",
    nav_tracker: "Tracker",
    nav_recipes: "Recipes",
    nav_shopping: "Shopping",
    nav_symptoms: "Symptoms",
    greeting: "Good day",
    hello: "Hello",
    hormone_score: "Hormone Balance Score",
    rewards_title: "Rewards",
    rewards_points: "Points",
    rewards_streak_active: "day(s) in a row eating well",
    rewards_streak_empty: "Log your first meal today to start your streak!",
    rewards_no_badges: "Reach a score of 60% or more on a day to unlock your first badge.",
    recommended_for: "Recommended for your",
    todays_recipe_picks: "Today's recipe picks",
    prep_time: "Prep",
    cook_time: "Cook time",
    total_time: "Total",
    focus_label: "Focus",
    to_recipe: "View recipe",
    nutrient_focus: "Nutrient focus",
    tracker_title: "Calories & Nutrients",
    today: "Today",
    calorie_bonus: "kcal bonus",
    history_search: "Browse history",
    protein: "Protein",
    carbs: "Carbs",
    fat: "Fat",
    remaining_kcal: "",
    remaining_kcal_suffix: "kcal remaining",
    eaten_label: "Eaten",
    meal_breakfast: "Breakfast",
    meal_lunch: "Lunch",
    meal_dinner: "Dinner",
    meal_snack: "Snacks",
    add_meal_aria: "Add meal",
    choose_meal_type: "Add to which meal?",
    logging_to: "Logging to",
    goal_label: "Goal",
    remaining_label: "Remaining",
    goal_from_profile: "Personalised goal from your profile",
    scanner_title: "AI Food Scanner",
    scanner_placeholder: "e.g. 1 bowl of oatmeal with berries and almonds… or 'fries'",
    listening: "Listening… tell me what you ate",
    photo_change: "Change photo",
    photo_take: "Photo",
    analyzing: "Analyzing…",
    analyze_button: "Analyze & log",
    your_shortcuts: "Your shortcuts",
    no_shortcuts_yet: "No shortcuts yet - create one for meals you eat often.",
    new_shortcut: "New shortcut",
    shortcut_name_label: "Name",
    logged_today: "Logged today",
    logged_on: "Logged on",
    no_meals_day: "No meals logged for this day yet.",
    match: "Match",
    edit: "Edit",
    delete: "Delete",
    cancel: "Cancel",
    back: "Back",
    save: "Save",
    close: "Close",
    close_recipe_aria: "Close recipe",
    shortcut_saved: "Saved as shortcut",
    added_label: "Added",
    ai_generated_tag: "AI-generated",
    leftover_tag: "Leftover recipe",
    filter_all: "All",
    clear_all_recipes: "Clear all",
    privacy_title: "Privacy",
    privacy_hint: "Your data is stored encrypted on this device only - nothing is sent to a server. You can delete it completely at any time.",
    delete_my_data: "Delete my data",
    confirm_delete: "Yes, delete everything",
    recipes_title: "Recipes for you",
    curated_for: "Curated for your",
    recipes_count: "recipes",
    search_results_all_phases: "Search results across all phases",
    filtered_by: "Filtered by",
    show_saved_only: "Show saved only",
    show_all_recipes: "Show all recipes",
    discover_tab: "Discover",
    my_favorites_tab: "My Favourites",
    popular_categories: "Popular Categories",
    recipes_by_kcal: "Recipes by Calories",
    by_cuisine: "By Cuisine",
    by_diet: "By Diet",
    category_filter_active: "Clear all",
    search_recipes: "Search recipes…",
    ai_generate_button: "Generate a new AI recipe for your phase",
    ai_generating: "AI is generating a recipe…",
    pantry_title: "What do you have at home?",
    pantry_placeholder: "e.g. broccoli, eggs, feta",
    pantry_button: "3 new recipe ideas from leftovers",
    pantry_generating: "Creating 3 recipe ideas…",
    pantry_generate_cta: "3 new recipe ideas from leftovers",
    newly_generated: "Freshly generated for you",
    min: "min",
    pantry_new_for_you: "Freshly generated for you",
    library_matches: "Matching recipes from the library",
    ingredients_present: "of",
    ingredients_available: "ingredients available",
    no_recipes_found: "No recipes found. Try a different filter or search term.",
    generating_ai_recipe: "AI is generating your recipe…",
    generate_ai_cta: "Generate new AI recipe",
    save_recipe_aria: "Save recipe",
    recipe_fallback: "Recipe",
    view_ingredients: "View ingredients & instructions",
    ingredients_for_one: "Ingredients (for 1 serving)",
    preparation: "Instructions",
    cycle_benefit: "Cycle benefit",
    fits_diet: "Fits",
    add_to_shopping: "Add to shopping list",
    added_to_shopping: "Added to shopping list",
    save_as_shortcut: "Save as a one-tap shortcut",
    save_as_favorite_recipe: "Save as a favorite recipe",
    edit_meal: "Edit meal",
    delete_meal: "Delete meal",
    cravings_swap: "Cravings swap",
    log_swap_instead: "Log swap instead",
    saved_as_shortcut: "Saved as shortcut",
    ai_generated: "AI-generated",
    leftovers: "Leftover recipe",
    shopping_title: "Shopping List",
    shopping_empty: "No ingredients added yet.",
    shopping_done_of: "of",
    shopping_done: "done",
    shopping_clear_list: "Clear list",
    shopping_add_placeholder: "Add your own item…",
    shopping_empty_hint: "Add your own items above, or open a recipe and tap \"Add to shopping list\".",
    for_recipe: "for",
    symptoms_title: "Symptoms & Mood",
    symptoms_subtitle: "Track how you feel today",
    mood_trend_title: "Mood trend (14 days)",
    no_entry: "no entry",
    mood_today: "Mood today",
    select_symptoms: "Select symptoms",
    why_happens: "Why does this happen?",
    helpful_ingredients: "Helpful ingredients",
    view: "View",
    select_symptoms_hint: "Select symptoms to get personalised AI tips & recipe recommendations.",
    ai_insight_label: "AI insight:",
    profile_title: "Your Profile",
    your_name: "Your name",
    name_placeholder: "e.g. Nic",
    height_cm: "Height (cm)",
    weight_kg: "Weight (kg)",
    age_years: "Age (years)",
    activity_level: "Activity level",
    diet_style: "Diet style",
    diet_multiselect: "(multiple selection possible)",
    language: "Language",
    daily_goal: "Calculated daily goal (Mifflin-St Jeor)",
    luteal_bonus: "kcal cycle bonus (luteal phase)",
    shortcut_name: "Name",
    shortcut_name_placeholder: "e.g. My breakfast",
    shortcut_hint: "For meals you eat often – e.g. your daily breakfast. One tap logs it instantly.",
    add_ingredient: "Add ingredient",
    portion_size: "Portion size",
    portion_hint: "Relative to {base} at 100%",
    ingredients_label: "Ingredients & amounts",
    no_ingredients_hint: "No ingredients - add some below.",
    remove_ingredient: "Remove ingredient",
    add: "Add",
    remove: "Remove",
    undo: "Undo",
    add_extra_placeholder: "e.g. 1 tbsp olive oil",
    remove_placeholder: "e.g. sauce",
    badge_streak3: "3-day streak",
    badge_streak7: "7-day streak",
    badge_streak14: "14-day streak",
    badge_perfect: "Perfect day",
    badge_pro: "Nutrition pro",
  },
};

function makeT(lang) {
  return (key) => (UI_TEXT[lang] && UI_TEXT[lang][key] != null ? UI_TEXT[lang][key] : UI_TEXT.de[key] || key);
}

/* ----------------------------- Design tokens ----------------------------- */
const PHASES = {
  menstruation: {
    key: "menstruation",
    name: "Menstruation",
    dayRange: [1, 5],
    color: "#8C3B47",
    tint: "#F6E1E3",
    soft: "#F0CBCF",
    icon: Droplet,
    focus: ["Eisen", "Vitamin C", "Magnesium"],
    desc: "Dein Körper verliert Eisen und Blut. Wärmende, eisenreiche Mahlzeiten mit Vitamin C helfen der Aufnahme.",
    mealTip: "Kombiniere eisenreiches Gemüse mit Zitrusfrüchten – Vitamin C verdreifacht die Eisenaufnahme.",
  },
  follikel: {
    key: "follikel",
    name: "Follikelphase",
    dayRange: [6, 13],
    color: "#5C7A4E",
    tint: "#E7EEDE",
    soft: "#CDDEC0",
    icon: Sprout,
    focus: ["Protein", "Zink", "B-Vitamine"],
    desc: "Östrogen steigt, die Energie nimmt zu. Ideal für proteinreiche, frische Kost und neue Rezepte.",
    mealTip: "Nutze die steigende Energie für ballaststoffreiches Gemüse und mageres Protein.",
  },
  ovulation: {
    key: "ovulation",
    name: "Eisprung",
    dayRange: [14, 16],
    color: "#BE6A28",
    tint: "#F6E6D2",
    soft: "#EFCCA0",
    icon: Sun,
    focus: ["Antioxidantien", "Ballaststoffe", "Omega-3"],
    desc: "Energie-Hoch rund um den Eisprung. Farbenfrohes, faserreiches Essen unterstützt deinen Hormonhaushalt.",
    mealTip: "Bunte Antioxidantien aus Beeren & Blattgemüse schützen die Eizelle vor oxidativem Stress.",
  },
  luteal: {
    key: "luteal",
    name: "Lutealphase",
    dayRange: [17, 28],
    color: "#7A5548",
    tint: "#EFE4D8",
    soft: "#D9C0AC",
    icon: Moon,
    focus: ["B-Vitamine", "Magnesium", "gesunde Fette"],
    desc: "PMS-Phase mit möglichem Heißhunger. Magnesium und komplexe Kohlenhydrate wirken stabilisierend.",
    mealTip: "Komplexe Kohlenhydrate & Magnesium senken Reizbarkeit und Heißhunger auf Süßes.",
  },
};

const PHASE_ORDER = ["menstruation", "follikel", "ovulation", "luteal"];

const PHASE_TEXT_EN = {
  menstruation: {
    name: "Menstruation",
    focus: ["Iron", "Vitamin C", "Magnesium"],
    desc: "Your body loses iron and blood. Warming, iron-rich meals with vitamin C support absorption.",
    mealTip: "Pair iron-rich vegetables with citrus fruit – vitamin C triples iron absorption.",
  },
  follikel: {
    name: "Follicular Phase",
    focus: ["Protein", "Zinc", "B vitamins"],
    desc: "Estrogen rises and energy increases. Great time for protein-rich, fresh food and new recipes.",
    mealTip: "Use your rising energy for fibre-rich vegetables and lean protein.",
  },
  ovulation: {
    name: "Ovulation",
    focus: ["Antioxidants", "Fibre", "Omega-3"],
    desc: "Energy peaks around ovulation. Colourful, fibre-rich food supports your hormone balance.",
    mealTip: "Colourful antioxidants from berries & leafy greens protect the egg from oxidative stress.",
  },
  luteal: {
    name: "Luteal Phase",
    focus: ["B vitamins", "Magnesium", "Healthy fats"],
    desc: "PMS phase with possible cravings. Magnesium and complex carbs have a stabilising effect.",
    mealTip: "Complex carbs & magnesium reduce irritability and sugar cravings.",
  },
};
function localizePhase(phase, lang) {
  if (lang !== "en" || !phase || !PHASE_TEXT_EN[phase.key]) return phase;
  const en = PHASE_TEXT_EN[phase.key];
  return { ...phase, name: en.name, focus: en.focus, desc: en.desc, mealTip: en.mealTip };
}
const CYCLE_LENGTH = 28;

function phaseForDay(day) {
  for (const key of PHASE_ORDER) {
    const [start, end] = PHASES[key].dayRange;
    if (day >= start && day <= end) return key;
  }
  return "follikel";
}

/* -------------------------- Date utils (timezone-safe) -------------------------- */
function toKey(d) {
  return new Date(d).toLocaleDateString("sv-SE");
}
function keyToDate(key) {
  return new Date(`${key}T00:00:00`);
}
function addDaysToKey(key, n) {
  const d = keyToDate(key);
  d.setDate(d.getDate() + n);
  return toKey(d);
}
function daysBetweenKeys(keyA, keyB) {
  return Math.round((keyToDate(keyA) - keyToDate(keyB)) / 86400000);
}
function cycleDayForKey(dateKey, anchorKey) {
  const diff = daysBetweenKeys(dateKey, anchorKey);
  return (((diff % CYCLE_LENGTH) + CYCLE_LENGTH) % CYCLE_LENGTH) + 1;
}
function formatDateLabel(dateKey, lang) {
  return keyToDate(dateKey).toLocaleDateString(lang === "en" ? "en-US" : "de-DE", { weekday: "short", day: "2-digit", month: "2-digit" });
}

/* -------------------------------- Diet system -------------------------------- */
const DIET_LABELS = {
  omnivore: "Allesesser",
  vegetarian: "Vegetarisch",
  vegan: "Vegan",
  pescetarian: "Pescetarisch",
  lactose_free: "Laktosefrei",
  gluten_free: "Glutenfrei",
};
const DIET_LABELS_EN = {
  omnivore: "Omnivore",
  vegetarian: "Vegetarian",
  vegan: "Vegan",
  pescetarian: "Pescetarian",
  lactose_free: "Lactose-free",
  gluten_free: "Gluten-free",
};
function dietLabel(d, lang) {
  return (lang === "en" ? DIET_LABELS_EN[d] : DIET_LABELS[d]) || d;
}
const TAG_LABELS_EN = {
  "High Protein": "High Protein",
  Vegan: "Vegan",
  "Omega-3": "Omega-3",
  "Anti-Bloat": "Anti-Bloat",
  "Eisen-Booster": "Iron Booster",
  Antioxidantien: "Antioxidants",
  Schnell: "Quick",
  Cravings: "Cravings",
  Magnesium: "Magnesium",
  Ausgewogen: "Balanced",
  Resteverwertung: "Leftover recipe",
  "KI-Generiert": "AI-generated",
  "Pasta-Liebe": "Pasta Love",
  "Asia-Style": "Asia-Style",
  Hausmannskost: "Comfort Classics",
  "Quick & Easy": "Quick & Easy",
  Ofenglück: "Oven Comfort",
  "Frisch & Leicht": "Fresh & Light",
  Frühstück: "Breakfast",
  Mittagessen: "Lunch",
  Abendessen: "Dinner",
  "One-Pot": "One-Pot",
};
function tagLabel(tag, lang) {
  return lang === "en" ? TAG_LABELS_EN[tag] || tag : tag;
}
const SHOPPING_CATEGORY_LABELS_EN = {
  "Gemüse & Obst": "Produce",
  Kühlregal: "Fridge",
  "Trockenwaren & Gewürze": "Pantry & Spices",
  Sonstiges: "Other",
};
function categoryLabel(cat, lang) {
  return lang === "en" ? SHOPPING_CATEGORY_LABELS_EN[cat] || cat : cat;
}
const DIET_ORDER = ["omnivore", "vegetarian", "vegan", "pescetarian", "lactose_free", "gluten_free"];
const DIET_EMOJI = { omnivore: "🍽️", vegetarian: "🧀", vegan: "🌱", pescetarian: "🐟", lactose_free: "🥛", gluten_free: "🌾" };

// Discover-page browsing chips for the Recipes tab, mapped to real recipe data
// (tags / kcal / cuisine) rather than a fabricated meal-time taxonomy we don't track per recipe.
const POPULAR_CATEGORY_CHIPS = [
  { value: "Vegan", emoji: "🌱" },
  { value: "High Protein", emoji: "💪" },
  { value: "Schnell", emoji: "⚡" },
  { value: "Anti-Bloat", emoji: "🌿" },
  { value: "Cravings", emoji: "🍫" },
];
const KCAL_RANGE_CHIPS = [
  { min: 100, max: 200, emoji: "🍎" },
  { min: 200, max: 300, emoji: "🥗" },
  { min: 300, max: 400, emoji: "🍲" },
  { min: 400, max: 500, emoji: "🍽️" },
  { min: 500, max: 600, emoji: "🍝" },
  { min: 600, max: 700, emoji: "🍛" },
];
const CUISINE_CHIPS = [
  { value: "Pasta-Liebe", emoji: "🍝" },
  { value: "Asia-Style", emoji: "🥢" },
  { value: "Hausmannskost", emoji: "🍲" },
  { value: "Quick & Easy", emoji: "⚡" },
  { value: "Ofenglück", emoji: "🔥" },
  { value: "Frisch & Leicht", emoji: "🥗" },
  { value: "One-Pot", emoji: "🍳" },
];

function isSingleDietCompatible(recipe, diet) {
  switch (diet) {
    case "vegetarian":
      return !recipe.meat && !recipe.fish;
    case "vegan":
      return !recipe.meat && !recipe.fish && !recipe.dairy && !recipe.egg;
    case "pescetarian":
      return !recipe.meat;
    case "lactose_free":
      return !recipe.dairy;
    case "gluten_free":
      return !recipe.gluten;
    default:
      return true;
  }
}
function isDietCompatible(recipe, diets) {
  const list = Array.isArray(diets) ? diets : [diets];
  if (list.length === 0) return true;
  return list.every((d) => isSingleDietCompatible(recipe, d));
}

/* ------------------------------ Recipe factory ------------------------------ */
const PROTEIN_POOL = [
  { name: "Hähnchenbrust", meat: true, fish: false, egg: false },
  { name: "Putenbrust", meat: true, fish: false, egg: false },
  { name: "Rinderhack", meat: true, fish: false, egg: false },
  { name: "Hähnchenschenkel", meat: true, fish: false, egg: false },
  { name: "Lammfilet", meat: true, fish: false, egg: false },
  { name: "Lachs", meat: false, fish: true, egg: false },
  { name: "Garnelen", meat: false, fish: true, egg: false },
  { name: "Thunfisch", meat: false, fish: true, egg: false },
  { name: "Kabeljau", meat: false, fish: true, egg: false },
  { name: "Forelle", meat: false, fish: true, egg: false },
  { name: "Tofu", meat: false, fish: false, egg: false },
  { name: "Tempeh", meat: false, fish: false, egg: false },
  { name: "Kichererbsen", meat: false, fish: false, egg: false },
  { name: "Rote Linsen", meat: false, fish: false, egg: false },
  { name: "Schwarze Bohnen", meat: false, fish: false, egg: false },
  { name: "Edamame", meat: false, fish: false, egg: false },
  { name: "Eier", meat: false, fish: false, egg: true },
];
// Everyday, satisfying staples make up the bulk of recipes. "Superfood" carbs/veg
// (sweet potato, quinoa, beetroot) are deliberately rare - capped to ~1 in 10 recipes -
// so the library reads like real, varied home cooking rather than the same five
// wellness-blog ingredients on repeat.
const COMMON_CARBS = [
  { name: "Vollkornnudeln", gluten: true },
  { name: "Spaghetti", gluten: true },
  { name: "Basmatireis", gluten: false },
  { name: "Naturreis", gluten: false },
  { name: "Gnocchi", gluten: true },
  { name: "Kartoffeln", gluten: false },
  { name: "Sauerteigbrot", gluten: true },
  { name: "Vollkornbrot", gluten: true },
  { name: "Tortilla-Wraps", gluten: true },
  { name: "Couscous", gluten: true },
  { name: "Bulgur", gluten: true },
  { name: "Hirse", gluten: false },
  { name: "Buchweizen", gluten: false },
  { name: "Reisnudeln", gluten: false },
];
const RARE_CARBS = [
  { name: "Süßkartoffel", gluten: false },
  { name: "Quinoa", gluten: false },
];
const CARB_POOL = [...COMMON_CARBS, ...RARE_CARBS]; // kept for code that just needs "any carb" (e.g. diet-conflict scanning)

const COMMON_VEG = [
  "Brokkoli", "Spinat", "Paprika", "Zucchini", "Karotten", "Rosenkohl", "Fenchel", "Grünkohl", "Blumenkohl",
  "Aubergine", "Champignons", "Lauch", "Kürbis", "Rotkohl", "Weißkohl", "Sellerie", "Tomaten", "Gurke", "Zuckerschoten",
  "Radieschen", "Mais", "Erbsen", "Mangold", "Pastinaken",
];
const RARE_VEG = ["Rote Bete"];
const VEG_POOL = [...COMMON_VEG, ...RARE_VEG];

const FAT_POOL = ["Olivenöl", "Walnüsse", "Mandeln", "Kürbiskerne", "Chiasamen", "Cashewkerne", "Sesam", "Leinöl", "Pinienkerne", "Haselnüsse", "Erdnussbutter", "Avocado"];
const HERB_POOL = ["Petersilie", "Basilikum", "Dill", "Thymian", "Rosmarin", "Koriander", "Frühlingszwiebeln", "Minze", "Schnittlauch", "geröstetem Sesam"];
const DAIRY_POOL = ["Feta", "Griechischer Joghurt", "Hüttenkäse", "Parmesan", "Mozzarella", "Ziegenkäse", "Ricotta"];

// Every cooking style carries a cuisine/category label, so the library mixes Italian
// pasta night, Asian curries/stir-fries, and bodenständige Hausmannskost rather than
// defaulting to the same "protein + grain bowl" shape every time.
const STYLE_POOL = [
  { style: "Pasta", cuisine: "Pasta-Liebe" },
  { style: "Curry", cuisine: "Asia-Style" },
  { style: "Stir-Fry", cuisine: "Asia-Style" },
  { style: "Auflauf", cuisine: "Hausmannskost" },
  { style: "Suppe", cuisine: "Hausmannskost" },
  { style: "Eintopf", cuisine: "Hausmannskost" },
  { style: "Bowl", cuisine: "Quick & Easy" },
  { style: "Wrap", cuisine: "Quick & Easy" },
  { style: "Ofengericht", cuisine: "Ofenglück" },
  { style: "Salat", cuisine: "Frisch & Leicht" },
  { style: "Pfanne", cuisine: "Quick & Easy" },
  { style: "One-Pot-Gericht", cuisine: "One-Pot" },
];

function stepsForStyle(style, carb, protein, veg, veg2, fat, dairyItem, herb) {
  const vegCombined = `${veg} und ${veg2}`;
  switch (style) {
    case "Pasta":
      return [
        `${carb} in reichlich Salzwasser al dente kochen.`,
        `${protein} in einer Pfanne mit etwas ${fat} anbraten.`,
        `${vegCombined} dazugeben und einige Minuten mitbraten.`,
        `Abgetropfte Nudeln unterheben und gut durchschwenken.`,
        dairyItem ? `Mit ${dairyItem} und ${herb} bestreut servieren.` : `Mit ${herb} bestreut servieren.`,
      ];
    case "Stir-Fry":
      return [
        `${vegCombined} in dünne Streifen schneiden.`,
        `${protein} bei hoher Hitze in einer Pfanne oder im Wok mit etwas ${fat} scharf anbraten.`,
        `${vegCombined} dazugeben und 3-4 Minuten unter Wenden braten.`,
        `${carb} bzw. Sojasauce unterrühren und kurz köcheln lassen.`,
        `Mit ${herb} servieren.`,
      ];
    case "Suppe":
    case "Eintopf":
      return [
        `${vegCombined} sowie ${carb} klein schneiden.`,
        `${protein} zusammen mit Zwiebeln in etwas Öl kurz andünsten.`,
        `${carb}, ${vegCombined} und Brühe hinzufügen und 20 Minuten köcheln lassen.`,
        `Nach Wunsch mit dem Stabmixer teilweise pürieren.`,
        `Mit ${fat} beträufeln${dairyItem ? `, mit ${dairyItem} toppen` : ""}, mit ${herb} bestreuen und servieren.`,
      ];
    case "Salat":
      return [
        `${carb} kochen und vollständig abkühlen lassen.`,
        `${protein} garen und in mundgerechte Stücke schneiden.`,
        `${vegCombined} waschen und klein schneiden.`,
        `Alle Zutaten in einer Schüssel vermengen und mit ${fat} verfeinern.`,
        dairyItem ? `Mit ${dairyItem} und ${herb} bestreuen und servieren.` : `Mit Zitronensaft, Salz, Pfeffer und ${herb} abschmecken.`,
      ];
    case "Curry":
      return [
        `${protein} in einem Topf mit etwas ${fat} anbraten.`,
        `Currypaste bzw. Currygewürze kurz mitrösten.`,
        `${carb}, ${vegCombined} und Kokosmilch hinzufügen.`,
        `15-20 Minuten köcheln lassen, bis alles gar ist.`,
        `Mit ${herb} servieren.`,
      ];
    case "Wrap":
      return [
        `${protein} würzen und anbraten oder garen.`,
        `${vegCombined} in feine Streifen schneiden.`,
        `${carb} als Basis vorbereiten.`,
        `Alles mit ${fat}${dairyItem ? ` und ${dairyItem}` : ""} sowie etwas ${herb} füllen und einrollen.`,
      ];
    case "Auflauf":
    case "Ofengericht":
      return [
        `Ofen auf 200°C Ober-/Unterhitze vorheizen.`,
        `${carb}, ${vegCombined} und ${protein} in eine Auflaufform geben.`,
        `Mit ${fat} beträufeln${dairyItem ? ` und mit ${dairyItem} bestreuen` : ""}.`,
        `20-25 Minuten im Ofen backen, bis alles gar ist.`,
        `Mit ${herb} bestreut servieren.`,
      ];
    case "One-Pot-Gericht":
      return [
        `${protein} in einem großen Topf anbraten.`,
        `${carb} und ${vegCombined} hinzufügen und kurz mitdünsten.`,
        `Mit Brühe aufgießen und köcheln lassen, bis alles gar ist.`,
        `Mit ${fat} und ${herb} verfeinern und abschmecken.`,
      ];
    default:
      return [
        `${carb} nach Packungsanweisung garen.`,
        `${protein} würzen und in einer Pfanne oder im Ofen gar ziehen lassen.`,
        `${vegCombined} putzen, klein schneiden und kurz andünsten oder roh dazugeben.`,
        `Alles in einer Bowl anrichten und mit ${fat} toppen.`,
        dairyItem ? `Mit ${dairyItem} und ${herb} garnieren und servieren.` : `Mit ${herb} abschmecken und servieren.`,
      ];
  }
}

// Creative, appetite-driven titles per cuisine style - "Cremige Vollkornnudeln mit
// Hähnchen" rather than the mechanically templated "Hähnchen-Vollkornnudeln-Pasta".
function creativeTitle(style, carbName, proteinName, vegName, seed) {
  const templates = {
    Pasta: [`Cremige ${carbName} mit ${proteinName} und ${vegName}`, `${proteinName}-Pasta mit ${vegName}`, `${vegName}-${proteinName}-Nudeln`],
    Curry: [`Cremiges ${proteinName}-Curry mit ${vegName}`, `${vegName}-Curry mit ${proteinName}`],
    "Stir-Fry": [`${proteinName}-${vegName}-Pfanne (Asia-Style)`, `Knackiges Wok-Gericht mit ${proteinName}`],
    Auflauf: [`Herzhafter ${carbName}-Auflauf mit ${proteinName}`, `${proteinName}-${vegName}-Auflauf`],
    Suppe: [`Wärmende ${vegName}-Suppe mit ${proteinName}`],
    Eintopf: [`Deftiger ${proteinName}-Eintopf mit ${vegName}`],
    Bowl: [`${proteinName}-Bowl mit ${carbName} und ${vegName}`],
    Wrap: [`Knackiger ${proteinName}-Wrap mit ${vegName}`],
    Ofengericht: [`${carbName} aus dem Ofen mit ${proteinName} und ${vegName}`],
    Salat: [`Sättigender ${carbName}-Salat mit ${proteinName}`],
    Pfanne: [`${proteinName}-Pfanne mit ${carbName} und ${vegName}`],
    "One-Pot-Gericht": [`One-Pot ${proteinName} mit ${carbName}`],
  };
  const options = templates[style] || [`${proteinName} mit ${carbName}`];
  return options[seed % options.length];
}


// Maps everyday ingredients to the nutrient story they actually support, so the "why"
// text names a real, specific reason (e.g. "Linsen ... für Eisen") instead of a vague
// "supports your phase" line - and never has to reach for a rare superfood to make its case.
const INGREDIENT_NUTRIENT_HINTS = {
  Rinderhack: "Eisen",
  "Rote Linsen": "Eisen",
  "Schwarze Bohnen": "Eisen",
  Lammfilet: "Eisen",
  Spinat: "Eisen",
  Kichererbsen: "Magnesium",
  Tofu: "Magnesium",
  Tempeh: "Magnesium",
  Edamame: "Magnesium",
  Vollkornnudeln: "B-Vitamine",
  Spaghetti: "B-Vitamine",
  Vollkornbrot: "B-Vitamine",
  Sauerteigbrot: "B-Vitamine",
  Buchweizen: "B-Vitamine",
  Hirse: "B-Vitamine",
  Eier: "B-Vitamine",
  Lachs: "Omega-3",
  Garnelen: "Jod",
  Thunfisch: "Omega-3",
  Kabeljau: "Jod",
  Forelle: "Omega-3",
  Hähnchenbrust: "Protein",
  Putenbrust: "Protein",
  "Griechischer Joghurt": "Protein",
};
function cleverWhyText(phase, proteinName, carbName, micronutrient) {
  const proteinHint = INGREDIENT_NUTRIENT_HINTS[proteinName];
  const carbHint = INGREDIENT_NUTRIENT_HINTS[carbName];
  if (proteinHint && proteinHint !== "Protein") {
    return `${proteinName} ist eine alltagstaugliche Quelle für ${proteinHint} - ganz ohne Superfood-Zwang - und passt damit genau zum Nährstoffbedarf deiner ${phase.name}.`;
  }
  if (carbHint) {
    return `${carbName} liefert ${carbHint} für deine ${phase.name}, während ${proteinName} für Sättigung und stabilen Blutzucker sorgt - eine bodenständige Alltagskombination.`;
  }
  return `${proteinName} und ${carbName} sind vertraute Alltagszutaten, die deinen ${micronutrient}-Bedarf in der ${phase.name} unauffällig mit abdecken.`;
}

function buildPhaseRecipes(phaseKey, count) {
  const phase = PHASES[phaseKey];
  const list = [];

  // Give every phase its own shuffled order per ingredient category so the
  // full pool gets used (instead of a fixed modulo step that only ever hit a
  // fraction of the pool - e.g. the same vegetable showing up constantly).
  const proteinOrder = shuffleArray(PROTEIN_POOL);
  const commonCarbOrder = shuffleArray(COMMON_CARBS);
  const rareCarbOrder = shuffleArray(RARE_CARBS);
  const vegOrder = shuffleArray(COMMON_VEG);
  const veg2Order = shuffleArray(COMMON_VEG);
  const fatOrder = shuffleArray(FAT_POOL);
  const herbOrder = shuffleArray(HERB_POOL);
  const dairyOrder = shuffleArray(DAIRY_POOL);
  const styleOrder = shuffleArray(STYLE_POOL);

  for (let i = 0; i < count; i++) {
    const protein = proteinOrder[i % proteinOrder.length];
    // Superfood cap: a "rare" carb (Süßkartoffel/Quinoa) shows up at most once every
    // 10 recipes; Rote Bete similarly, offset so the two rare slots don't always coincide.
    const carb = i % 10 === 0 ? rareCarbOrder[Math.floor(i / 10) % rareCarbOrder.length] : commonCarbOrder[i % commonCarbOrder.length];
    const veg = i % 10 === 5 ? RARE_VEG[0] : vegOrder[i % vegOrder.length];
    let veg2 = veg2Order[i % veg2Order.length];
    if (veg2 === veg) veg2 = veg2Order[(i + 1) % veg2Order.length];
    const fat = fatOrder[i % fatOrder.length];
    const herb = herbOrder[i % herbOrder.length];
    const { style, cuisine } = styleOrder[i % styleOrder.length];
    const includeDairy = i % 3 === 1;
    const dairyItem = includeDairy ? dairyOrder[i % dairyOrder.length] : null;

    const title = creativeTitle(style, carb.name, protein.name, veg, i);

    const proteinAmt = protein.meat || protein.fish ? "140g" : protein.egg ? "2 Stück" : "150g";
    const fatAmt = fat === "Olivenöl" || fat === "Leinöl" ? "1 EL" : "20g";

    const ingredients = [`80g ${carb.name}`, `${proteinAmt} ${protein.name}`, `80g ${veg}`, `80g ${veg2}`, `${fatAmt} ${fat}`, `etwas ${herb}`];
    if (dairyItem) ingredients.push(`30g ${dairyItem}`);

    const steps = stepsForStyle(style, carb.name, protein.name, veg, veg2, fat, dairyItem, herb);

    const protein_g = protein.meat || protein.fish ? 30 + (i % 8) : protein.egg ? 24 : 20 + (i % 6);
    const carbs_g = 40 + (carb.gluten ? 10 : 0) + (i % 10);
    const fat_g = 14 + (dairyItem ? 4 : 0) + (i % 5);
    const kcal = protein_g * 4 + carbs_g * 4 + fat_g * 9;
    const time = 12 + ((i * 3) % 26);
    const micronutrient = phase.focus[i % phase.focus.length];

    const tagPool = [];
    if (protein_g >= 30) tagPool.push("High Protein");
    if (!protein.meat && !protein.fish && !dairyItem && !protein.egg) tagPool.push("Vegan");
    if (protein.fish) tagPool.push("Omega-3");
    if (style === "Suppe" || style === "Eintopf") tagPool.push("Anti-Bloat");
    if (protein.name === "Rinderhack" || protein.name === "Rote Linsen" || veg === "Spinat" || veg === "Rote Bete" || veg2 === "Spinat" || veg2 === "Rote Bete") tagPool.push("Eisen-Booster");
    if ([veg, veg2].includes("Rote Bete") || [veg, veg2].includes("Rosenkohl") || [veg, veg2].includes("Grünkohl")) tagPool.push("Antioxidantien");
    if (time <= 15) tagPool.push("Schnell");
    if (dairyItem || carb.gluten) tagPool.push("Cravings");
    tagPool.push("Magnesium");
    const tags = Array.from(new Set(tagPool)).slice(0, 3);
    if (tags.length === 0) tags.push("Ausgewogen");

    list.push({
      id: `${phaseKey}-${i}`,
      title,
      cuisine,
      phase: phaseKey,
      time,
      kcal: Math.round(kcal),
      protein: protein_g,
      carbs: carbs_g,
      fat: fat_g,
      tags,
      micronutrient,
      ingredients,
      steps,
      why: cleverWhyText(phase, protein.name, carb.name, micronutrient),
      color: phase.color,
      meat: protein.meat,
      fish: protein.fish,
      dairy: !!dairyItem,
      gluten: carb.gluten,
      egg: protein.egg,
    });
  }
  return list;
}

function buildRecipeLibrary() {
  let all = [];
  PHASE_ORDER.forEach((key) => {
    all = all.concat(buildPhaseRecipes(key, 50));
  });
  return all;
}

// Hand-curated "signature" recipes used for symptom recommendations (kept alongside the 200-recipe factory library).
const SIGNATURE_RECIPES = [
  {
    id: "signature-cramps",
    title: "Ingwer-Kurkuma-Suppe",
    phase: "menstruation",
    time: 25,
    kcal: 310,
    protein: 10,
    carbs: 34,
    fat: 12,
    tags: ["Anti-Bloat", "Schnell"],
    micronutrient: "Curcumin & Ingwerol",
    ingredients: ["2 cm Ingwer (frisch)", "1 TL Kurkuma", "200ml Kokosmilch", "100g Karotten", "50g rote Linsen", "300ml Gemüsebrühe"],
    steps: [
      "Ingwer schälen und fein hacken, Karotten in Scheiben schneiden.",
      "Ingwer und Kurkuma kurz im Topf andünsten.",
      "Karotten, Linsen, Brühe und Kokosmilch hinzufügen, 15 Minuten köcheln.",
      "Mit dem Stabmixer fein pürieren.",
      "Mit Salz und Pfeffer abschmecken und servieren.",
    ],
    why: "Ingwer lindert Krämpfe, Kurkuma wirkt entzündungshemmend gegen Regelschmerzen.",
    color: "#8C3B47",
    meat: false,
    fish: false,
    dairy: false,
    gluten: false,
    egg: false,
  },
  {
    id: "signature-cravings",
    title: "Süßkartoffel-Kichererbsen-Curry",
    phase: "luteal",
    time: 35,
    kcal: 610,
    protein: 20,
    carbs: 72,
    fat: 22,
    tags: ["Cravings", "Magnesium"],
    micronutrient: "Magnesium & Beta-Carotin",
    ingredients: ["200g Süßkartoffel", "150g Kichererbsen (abgetropft)", "200ml Kokosmilch", "1 EL Currypaste", "1 EL Koriander (frisch)"],
    steps: [
      "Süßkartoffel schälen und würfeln.",
      "Currypaste kurz anrösten.",
      "Süßkartoffel, Kichererbsen und Kokosmilch hinzufügen.",
      "15-20 Minuten köcheln, bis die Süßkartoffel weich ist.",
      "Mit frischem Koriander servieren.",
    ],
    why: "Komplexe Kohlenhydrate stabilisieren den Blutzucker und bremsen Heißhunger.",
    color: "#7A5548",
    meat: false,
    fish: false,
    dairy: false,
    gluten: false,
    egg: false,
  },
  {
    id: "signature-fatigue",
    title: "Rote-Bete-Linsen-Bowl",
    phase: "menstruation",
    time: 20,
    kcal: 480,
    protein: 22,
    carbs: 58,
    fat: 16,
    tags: ["Eisen-Booster", "High Protein"],
    micronutrient: "Eisen & Folsäure",
    ingredients: ["80g Quinoa", "100g Rote Bete (gekocht)", "60g rote Linsen", "30g Spinat", "1 EL Zitronensaft", "1 TL Kreuzkümmel", "1 EL Olivenöl"],
    steps: [
      "Quinoa nach Packungsanweisung ca. 15 Minuten in Salzwasser köcheln lassen.",
      "Rote Linsen separat 10 Minuten weich kochen und abgießen.",
      "Rote Bete würfeln und mit Spinat, Zitronensaft, Kreuzkümmel und Olivenöl vermengen.",
      "Quinoa und Linsen in eine Bowl geben und mit dem Rote-Bete-Mix toppen.",
      "Mit Salz und Pfeffer abschmecken.",
    ],
    why: "Rote Bete & Linsen liefern pflanzliches Eisen, das dein Körper jetzt braucht.",
    color: "#8C3B47",
    meat: false,
    fish: false,
    dairy: false,
    gluten: false,
    egg: false,
  },
  {
    id: "signature-bloating",
    title: "Kürbis-Kokos-Suppe mit Ingwer",
    phase: "luteal",
    time: 25,
    kcal: 340,
    protein: 8,
    carbs: 36,
    fat: 18,
    tags: ["Anti-Bloat", "Schnell"],
    micronutrient: "Kalium & Ingwerol",
    ingredients: ["300g Hokkaido-Kürbis", "200ml Kokosmilch", "1 cm Ingwer", "1/2 Zwiebel", "300ml Gemüsebrühe"],
    steps: [
      "Kürbis würfeln (Hokkaido muss nicht geschält werden).",
      "Zwiebel und Ingwer fein hacken und andünsten.",
      "Kürbis, Brühe und Kokosmilch hinzufügen.",
      "20 Minuten köcheln, dann fein pürieren.",
      "Mit Salz, Pfeffer und etwas Kokosmilch garnieren.",
    ],
    why: "Kalium & Ingwer wirken entwässernd und lindern das Blähbauch-Gefühl vor der Periode.",
    color: "#7A5548",
    meat: false,
    fish: false,
    dairy: false,
    gluten: false,
    egg: false,
  },
  {
    id: "signature-headache",
    title: "Grüner Power-Smoothie",
    phase: "follikel",
    time: 8,
    kcal: 290,
    protein: 14,
    carbs: 40,
    fat: 8,
    tags: ["Schnell", "Anti-Bloat"],
    micronutrient: "Folsäure & Chlorophyll",
    ingredients: ["40g Spinat", "1 Banane", "1 EL Chiasamen", "200ml Mandelmilch", "1 cm Ingwer"],
    steps: ["Alle Zutaten in einen Mixer geben.", "60 Sekunden auf hoher Stufe fein pürieren.", "Bei Bedarf mit etwas Wasser die Konsistenz anpassen.", "Sofort servieren."],
    why: "Spinat & Chia liefern B-Vitamine für deine steigende Energie.",
    color: "#5C7A4E",
    meat: false,
    fish: false,
    dairy: false,
    gluten: false,
    egg: false,
  },
  {
    id: "signature-mood",
    title: "Lachs mit Ofengemüse",
    phase: "ovulation",
    time: 30,
    kcal: 560,
    protein: 40,
    carbs: 32,
    fat: 26,
    tags: ["Omega-3", "High Protein"],
    micronutrient: "Omega-3 & Selen",
    ingredients: ["150g Lachsfilet", "100g Zucchini", "100g Süßkartoffel", "1 EL Olivenöl", "1 Zweig Rosmarin"],
    steps: [
      "Ofen auf 200°C vorheizen.",
      "Süßkartoffel und Zucchini schneiden, mit Olivenöl und Rosmarin vermengen.",
      "Gemüse 20 Minuten vorgaren.",
      "Lachsfilet dazulegen, weitere 10-12 Minuten backen.",
      "Mit Salz, Pfeffer und Zitrone servieren.",
    ],
    why: "Omega-3-Fettsäuren aus Lachs unterstützen den Hormonhaushalt rund um den Eisprung.",
    color: "#BE6A28",
    meat: false,
    fish: true,
    dairy: false,
    gluten: false,
    egg: false,
  },
];

// ---------------------------------------------------------------------------
// Zyklus-Rezepte-Datenbank (lokal geladen aus zyklus_rezepte_datenbank.json)
// 240 kuratierte Rezepte - 20 pro Zyklusphase, aufgeteilt in Frühstück/
// Mittagessen/Abendessen (je 20 pro Phase-Mahlzeit-Kombination). Eigenes,
// schlankes Datenmodell (kein kcal/Makro-Tracking) - separat von der
// KI-generierten Rezept-Bibliothek weiter unten.
// ---------------------------------------------------------------------------
const CYCLE_RECIPE_DB = [
  {
    "id": 1,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Warmer Quinoa-Brei mit Ingwer und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 2,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Buchweizen-Pancakes mit Kurkuma und Rote Bete",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Rote Bete",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 3,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Buchweizen-Pancakes mit Leinsamen und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 4,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Warmer Quinoa-Brei mit Rote Bete und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 5,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Amaranth-Pfanne mit Linsen und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 6,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Amaranth-Pfanne mit Kurkuma und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 7,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Rührei mit Spinat mit Walnüsse und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 8,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Kurkuma-Porridge mit Linsen und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 9,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Proteinreiche(r) Buchweizen-Pancakes mit Kurkuma und Linsen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Linsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 10,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Warmer Quinoa-Brei mit Walnüsse und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 11,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Buchweizen-Pancakes mit Linsen und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 12,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Buchweizen-Pancakes mit Leinsamen und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 13,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Warmer Quinoa-Brei mit Linsen und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 14,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Warmer Quinoa-Brei mit Ingwer und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 15,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Kurkuma-Porridge mit Kurkuma und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 16,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Kurkuma-Porridge mit Walnüsse und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 17,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Proteinreiche(r) Amaranth-Pfanne mit Rote Bete und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 18,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Warmer Quinoa-Brei mit Rote Bete und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 19,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Kurkuma-Porridge mit Linsen und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 20,
    "phase": "Menstruation",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Rührei mit Spinat mit Rote Bete und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Flüssigkeit in einem Topf erwärmen.",
      "Basis-Zutat einrühren und 5-10 Minuten köcheln lassen.",
      "Mit Gewürzen abschmecken und warm servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 21,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Rote-Bete-Eintopf mit Rote Bete und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 22,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Kürbissuppe mit Rote Bete und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 23,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Linsen-Dal mit Walnüsse und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 24,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Rote-Bete-Eintopf mit Kurkuma und Spinat",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 25,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Kürbissuppe mit Leinsamen und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 26,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Warmer Spinatsalat mit Linsen und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 27,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Linsen-Dal mit Ingwer und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 28,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Rote-Bete-Eintopf mit Leinsamen und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 29,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Rote-Bete-Eintopf mit Rote Bete und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 30,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Bunte(r) Linsen-Dal mit Spinat und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Spinat",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 31,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Rote-Bete-Eintopf mit Rindfleisch und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rindfleisch",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 32,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Kürbissuppe mit Rote Bete und Leinsamen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Leinsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 33,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Linsen-Dal mit Kurkuma und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 34,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Rote-Bete-Eintopf mit Kurkuma und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 35,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Bunte(r) Süßkartoffel-Bowl mit Ingwer und Leinsamen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Leinsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 36,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Warmer Spinatsalat mit Rindfleisch und Rote Bete",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rindfleisch",
      "50g Rote Bete",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 37,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Süßkartoffel-Bowl mit Leinsamen und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 38,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Linsen-Dal mit Linsen und Lachs",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 39,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Süßkartoffel-Bowl mit Lachs und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Lachs",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 40,
    "phase": "Menstruation",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Süßkartoffel-Bowl mit Walnüsse und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Zwiebeln in etwas Öl andünsten.",
      "Mit Wasser oder Brühe ablöschen.",
      "15-20 Minuten garen, bis alles weich ist. Mit frischen Kräutern toppen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 41,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Gebackener Tofu mit Brokkoli mit Ingwer und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 42,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Rinderstreifen-Pfanne mit Ingwer und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 43,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Wildlachs aus dem Ofen mit Linsen und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 44,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Rinderstreifen-Pfanne mit Linsen und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 45,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Rinderstreifen-Pfanne mit Linsen und Leinsamen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Leinsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 46,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Eisenreiches Kichererbsen-Curry mit Leinsamen und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 47,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Schwarze-Bohnen-Chili mit Lachs und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Lachs",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 48,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Rinderstreifen-Pfanne mit Spinat und Leinsamen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Spinat",
      "50g Leinsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 49,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Schwarze-Bohnen-Chili mit Rindfleisch und Linsen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rindfleisch",
      "50g Linsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 50,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Gebackener Tofu mit Brokkoli mit Rote Bete und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rote Bete",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 51,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Wildlachs aus dem Ofen mit Leinsamen und Linsen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Leinsamen",
      "50g Linsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 52,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Schwarze-Bohnen-Chili mit Ingwer und Linsen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Linsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 53,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Rinderstreifen-Pfanne mit Walnüsse und Leinsamen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Leinsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 54,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Schwarze-Bohnen-Chili mit Lachs und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Lachs",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 55,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Wildlachs aus dem Ofen mit Kurkuma und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Kurkuma",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 56,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Wildlachs aus dem Ofen mit Ingwer und Linsen",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Ingwer",
      "50g Linsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 57,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Gebackener Tofu mit Brokkoli mit Walnüsse und Ingwer",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Ingwer",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 58,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Rinderstreifen-Pfanne mit Walnüsse und Rindfleisch",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Walnüsse",
      "50g Rindfleisch",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 59,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Eisenreiches Kichererbsen-Curry mit Linsen und Walnüsse",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Linsen",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 60,
    "phase": "Menstruation",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Gebackener Tofu mit Brokkoli mit Rindfleisch und Kurkuma",
    "fokus": "Eisen, Omega-3, wärmende Speisen",
    "zutaten": [
      "100g Rindfleisch",
      "50g Kurkuma",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Protein (Fleisch/Fisch/Tofu) marinieren und anbraten.",
      "Gemüse der Saison hinzugeben und mitgaren.",
      "Mit einer eisenreichen Beilage (z.B. Quinoa oder Linsen) anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 61,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Leinsamen-Pancakes mit Soja und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Soja",
      "50g Quinoa",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 62,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Chia-Pudding mit Quinoa und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 63,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Chia-Pudding mit Quinoa und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 64,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Chia-Pudding mit Quinoa und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 65,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Chia-Pudding mit Quinoa und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 66,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Haferflocken mit Beeren mit Quinoa und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 67,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Leichte(r) Grüner Smoothie mit Quinoa und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene
