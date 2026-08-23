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
    "kochzeit_min": 30
  },
  {
    "id": 68,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Grüner Smoothie mit Soja und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Soja",
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
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 69,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Chia-Pudding mit Blaubeeren und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Blaubeeren",
      "50g Brokkoli",
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
    "id": 70,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Chia-Pudding mit Quinoa und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 71,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Leinsamen-Pancakes mit Leinsamen und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
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
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 72,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Soja-Joghurt Bowl mit Quinoa und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Zuckerschoten",
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
    "id": 73,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Grüner Smoothie mit Quinoa und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Zuckerschoten",
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
    "id": 74,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Haferflocken mit Beeren mit Tofu und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Zuckerschoten",
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
    "id": 75,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Haferflocken mit Beeren mit Blaubeeren und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Blaubeeren",
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
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 76,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Leinsamen-Pancakes mit Zuckerschoten und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 77,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Haferflocken mit Beeren mit Soja und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Soja",
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
    "id": 78,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Grüner Smoothie mit Brokkoli und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
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
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 79,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Leinsamen-Pancakes mit Zitronen und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zitronen",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Alle Zutaten frisch vermengen oder kurz mixen.",
      "Phytoöstrogen-reiche Toppings (wie Leinsamen) darüberstreuen.",
      "Frisch und kühl genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 80,
    "phase": "Follikelphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Leinsamen-Pancakes mit Tofu und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
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
    "kochzeit_min": 20
  },
  {
    "id": 81,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Bunte Edamame-Bowl mit Zuckerschoten und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 82,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Vollkornnudelsalat mit Leinsamen und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 83,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Bunte Edamame-Bowl mit Quinoa und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 84,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Quinoa-Salat mit Leinsamen und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 85,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Quinoa-Salat mit Tofu und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 86,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Vollkornnudelsalat mit Zitronen und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zitronen",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 87,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Bunte Edamame-Bowl mit Soja und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Soja",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 88,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Linsen-Wraps mit Leinsamen und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 89,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Bunte Edamame-Bowl mit Brokkoli und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 90,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Linsen-Wraps mit Edamame und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 91,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Frühlingsrollen mit Tofu mit Zuckerschoten und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 92,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Vollkornnudelsalat mit Zitronen und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zitronen",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 93,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Bunte Edamame-Bowl mit Tofu und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Quinoa",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 94,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Linsen-Wraps mit Tofu und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 95,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Frühlingsrollen mit Tofu mit Blaubeeren und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Blaubeeren",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 96,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Linsen-Wraps mit Brokkoli und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 97,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Vollkornnudelsalat mit Brokkoli und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 98,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Quinoa-Salat mit Brokkoli und Soja",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
      "50g Soja",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 99,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Bunte Edamame-Bowl mit Zuckerschoten und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 100,
    "phase": "Follikelphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Bunte Edamame-Bowl mit Quinoa und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Kohlenhydratquelle (Quinoa/Vollkorn) kochen und abkühlen lassen.",
      "Frisches Gemüse schnippeln.",
      "Alles mit einem leichten Zitronen-Dressing vermischen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 101,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Tempeh-Spieße mit Zuckerschoten und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 102,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Brokkoli-Auflauf mit Edamame und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 103,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Gemüse-Stir-fry mit Zitronen und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zitronen",
      "50g Quinoa",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 104,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Tempeh-Spieße mit Edamame und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 105,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Tempeh-Spieße mit Quinoa und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 106,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Gemüse-Stir-fry mit Tofu und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 107,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Tempeh-Spieße mit Zuckerschoten und Soja",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Soja",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 108,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Tofu-Pfanne mit Zuckerschoten mit Zuckerschoten und Quinoa",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zuckerschoten",
      "50g Quinoa",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 109,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Gemüse-Stir-fry mit Leinsamen und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 110,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Tempeh-Spieße mit Edamame und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 111,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Tofu-Pfanne mit Zuckerschoten mit Edamame und Tofu",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Tofu",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 112,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Tempeh-Spieße mit Brokkoli und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Brokkoli",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 113,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Gemüse-Stir-fry mit Zitronen und Blaubeeren",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Zitronen",
      "50g Blaubeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 114,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Tofu-Pfanne mit Zuckerschoten mit Tofu und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Tofu",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 115,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Zitronen-Hähnchen mit Edamame und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 116,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Brokkoli-Auflauf mit Quinoa und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 117,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Tofu-Pfanne mit Zuckerschoten mit Leinsamen und Brokkoli",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Leinsamen",
      "50g Brokkoli",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 118,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Tempeh-Spieße mit Edamame und Zitronen",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Edamame",
      "50g Zitronen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 119,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Tofu-Pfanne mit Zuckerschoten mit Soja und Zuckerschoten",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Soja",
      "50g Zuckerschoten",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 120,
    "phase": "Follikelphase",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Brokkoli-Auflauf mit Quinoa und Edamame",
    "fokus": "Komplexe Kohlenhydrate, Phytoöstrogene, frische Kost",
    "zutaten": [
      "100g Quinoa",
      "50g Edamame",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse knackig im Wok oder der Pfanne anbraten.",
      "Sojaprodukte oder mageres Fleisch hinzufügen.",
      "Mit Sojasauce oder leichten Gewürzen abschmecken."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 121,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Kokos-Joghurt mit Hanfsamen mit Hanfsamen und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 122,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Proteinreiche(r) Kokos-Joghurt mit Hanfsamen mit Spinat und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 123,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Matcha-Chia-Pudding mit Spinat und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 124,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Grüne Smoothie-Bowl mit Spinat und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 125,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Matcha-Chia-Pudding mit Zucchini und Blumenkohl",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Blumenkohl",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 126,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Mandel-Porridge mit Blumenkohl und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 127,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Grüne Smoothie-Bowl mit Spinat und Erdbeeren",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Erdbeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 128,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Grüne Smoothie-Bowl mit Hanfsamen und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 129,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Leichte(r) Beeren-Müsli mit Zucchini und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 130,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Grüne Smoothie-Bowl mit Hanfsamen und Erdbeeren",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Erdbeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 131,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Grüne Smoothie-Bowl mit Spargel und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 132,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Mandel-Porridge mit Spinat und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 133,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Mandel-Porridge mit Erdbeeren und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Erdbeeren",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 134,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Leichte(r) Beeren-Müsli mit Spargel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 135,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Kokos-Joghurt mit Hanfsamen mit Kabeljau und Erdbeeren",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Erdbeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 136,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Mandel-Porridge mit Spargel und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 137,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Beeren-Müsli mit Spinat und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 138,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Mandel-Porridge mit Hanfsamen und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 139,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Grüne Smoothie-Bowl mit Kabeljau und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 140,
    "phase": "Eisprung",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Matcha-Chia-Pudding mit Mandel und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Zutaten im Mixer pürieren, bis sie geschmeidig sind.",
      "In eine Schale füllen.",
      "Mit Antioxidantien (Beeren, Nüsse) reichhaltig garnieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 141,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Erdbeer-Spinat-Salat mit Blumenkohl und Erdbeeren",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Erdbeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 142,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Rote-Linsen-Suppe mit Hanfsamen und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 143,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Rote-Linsen-Suppe mit Kabeljau und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 144,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Rote-Linsen-Suppe mit Mandel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 145,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Blumenkohl-Reis-Bowl mit Kabeljau und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 146,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Zucchini-Nudeln mit Hanfsamen und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 147,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Rote-Linsen-Suppe mit Zucchini und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 148,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Erdbeer-Spinat-Salat mit Mandel und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 149,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Blumenkohl-Reis-Bowl mit Hanfsamen und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 150,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Zucchini-Nudeln mit Kabeljau und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 151,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Spargel-Salat mit Spargel und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 152,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Blumenkohl-Reis-Bowl mit Blumenkohl und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 153,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Spargel-Salat mit Spinat und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 154,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Rote-Linsen-Suppe mit Mandel und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 155,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Cremige(r) Zucchini-Nudeln mit Kabeljau und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 156,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Bunte(r) Blumenkohl-Reis-Bowl mit Zucchini und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 157,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Fruchtige(r) Rote-Linsen-Suppe mit Spinat und Mandel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Mandel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 158,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Erdbeer-Spinat-Salat mit Kabeljau und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Kabeljau",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 159,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Rote-Linsen-Suppe mit Blumenkohl und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 160,
    "phase": "Eisprung",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Blumenkohl-Reis-Bowl mit Mandel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse roh verarbeiten oder nur sehr kurz blanchieren.",
      "Mit einem leichten Essig-Öl-Dressing marinieren.",
      "Sofort servieren, um Vitamine zu erhalten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 161,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Blumenkohl-Curry mit Blumenkohl und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 162,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Blumenkohl-Curry mit Mandel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 163,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Gebackener Spargel mit Erdbeeren und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Erdbeeren",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 164,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Gedünsteter Kabeljau mit Zucchini und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 165,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Blumenkohl-Curry mit Spargel und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 166,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Blumenkohl-Curry mit Hanfsamen und Spargel",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Spargel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 167,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Fruchtige(r) Blumenkohl-Curry mit Spinat und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spinat",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 168,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Hähnchenbrust auf Salat mit Hanfsamen und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 169,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Gebackener Spargel mit Hanfsamen und Blumenkohl",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Hanfsamen",
      "50g Blumenkohl",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 170,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Hähnchenbrust auf Salat mit Mandel und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 171,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Hähnchenbrust auf Salat mit Zucchini und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 172,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Gebackener Spargel mit Blumenkohl und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 173,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Gedünsteter Kabeljau mit Erdbeeren und Zucchini",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Erdbeeren",
      "50g Zucchini",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 174,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Ratatouille mit Blumenkohl und Hanfsamen",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Hanfsamen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 175,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Gebackener Spargel mit Spargel und Erdbeeren",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Erdbeeren",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 176,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Gedünsteter Kabeljau mit Spargel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Spargel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 177,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Blumenkohl-Curry mit Zucchini und Blumenkohl",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Zucchini",
      "50g Blumenkohl",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 178,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Gebackener Spargel mit Blumenkohl und Kabeljau",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Blumenkohl",
      "50g Kabeljau",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 179,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Hähnchenbrust auf Salat mit Mandel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 180,
    "phase": "Eisprung",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Hähnchenbrust auf Salat mit Mandel und Spinat",
    "fokus": "Ballaststoffe, Antioxidantien, leichte Kost",
    "zutaten": [
      "100g Mandel",
      "50g Spinat",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Gemüse und Protein schonend garen (dünsten oder dämpfen).",
      "Schwere Saucen vermeiden, stattdessen Kräuter verwenden.",
      "Warm, aber nicht zu heiß servieren."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 181,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Avocado-Brot mit Ei mit Kürbis und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kürbis",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 182,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Buchweizen-Waffeln mit Süßkartoffel und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Süßkartoffel",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 183,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Avocado-Brot mit Ei mit Banane und Kürbis",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kürbis",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 184,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Schnelle(r) Schoko-Bananen-Porridge mit Banane und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 185,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Süßkartoffel-Toast mit Avocado und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 186,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Avocado-Brot mit Ei mit Süßkartoffel und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Süßkartoffel",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 187,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Schoko-Bananen-Porridge mit Avocado und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 188,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Proteinreiche(r) Schoko-Bananen-Porridge mit Lachs und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 189,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Herzhafte(r) Süßkartoffel-Toast mit Kichererbsen und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 190,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Würzige(r) Nussmus-Oats mit Kichererbsen und Lachs",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 191,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Schoko-Bananen-Porridge mit Banane und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 192,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Buchweizen-Waffeln mit Avocado und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 193,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Proteinreiche(r) Avocado-Brot mit Ei mit Kichererbsen und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 194,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Cremige(r) Avocado-Brot mit Ei mit Süßkartoffel und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Süßkartoffel",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 195,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Avocado-Brot mit Ei mit Avocado und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 196,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Nussmus-Oats mit Kakao und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 197,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Kraftgebende(r) Avocado-Brot mit Ei mit Kakao und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 198,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Sättigende(r) Buchweizen-Waffeln mit Kichererbsen und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 199,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Bunte(r) Nussmus-Oats mit Magnesiumreiches Getreide und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Magnesiumreiches Getreide",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 200,
    "phase": "Lutealphase",
    "mahlzeit": "Frühstück",
    "titel": "Fruchtige(r) Süßkartoffel-Toast mit Banane und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Haferflocken oder Buchweizen mit pflanzlicher Milch andicken.",
      "Mit Magnesiumquellen (Rohkakao, Banane, Nüsse) toppen.",
      "Warm und sättigend zubereiten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 201,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Gefüllte Süßkartoffel mit Kakao und Lachs",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 202,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Herzhafte(r) Quinoa-Bratlinge mit Avocado und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 203,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Avocado-Lachs-Wrap mit Banane und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 204,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Bunte(r) Quinoa-Bratlinge mit Banane und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 205,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Kichererbsen-Eintopf mit Kakao und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 206,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Proteinreiche(r) Quinoa-Bratlinge mit Avocado und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 207,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Fruchtige(r) Avocado-Lachs-Wrap mit Banane und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 208,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Fruchtige(r) Gefüllte Süßkartoffel mit Kichererbsen und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 209,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Quinoa-Bratlinge mit Banane und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 210,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Würzige(r) Kichererbsen-Eintopf mit Süßkartoffel und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Süßkartoffel",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 211,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Gefüllte Süßkartoffel mit Banane und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 212,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Kraftgebende(r) Avocado-Lachs-Wrap mit Lachs und Kürbis",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Kürbis",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 213,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Kichererbsen-Eintopf mit Walnüsse und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Walnüsse",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 214,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Avocado-Lachs-Wrap mit Kürbis und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kürbis",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 215,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Kichererbsen-Eintopf mit Kürbis und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kürbis",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 216,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Leichte(r) Avocado-Lachs-Wrap mit Banane und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  },
  {
    "id": 217,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Schnelle(r) Kichererbsen-Eintopf mit Avocado und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 218,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Vollkorn-Pasta mit Pesto mit Banane und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 219,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Avocado-Lachs-Wrap mit Lachs und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 30
  },
  {
    "id": 220,
    "phase": "Lutealphase",
    "mahlzeit": "Mittagessen",
    "titel": "Sättigende(r) Gefüllte Süßkartoffel mit Lachs und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Komplexe Kohlenhydrate (Süßkartoffel/Vollkorn) backen oder kochen.",
      "Mit gesunden Fetten (Avocado, Olivenöl) kombinieren.",
      "Abschmecken und als sättigende Mahlzeit genießen."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 221,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Lachs auf Ofengemüse mit Banane und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 222,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Herzhafte Linsen-Bolognese mit Avocado und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 223,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Gebackener Feta mit Gemüse mit Walnüsse und Lachs",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Walnüsse",
      "50g Lachs",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 224,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Bohnen-Burrito mit Walnüsse und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Walnüsse",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 225,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Bohnen-Burrito mit Kakao und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 10
  },
  {
    "id": 226,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Gebackener Feta mit Gemüse mit Lachs und Kürbis",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Kürbis",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 227,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Herzhafte Linsen-Bolognese mit Banane und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 10
  },
  {
    "id": 228,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Sättigende(r) Lachs auf Ofengemüse mit Magnesiumreiches Getreide und Kürbis",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Magnesiumreiches Getreide",
      "50g Kürbis",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 229,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Kürbis-Curry mit Kichererbsen und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 230,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Proteinreiche(r) Herzhafte Linsen-Bolognese mit Kürbis und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kürbis",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 231,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Herzhafte(r) Gebackener Feta mit Gemüse mit Kakao und Banane",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Banane",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 232,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Bohnen-Burrito mit Kichererbsen und Kakao",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kichererbsen",
      "50g Kakao",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 233,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Kürbis-Curry mit Lachs und Süßkartoffel",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Süßkartoffel",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 10
  },
  {
    "id": 234,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Bunte(r) Gebackener Feta mit Gemüse mit Lachs und Walnüsse",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Walnüsse",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 235,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Bohnen-Burrito mit Avocado und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Avocado",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 30
  },
  {
    "id": 236,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Würzige(r) Bohnen-Burrito mit Banane und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Banane",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 237,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Kraftgebende(r) Lachs auf Ofengemüse mit Kakao und Avocado",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kakao",
      "50g Avocado",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 30
  },
  {
    "id": 238,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Schnelle(r) Gebackener Feta mit Gemüse mit Lachs und Kürbis",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Lachs",
      "50g Kürbis",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 15,
    "kochzeit_min": 20
  },
  {
    "id": 239,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Cremige(r) Herzhafte Linsen-Bolognese mit Kürbis und Magnesiumreiches Getreide",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Kürbis",
      "50g Magnesiumreiches Getreide",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 5,
    "kochzeit_min": 20
  },
  {
    "id": 240,
    "phase": "Lutealphase",
    "mahlzeit": "Abendessen",
    "titel": "Leichte(r) Lachs auf Ofengemüse mit Magnesiumreiches Getreide und Kichererbsen",
    "fokus": "Komplexe Carbs, Magnesium, gesunde Fette",
    "zutaten": [
      "100g Magnesiumreiches Getreide",
      "50g Kichererbsen",
      "1 EL Olivenöl oder Topping nach Wahl",
      "Eine Prise Salz und Gewürze passend zur Phase",
      "Ggf. 100-200ml Wasser/Brühe/Pflanzendrink"
    ],
    "zubereitung": [
      "Ofen auf 200 Grad vorheizen.",
      "Gemüse und Protein auf einem Blech oder in einem Topf schmoren.",
      "Mit wärmenden Gewürzen und komplexen Carbs anrichten."
    ],
    "vorbereitungszeit_min": 10,
    "kochzeit_min": 20
  }
];

// Maps our internal English phase keys to the German phase labels used in the JSON.
const CYCLE_RECIPE_PHASE_MAP = {
  menstruation: "Menstruation",
  follikel: "Follikelphase",
  ovulation: "Eisprung",
  luteal: "Lutealphase",
};
const CYCLE_RECIPE_MEALS = ["Frühstück", "Mittagessen", "Abendessen"];
function mealTypeKeyFromDb(meal) {
  if (meal === "Frühstück") return "meal_breakfast";
  if (meal === "Mittagessen") return "meal_lunch";
  return "meal_dinner";
}

// Converts one JSON database recipe into our full app Recipe schema (with estimated
// kcal/protein/carbs/fat via FOOD_DB ingredient matching) so it can appear in the normal,
// searchable/filterable/favoritable Rezepte tab alongside AI-generated recipes.
// Only ever called lazily (well after module load), since it depends on FOOD_DB /
// parseIngredientString / resolveGrams / DIET_CONFLICT_WORDS defined further below.
// ---------------------------------------------------------------------------
// Open-source recipe collection (converted from tabatkins/recipe-db, CC-licensed
// public recipe data). Kept in English since translating 227 full recipes isn't
// practical here - these display as-is regardless of the app's language setting.
// Includes real per-serving nutrition data from the original source (not estimated).
// ---------------------------------------------------------------------------
const OPEN_RECIPE_DB = [
  {
    "title": "Baked Shrimp Scampi",
    "kcal": 428,
    "protein": 33,
    "carbs": 13,
    "fat": 26,
    "time": 30,
    "ingredients": [
      "2/3 cup panko",
      "1/4 teaspoon red pepper flakes",
      "1/2 lemon, zested and juiced",
      "1 extra-large egg yolk",
      "1 teaspoon rosemary, minced",
      "3 tablespoon parsley, minced",
      "4 clove garlic, minced",
      "1/4 cup shallots, minced",
      "8 tablespoon unsalted butter, softened at room temperature",
      "2 tablespoon dry white wine",
      "Freshly ground black pepper",
      "Kosher salt",
      "3 tablespoon olive oil",
      "2 pound frozen shrimp"
    ],
    "steps": [
      "Preheat the oven to 425 degrees F.",
      "Defrost shrimp by putting in cold water, then drain and toss with wine, oil, salt, and pepper. Place in oven-safe dish and allow to sit at room temperature while you make the butter and garlic mixture.",
      "In a small bowl, mash the softened butter with the rest of the ingredients and some salt and pepper.",
      "Spread the butter mixture evenly over the shrimp. Bake for 10 to 12 minutes until hot and bubbly. If you like the top browned, place under a broiler for 1-3 minutes (keep an eye on it). Serve with lemon wedges and French bread.",
      "Note: if using fresh shrimp, arrange for presentation. Starting from the outer edge of a 14-inch oval gratin dish, arrange the shrimp in a single layer cut side down with the tails curling up and towards the center of the dish. Pour the remaining marinade over the shrimp."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Greek Salad",
    "kcal": 764,
    "protein": 10,
    "carbs": 20,
    "fat": 74,
    "time": 30,
    "ingredients": [
      "6 tablespoon lemon juice",
      "2 clove garlic, minced",
      "2 teaspoon kosher salt, plus more to taste",
      "1 cup extra-virgin olive oil, preferably Greek",
      "1 head romaine lettuce, trimmed of tough stems and torn into bite-sized pieces",
      "1 cup kalamata olives, about 6oz/cup",
      "1/2 pound Feta cheese, crumbled",
      "1 cucumber, trimmed, cut into 1 inch chunks",
      "1 1/2 cup grape tomatoes, halved",
      "1 small red onion, cut into 1/2-inch wedges, soaked in cold water for 5 minutes and drained",
      "2 teaspoon dried oregano",
      "Freshly ground black pepper"
    ],
    "steps": [
      "In a small bowl, whisk together the lemon juice, garlic, salt, and oil. Set aside.   In a large bowl lightly toss the lettuce with the olives, cheese, cucumber, tomatoes, onion, oregano, and black pepper. Let sit up to 2 hours.  To serve, toss salad with dressing and place sliced chicken on top."
    ],
    "phase": "follikel"
  },
  {
    "title": "Margherita Salad",
    "kcal": 721,
    "protein": 57,
    "carbs": 30,
    "fat": 41,
    "time": 30,
    "ingredients": [
      "1 plum tomato, halved",
      "4 sun-dried tomatoes packed in oil",
      "2 tablespoon oil from the sun-dried tomato jar",
      "2 tablespoon red wine vinegar",
      "1 clove garlic",
      "1/2 teaspoon dried oregano",
      "1/4 bunch fresh basil, torn",
      "2 tbsp parmesan, grated",
      "Kosher salt and freshly ground pepper",
      "2 tablespoon extra-virgin olive oil",
      "1 cup breadcrumbs",
      "2 tablespoon chopped fresh parsley",
      "1/4 cup parmesan, grated",
      "8 cup Italian-blend salad greens",
      "3/4 bunch fresh basil, chiffonade",
      "8 ounce bocconcini (mozzarella), quartered"
    ],
    "steps": [
      "Puree the plum tomato, sun-dried tomatoes, vinegar, garlic, oregano, a basil leaves and parmesan in a blender, drizzling in the sun-dried tomato oil until smooth. Add 2 to 3 tablespoons water, if needed to make a pour-able dressing; season with salt and pepper.",
      "Heat the olive oil in a large skillet over medium-high heat. Add the breadcrumbs, season with salt and pepper and cook, stirring occasionally, until golden, about 2 minutes. Add the remaining parmesan and the parsley and cook until toasted, about 1 more minute.",
      "Toss the salad greens, mozzarella, and remaining basil in a large bowl. Toss with the dressing, then sprinkle with the breadcrumb mixture."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mexican Ensalada",
    "kcal": 668,
    "protein": 18,
    "carbs": 86,
    "fat": 31,
    "time": 30,
    "ingredients": [
      "1 lime, zested and juiced",
      "1 tablespoon balsamic vinegar",
      "1/4 cup basil leaves, chopped",
      "1/2 teaspoon cumin",
      "2 tablespoon extra-virgin olive oil",
      "Kosher salt and freshly ground black pepper",
      "1/2 cucumber, cubed",
      "1 avocado, cubed",
      "1 red bell pepper, cubed",
      "1/2 cup black beans, rinsed and drained",
      "1 tomato, cubed",
      "1/2 cup brown rice, cooked"
    ],
    "steps": [
      "In small bowl, whisk together dressing ingredients.",
      "Chop up additional ingredients bite size and add to a medium bowl.",
      "Combine dressing and all ingredients in a large bowl, toss, and serve.",
      "Includes recipe for [basil-lime vinaigrette](http://www.xanthir.com/recipes/showrecipe.php?id=id6).",
      "Alternate dressing (for 2 servings):\n1/2 lemon, juiced; 1 tbsp apple cider vinegar; 2 tbsp olive oil; 2 tablespoons cilantro, chopped"
    ],
    "phase": "luteal"
  },
  {
    "title": "Guacamole",
    "kcal": 194,
    "protein": 3,
    "carbs": 9,
    "fat": 15,
    "time": 30,
    "ingredients": [
      "4 ripe avocados",
      "2 roma tomatoes, diced fine",
      "1/2 red onion, minced",
      "1/2 handful cilantro, minced",
      "2 clove garlic, minced",
      "1 lime, juiced",
      "Pinch of sea salt",
      "1 jalapeno, seeded and minced fine"
    ],
    "steps": [
      "1. Place all ingredients in a bowl with a flat bottom and mash it with a potato masher.  Alternatively, you can mix everything briefly in a food processor.\n2. Stir well and keep refrigerated. This dish will brown on the areas exposed to air within a few hours, so serve it shortly after making it or just stir again before serving."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Super Protein Salad",
    "kcal": 684,
    "protein": 24,
    "carbs": 73,
    "fat": 35,
    "time": 30,
    "ingredients": [
      "2 cup salad greens",
      "1/4 cucumber, sliced",
      "1/2 cup grape tomatoes",
      "1/4 cup black beans, drained and rinsed",
      "1/4 cup chickpeas, drained and rinsed",
      "1 tbsp pistachios",
      "2 tbsp dried cranberries",
      "salt and pepper, to taste",
      "2 tbsp olive oil",
      "1 tbsp red wine vinegar",
      "1 tsp Dijon mustard"
    ],
    "steps": [
      "Combine olive oil, vinegar, mustard, salt and pepper to taste. Toss with other ingredients in a bowl and serve."
    ],
    "phase": "follikel"
  },
  {
    "title": "The Shake",
    "kcal": 320,
    "protein": 19,
    "carbs": 40,
    "fat": 11,
    "time": 30,
    "ingredients": [
      "1 scoop protein powder (optional)",
      "1 tbsp ground flax seeds",
      "2 tbsp hemp seeds",
      "2 tbsp peanut butter",
      "1 banana",
      "1 cup raspberries",
      "1 cup blueberries",
      "1 1/2 cup milk"
    ],
    "steps": [
      "Combine all ingredients in blender. Blend until smooth."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Extreme Green Salad",
    "kcal": 279,
    "protein": 6,
    "carbs": 20,
    "fat": 22,
    "time": 30,
    "ingredients": [
      "4 handful baby spinach leaves",
      "1 cup edamame",
      "1 large avocado, diced",
      "1/2 cucumber, finely sliced into half moons",
      "3 tablespoon sesame seeds",
      "1/2 lime, juiced",
      "1/2 teaspoon wasabi paste",
      "1 tablespoon soy sauce",
      "2 teaspoon sesame oil",
      "black pepper, to taste"
    ],
    "steps": [
      "1. Place all the salad ingredients, except the sesame seeds, into a large bowl or platter.",
      "2. Whisk together all the dressing ingredients in a small bowl. Drizzle over the salad and toss lightly to coat.",
      "3. Sprinkle with sesame seeds and serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Popeye's Muscle Salad",
    "kcal": 559,
    "protein": 12,
    "carbs": 30,
    "fat": 21,
    "time": 30,
    "ingredients": [
      "1 cup baby spinach",
      "1 cup salad greens",
      "1 carrots, shredded",
      "1/2 avocado, diced",
      "1 hard boiled eggs, peeled and carefully sliced",
      "2 tbsp pecans, chopped",
      "1/4 cup fresh berries",
      "1 1/2 tbsp olive oil",
      "2 tsp balsamic vinegar",
      "1 tsp dijon mustard",
      "salt and pepper"
    ],
    "steps": [
      "Combine all ingredients in a bowl, toss, and serve.",
      "Use whatever vinaigrette you want."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Breakfast Mediterranean Scramble",
    "kcal": 282,
    "protein": 17,
    "carbs": 13,
    "fat": 18,
    "time": 30,
    "ingredients": [
      "1 tsp olive oil",
      "1 cup chopped veggies, your choice",
      "2 eggs, lightly beaten",
      "1/2 tsp greek seasoning",
      "1/4 cup feta cheese"
    ],
    "steps": [
      "Heat oil in a small non-stick skillet. Once hot, add veggies and saute until soft. Meanwhile, beat greek seasoning and feta into eggs. Once veggies are at desired doneness, add egg mixture to skillet and gently stir until cooked. Serve immediately."
    ],
    "phase": "follikel"
  },
  {
    "title": "Best Oatmeal Ever",
    "kcal": 376,
    "protein": 11,
    "carbs": 57,
    "fat": 14,
    "time": 30,
    "ingredients": [
      "1/2 cup quick-cooking oats, cooked to your liking",
      "1/2 apple, diced",
      "1/2 tsp cinnamon",
      "1 tbsp maple syrup",
      "1 tbsp nut butter",
      "1 tbsp ground flax seed"
    ],
    "steps": [
      "1. To prepare, once oatmeal has been sufficiently cooked, add diced apples and nut butter. Stir for 2-3 minutes.\n2. Serve into a bowl and mix in cinnamon, flax seeds, maple syrup/agave. Stir and enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "The Original Chex Party Mix",
    "kcal": 150,
    "protein": 3,
    "carbs": 20,
    "fat": 7,
    "time": 30,
    "ingredients": [
      "3 cup Corn Chex® cereal",
      "3 cup Rice Chex® cereal",
      "3 cup Wheat Chex® cereal",
      "1 cup mixed nuts",
      "1 cup bite-size pretzels",
      "1 cup garlic-flavor bite-size bagel chips or regular-size bagel chips, broken into 1-inch pieces",
      "6 tablespoon butter or margarine",
      "2 tablespoon Worcestershire sauce",
      "1 1/2 teaspoon seasoned salt",
      "3/4 teaspoon garlic powder",
      "1/2 teaspoon onion powder"
    ],
    "steps": [
      "Heat oven to 250. Place butter in large roasting pan and melt in the oven. Mix together cereals, nuts, pretzels and bagel chips in a large bowl. Remove pan from oven and mix seasonings into the melted butter. Add cereal mix and stir well to coat with seasoned butter. Place in the oven and bake for 1 hour, stirring every 15 minutes. Spread mix out to cool before storing."
    ],
    "phase": "luteal"
  },
  {
    "title": "Handmade Pasta",
    "kcal": 240,
    "protein": 9,
    "carbs": 39,
    "fat": 5,
    "time": 30,
    "ingredients": [
      "1 cup all-purpose flour",
      "1/2 cup semolina",
      "1/4 tsp salt",
      "2 eggs, at room temperature",
      "2 tsp extra-virgin olive oil"
    ],
    "steps": [
      "Sift flour and semolina into a medium bow.  Mix in salt.  Add eggs and olive oil, and beginning in the center, mix with two fingers in a circular motion until flour is combined with eggs.  Do not overmix.  Remove dough from bowl and gather into a ball.  On a lightly-floured board, knead gently with the heels of your hands, folding dough over onto itself until it forms a smooth mass.  Pat into a ball, flatten slightly, wrap in waxed paper or plastic wrap, and refrigerate for 30 minutes or as long as overnight.",
      "Work on a lightly floured surface.  Keep the dough lightly dusted with flour.  Roll dough into a sheet about 1/16-inch thick.  Gently roll dough up into a cylinder.  With a slicing knife, cut crosswise in 1/4-inch slices.  Dust dough with semolina and unwrap noodles.  Cover with a tea towel until ready to cook.  (The past may be made an hour ahead of time or frozen for up to 1 month.  Defrost in refrigerator.)  Fresh pasta will cook, in boiling salted water, in about 2-3 minutes."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Emeril Essence Creole Seasoning",
    "kcal": 92,
    "protein": 4,
    "carbs": 20,
    "fat": 2,
    "time": 30,
    "ingredients": [
      "2 1/2 tablespoon paprika",
      "2 tablespoon salt",
      "2 tablespoon garlic powder",
      "1 tablespoon black pepper",
      "1 tablespoon onion powder",
      "1 tablespoon cayenne pepper",
      "1 tablespoon dried oregano",
      "1 tablespoon dried thyme"
    ],
    "steps": [
      "Combine all ingredients thoroughly."
    ],
    "phase": "follikel"
  },
  {
    "title": "Vegetarian Chili",
    "kcal": 195,
    "protein": 9,
    "carbs": 31,
    "fat": 5,
    "time": 30,
    "ingredients": [
      "2 tablespoon canola oil",
      "1 1/2 cup yellow onions, chopped",
      "1 cup red bell peppers, chopped",
      "2 tablespoon garlic, minced",
      "2 serrano peppers, stemmed, seeded, and minced",
      "1 medium zucchini, stem ends trimmed and cut into small dice",
      "5 large portobello mushrooms, stemmed, wiped clean and cubed",
      "2 tablespoon chili powder",
      "1 tablespooon ground cumin",
      "1 1/4 teaspoon salt",
      "1/4 teaspoon cayenne",
      "4 large tomatoes, peeled, seeded and chopped",
      "2 can black beans, rinsed and drained",
      "1 15oz can tomato sauce",
      "1 cup vegetable stock, or water",
      "1 lime, juiced",
      "1/4 cup cilantro, chopped",
      "Cooked brown rice, accompaniment",
      "Sour cream or strained plain yogurt, garnish",
      "Diced avocado or guacamole, garnish",
      "Essence, garnish",
      "Chopped green onions, garnish"
    ],
    "steps": [
      "In a large (6qt), heavy pot, heat the oil over medium-high heat. Add the onions, bell peppers, garlic, and serrano peppers, and cook, stirring, until soft, about 3 minutes.",
      "Add the zucchini and mushrooms, and cook, stirring, until soft and the vegetables give off their liquid and start to brown around the edges, about 6 minutes. Add the chili powder, cumin, salt and cayenne, and cook, stirring, until fragrant, about 30 seconds.",
      "Add the tomatoes and stir well. Add the beans, tomato sauce, and vegetable stock, stir well, and bring to a boil. Reduce the heat to medium-low and simmer, stirring occasionally, for about 20 minutes.",
      "Remove from the heat and stir in the cilantro and lime juice. Adjust the seasoning, to taste.",
      "To serve, place 1/4 cup of brown rice in the bottom of each bowl. Ladle the chili into the bowls over the rice. Top each serving with a dollop of sour cream and spoonful of avocado or [guacamole](http://www.xanthir.com/recipes/showrecipe.php?id=28). Sprinkle with [Essence](http://www.xanthir.com/recipes/showrecipe.php?id=id4) and green onions and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Basil-Lime Vinaigrette",
    "kcal": 244,
    "protein": 1,
    "carbs": 8,
    "fat": 26,
    "time": 30,
    "ingredients": [
      "2 limes, zested and juiced",
      "2 tablespoon balsamic vinegar",
      "1/2 cup basil, chopped",
      "1 teaspoon ground cumin",
      "1/4 cup extra-virgin olive oil",
      "Kosher salt and freshly ground black pepper"
    ],
    "steps": [
      "In a small bowl, combine the lime zest, lime juice, balsamic vinegar, basil, and cumin. Slowly add the oil, whisking constantly until the mixture thickens. Season with salt and pepper, to taste."
    ],
    "phase": "luteal"
  },
  {
    "title": "Lentil Soup",
    "kcal": 282,
    "protein": 20,
    "carbs": 38,
    "fat": 5,
    "time": 30,
    "ingredients": [
      "2 tablespoon olive oil",
      "1 cup onion, chopped",
      "1/2 cup carrot, finely chopped",
      "1/2 cup celery, finely chopped",
      "2 teaspoon kosher salt",
      "1 pound lentils, picked and rinsed",
      "1 cup tomatoes, peeled and chopped",
      "2 quart vegetable broth",
      "1/2 teaspoon coriander, freshly ground",
      "1/2 teaspoon cumin, freshly ground and toasted",
      "1/2 teaspoon black pepper, freshly ground"
    ],
    "steps": [
      "Place the olive oil into a large 6-quart Dutch oven and set over medium heat. Once hot, add the onion, carrot, celery and salt and sweat until the onions are translucent, approximately 6 to 7 minutes. Add the lentils, tomatoes, broth, coriander, cumin and pepper and stir to combine. Increase the heat to high and bring just to a boil. Reduce the heat to low, cover and cook at a low simmer until the lentils are tender, approximately 35 to 40 minutes. Using a stick blender, puree to your preferred consistency (optional). Serve immediately."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Natural sports drink",
    "kcal": 168,
    "protein": 0,
    "carbs": 44,
    "fat": 0,
    "time": 30,
    "ingredients": [
      "2 cup water",
      "1/2 lemon, juiced",
      "1/2 lime, juiced",
      "4 tbsp maple syrup",
      "pinch of sea salt"
    ],
    "steps": [
      "Mix together"
    ],
    "phase": "follikel"
  },
  {
    "title": "Spicy Rice Casserole",
    "kcal": 647,
    "protein": 22,
    "carbs": 93,
    "fat": 23,
    "time": 2400,
    "ingredients": [
      "1 cup brown rice (uncooked)",
      "1/2 cup quick-cooking oats",
      "1/2 cup onion, chopped",
      "1/4 cup panko",
      "1/4 cup milk",
      "1 tbsp italian seasoning",
      "1/8 tsp cayenne pepper",
      "1 large egg, beaten",
      "salt and pepper",
      "4 serving [marinara sauce](http://www.xanthir.com/recipes/showrecipe.php?id=id34)",
      "2 servings [toasted panko breadcrumbs](https://www.xanthir.com/recipes/showrecipe.php?id=id631)"
    ],
    "steps": [
      "Preheat oven to 425 degrees. (If not already done, cook rice according to package directions. Ideally, use a rice cooker earlier in the day.)",
      "Mix rice, oats, onion, bread crumbs, milk, basil, oregano, cayenne, and egg.  Season to taste.  Press mixture into small baking dish.  Bake for 25 minutes, then let rest for 5 minutes out of the oven.",
      "As the rice goes into the oven, make the marinara sauce. Once the marinara is simmering, make the breadcrumbs.",
      "Serve rice, topped with marinara and then panko."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Citrus Rice Salad",
    "kcal": 845,
    "protein": 20,
    "carbs": 76,
    "fat": 55,
    "time": 30,
    "ingredients": [
      "3 cup cooked brown rice, hot",
      "3 cup spinach leaves, stemmed and well rinsed",
      "1 cup toasted pine nuts",
      "1/2 cup crumbled feta cheese",
      "1 orange, zested and juiced",
      "1 tablespoon fresh lemon juice",
      "1 tablespoon shallot, minced",
      "1/4 cup extra-virgin olive oil",
      "salt and freshly ground pepper"
    ],
    "steps": [
      "To make the dressing, combine the orange zest and juice, lemon juice, and shallot. Whisk in the olive oil and season with a few pinches of salt and a few grinds of pepper.",
      "Toss the hot rice with the spinach, pine nuts, citrus dressing, then top with the feta. Taste for seasoning and sprinkle with a bit more salt if needed."
    ],
    "phase": "luteal"
  },
  {
    "title": "Straw and Hay Fettuccine Tangle",
    "kcal": 584,
    "protein": 22,
    "carbs": 69,
    "fat": 28,
    "time": 1800,
    "ingredients": [
      "4 serving asparagus pesto",
      "1/4 cup toasted pine nuts",
      "4 tbsp parmesan, grated",
      "12 oz dried pasta"
    ],
    "steps": [
      "http://www.xanthir.com/recipes/showrecipe.php?id=id436 Asparagus pesto can be made in large batches ahead of time, and frozen in servings.",
      "Bring a large pot of water to a rolling boil.",
      "Meanwhile, make asparagus pesto.",
      "Salt the pasta water well and cook the pasta until just tender. Drain and toss immediately with the asparagus pesto (1/4 cup per serving), stirring in more afterward depending on how heavily coated you like your pasta. Serve sprinkled with the remaining toasted pine nuts, a dusting of Parmesan, and a quick drizzle of extra-virgin olive oil."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Green-packed Stir Fry with Fresh Herbs",
    "kcal": 385,
    "protein": 20,
    "carbs": 41,
    "fat": 16,
    "time": 30,
    "ingredients": [
      "1 cup cooked rice",
      "1 tbsp safflower oil",
      "8 oz extra-firm tofu, cut into slices 1-inch long and as thick as a pencil",
      "4 clove garlic, minced",
      "5 green onions, chopped with white and green parts separated",
      "1 tbsp fresh ginger, peeled and minced",
      "1/2 jalapeno, deseeded and chopped",
      "1/2 bunch thin asparagus (about 1/2 pound), trimmed and cut diagonally into 1-inch slices",
      "1/2 cup cashews, coarsely chopped",
      "2 1/2 cup spinach leaves, stemmed",
      "2 tablespoon fresh mint, slivered",
      "2 tablespoon fresh basil, slivered",
      "2 servings stir-fry sauce"
    ],
    "steps": [
      "Cook the rice, if it is not already.",
      "When you have all your ingredients prepped, arrange them within arm's reach of the stove. Heat a small splash of safflower oil in a wok or large nonstick pan over medium-high heat. When the oil is hot, add the tofu and cook for a couple of minutes, until the tofu is golden. Remove from the pan. (You can also cook the tofu in a dry nonstick or well seasoned pan.)",
      "Add another splash of oil to the wok and, as soon as it's hot, add the asparagus and stir for 2 minutes.  Add the white part of the green onions and chiles, and stir for another 2 minutes.  Add the green part of the green onions, and stir for another 2 minutes.  Add the garlic and ginger, and stir for 30 seconds, then add the cashews and spinach and stir for another minute, or until the spinach wilts and collapses.",
      "Return the tofu to the pan. Stir in the stir-fry sauce. Cook for another minute, stirring constantly.",
      "Remove from heat and stir in the mint and basil. Season with enough soy sauce to make the flavors pop, starting with a splash.",
      "Serve over cooked rice.",
      "Nutrition information does not include stir-fry sauce."
    ],
    "phase": "follikel"
  },
  {
    "title": "Almond Caesar salad with croutons",
    "kcal": 552,
    "protein": 8,
    "carbs": 36,
    "fat": 43,
    "time": 30,
    "ingredients": [
      "4 oz Italian bread, cubed",
      "2 tbsp olive oil",
      "salt and pepper",
      "1/4 cup sliced almonds",
      "1/4 cup Parmesan, grated",
      "3 anchovies",
      "1 garlic clove",
      "2 tsp dijon mustard",
      "1 lemon, juiced",
      "1/4 cup olive oil",
      "6 cup lettuce"
    ],
    "steps": [
      "For croutons: Toss bread with olive oil, season with salt and pepper. Spread on a baking sheet and bake at 425, about 8 minutes. Allow to cool.",
      "For dressing: Meanwhile, process almonds, parmesan, anchovies, and garlic in a food processor until finely chopped. Transfer to a large mixing bowl. Add dijon and lemon juice, whisk until just combined. Drizzle in olive oil and whisk constantly until thoroughly combined. Season with salt and pepper if needed.",
      "Toss dressing with lettuce and croutons."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Black bean and cheese tacos",
    "kcal": 600,
    "protein": 22,
    "carbs": 72,
    "fat": 26,
    "time": 900,
    "ingredients": [
      "1 tsp extra-virgin olive oil",
      "1/2 small yellow onion, diced small",
      "2 garlic cloves, roughly chopped",
      "1/2 tsp taco seasoning",
      "1 cup black beans, ideally *not* drained",
      "1/4 cup water",
      "coarse salt and ground pepper",
      "4 flour tortillas, warmed or lightly toasted",
      "2/3 cup Monterey Jack cheese, shredded (1 cup ≈ 3 oz)",
      "1/2 avocado, pitted, peeled and thinly sliced",
      "1 cup packed shredded romaine lettuce",
      "2 tbsp pickled jalapeno"
    ],
    "steps": [
      "In a small pot, heat oil over medium. Add onion and garlic and cook until onion is soft and garlic is fragrant, 3 minutes. Add seasoning and cook until fragrant, 1 minute. Add beans, water (using bean water if possible), salt, and pepper, and simmer until beans are heated through, 5 minutes. Mash in pan with wooden spoon.",
      "Season to taste with salt and pepper if needed. Serve with tortillas, cheese, avocado, lettuce, and jalapenos."
    ],
    "phase": "luteal"
  },
  {
    "title": "Joan's Broccoli Madness",
    "kcal": 391,
    "protein": 10,
    "carbs": 38,
    "fat": 24,
    "time": 30,
    "ingredients": [
      "1 bunch broccoli, raw",
      "½ cup bacon, cooked and crumbled",
      "½ cup cashews",
      "1/3 cup raisins",
      "¼ cup red onion, chopped",
      "1 cup mayonnaise",
      "1/3 cup sugar",
      "2 tablespoon apple cider vinegar"
    ],
    "steps": [
      "Mix the first five ingredients in a large bowl.\nIn a second bowl, beat dressing ingredients together gently until smooth.\nToss the salad with the dressing approximately 10 minutes before serving to allow flavors to meld. Serve on chilled salad dishes."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Creamy tomato soup",
    "kcal": 223,
    "protein": 2,
    "carbs": 8,
    "fat": 21,
    "time": 30,
    "ingredients": [
      "1/4 cup extra-virgin olive oil",
      "1 medium onion, finely chopped",
      "1 clove garlic, chopped",
      "1 small inner stalk celery, chopped",
      "2 pound tomatoes, chopped",
      "1/2 teaspoon sugar",
      "1 tsp salt",
      "1 tablespoon fresh basil (or 1/2 teaspoon dried basil), chopped",
      "1 cup milk, half-and-half, or cream",
      "Kosher salt and freshly ground black pepper"
    ],
    "steps": [
      "Combine the olive oil, onion, garlic, celery, tomatoes, sugar, and salt in a saucepan. Cook over medium heat, stirring occasionally, until the vegetables are tender, about 25 minutes. Puree until smooth (or desired consistency), or transfer to a regular blender in batches and puree. Pour back into saucepan and add milk and basil. Add salt and pepper to taste. For vegans or non-creamy soup, thin with water if needed."
    ],
    "phase": "follikel"
  },
  {
    "title": "Triple Grilled Cheese",
    "kcal": 462,
    "protein": 25,
    "carbs": 33,
    "fat": 26,
    "time": 1080,
    "ingredients": [
      "1 cup shredded muenster cheese (about 4 oz)",
      "1 cup shredded mozzarella cheese (about 4 oz)",
      "1/2 cup grated Parmesan cheese (about 1 oz)",
      "8 slices thick sandwich bread",
      "2 tablespoon unsalted butter"
    ],
    "steps": [
      "Combine all three cheeses in a bowl. Divide evenly among 4 bread slices and top with the remaining bread. Heat 1 tablespoon butter in a large skillet or griddle over medium heat. Cook the sandwiches in batches, adding the remaining butter as needed, until the cheese melts and the bread is golden, 3-4 minutes per side. Serve the sandwiches with the soup."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Soba salad with asparagus and shrimp",
    "kcal": 482,
    "protein": 39,
    "carbs": 73,
    "fat": 6,
    "time": 30,
    "ingredients": [
      "Sea salt",
      "1 pound asparagus, trimmed",
      "1 pound frozen large shrimp (peeled and deveined), thawed",
      "3/4 pound soba noodles",
      "3 tablespoon soy sauce",
      "1 tablespoon toasted sesame oil",
      "1 tablespoon rice vinegar",
      "1 tablespoon sugar",
      "3 green onions, thinly sliced",
      "1 tbsp mint, roughly chopped",
      "1/4 cup cilantro, roughly chopped"
    ],
    "steps": [
      "1. In a large pot of boiling salted water, cook asparagus until crisp-tender, about 3 minutes. With a slotted spoon or mesh strainer, transfer asparagus to a colander and rinse under cool water to stop the cooking. Transfer asparagus to a medium bowl. Return water to a boil; add shrimp and cook until pink and opaque throughout, about 2 minutes. Transfer shrimp to bowl with asparagus. Return water to a boil; add noodles and cook according to package instructions. Drain noodles and rinse under cool water.",
      "2. Meanwhile, in a small bowl, whisk together soy sauce oil, vinegar, and sugar. Divide noodles among bowls and drizzle with dressing. Top with asparagus and shrimp and sprinkle with scallions and herbs."
    ],
    "phase": "luteal"
  },
  {
    "title": "Tofu and Sweet Potato Jambalaya",
    "kcal": 398,
    "protein": 19,
    "carbs": 74,
    "fat": 7,
    "time": 30,
    "ingredients": [
      "14 oz firm tofu",
      "1 tablespoon olive oil",
      "1 large sweet potato, peeled and cut into 1/2-inch cubes",
      "2 clove garlic, finely chopped",
      "2 cup vegetable broth",
      "3/4 cup uncooked regular long-grain white rice",
      "2 tablespoon Worcestershire sauce",
      "1/4 teaspoon ground red pepper",
      "1 can black beans (15 oz), rinsed and drained",
      "12 medium green onions, sliced"
    ],
    "steps": [
      "1. Drain tofu; cut into 3/4-inch cubes. Carefully press cubes between paper towels to remove as much water as possible.\n2. Heat oil in 12-inch skillet over medium heat. Cook tofu in oil 6 to 8 minutes, turning frequently, until light golden brown. Remove tofu from skillet; set aside.\n3. Add sweet potato and garlic to skillet. Cook 2 to 3 minutes, stirring occasionally, just until sweet potato begins to brown. Stir in broth, rice, Worcestershire sauce and red pepper. Heat to boiling; reduce heat. Cover and simmer 10 minutes.\n4. Stir in beans. Cover and cook 8 to 10 minutes, stirring occasionally, until rice is tender and liquid is absorbed. Stir in tofu and onions. Cook 1 to 2 minutes or until heated through."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Wild Mushroom Risotto",
    "kcal": 754,
    "protein": 24,
    "carbs": 83,
    "fat": 35,
    "time": 3600,
    "ingredients": [
      "2 1/2 tablespoon olive oil",
      "1 small yellow onion, diced",
      "8 oz shiitake or cremini mushrooms, cleaned and sliced (if using shiitakes, discard stems)",
      "1 tbsp garlic, roughly chopped",
      "3/4 cup arborio rice",
      "1/2 cup dry white wine",
      "2 1/2 cup vegetable stock (or chicken stock)",
      "3/8 cup Parmesan cheese, grated, divided use",
      "1/2 tsp thyme",
      "1 tbsp unsalted butter",
      "Salt and freshly ground pepper",
      "Truffle oil, for drizzling, optional",
      "1 tbsp parsley, chopped"
    ],
    "steps": [
      "Heat the olive oil in a large pot over medium-high heat. Add the onion and saute, stirring frequently with a wooden spoon for 2 minutes. Add the mushrooms and cook until tender and slightly brown, about 8 minutes (add a splash more oil if necessary). Add the garlic and cook for 2 minutes more.",
      "Add the rice and stir well, about 30 seconds. Add the wine and simmer, stirring constantly until the liquid is absorbed, 2 to 3 minutes. Add the stock, reduce the heat to medium, and cook, stirring occasionally, until the stock is absorbed, the rice is just tender, and the risotto is creamy. The total cooking time is 20 to 25 minutes.",
      "Stir in 1/4 cup cheese, the thyme, and butter. If the rice appears dry, add up to 1/4 cup water to loosen the risotto slightly. Season with salt and pepper to taste.",
      "Divide the risotto between 2 large bowls and drizzle with truffle oil, if desired. Sprinkle with the remaining cheese and the chives."
    ],
    "phase": "follikel"
  },
  {
    "title": "Brown rice, chickpea, feta, and mint salad",
    "kcal": 498,
    "protein": 18,
    "carbs": 69,
    "fat": 30,
    "time": 30,
    "ingredients": [
      "1 1/2 cup cooked brown rice",
      "2 1/2 tbsp lemon juice",
      "1 cup chickpeas, drained and rinsed",
      "2 tsp lemon zest",
      "1 tbsp olive oil",
      "1/2 cup feta cheese, crumbled",
      "1/2 cup grape or cherry tomatoes, halved",
      "1/2 cup fresh mint",
      "1/4 small red onion, chopped",
      "Salt"
    ],
    "steps": [
      "1. Mix rice with 1 tbsp lemon juice while warm.",
      "2. Combine rice and chickpeas in a bowl. Stir in lemon zest, remaining juice, and oil. Let cool.",
      "3. Stir in cheese, tomatoes, mint, and onion. Season with salt. Refrigerate until ready to serve.",
      "Can be refrigerated for up to 2 days."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Spinach souffle",
    "kcal": 450,
    "protein": 22,
    "carbs": 11,
    "fat": 39,
    "time": 30,
    "ingredients": [
      "4 eggs, separated",
      "4 cup spinach, chopped fine",
      "2 sundried tomatoes, chopped fine",
      "1/4 cup feta or goat cheese, crumbled",
      "1/4 tsp salt",
      "1/4 tsp pepper, or to taste",
      "1/2 cup pine nuts, toasted"
    ],
    "steps": [
      "Preheat the oven to 425F with the pan in the oven, and toast the pine nuts.",
      "Whisk the egg whites in a clean bowl to form stiff peaks. In a separate bowl, mix the egg yolks with the spinach, tomato, goat cheese, salt, and pepper to combine. Gently fold the egg whites into the spinach mixture.",
      "Spray the hot pan with oil, then spoon the mixture in and sprinkle with the pine nuts.",
      "Bake in the oven for 10 minutes, or until well risen, golden, and firm. Serve.",
      "Rather than fresh spinach, one can use 3.5oz per serving cooked spinach, chopped or pureed."
    ],
    "phase": "luteal"
  },
  {
    "title": "Peanut Noodle Salad",
    "kcal": 477,
    "protein": 10,
    "carbs": 50,
    "fat": 20,
    "time": 1500,
    "ingredients": [
      "8 ounce rice vermicelli noodles",
      "6 tbsp lime juice",
      "3 tbsp soy sauce, low-sodium",
      "3 tbsp peanut butter, creamy",
      "3 tbsp dark brown sugar",
      "3 tbsp vegetable oil",
      "1 red bell pepper, small and thinly sliced",
      "1/2 cup green onions",
      "1/2 cup basil",
      "1/2 cup cilantro",
      "1/2 cup mint",
      "kosher salt",
      "1/3 cup roasted peanuts"
    ],
    "steps": [
      "Thinly slice the bell pepper and scallions.  Roughly chop the basil, cilantro, mint, and peanuts.",
      "Cook noodles according to package instructions.  Transfer to a serving bowl.",
      "Whisk the lime juice soy sauce, peanut butter, brown sugar, and vegetable oil in a medium bowl until smooth.  Pour the dressing over the noodles.  (If possible, do this when the noodles are hot - it helps melt the peanut butter, which will still be chunky in the dressing.)",
      "Add the bell pepper , scallions, basil, cilantro, and mint and toss to combine.  Season with salt and sprinkle with the peanuts."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Pizza bianca",
    "kcal": 492,
    "protein": 26,
    "carbs": 53,
    "fat": 24,
    "time": 30,
    "ingredients": [
      "all-purpose flour, for dusting and rolling",
      "1 pound pizza dough, thawed if frozen",
      "1 teaspoon extra-virgin olive oil, for brushing",
      "1/2 cup whole-milk ricotta cheese",
      "1 tablespoon extra-virgin olive oil",
      "1 garlic clove, minced",
      "salt and freshly ground pepper",
      "6 oz mozzarella, shredded",
      "1 oz Parmesan, grated (or Pecorino Romano)",
      "2 oz baby arugula",
      "1 tsp extra-virgin olive oil"
    ],
    "steps": [
      "Preheat oven to 500. Lightly dust a work surface, rolling pin, and a baking sheet with flour. Roll dough out to a 13-inch round and transfer to sheet.",
      "In a small bowl, stir together ricotta, oil and garlic; season with salt and pepper. Spread ricotta mixture on dough, leaving a 1/2-inch border. Top with mozzarella, then Parmesan. Brush oil on edge of dough. Bake until crust is golden and cheese is melted and browned in spots, 12 to 14 minutes.",
      "In a small bowl, toss arugula with oil and season to taste with salt and pepper. Top pizza with arugula and serve."
    ],
    "phase": "follikel"
  },
  {
    "title": "Cherry-lime cups",
    "kcal": 356,
    "protein": 7,
    "carbs": 49,
    "fat": 17,
    "time": 30,
    "ingredients": [
      "7 tbsp unsalted butter, cold and cut into pieces, plus more for pan",
      "1 1/3 cup all-purpose flour, spooned and leveled",
      "1/4 cup sugar",
      "1/2 tsp coarse salt",
      "2 egg yolks",
      "1/2 tsp vanilla extract",
      "2 eggs, lightly beaten",
      "3 tbsp all-purpose flour",
      "2/3 cup sugar",
      "5 tbsp fresh lime juice",
      "1/4 tsp coarse salt",
      "9 cherries, halved and pitted"
    ],
    "steps": [
      "1. Make crust: preheat oven to 350. Lightly butter six standard muffin cups. In a food processor, process butter, flour, sugar, and salt until mixture resembles coarse meal. Add yolks and vanilla and process until dough comes together when pressed (dough will be crumbly).",
      "2. Divide dough into 6 pieces. Roll each into a ball and place in a muffin cup, pressing evenly into bottom and up sides. Place a paper cupcake liner into each muffin cup over dough and fill with pie weights or dried beans. Bake until edges are dry, 15 minutes. Carefully remove liners and weights; bake until crusts are dry and barely golden, 5 to 7 minutes.",
      "3. Meanwhile, make filling: in a medium bowl, whisk together eggs, flour, sugar, lime juice, and salt. Place 3 cherry halves into each crust and divide filling among each. Bake until filling is set, about 25 minutes. With the tip of a knife or small offset spatula, remove cups from pan. Let cool completely on a wire rack.",
      "To store, refrigerate in an airtight container, up to 1 day."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Shrimp and edamame with lime",
    "kcal": 347,
    "protein": 38,
    "carbs": 30,
    "fat": 7,
    "time": 2280,
    "ingredients": [
      "1 cup long-grain rice, such as jasmine or basmati",
      "1 tbsp extra-virgin olive oil",
      "1 1/4 lb medium shrimp, peeled and deveined",
      "1 large clove garlic, minced",
      "2 cup frozen shelled edamame, thawed (from a 10 oz package)",
      "5 green onions, halved lengthwise and cut into 1-inch pieces, white and green parts separated",
      "1 tbsp fresh lime juice, plus wedges for serving (optional)",
      "salt and freshly ground pepper"
    ],
    "steps": [
      "Cook rice according to package instructions. Meanwhile, in a large nonstick skillet, heat oil over medium-high. Add shrimp and garlic and cook, stirring occasionally, 4 minutes. Add edamame and scallion whites and cook until shrimp are opaque and garlic is golden, about 3 minutes. Add scallion greens ad lime juice and cook 1 minute. Season to taste with salt and pepper; serve with rice and lime wedges, if desired."
    ],
    "phase": "luteal"
  },
  {
    "title": "Strawberries and cream bars",
    "kcal": 140,
    "protein": 3,
    "carbs": 24,
    "fat": 5,
    "time": 23100,
    "ingredients": [
      "2 lb strawberries, hulled, halved if large (6 cups)",
      "1 1/2 cup sugar",
      "coarse salt",
      "7 egg whites",
      "2/3 cup cold heavy cream",
      "1 tsp vanilla extract"
    ],
    "steps": [
      "1. In a blender, combine strawberries, 3/4 cup sugar, and a pinch of salt and puree until smooth. Pour into a 9x13 baking dish. Transfer to freezer and scrape with a fork every 30 minutes until mixture is thick and slushy, 2 hours. Smooth top with rubber spatula.",
      "2. In a large bowl, using and electric mixer, beat egg whites on high until foamy. With mixer on medium, gradually add 3/4 cup sugar. Increase speed to high and beat until stiff, glossy peaks form, 3 minutes. In another medium bowl, beat cream and vanilla on high until stiff peaks form, 1 to 2 minutes. With rubber spatula, gently fold whipped cream into egg white mixture. Pour over strawberry mixture and smooth top with rubber spatula. Freeze until firm, about 4 hours (or, covered, up to 3 days), before cutting into 12 squares."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Frozen chocolate mousse trifles",
    "kcal": 297,
    "protein": 9,
    "carbs": 40,
    "fat": 13,
    "time": 12300,
    "ingredients": [
      "2 cup chocolate angel food cake, crumbled (5 oz)",
      "1 tbsp brandy (optional)",
      "4 egg whites",
      "1/2 cup sugar",
      "1/3 cup unsweetened cocoa powder, sifted",
      "1/2 cup heavy cream, cold",
      "1/2 oz bittersweet chocolate"
    ],
    "steps": [
      "1. In a medium bowl, toss together cake and brandy, if desired. In another medium bowl, using and electric mixer, beat egg whites on high until foamy. With mixer on medium, gradually add sugar. Increase speed to high and beat until stiff, glossy peaks form, 2 minutes. With a rubber spatula, gently fold cocoa powder into egg white mixture.",
      "2. In another medium bowl, beat cream on high until stiff peaks form, 3 minutes. Gently fold whipped cream into egg white mixture.",
      "3. Fill each of four small glasses with 1/4 cup cake and top with heaping 1/4 cup mousse. Repeat to make a second layer with remaining cake and mousse. Freeze until firm, 3 hours (or up to overnight). Let sit 10 minutes at room temperature, then finely grate chocolate over tops to serve."
    ],
    "phase": "follikel"
  },
  {
    "title": "Frozen lemon souffle",
    "kcal": 433,
    "protein": 14,
    "carbs": 49,
    "fat": 25,
    "time": 24900,
    "ingredients": [
      "1 cup granulated sugar",
      "1 tbsp lemon zest, grated",
      "3/4 cup lemon juice",
      "8 large eggs, whites and yolks separated",
      "1/4 tsp salt",
      "2/3 cup heavy cream, cold",
      "1 1/2 cup raspberries, about 6 oz",
      "confectioners' sugar, for dusting"
    ],
    "steps": [
      "1. Wrap outside of a 3.5-cup souffle mold or four 6-ounce ramekins with parchment, extending 2 to 3 inches above rim (it should fit snugly). Secure with tape, set aside.",
      "2. In a medium saucepan, whisk together granulated sugar, lemon zest and juice, egg yolks, and salt over medium-high. Cook, whisking constantly, until mixture is thick enough to coat the back of a spoon and small bubbles form around edge of pan, about 5 minutes (do not boil). Immediately remove from heat while continuing to whisk. Pour through a fine-mesh sieve into a heatproof bowl, pressing on lemon curd with a rubber spatula.",
      "3. Place plastic wrap directly against surface of curd and refrigerate until cool, about 30 minutes (or up to overnight).",
      "4. In a large bowl, using an electric mixer, beat egg whites on high until stiff peaks form, 2 minutes. Gently fold egg whites into cooled lemon curd. In the same large bowl, beat cream on high until stiff peaks form, 1 to 2 minutes. Gently fold whipped cream into lemon curd mixture. Pour into mold and freeze until firm, 6 hours (or up to overnight). To serve, remove parchment, top with raspberries and dust with confectioners' sugar."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Coconut lime semifreddo",
    "kcal": 307,
    "protein": 4,
    "carbs": 24,
    "fat": 23,
    "time": 23400,
    "ingredients": [
      "1 13.5oz can unsweetened coconut milk",
      "1 14oz can sweetened condensed milk",
      "1 tbsp lime zest, grated",
      "1/4 tsp coarse salt",
      "1 1/2 cup heavy cream, cold",
      "1/2 cup sweetened shredded coconut, toasted",
      "1/2 ripe mango, thinly sliced"
    ],
    "steps": [
      "1. Line a 4.5x8.5-inch loaf pan with parchment, leaving a 4-inch overhang on all sides. Prepare a large bowl of ice water. In a medium saucepan, combine coconut milk and condensed milk and bring to a boil over  high. Reduce heat and cook at a rapid simmer, stirring frequently until thickened, 10 minutes. Remove from heat and stir in lime zest and salt. Place saucepan in bowl of ice water and stir until mixture is cool, 4 minutes.",
      "2. In a large bowl, using an electric mixer, beat cream on high until stiff peaks from, 2 minutes. Gently fold whipped cream into coconut milk mixture. Pour into loaf pan; evenly sprinkle coconut over top. Freeze until firm, 6 hours (or covered, up to 3 days). Let sit 20 minutes at room temperature. Invert onto a serving platter; peel away parchment. Layer mango on top and serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Sweet cherry granita",
    "kcal": 110,
    "protein": 1,
    "carbs": 23,
    "fat": 0,
    "time": 22200,
    "ingredients": [
      "2 lb cherries, stemmed and pitted, or 3 bags (12 oz each) frozen cherries, thawed",
      "1/2 cup sugar",
      "1 tbsp lemon juice",
      "3/4 cup almond-flavored liqueur, such as Disaronno (optional)",
      "whipped cream or mascarpone cheese (optional), for serving"
    ],
    "steps": [
      "1. In a blender, puree cherries, sugar, and lemon juice until sugar is dissolved and mixture is smooth. Pour into an 8-inch square baking dish. Freeze 6 hours, scraping with fork every hour (mixture should be icy and fluffy).",
      "2. To serve, pour 1 tablespoon liqueur into each of 12 small bowls or glasses. Top with 1/2 cup granita and a small dollop of whipped cream, if desired. Serve immediately."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Tex-mex rice and black eyed peas",
    "kcal": 542,
    "protein": 21,
    "carbs": 66,
    "fat": 22,
    "time": 30,
    "ingredients": [
      "1 cup uncooked brown rice",
      "1 tbsp extra-virgin olive oil",
      "1 cup fresh salsa, plus more for topping",
      "1/2 tsp ground cumin",
      "2 14oz cans black-eyed peas, 1 undrained; 1 drained and rinsed",
      "3 cup baby spinach",
      "1/4 cup fresh cilantro, chopped",
      "1 avocado, halved, pitted and sliced",
      "1 cup shredded cheddar cheese",
      "Sour cream or Greek yogurt, for serving (optional)"
    ],
    "steps": [
      "1. Cook the rice as the label directs. Meanwhile, heat the olive oil in a medium saucepan over medium-high heat. Add the salsa and cumin and cook, stirring, until the salsa is soft, about 5 minutes. Add the black-eyed peas, plus the liquid from one of the cans and 1/4 cup water. Cook, stirring occasionally, until the beans are creamy and tender, about 12 minutes.",
      "2. Fluff the rice with a fork and divide among bowls. Add the spinach and cilantro to the black-eyed pea mixture and stir until wilted, about 1 minute; spoon evenly over the rice. Top each serving with a few avocado slices, some cheese and more salsa. Serve with sour cream or Greek yogurt, if desired."
    ],
    "phase": "follikel"
  },
  {
    "title": "Baked eggs and beans on toast",
    "kcal": 559,
    "protein": 29,
    "carbs": 67,
    "fat": 20,
    "time": 30,
    "ingredients": [
      "1 1/2 tbsp extra-virgin olive oil, plus more for brushing",
      "1/2 small onion, chopped",
      "1 tbsp tomato paste",
      "2 tbsp apple cider vinegar",
      "1 tbsp honey mustard",
      "2 tsp Worcestershire sauce",
      "1/2 cup water",
      "Kosher salt and freshly ground pepper",
      "2 can navy beans, 1 undrained; 1 drained and rinsed",
      "8 large eggs",
      "8 thick slices crusty bread",
      "2 cup grape tomatoes, halved",
      "1/4 cup fresh parsley, chopped",
      "1/2 tbsp olive oil"
    ],
    "steps": [
      "Heat olive oil in a large skillet over medium-high heat. Add the onion and cook, stirring, until golden, about 5 minutes. Add the tomato paste and cook, stirring, 1 more minute. Stir in the vinegar, honey mustard, Worcestershire sauce, water, and salt and pepper to taste. Bring to a simmer, then add the beans, plus the liquid from one of the cans. Cook until the beans are soft, about 5 more minutes.",
      "Make indentations in the bean mixture and crack an egg into each. Sprinkle with salt and pepper, then cover and cook until the egg whites are set, 3 minutes or so. (Whites should still be slightly \"jiggly\" when you remove from heat, as they'll continue cooking for a bit and you want the yolks runny.)",
      "Meanwhile, make toast. Butter it when it comes out. (Or make skillet toast with butter over high heat, 1 minute per side or until browned.)",
      "Toss the tomatoes, parsley and remaining olive oil, and salt and pepper to taste in a bowl. Serve the beans and eggs topped with tomato salad, and toast on the side."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Warm shrimp and potato salad",
    "kcal": 430,
    "protein": 29,
    "carbs": 24,
    "fat": 24,
    "time": 2700,
    "ingredients": [
      "1 lb small red-skinned potatoes, halved",
      "1 red bell pepper, thinly sliced",
      "1 tbsp extra-virgin olive oil",
      "1/2 tsp salt",
      "Freshly ground pepper",
      "1 lb medium shrimp, peeled, deveined and halved crosswise",
      "2 clove garlic, chopped",
      "1 tsp dried oregano",
      "1/2 tsp paprika",
      "1 tbsp extra-virgin olive oil",
      "1/4 tsp salt",
      "4 cup romaine lettuce, torn into bite-sized pieces",
      "1 1/2 tbsp fresh lemon juice",
      "3 tbsp extra-virgin olive oil",
      "1/2 cup crumbled feta cheese"
    ],
    "steps": [
      "1. Preheat the oven to 400F. Toss the potatoes and bell pepper with olive oil, salt and pepper to taste in a shallow baking dish. Roast 15 minutes. Meanwhile, toss the shrimp with the garlic, oregano, paprika, olive oil, salt, and pepper to taste in a medium bowl.",
      "2. Add the shrimp to the baking dish. Roast, stirring once, until the shrimp are just cooked through and the potatoes are golden brown, 12 to 15 more minutes.",
      "3. Toss the romaine in a serving bowl with the lemon juice, olive oil, and salt and pepper to taste. Add the warm shrimp and vegetables and toss to combine. Top with the feta."
    ],
    "phase": "luteal"
  },
  {
    "title": "Broccoli soup with cheddar toasts",
    "kcal": 292,
    "protein": 24,
    "carbs": 32,
    "fat": 12,
    "time": 30,
    "ingredients": [
      "1 1/2 tablespoon extra-virgin olive oil",
      "1 medium onion, coarsely chopped",
      "2 garlic cloves, coarsely chopped",
      "2 bunches broccoli (1 bunch ≈ 1½lbs), stems and florets chopped separately into 1/2-inch pieces",
      "7 cup low-sodium chicken stock",
      "1 teaspoon coarse salt",
      "1 cup skim milk",
      "1/8 teaspoon cayenne pepper",
      "2 ounce extra-sharp cheddar cheese, grated or crumbled (about 1/2 cup)",
      "8 thin slices crusty baguette"
    ],
    "steps": [
      "Heat oil in a large pot over medium heat until hot but not smoking. Add onion, garlic, and broccoli stems; cover, and cook, stirring occasionally, until vegetables are soft, about 15 minutes. Add stock and salt; cover, raise heat to medium-high, and bring to a boil. Add broccoli florets; reduce heat, and simmer, uncovered, until florets are just tender, about 10 minutes.",
      "Remove soup from heat, and let cool, about 10 minutes. Fill a blender no more than halfway to puree soup in batches until smooth. Return soup to pot; stir in milk and cayenne. Cook over medium heat until heated through (do not boil).",
      "Heat broiler. Divide cheese among bread slices; toast under broiler until melted and golden brown, 45 to 60 seconds. Divide soup among bowls. Top each bowl with a cheese toast, and serve."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Dang cold Asian noodle salad",
    "kcal": 590,
    "protein": 18,
    "carbs": 75,
    "fat": 28,
    "time": 2100,
    "ingredients": [
      "12 oz soba noodles",
      "1 tsp sesame oil",
      "1 tsp hot chili oil",
      "1 tbsp hoisin sauce",
      "2 tbsp rice wine vinegar",
      "3 tbsp soy sauce",
      "5 tbsp extra-virgin olive oil",
      "1 carrot, thinly sliced or julienned",
      "2 stalk celery, thinly sliced or julienned",
      "5 green onions, bottom 4 inches, thinly sliced",
      "1 cup thinly sliced napa cabbage",
      "1/2 red bell pepper, thinly sliced or julienned",
      "3 tablespoon cilantro, minced",
      "3 tablespoon sesame seeds, toasted, for garnish",
      "4 tablespoon unsalted peanuts, for garnish"
    ],
    "steps": [
      "In a medium stock pot, boil water, add salt and cook noodles. When finished, place noodles in an ice water bath to cool. Drain and set aside.",
      "In a medium bowl combine, sesame oil, vinegar, soy sauce, hot chili oil, hoisin and extra-virgin olive oil. Mix thoroughly and then combine prepared vegetables and noodles.",
      "Garnish with sesame seeds and peanuts."
    ],
    "phase": "follikel"
  },
  {
    "title": "Shrimp and cabbage stir fry",
    "kcal": 262,
    "protein": 32,
    "carbs": 10,
    "fat": 10,
    "time": 1620,
    "ingredients": [
      "1 large egg white",
      "1 tbsp potato starch",
      "1 tsp soy sauce",
      "1 1/4 lb medium shrimp, peeled and deveined",
      "2 tsp potato starch",
      "1 tbsp soy sauce",
      "2 tsp hoisin sauce",
      "1 1/2 tsp rice wine vinegar",
      "1/2 cup chicken broth, or water",
      "2 tbsp vegetable oil",
      "4 green onions, cut into 1/2-inch pieces, white and green parts separated",
      "1 tbsp ginger, finely grated",
      "1 clove garlic, finely grated",
      "1 lb Napa cabbage, about 1/2 head=1 lb, cut into 1-inch pieces",
      "Cooked rice, for serving (optional)"
    ],
    "steps": [
      "1. Whisk egg white, 1 tbsp potato starch and 1 teaspoon soy sauce in a large bowl until frothy. Add the shrimp and toss to coat. Refrigerate 10 minutes. Meanwhile, whisk the hoisin sauce, vinegar, and the remaining 1 tablespoon soy sauce and 2 teaspoons potato starch in a small bowl, the whisk in the chicken broth. Set aside.",
      "2. Drain the shrimp. Heat the vegetable oil in a wok or large skillet over medium-high heat, then stir-fry the scallion whites, ginger and garlic, about 30 seconds. Add the shrimp and stir-fry until almost cooked through,a bout 3 minutes. Add the cabbage and stir-fry until wilted and the shrimp are just cooked through, about 2 more minutes.",
      "3. Stir the hoisin sauce mixture, then add to the wok and simmer, stirring occasionally, 2 minutes. Stir in the scallion greens. Serve with rice, if desired."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Orecchiette with roasted cauliflower",
    "kcal": 765,
    "protein": 24,
    "carbs": 87,
    "fat": 30,
    "time": 30,
    "ingredients": [
      "8 oz dried orecchiette pasta",
      "1/2 cup panko",
      "1 tbsp olive oil",
      "1 garlic cloves, pressed",
      "1/4 cup fresh parsley, chopped",
      "3 cup cauliflower, cut into small florets",
      "1 medium red onion",
      "1/4 tsp salt",
      "1 tbsp olive oil",
      "5 garlic cloves",
      "1 1/2 cup dry white wine",
      "1/4 tsp red pepper flakes",
      "1 tsp salt",
      "1/3 cup mascarpone cheese",
      "2 oz Parmesan cheese, grated",
      "1/2 tsp ground black pepper",
      "2 roma tomato, diced",
      "5 cup baby spinach"
    ],
    "steps": [
      "Cook pasta according to package directions, omitting salt and oil.  Carefully remove 1/2 cup (for 4 servings) of the cooking water for later use.  Drain pasta and set aside.",
      "Meanwhile, combine bread crumbs, oil and pressed garlic cloves in microwave-safe bowl.  Microwave, uncovered, on high 1-2 minutes or until light golden brown, stirring every 30 seconds.  Stir in parsley; set aside.",
      "Cut cauliflower into small florets and onion into 1/2-in wedges.  Spritz medium skillet with olive oil.  Heat over medium-high heat until hot, then add cauliflower and onion, and season with salt. Cook 3-4 minutes or until cauliflower is golden brown on all sides, stirring occasionally.",
      "Stir in remaining 1 tbsp oil, remaining pressed garlic cloves, wine, and pepper flakes; bring to a boil.  Cook 2-3 minutes or until wine is reduced by half.",
      "Add pasta, reserved cooking water, cheeses, black pepper, and remaining 1tsp salt; mix well. Remove skillet from heat, add spinach and tomatoes, stir until spinach wilts.  Cover and let stand 10 minutes or until spinach is wilted and sauce is thickened, stirring once halfway through.  Top each serving with bread crumb mixture and additional parmesan cheese."
    ],
    "phase": "luteal"
  },
  {
    "title": "Black bean salad with chipotle honey dressing",
    "kcal": 360,
    "protein": 16,
    "carbs": 52,
    "fat": 11,
    "time": 1800,
    "ingredients": [
      "2 cup cooked rice",
      "1/2 cup pumpkin seeds, toasted",
      "2 avocados, diced",
      "2 can black beans, rinsed and drained",
      "1 cup grape tomatoes, halved",
      "1 red bell pepper, chopped",
      "4 servings [chipotle honey vinaigrette](https://www.xanthir.com/recipes/showrecipe.php?id=id258)"
    ],
    "steps": [
      "Mix all ingredients, toss with dressing."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Pasta with asparagus and egg",
    "kcal": 494,
    "protein": 21,
    "carbs": 68,
    "fat": 16,
    "time": 1800,
    "ingredients": [
      "3/4 lb angel hair pasta",
      "3 tbsp unsalted butter",
      "1/4 cup parmesan, grated, about 1/2 oz=1/4 cup",
      "1 bunch thin asparagus (about 1 pound=1 bunch), trimmed to bite-size",
      "4 large eggs"
    ],
    "steps": [
      "Cook pasta. Meanwhile, toss chopped asparagus with oil, salt, pepper, and whatever other seasoning you desire. Roast at 450F for 8 minutes.",
      "When pasta is done, drain it, reserving some pasta water. Return it to the pot, and add butter, parmesan, and enough pasta water to make a thin sauce. Also add asparagus.",
      "Fry eggs over easy. Dish the pasta, and top with egg and a little more parmesan."
    ],
    "phase": "follikel"
  },
  {
    "title": "Spanakopita",
    "kcal": 388,
    "protein": 11,
    "carbs": 41,
    "fat": 21,
    "time": 5100,
    "ingredients": [
      "1/2 cup extra-virgin olive oil, plus more for baking dish",
      "3 1/2 lb spinach, trimmed and washed",
      "1 3/4 lb leeks, white and green parts only, halved lengthwise, rinsed well, and sliced crosswise",
      "2 garlic cloves, minced",
      "salt and pepper",
      "1/4 tsp ground nutmeg",
      "24 sheets frozen phyllo dough, from a 16 oz package, thawed",
      "3/4 cup crumbled feta, about 4 oz=3/4 cup"
    ],
    "steps": [
      "1. Preheat oven to 400F. With a pasry brush, brush bottom and sides of a 9x13-inch baking dish with oil. In a large skillet, heat 1/4 cup (for 8 servings) water over medium-high. Working in batches, add spinach and cook, tossing, until completely wilted, about 8 minutes. Transfer to a colander to drain, pressing out as much water as possible. Return skillet to heat and add 1 tablespoon oil (for 8 servings). Add leeks and cook until softened, about 8 minutes. Stir in garlic, season with salt and pepper, and cook until fragrant about 1 minute. Stir in nutmeg. Transfer spinach and leek mixture to a food processor; pulse until coarsely chopped.",
      "2. Cut phyllo sheets to fit baking dish. Place 1 sheet in dish (keeping remaining sheets covered with a damp towel) and brush lightly with oil. Stack 7 more phyllo sheets on top, brushing each with oil. Spread half the spinach mixture over phyllo and evenly sprinkle the feta on top. Add 8 more phyllo sheets, brushing each with oil. Spread with remaining spinach mixture and feta. Top with remaining 8 phyllo sheets, brushing each with oil.",
      "3. Bake until phyllo is golden and crisp on top, about 30 minutes. Let cool 15 minutes before cutting  into squares. Serve warm or at room temperature."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Simple lemon cake",
    "kcal": 360,
    "protein": 5,
    "carbs": 55,
    "fat": 16,
    "time": 8400,
    "ingredients": [
      "3/4 cup unsalted butter, room temperature, plus more for pan",
      "2 cup all-purpose flour, plus more for pan",
      "3/4 pound lemons, about 4, ends removed, cut into thin slices",
      "coarse salt",
      "2 cup granulated sugar",
      "2 large eggs",
      "2 egg yolks",
      "1 tsp baking powder",
      "2/3 cup whole milk",
      "2 tsp vanilla extract",
      "confectioners' sugar, for dusting",
      "raspberries (optional), for serving",
      "whipped cream (optional), for serving"
    ],
    "steps": [
      "1. Preheat oven to 400F. Lightly butter and flour a 9-inch round cake pan (2 inches deep). In a medium saucepan, cover lemon slices with 3 cups water. Add pinch of salt, cover, and bring to a boil over high. Boil lemons, partially covered, until very tender, 15 minutes. Drain and transfer to food processor. Add butter and process until smooth, scraping down bowl as needed. Add granulated sugar, eggs, and yolks and process to combine; transfer to a large bowl.",
      "2. In a medium bowl, whisk together flour, baking powder, and 1/2 tsp salt. Measure milk in a liquid-measuring cup and add vanilla. In two additions, add flour mixture to lemon mixture, alternating with milk.",
      "3. Transfer batter to pan and smooth top. Bake until cake is golden brown and a toothpick inserted in center comes out with a few moist crumbs attached, 40 minutes. Let cool in pan on a wire rack, 20 minutes. Remove cake from pan and let cool completely on rack, 1 hour. (Store cooled cake, tightly wrapped in plastic, at room temperature up to 1 day.) Dust with confectioners' sugar and serve with raspberries and cream, if desired."
    ],
    "phase": "luteal"
  },
  {
    "title": "Gooey layered everything bars",
    "kcal": 334,
    "protein": 5,
    "carbs": 40,
    "fat": 19,
    "time": 3600,
    "ingredients": [
      "nonstick cooking spray",
      "3/4 cup unsalted butter, cut into small pieces",
      "1/2 cup confectioners' sugar",
      "1 1/2 cup all-purpose flour",
      "1/2 tsp coarse salt",
      "3/4 cup rolled oats, not quick-cooking",
      "1 cup semisweet chocolate chips, 6 ounces",
      "1 cup walnut, broken and toasted",
      "1/2 cup raisins",
      "1 14oz can condensed milk",
      "2 cup sweetened shredded coconut, 7 ounces"
    ],
    "steps": [
      "1. Preheat oven to 375F. Line a 9x13-inch baking dish with parchment paper, leaving overhang on short sides; lightly coat paper with cooking spray. In a food processor, pulse together butter, confectioners' sugar, flour and salt until mixture resembles coarse meal. Add oats and pulse until just combined. Press dough evenly into bottom of dish and bake until lightly browned and firm, about 20 minutes.",
      "2. Scatter chocolate chips, walnuts, and raisins on top of crust. Drizzle with condensed milk and top with coconut. Bake until coconut is golden, about 20 minutes. Let cool completely in dish on a wire rack before cutting into 18 squares.",
      "Store in an airtight container, at room temperature up to 3 days."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Pecan molasses granola",
    "kcal": 270,
    "protein": 6,
    "carbs": 30,
    "fat": 16,
    "time": 3900,
    "ingredients": [
      "1/3 cup unsulfured molasses, not blackstrap",
      "2 tbsp vegetable oil",
      "1/2 tsp ground cinnamon",
      "1/2 tsp coarse salt",
      "3 cup rolled oats (not quick cooking)",
      "1 cup shredded coconut",
      "1 cup pecans, roughly chopped"
    ],
    "steps": [
      "Preheat oven to 325F. In a large bowl, whisk together molasses, oil, cinnamon, and salt. Add oats, coconut, and pecans; stir gently with a rubber spatula until oats are completely coated. Transfer to a rimmed baking sheet and spread in an even layer. Bake, stirring occasionally, until oats are lightly browned, 25 to 30 minutes (watch carefully, as mixture burns easily). Let cool completely on sheet on a wire rack, 30 minutes.",
      "Store in airtight container at room temperature up to 3 weeks.",
      "Each serving is 1/2 cup."
    ],
    "phase": "follikel"
  },
  {
    "title": "Salmon and potatoes in tomato sauce",
    "kcal": 556,
    "protein": 43,
    "carbs": 26,
    "fat": 31,
    "time": 3060,
    "ingredients": [
      "2 tbsp extra-virgin olive oil",
      "1/2 medium onion, diced small",
      "2 garlic cloves, minced",
      "1 28oz can diced tomatoes",
      "3/4 lb small white potatoes, halved or quartered",
      "1/2 cup Kalamata olives, pitted",
      "1/4 cup fresh parsley, chopped",
      "4 salmon fillets, skin removed",
      "salt and pepper"
    ],
    "steps": [
      "In a large, straight-sided skillet, heat oil over medium. Add onion and garlic; cook, stirring occasionally, until onion is softened, 8 minutes.",
      "Add tomatoes and juice; cook until liquid is slightly reduced, 10 minutes.",
      "Add potatoes, olives, and 1/2 cup water (for 4 servings) to skillet with tomato sauce. Partially cover and cook until potatoes are almost tender, 8 minutes.",
      "Stir in parsley. Season salmon with salt and pepper; nestly among potatoes and sauce. Cover and cook until fish is opaque throughout and potatoes are tender when pierced with a knife, 10 minutes. Serve salmon with potatoes and sauce.",
      "If cooking for 2 servings, reduce the cook times of all phases by 2 minutes."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Marinated feta, spinach & poached egg salad",
    "kcal": 330,
    "protein": 18,
    "carbs": 32,
    "fat": 16,
    "time": 2400,
    "ingredients": [
      "1/2 cup red wine vinegar",
      "6 tbsp fresh orange juice, see tip below",
      "3 tbsp olive oil",
      "2 tbsp fresh thyme, finely chopped",
      "2 tbsp fresh oregano, finely chopped",
      "2 tsp sugar",
      "4 garlic cloves, pressed",
      "1 tsp crushed red pepper flakes",
      "4 eggs",
      "4 oz feta cheese, cut into 1/2 inch cubes",
      "8 slices french bread, cut 1/4 in thick, brushed with oil and toasted",
      "6 cup baby spinach",
      "1 cup grape tomatoes, halved",
      "2 medium oranges, cut into segments",
      "1/4 small red onion, thinly sliced"
    ],
    "steps": [
      "1. For vinaigrette, whisk together all ingredients. Combine half of the vinaigrette and feta in a small mixing bowl; let feta stand 20 minutes. Set aside remaining vinaigrette.\n2. Poach the eggs.\n3. Combine spinach, tomatoes, orange segments, onion and remaining vinaigrette in a large bowl; toss to coat.\n4. Remove feta from vinaigrette; discard vinaigrette. To serve, divide spinach mixture among serving plates. Top with feta and poached eggs; sprinkle with salt and black pepper. Serve with toasted breads slices."
    ],
    "phase": "luteal"
  },
  {
    "title": "Smoky white bean and arugula panini",
    "kcal": 410,
    "protein": 18,
    "carbs": 43,
    "fat": 18,
    "time": 1500,
    "ingredients": [
      "1 tbsp olive oil",
      "1 tbsp fresh rosemary, finely chopped",
      "1 garlic clove, pressed",
      "2 tsp lemon juice",
      "1 can great northern beans, drained and rinsed",
      "1/4 tsp salt",
      "1/4 tsp ground black pepper",
      "1/2 tbsp olive oil",
      "8 slices Italian bread, cut 1/2-in. thick",
      "6 oz smoked mozzarella cheese, shredded",
      "2 medium tomatoes, sliced",
      "1/4 small red onion, thinly sliced",
      "2 cup arugula"
    ],
    "steps": [
      "1. Combine 1 tbsp of the oil (for 4 servings), rosemary, and pressed garlic in a small bowl, microwave on high 1 minute. Place rosemary mixture, lemon juice, beans, salt and black pepper in food processor. Pulse until a coarse paste forms, scraping down sides of bowl as necessary.",
      "2. To assemble panini, brush one side of each bread slice with remaining oil; place bread oil side down on cutting board. Spread 2 tbsp of the bean mixture over each bread slice; sprinkle with cheese, pressing down firmly. Arrange tomato slices, onion and arugula over half of the bread slices; top with remaining bread slices, oil side up.",
      "3. Heat grill pan or griddle over medium heat. Cook panini 2-3 minutes per side or until grill marks appear and bread is golden brown. Cook in batches if needed. Slice panini in half crosswise; serve immediately."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Easy chickpea and vegetable curry",
    "kcal": 456,
    "protein": 11,
    "carbs": 72,
    "fat": 17,
    "time": 2400,
    "ingredients": [
      "1 cup uncooked basmati rice",
      "1 medium onion, chopped",
      "1 serrano pepper, chopped",
      "1 small sweet potato, peeled and diced small",
      "2 tbsp olive oil",
      "2 can chickpeas, drained and rinsed",
      "2 tbsp yellow curry paste",
      "4 garlic cloves, pressed",
      "1 1/2 tbsp ginger",
      "2 can lite coconut milk",
      "1/2 medium head cauliflower, cut into small florets",
      "2 tbsp lemon juice",
      "1 cup frozen peas",
      "1 3/4 tsp salt"
    ],
    "steps": [
      "Cook the rice.",
      "Heat oil in a large saucepan over medium heat. Add onion and serrano; cook 3-4 minutes or until onion is softened.",
      "Add potato, chickpeas, curry powder, garlic, and ginger. Cook and stir 3-4 minutes or until fragrant.",
      "Stir in coconut milk and cauliflower and bring to a simmer. Reduce heat to medium low; cover and cook 8-9 minutes or until potato is tender, stirring frequently.",
      "Add lemon juice, peas, and salt to pan; simmer 4-5 minutes or until cauliflower is tender. Serve curry with rice."
    ],
    "phase": "follikel"
  },
  {
    "title": "Maple brown butter semifreddo",
    "kcal": 314,
    "protein": 2,
    "carbs": 18,
    "fat": 27,
    "time": 19500,
    "ingredients": [
      "2 cup heavy cream, cold",
      "6 tablespoon unsalted butter",
      "3/4 cup maple syrup",
      "5 egg yolks",
      "Hazelnuts, toasted and chopped (optional), for serving"
    ],
    "steps": [
      "In a medium bowl, using an electric mixer, beat cream on high until stiff peaks form, 2 minutes; refrigerate. In a small saucepan, heat butter over medium, swirling pan occasionally, until golden brown and most of the foam has subsided, 8 to 10 minutes. Immediately pour into a small bowl. In clean saucepan, bring maple syrup to a boil over medium-high and cook 2 minutes.",
      "In a medium bowl, using an electric mixer, beat egg yolks on high until pale yellow, 1 to 2 minutes. With mixer running, add hot maple syrup in a slow, steady stream, then add brown butter. Beat on high until mixture has cooled to room temperature, about 5 minutes. With a rubber spatula, gently fold in whipped cream. Transfer mixture to a 5-by-10-inch loaf pan and cover with plastic wrap. Freeze until firm, 5 hours (or up to 1 week). Serve topped with hazelnuts if desired."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Brown sugar buttermilk pie",
    "kcal": 423,
    "protein": 7,
    "carbs": 47,
    "fat": 24,
    "time": 14700,
    "ingredients": [
      "1 1/4 cup all-purpose flour, spooned and leveled, plus more for rolling",
      "1 teaspoon sugar",
      "1/4 teaspoon fine salt",
      "1/2 cup cold unsalted butter, cut into small pieces",
      "3 to 5 tablespoons ice water",
      "3 tablespoon all-purpose flour",
      "3 eggs, lightly beaten",
      "2 egg yolks, lightly beaten",
      "1 cup packed dark-brown sugar",
      "1 1/2 cup buttermilk, room temperature",
      "1/2 teaspoon ground nutmeg",
      "1/4 teaspoon ground cinnamon",
      "6 tablespoon unsalted butter"
    ],
    "steps": [
      "Make the crust: In a food processor, pulse flour, sugar, and salt until combined. Add butter and pulse until mixture resembles coarse meal, with a few pea-size pieces of butter remaining. Sprinkle with 3 tablespoons ice water. Pulse until dough is crumbly but holds together when squeezed (if necessary, add up to 2 tablespoons ice water, 1 tablespoon at a time); do not overmix. Form dough into a disk, wrap tightly in plastic, and refrigerate until firm, 1 hour.",
      "Preheat oven to 375 degrees. On a floured surface, roll out dough to a 12-inch round. Place in a 9-inch pie plate, fold overhang under, and crimp edges. Prick dough all over with a fork. Place a sheet of parchment paper over dough and fill with pie weights or dried beans. Bake until edge is light golden, about 15 minutes; remove parchment and weights.",
      "Make the filling: In a large bowl, whisk together flour, eggs, and brown sugar until smooth. Whisk in buttermilk, nutmeg, and cinnamon until combined. In a small saucepan, heat butter over medium, swirling pan occasionally, until golden brown and most of the foam has subsided, 8 to 10 minutes. Immediately whisk into buttermilk mixture. Pour filling into pie shell and bake until set but still slightly wobbly in center, 25 to 35 minutes. Let cool completely on a wire rack, 2 hours, before serving.",
      "Cook's Note",
      "Refrigerate, wrapped in plastic, up to 3 days.",
      "How to Crimp a Crust: Using a knuckle on one hand and the thumb and forefinger of the other, crimp the rim of the crust."
    ],
    "phase": "luteal"
  },
  {
    "title": "Mushroom and lentil soup",
    "kcal": 414,
    "protein": 26,
    "carbs": 58,
    "fat": 8,
    "time": 30,
    "ingredients": [
      "2 tablespoon extra-virgin olive oil",
      "5 small carrots, diced small",
      "1 medium red onion, diced small",
      "4 clove garlic, minced",
      "3/4 pound cremini mushrooms, trimmed and coarsely chopped (4 cups)",
      "Coarse salt and ground pepper",
      "9 sprig thyme",
      "3/4 pound brown lentils",
      "7 cup water",
      "2 tablespoon soy sauce",
      "1/4 lemon, juiced",
      "2/3 cup nonfat plain Greek yogurt, for serving"
    ],
    "steps": [
      "In a large Dutch oven or other heavy pot, heat oil over medium. Add carrots, onion, and garlic and cook, stirring occasionally, until beginning to soften, about 6 minutes. Add mushrooms and season with salt and pepper. Cook until mushrooms are softened and golden brown at edges, about 8 minutes.",
      "Add thyme, lentils, soy sauce, lemon, and water; bring to a boil. Reduce heat, partially cover, and simmer until lentils are tender, about 25 minutes. Season to taste with salt and pepper. Serve soup topped with yogurt.",
      "Alternate recipe: use half rice and half lentils.  Add the rice with the water; cook for 15 minutes on medium, before boiling.  Then add lentils, bring to a boil, and simmer for 25 minutes."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Indian Chickpea Wrap",
    "kcal": 441,
    "protein": 17,
    "carbs": 67,
    "fat": 11,
    "time": 1500,
    "ingredients": [
      "1 tbsp ginger, peeled",
      "1 serrano chile pepper, halved, seeded and finely chopped",
      "1/2 small onion, finely chopped",
      "1/2 teaspoon ground cumin",
      "salt",
      "1/2 cup low-fat plain greek yogurt",
      "2 teaspoon fresh lime juice",
      "1/3 cup fresh cilantro, chopped",
      "1 tablespoon vegetable oil",
      "2 cup chickpeas",
      "2 medium carrots, shredded",
      "1/4 tsp salt",
      "1/2 cup water",
      "4 pieces naan bread, warmed"
    ],
    "steps": [
      "Mix the yogurt, lime juice, cilantro and a pinch of salt in a bowl. Cover and chill until ready to use.",
      "Heat the vegetable oil in a large skillet over medium-high heat. Combine the ginger, chile, onion, cumin, and heavy pinch of salt, then add to the hot oil and cook, stirring, until most of the liquid has evaporated and the mixture is slightly toasted, about 5 minutes.",
      "Stir in the chickpeas, carrots, salt and water and continue to cook, stirring, until the sauce is thick and the chickpea is heated through, about 2 more minutes. While cooking, lightly mash the chickpeas so they won't roll around when served.  Season with additional salt if necessary.",
      "Divide the chickpea filling among the naan bread. Drizzle with some of the yogurt sauce and roll up. Serve with chips."
    ],
    "phase": "follikel"
  },
  {
    "title": "Kale and feta salad",
    "kcal": 515,
    "protein": 16,
    "carbs": 17,
    "fat": 46,
    "time": 30,
    "ingredients": [
      "1/2 cup pumpkin seeds",
      "8 cup baby kale, or chopped regular kale",
      "8 oz feta cheese, crumbled",
      "1 small red onion, sliced",
      "1/2 cup olive oil",
      "1 lemon, zested and juiced",
      "Salt and freshly ground pepper"
    ],
    "steps": [
      "1. Toast the pumpkin seeds in a medium skillet over medium-high heat, watching carefully, stirring until light brown, about 5 minutes.",
      "2. Combine the kale, feta, and onions in a large bowl. Toss with the olive oil, lemon zest, lemon juice, and season with salt and pepper. Scatter the pumpkin seeds over the top and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Antipasto Chef's Salad",
    "kcal": 445,
    "protein": 18,
    "carbs": 24,
    "fat": 30,
    "time": 1500,
    "ingredients": [
      "4 eggs",
      "2 medium russet potatoes, peeled and cut into 1-inch chunks",
      "2 tablespoon red wine vinegar",
      "1 tablespoon whole-grain mustard",
      "Kosher salt",
      "Freshly ground pepper",
      "4 tbsp extra-virgin olive oil",
      "2 cup giardiniera (Italian pickled vegetables), drained, rinsed and coarsely chopped",
      "6 oz mozzarella (or other mild cheese), shredded or thinly sliced into strips",
      "1/4 cup green olives, pitted and chopped",
      "1/4 cup fresh chives, chopped",
      "4 ounce baby kale, torn (about 5 cups=4 oz)"
    ],
    "steps": [
      "Put the eggs in a medium saucepan and cover with water by 2 inches; bring to a simmer and cook 10 minutes. Remove the eggs with a slotted spoon and transfer to a bowl of ice water to cool.",
      "Meanwhile, put the potatoes in a pot of salted water, bring to a simmer and cook until tender, about 10 minutes. Drain and keep warm.",
      "Whisk the vinegar, mustard, and salt and pepper to taste in a large bowl. Drizzle in the olive oil, whisking, until the dressing is creamy. Add the potatoes, giardiniera, cheese, olives, chives and kale, and toss.",
      "Peel and quarter the eggs. Add to the salad and gently toss."
    ],
    "phase": "luteal"
  },
  {
    "title": "Moroccan lentil salad",
    "kcal": 400,
    "protein": 21,
    "carbs": 62,
    "fat": 11,
    "time": 30,
    "ingredients": [
      "1/2 cup dried lentils",
      "1/2 cup farro",
      "4 cup water",
      "1/2 tsp salt",
      "1 bay leaf",
      "1 plum tomato, diced",
      "1/4 cup red onion, finely diced",
      "2 oz feta cheese, finely diced",
      "3 tbsp fresh mint, chopped",
      "2 tbsp fresh parsley, chopped",
      "1 tbsp olive oil",
      "1 tbsp lemon juice",
      "1 tsp lemon zest",
      "1 garlic clove, pressed or minced",
      "1/2 tsp paprika"
    ],
    "steps": [
      "1. Place lentils in colander; rinse and pick out any stones or other debris. Bring water to a boil in a 2 qt saucepan; add lentils, farro, salt and bay leaf. Simmer, uncovered, 20-25 minutes or until lentils are tender. Drain lentils; remove and discard bay leaf. Set lentils aside to cool.",
      "2. In a mixing bowl, combine lentils, tomato, onion, cheese, mint and parsley. In a small bowl, whisk together oil, lemon juice, lemon zest and garlic until blended. Drizzle dressing over salad, tossing gently to coat. Sprinkle with paprika."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Tuscan panzanella salad",
    "kcal": 620,
    "protein": 20,
    "carbs": 78,
    "fat": 30,
    "time": 30,
    "ingredients": [
      "4 oz ciabatta bread, cut into 1/2-inch cubes",
      "1/4 cup kalamata olives, pitted and coarsely chopped",
      "1 cup cherry tomatoes, halved",
      "1/2 medium cucumber, peeled, seeded and diced",
      "1/4 cup red onion, thinly sliced",
      "1/2 cup chickpeas",
      "1/4 cup fresh basil, thinly sliced",
      "1 tbsp lemon juice",
      "1 tbsp red wine vinegar",
      "1 garlic clove, pressed or minced",
      "2 tbsp olive oil",
      "1/2 oz Parmesan, shaved"
    ],
    "steps": [
      "1. Preheat oven to 450F. For salad, place bread cubes on baking sheet; bake 7-10 minutes or until golden brown. Remove from oven; cool completely. In large serving bowl, combine bread cubes, olives, tomatoes, cucumber, onion, chickpeas, and basil.",
      "2. For vinaigrette, combine lemon juice, vinegar and garlic in small mixing bowl. While continuously whisking, add oil in a thin, steady stream. Drizzle dressing over salad; toss to coat. Let stand 20 minutes to allow flavors to blend. Spoon salad onto serving plates; shave cheese over each serving using a vegetable peeler."
    ],
    "phase": "follikel"
  },
  {
    "title": "Salmon Tuscano with Herbed Orzo",
    "kcal": 756,
    "protein": 46,
    "carbs": 41,
    "fat": 46,
    "time": 30,
    "ingredients": [
      "1 cup uncooked orzo",
      "2 tablespoon olive oil",
      "1/2 small onion, chopped",
      "1 tablespoon rosemary, chopped",
      "1/2 small onion, chopped",
      "1 teaspoon garlic, minced",
      "1 pint grape tomatoes, halved",
      "8 oz seasoned kalamata olives",
      "2 tablespoon fresh basil, chopped",
      "2 tablespoon fresh parsley, chopped",
      "4 salmon fillets",
      "2 tablespoon olive oil",
      "1/4 teaspoon salt",
      "1/8 teaspoon ground black pepper",
      "2 tablespoon fresh basil, chopped"
    ],
    "steps": [
      "Bring a pot of salted water to a boil. Cook orzo for al dente texture.",
      "In a large, nonstick saucepan, heat the olive oil on a medium setting. Cook half of onion until tender, about 5 minutes. Combine with rosemary and cooked orzo in a large bowl. Toss well to incorporate, then set aside.",
      "Add garlic and remaining onion to the pan. Cook until soft, about 2 minutes. Add grape tomatoes and Calamata olives. Cook together for about 3 minutes. Remove the skillet from heat, then stir in parsley, and remaining basil. Season with salt and pepper. Set aside.",
      "Rub salmon with salt, pepper and half of the chopped basil. Using the same saucepan from the onions, sauté salmon in the remaining olive oil, until golden on each side. Cook flesh side first, then approximately 5 minutes per side.",
      "Serve salmon atop a small bed of orzo, dazzled with the warm tomato and olive salsa."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Tomato-Basil Soup with Ricotta Dumplings",
    "kcal": 250,
    "protein": 15,
    "carbs": 34,
    "fat": 7,
    "time": 1440,
    "ingredients": [
      "1 tsp olive oil",
      "1 garlic clove, pressed",
      "1 15oz can crushed tomatoes, undrained",
      "1 1/2 cup vegetable broth, or chicken broth",
      "1/4 cup fresh basil, snipped",
      "1/4 cup part-skim ricotta cheese",
      "2 tbsp grated fresh Parmesan cheese",
      "1 egg white, lightly beaten",
      "1/2 tsp salt",
      "1/4 tsp coarsely ground black pepper",
      "1/3 cup all-purpose flour",
      "2 tbsp fresh basil leaves, chiffonade, for garnish"
    ],
    "steps": [
      "1. For soup, combine oil and garlic in 3-qt. Saucepan; cook and stir over medium heat 1-2 minutes or just until garlic begins to turn light golden brown. Immediately add tomatoes, broth and basil. Bring to a boil. Reduce heat; simmer 5-7 minutes, stirring occasionally.",
      "2. Meanwhile, for dumplings, combine ricotta cheese, Parmesan cheese, egg white, salt and black pepper in Small Bowl; mix well. Add flour; stir just until combined. Using a Small Scoop or spoons, scoop dumpling mixture directly into simmering soup. Cook until dumplings float to the surface, about 2 minutes. Remove from heat. Ladle soup into bowls; sprinkle with thinly sliced fresh basil."
    ],
    "phase": "luteal"
  },
  {
    "title": "Tomato, Basil and Portobello Napoleons",
    "kcal": 284,
    "protein": 11,
    "carbs": 19,
    "fat": 17,
    "time": 2100,
    "ingredients": [
      "2 tbsp white wine vinegar",
      "2 garlic clove, pressed",
      "1/4 tsp Italian Seasoning",
      "1/4 tsp salt",
      "2 tbsp olive oil",
      "8 large portobello mushroom caps, stem removed",
      "4 large tomatoes, cut into 2 thick slices each",
      "4 oz log goat cheese",
      "1/3 cup pine nuts, toasted and chopped",
      "1/2 cup fresh bread crumbs, toasted",
      "1/2 tsp Italian Seasoning",
      "1 tbsp olive oil",
      "4 large basil leaves, thinly sliced"
    ],
    "steps": [
      "Preheat oven to 450°F (230°C).",
      "Make the dressing: whisk vinegar, oil, garlic, seasoning, and salt together. Baste mushrooms on both sides, then place mushrooms gills-down and bake for 10 min. Flip, top with tomato slices, and bake for another 10 min.",
      "Meanwhile, toast the nuts, and pan-toast the breadcrumbs (with olive oil, salt, and italian seasoning) to desired darkness.",
      "Plate the mushrooms when finished, then top with goat cheese, basil, nuts, and bread crumbs. Drizzle with olive oil if desired."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Creamy Broccoli & Sun-Dried Tomato Orzotto",
    "kcal": 700,
    "protein": 22,
    "carbs": 74,
    "fat": 34,
    "time": 30,
    "ingredients": [
      "1 medium onion, finely chopped",
      "3 garlic cloves, pressed",
      "2 tsp olive oil",
      "1 1/2 cup uncooked orzo pasta",
      "3 3/4 cup vegetable broth",
      "3/4 cup dry white wine, such as Chardonnay",
      "1 8oz jar sun-dried tomatoes in oil, drained and patted dry",
      "1 head broccoli",
      "2 oz Parmesan cheese",
      "6 oz mascarpone cheese",
      "Fresh parsley, chopped (optional)"
    ],
    "steps": [
      "Heat oil in 12\" skillet over medium-high heat.",
      "Add onion and garlic; cook 30-45 seconds or until fragrant. Stir in orzo, vegetable broth and wine; cook, uncovered, 14-16 minutes or until almost all liquid is absorbed and orzo is tender.",
      "Remove skillet from heat. Add tomatoes and broccoli. Cover; let stand 5 minutes. Add cheeses; mix well. Add parsley for garnish, if desired."
    ],
    "phase": "follikel"
  },
  {
    "title": "Gnocchi",
    "kcal": 429,
    "protein": 18,
    "carbs": 73,
    "fat": 7,
    "time": 6300,
    "ingredients": [
      "5 large Idaho potatoes",
      "2 eggs",
      "3/4 cup grated Parmesan",
      "3 1/2 cup all-purpose flour",
      "1 tablespoon salt"
    ],
    "steps": [
      "Preheat the oven to 375 or 400 degrees F.",
      "Bake the potatoes until they are fork tender, about 45 minutes to 1 hour. Check them!",
      "While the potatoes are still hot peel and pass them through a food mill or ricer. (I find that the food mill works just as well as a ricer and is much easier to handle) onto a sheet tray lined with parchment paper. When doing this pay careful attention to keep the potatoes as light and fluffy as possible. This will aid in keeping the gnocchi light. Refrigerate the potatoes on the sheet tray until cold. This is also a very important step. If the potatoes are warm while adding flour they will require more flour which will result in a much heavier finished product.",
      "When the potatoes are absolutely cold, transfer to a clean work surface. Beat together the eggs and cheese and pour onto the potatoes. Season with salt. Cover generously with flour. It should look like snow on the mountains.",
      "Crumble the potato flour mixture between your fingers. Begin to knead the dough until it is a dry homogeneous mixture. The dough should feel slightly moist, but not tacky. If too tacky, repeat the snow on the mountains stage.",
      "Form the dough into a large log. Cut slices off the log and begin to roll into long ropes that are about 1-inch in thickness. Cut the ropes into 1/2-inch lengths. Cover generously with flour. Place the gnocchi in a single layer on a sheet tray dusted with flour. DO NOT PILE ON TOP OF EACH OTHER!!",
      "Use or freeze the gnocchi immediately. If freezing, place tray directly into the freezer. Once frozen, the gnocchi can be stored in plastic bags, in the freezer, indefinitely. When cooking gnocchi they can go directly from the freezer into salted boiling water.",
      "Note: It is a general practice to take gnocchi out of the water when they float. This is a big mistake. Gnocchi need to be cooked in boiling water until they float and get nice and puffy. Not cooking gnocchi long enough will also result in heavy gnocchi.",
      "P.S. These are Chef Anne \"Secrets\" to great gnocchi, use them and you will be successful every time.",
      "Read more at: http://www.foodnetwork.com/recipes/anne-burrell/gnocchi-with-prosciutto-spring-peas-and-chanterelles-recipe/index.html?oc=linkback"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Grilled Cheese & Tomato Skillet",
    "kcal": 538,
    "protein": 2,
    "carbs": 65,
    "fat": 22,
    "time": 30,
    "ingredients": [
      "8 slices bread, halved",
      "3 tbsp butter, melted",
      "4 cup grape tomatoes, divided",
      "3 cup vegetable broth",
      "1 medium onion, finely chopped",
      "1 1/2 tbsp olive oil",
      "3 garlic cloves, pressed",
      "16 oz uncooked medium shell pasta",
      "1/2 cup heavy whipping cream",
      "2 tsp salt",
      "1 tsp coarsely ground black pepper",
      "2 cup sharp cheddar, shredded and divided",
      "Fresh parsley, chopped (optional)"
    ],
    "steps": [
      "Brush bread slices with butter. Toast in skillet 3-5 minutes until golden brown, turning once.",
      "Meanwhile, cut 1/16th (1/4 cup from 4 cups) of the tomatoes into quarters; set aside for garnish. Finely dice remaining tomatoes.",
      "Add oil, onion, and garlic to skillet; cook over medium-high heat 2–3 minutes or until onion is translucent, stirring frequently. Carefully add diced tomatoes, broth, pasta, cream, salt and black pepper. Bring to a boil. Cover and cook 6–8 minutes or until pasta is still slightly firm, stirring occasionally.",
      "Remove skillet from heat; add half of the cheese and stir until cheese is completely melted. Top with remaining cheese. Cover and let stand 3–4 minutes or until cheese is melted. Arrange bread in an overlapping circular pattern around edge of skillet. Garnish with reserved tomatoes and parsley, if desired."
    ],
    "phase": "luteal"
  },
  {
    "title": "Mediterranean Patio Pizza",
    "kcal": 525,
    "protein": 0,
    "carbs": 0,
    "fat": 28,
    "time": 30,
    "ingredients": [
      "1 lb refrigerated pizza dough",
      "Olive oil",
      "1 garlic clove, pressed",
      "2 14oz can artichoke hearts in water, drained, divided",
      "4 ounce cream cheese, softened",
      "4 ounce feta cheese, crumbled, divided",
      "1/2 teaspoon dried oregano",
      "2 tablespoon pine nuts, toasted (optional)",
      "2 plum tomatoes, seeded and chopped",
      "1/3 cup black olives, pitted and sliced",
      "1/3 cup cucumber, sliced and quartered",
      "1/4 small red onion, sliced into thin wedges",
      "2 tsp olive oil",
      "1 tsp red wine vinegar",
      "1/4 tsp dijon mustard",
      "salt and pepper"
    ],
    "steps": [
      "Preheat oven to 375°F. Roll out dough.  Lightly spray dough with olive oil, then add garlic.  Bake 14-16 minutes or until golden brown; cool completely.",
      "For cheese spread, finely chop enough artichoke hearts to make 1/4 cup. Combine with cream cheese, half of the feta cheese and oregano in bowl; mix well. Spread mixture evenly over crust.",
      "For toppers, quarter remaining artichoke hearts. Arrange them and all other vegetables over cream cheese mixture. Sprinkle with remaining feta cheese and pine nuts.  Drizzle with salad dressing just before serving."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Baked Ziti with Crunchy Italian Salad and Garlic Bread",
    "kcal": 835,
    "protein": 51,
    "carbs": 82,
    "fat": 36,
    "time": 30,
    "ingredients": [
      "Coarse salt and ground pepper",
      "6 ounce ziti rigate (ridged) or other short pasta",
      "1 cup part-skim ricotta",
      "1 large egg, lightly beaten",
      "1/4 cup parmesan, finely grated",
      "1/2 cup mozzarella, shredded",
      "1 24oz can tomato sauce",
      "1/2 cup parmesan, finely grated",
      "1/2 cup mozzarella, shredded",
      "1/2 loaf Italian bread (5 ounces)",
      "2 tablespoon butter, melted",
      "2 garlic cloves, minced",
      "1 tablespoon sherry vinegar or red-wine vinegar",
      "1 tablespoon olive oil",
      "1 head Belgian endive, stem end trimmed, thinly sliced",
      "3 1/2 oz arugula, thick stems removed"
    ],
    "steps": [
      "Preheat oven to 450 degrees. Bring a large pot of salted water to a boil. Cook pasta until al dente, according to package instructions; drain and reserve.",
      "In a small bowl, combine ricotta, egg, a third of the Parmesan, and half the mozzarella; season with salt and pepper.",
      "In the bottom of a shallow 2-quart casserole dish, spread half the tomato sauce. Top with ziti, then ricotta mixture and remaining sauce. Sprinkle with remaining Parmesan and mozzarella. Place casserole on a rimmed baking sheet, and bake until top is browned and sauce is bubbling, 20 to 25 minutes.",
      "Meanwhile, prepare garlic bread: Make deep, even cuts into the bread, about 1/2 inch apart, without cutting through the bottom. In a small bowl, combine butter and garlic; season with salt and pepper. Brush garlic butter between cuts in bread. Wrap bread loosely in aluminum foil, and bake with ziti during last 10 minutes of baking.",
      "In a large bowl, whisk together vinegar and oil; season with salt and pepper. Add endive and arugula, and toss to coat. Serve baked ziti with salad and garlic bread."
    ],
    "phase": "follikel"
  },
  {
    "title": "All-day minestrone (slow cooker)",
    "kcal": 209,
    "protein": 6,
    "carbs": 26,
    "fat": 8,
    "time": 26400,
    "ingredients": [
      "1 tbsp olive oil",
      "1 medium yellow onion, minced",
      "1 stalk celery, chopped",
      "1 carrot, chopped",
      "2 clove garlic, minced",
      "4 oz green beans, ends trimmed and cut into 1-inch pieces",
      "1 can chickpeas, drained and rinsed",
      "1 14.5oz can diced tomatoes, left undrained",
      "1 medium zucchini",
      "6 cup vegetable stock",
      "Salt and black pepper",
      "1/2 cup dried ditalini",
      "1/4 cup pesto"
    ],
    "steps": [
      "Pour the oil in the bottom of a 4-6 quart slow cooker.  Add the onion, celery, carrot, and garlic,  cover, and cook on High while you assemble the remaining ingredients.",
      "After they've been prepped, add the green beans, chickpeas, tomatoes, zucchini, and stock to the slow cooker and season with salt and pepper.  Cover and cook on Low for 7 to 8 hours.",
      "If using raw ditalini, about an hour before you're ready to serve, add it to the slow cooker and cover.",
      "Just before serving, stir in the pesto and already-cooked pasta, if using."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Berry Granola Parfait",
    "kcal": 275,
    "protein": 23,
    "carbs": 34,
    "fat": 7,
    "time": 30,
    "ingredients": [
      "3/4 cup fresh berries",
      "7 oz Greek yogurt (2% Fage)",
      "2 tablespoon granola"
    ],
    "steps": [
      "Mix all ingredients."
    ],
    "phase": "luteal"
  },
  {
    "title": "Smoked salmon baked potatoes",
    "kcal": 438,
    "protein": 15,
    "carbs": 60,
    "fat": 16,
    "time": 4500,
    "ingredients": [
      "4 russet potatoes, scrubbed clean",
      "6 oz cream cheese, softened",
      "4 oz smoked salmon",
      "1 tbsp capers, rinsed and chopped",
      "1 tbsp red onion, minced"
    ],
    "steps": [
      "Preheat oven to 400F. Poke potatoes all over with a fork. Place on oven rack and bake for 1 hour. Meanwhile mix remaining ingredients together. Split potatoes open and fluff with fork. Spoon salmon mixture onto potatoes and serve."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Samosa baked potatoes",
    "kcal": 376,
    "protein": 11,
    "carbs": 73,
    "fat": 5,
    "time": 4500,
    "ingredients": [
      "4 russet potatoes, scrubbed clean",
      "olive oil",
      "1 yellow onion, chopped",
      "1 tbsp curry powder",
      "1 tbsp ginger, minced",
      "1 tsp mustard seeds",
      "salt",
      "pepper",
      "1 cup frozen peas",
      "4 tbsp yogurt",
      "1/4 cup cilantro, chopped"
    ],
    "steps": [
      "Preheat oven to 400F. Pierce potatoes all over with fork. Place directly on oven rack and bake for 1 hour. Meanwhile, cook onion, curry powder, ginger, mustard seeds, salt, and pepper in olive oil until lightly browned; one or two minutes before they're done, add the frozen peas to defrost and warm them.",
      "When potatoes are done, remove and let cool for a few minutes. Scoop out their flesh, mash with onion mixture, and stuff back into the skins. Top with yogurt and cilantro."
    ],
    "phase": "follikel"
  },
  {
    "title": "Apple-cheddar baked sweet potatoes",
    "kcal": 357,
    "protein": 15,
    "carbs": 34,
    "fat": 20,
    "time": 3900,
    "ingredients": [
      "4 sweet potatoes, scrubbed clean",
      "2 apples, peeled and diced",
      "2 tbsp butter",
      "1/2 cup cheddar, shredded",
      "4 slices bacon, optional, cooked and crumbled"
    ],
    "steps": [
      "Preheat oven to 400F. Pierce potatoes all over with fork and place directly on oven rack. Bake for 50 minutes. Meanwhile, cook apples in butter until tender. Spoon onto the baked sweet potatoes, top with cheddar and broil to melt. Top with crumbled bacon."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Paella pasta salad",
    "kcal": 140,
    "protein": 4,
    "carbs": 19,
    "fat": 4,
    "time": 1500,
    "ingredients": [
      "12 oz uncooked orzo pasta",
      "1/4 cup canola oil",
      "1/4 tsp saffron powder",
      "2 tbsp lemon juice",
      "2 tbsp light mayonnaise",
      "2 tsp salt",
      "2 garlic cloves, pressed",
      "4 green onions, with tops thinly sliced",
      "2 tbsp tarragon, thinly sliced",
      "1 1/2 cup grape tomatoes, halved",
      "1/2 cup green olives, pitted and quartered",
      "1 cup frozen green peas, thawed"
    ],
    "steps": [
      "1. Cook orzo according to package directions a the high end of the time range, omitting salt and oil. Drain, rinse under cold water; set aside.",
      "2. Meanwhile, for dressing, combine oil and saffron powder in small microwave safe bowl. Microwave on high 30-45 seconds or until hot. Place into refrigerator; cool completely. Combine lemon juice, mayo, salt and garlic in a small bowl. Whisk until smooth. Slowly add oil mixture, whisking constantly.",
      "3. Combine orzo, dressing, and remaining ingredients in a large mixing bowl. Mix well and serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Pinto bean and poblano tacos",
    "kcal": 590,
    "protein": 21,
    "carbs": 93,
    "fat": 15,
    "time": 2880,
    "ingredients": [
      "6 fresh poblano chili peppers, (about 1/4 pound each)",
      "1 teaspoon extra-virgin olive oil",
      "1 medium onion, halved and thinly sliced",
      "1 can pinto beans, drained and rinsed",
      "1/4 cup vegetable stock",
      "1 teaspoon salt",
      "1/4 cup fromage blanc, or plain nonfat yogurt",
      "8 small tortillas, warmed",
      "Lime wedges, for serving",
      "Cilantro, for garnish"
    ],
    "steps": [
      "1. Preheat broiler, with the rack 6 inches from the heat source. Place chiles on a baking sheet. Broil, flipping once, until charred, 10 to 15 minutes. Transfer to a heatproof bowl, and cover with plastic wrap. Let stand 15 minutes. Remove skins and seeds, and discard. Cut chiles into 1/2-inch-thick strips, and set aside.\n2. Heat oil in a large nonstick skillet over medium heat. Add onion. Cook, stirring often, until onion is translucent and pale golden, 10 to 12 minutes. Stir in beans, stock, and salt. Using a heatproof rubber spatula, fold in chiles; cook until chiles are warmed though, 3 to 5 minutes.\n3. Remove from heat; stir in fromage blanc. Spoon into the warm tortillas. Serve with lime, and garnish with cilantro."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Tofu Parmesan",
    "kcal": 491,
    "protein": 24,
    "carbs": 50,
    "fat": 22,
    "time": 2100,
    "ingredients": [
      "8 serving [marinara sauce](http://www.xanthir.com/recipes/showrecipe.php?id=id34)",
      "4 tbsp flour",
      "1 large egg",
      "1 cup breadcrumbs",
      "1/2 teaspoon dried Italian seasoning",
      "14 oz firm tofu, drained and sliced into thick planks",
      "2 1/2 tablespoon extra-virgin olive oil, plus more for drizzling",
      "1/4 cup part-skim mozzarella cheese, shredded",
      "1/3 cup parmesan cheese",
      "8 cup baby spinach",
      "4 slices Italian bread"
    ],
    "steps": [
      "Make marinara sauce, reducing it well.",
      "Season the tofu with salt. Sprinkle the flour on a plate; beat the egg on another; mix breadcrumbs and Italian seasoning on a third. Coat the tofu in flour, then egg, then breadcrumbs. Fry, spending ~2min on each side.",
      "Move the tofu to a broiler pan. Top with marinara, then cheese, and broil for 3-4 minutes, until cheese is bubbly and browning.",
      "Meanwhile, pan-toast the bread in butter, then sprinkle with garlic salt. Wilt the spinach in another pan, lightly seasoning it.",
      "When everything's finished, plate the spinach with the tofu on top, and serve with garlic bread."
    ],
    "phase": "follikel"
  },
  {
    "title": "Pasta with escarole",
    "kcal": 568,
    "protein": 21,
    "carbs": 71,
    "fat": 23,
    "time": 2100,
    "ingredients": [
      "Kosher salt",
      "12 ounce gemelli, fusilli or spaghetti",
      "1 head escarole, roughly chopped",
      "1 tablespoon pine nuts",
      "2 tablespoon extra-virgin olive oil, plus more for drizzling",
      "2 tablespoon breadcrumbs",
      "Freshly ground pepper",
      "1/4 pound pancetta, cut into thin strips",
      "2 clove garlic, thinly sliced",
      "1 red jalapeno pepper, thinly sliced (remove seeds for less heat)",
      "2 tablespoon parmesan cheese, grated"
    ],
    "steps": [
      "Bring a large pot of salted water to a boil. Add the pasta and cook until just al dente, about 10 minutes. Add the escarole and cook, stirring occasionally, until tender, about 2 more minutes.",
      "Meanwhile, toast the pine nuts in a large skillet over medium-high heat, about 1 minute. Add 1 tablespoon olive oil, the breadcrumbs, and salt and pepper to taste; cook until golden, about 2 minutes. Transfer the mixture to a plate. Wipe out the skillet, add the pancetta and cook until crisp, about 5 minutes. Transfer to paper towels and blot dry.",
      "Add the remaining 1 tablespoon olive oil to the skillet, then add the garlic and jalapeno and cook until fragrant, about 1 minute. Drain the pasta and escarole, reserving 1 cup cooking water, and add to the skillet. Add half of the pancetta and toss, drizzling in enough pasta water to moisten. Season with salt and pepper.",
      "Divide the pasta among bowls, top with the breadcrumb mixture, remaining pancetta and the parmesan. Drizzle with olive oil.",
      "Read more at: http://www.foodnetwork.com/recipes/food-network-kitchens/pasta-with-escarole-recipe.html?oc=linkback"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Squash and bean burritos",
    "kcal": 497,
    "protein": 24,
    "carbs": 70,
    "fat": 15,
    "time": 2400,
    "ingredients": [
      "1/2 cup brown rice",
      "2 clove garlic, 1 smashed, 1 minced",
      "Kosher salt and freshly ground pepper",
      "1/2 pound frozen diced butternut squash, thawed",
      "1 15oz can black beans",
      "1 cup grape tomatoes",
      "1/2 cup fresh cilantro",
      "1/4 cup pickled jalapeno peppers, plus 2 tablespoons pickling liquid",
      "4 tortillas, warmed",
      "1/2 cup cheddar cheese, shredded",
      "1 avocado, sliced",
      "Plain low-fat yogurt or sour cream, for serving (optional)"
    ],
    "steps": [
      "Heat a medium skillet over high heat. Add the rice and smashed garlic and cook, stirring, until fragrant, 2 to 3 minutes. Add 1 cup water, season with salt and pepper and bring to a boil. Add the squash and reduce the heat to low; cover and simmer, undisturbed, about 25 minutes; remove from the heat.",
      "Meanwhile, make the bean salsa: Drain and rinse the beans, quarter the tomatoes and chop the cilantro and jalapenos. Toss with the pickling liquid and minced garlic in a bowl. Season with salt and pepper.",
      "Stir the rice mixture and spoon it down the center of each tortilla, then top with half of the bean salsa and sprinkle with the cheese. Fold in the sides and roll up. Slice in half and serve with avocado, the remaining bean salsa and yogurt, if desired.",
      "Read more at: http://www.foodnetwork.com/recipes/food-network-kitchens/chicken-and-bean-burritos-recipe.html?oc=linkback"
    ],
    "phase": "luteal"
  },
  {
    "title": "Broiled halibut with ricotta-pea puree",
    "kcal": 429,
    "protein": 42,
    "carbs": 18,
    "fat": 20,
    "time": 1500,
    "ingredients": [
      "3 small carrots, quartered lengthwise",
      "1 medium red onion, thinly sliced",
      "1 tablespoon extra-virgin olive oil",
      "Kosher salt and freshly ground pepper",
      "4 6-ounce center-cut skinless halibut fillets (1 3/4 inches thick)",
      "2 tablespoon extra-virgin olive oil",
      "1/2 teaspoon smoked paprika",
      "10 ounce frozen peas",
      "1/4 cup water",
      "1/3 cup ricotta cheese",
      "1 tablespoon unsalted butter"
    ],
    "steps": [
      "Preheat the broiler. Line a broiler pan with foil and preheat 5 minutes.",
      "Meanwhile, brush the carrots and onion with olive oil and season with salt and pepper. Brush the fish with the remaining  olive oil, season with salt and pepper and sprinkle with the paprika; brush to coat the fish evenly with paprika.",
      "Carefully remove the pan from the oven, place the fish in the center and scatter the onion and carrots around. Broil until the fish is golden and just cooked through, 8 to 10 minutes.",
      "Meanwhile, microwave the peas in a bowl with water until just tender, about 4 minutes. Transfer the peas and liquid to a food processor and pulse with the ricotta, butter and a pinch of salt to make a slightly chunky puree. Divide the puree among plates and top with the fish, carrots, onion and pan juices.",
      "Read more at: http://www.foodnetwork.com/recipes/food-network-kitchens/broiled-halibut-with-ricotta-pea-puree-recipe.html?oc=linkback"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Veggie Carribean Panini",
    "kcal": 682,
    "protein": 18,
    "carbs": 105,
    "fat": 24,
    "time": 1680,
    "ingredients": [
      "2 tbsp butter",
      "2 soft rolls, split",
      "1 tbsp yellow mustard",
      "Hot sauce",
      "2 oz queso blanco, sliced",
      "1 plantain, sliced and fried or sauteed",
      "4 slices of red onion, charred",
      "1/2 avocado, sliced",
      "1/2 medium tomato, sliced"
    ],
    "steps": [
      "Preheat a skillet with butter to medium low heat.",
      "Char the onion slices in a broiler for ~5m. (And maybe do the plantain with it? Experiment here.)",
      "Assemble the sandwich: spread the inside of the split roll with mustard and drizzle with hot sauce to taste. Fill with sliced queso blanco, plantains, red onion, avocado, tomato and more queso blanco.",
      "Add the sandwich to the hot skillet and press with a heavy pan. Cook until golden, 3 to 4 minutes per side."
    ],
    "phase": "follikel"
  },
  {
    "title": "Baja fish tacos",
    "kcal": 777,
    "protein": 31,
    "carbs": 66,
    "fat": 45,
    "time": 1200,
    "ingredients": [
      "Vegetable oil, for frying",
      "1/4 red cabbage, thinly sliced (about 1 1/2 cups)",
      "1/2 cup fresh cilantro, roughly chopped",
      "1 lime, juiced, plus wedges for serving",
      "2 tablespoon honey or agave nectar",
      "1/2 cup mayonnaise",
      "Kosher salt",
      "12 corn tortillas",
      "3/4 cup all-purpose flour",
      "1/2 teaspoon chili powder",
      "Freshly ground pepper",
      "1 1/4 pound skinless halibut fillet, cut into 2-by-1/2-inch pieces",
      "1 avocado",
      "1/2 cup fresh salsa"
    ],
    "steps": [
      "Heat about 3 inches vegetable oil in a medium pot over medium-low heat until a deep-fry thermometer registers 375 degrees F. Meanwhile, toss the cabbage, cilantro, lime juice, honey and mayonnaise in a bowl. Season the slaw with salt.",
      "Warm the tortillas in a skillet over medium-low heat or wrap in a damp cloth and microwave 25 seconds. Wrap in a towel to keep warm.",
      "Mix the flour, chili powder, and salt and pepper to taste in a shallow bowl. Dredge the fish in the flour mixture, then fry in batches until golden and just cooked through, 2 to 3 minutes. Transfer with a slotted spoon to a paper-towel-lined plate to drain. Season with salt.",
      "Halve, pit and slice the avocado. Fill the tortillas with the fish, avocado, slaw and salsa. Serve with lime wedges.",
      "Read more at: http://www.foodnetwork.com/recipes/food-network-kitchens/baja-fish-tacos-recipe.html?oc=linkback"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Open face egg and tomato sandwich",
    "kcal": 218,
    "protein": 12,
    "carbs": 15,
    "fat": 13,
    "time": 600,
    "ingredients": [
      "1 whole-wheat English muffin, split in half",
      "2 thick slices tomato",
      "1 teaspoon vegetable oil, such as safflower",
      "2 eggs",
      "2 thin slices cheddar, (1 ounce total)",
      "Coarse salt and ground pepper"
    ],
    "steps": [
      "Toast each muffin half. Top with tomato, sprinkle with salt, and broil for 3 minutes.",
      "In a small nonstick skillet, heat oil over medium-low. Gently crack eggs into skillet, and add salt, pepper, and cheese. Cover, and cook until whites are set, about 2 minutes.",
      "Slide one egg onto each muffin."
    ],
    "phase": "luteal"
  },
  {
    "title": "Black bean and brown rice cakes",
    "kcal": 313,
    "protein": 19,
    "carbs": 49,
    "fat": 5,
    "time": 4500,
    "ingredients": [
      "2 can black beans, rinsed and drained",
      "2 green onions, coarsely chopped",
      "1 jalapeno, seeded and chopped",
      "1/4 teaspoon ground cumin",
      "3/4 cup cooked brown rice",
      "Coarse salt and ground pepper",
      "1 tablespoon extra-virgin olive oil",
      "1/2 cup plain low-fat yogurt",
      "1 tablespoon fresh cilantro, finely chopped , plus leaves for serving",
      "1 tablespoon fresh lime juice"
    ],
    "steps": [
      "1. Preheat oven to 450 degrees. In a food processor, pulse half the beans with scallions, jalapeno, and cumin until a chunky paste forms. In a large bowl, combine bean puree with rice and remaining beans; season with salt and pepper. Divide mixture into eight 3-inch-wide patties. (To freeze, wrap individually in plastic and freeze up to 2 weeks; thaw before cooking.)",
      "2. Brush a rimmed baking sheet with oil; place in oven to heat, 5 minutes. Carefully place patties on hot sheet; bake until bottoms are golden brown, 10 to 12 minutes, rotating sheet halfway through. Let rest on sheet 5 minutes before removing.",
      "3. Meanwhile, in a small bowl, combine yogurt, cilantro, and lime juice; season with salt and pepper. Serve patties topped with yogurt sauce and cilantro leaves."
    ],
    "phase": "menstruation"
  },
  {
    "title": "English muffin with apple and cheddar",
    "kcal": 339,
    "protein": 16,
    "carbs": 38,
    "fat": 15,
    "time": 600,
    "ingredients": [
      "1 English muffin, split",
      "1 tsp grainy mustard",
      "1/2 apple, thinly sliced",
      "3/8 cup cheddar cheese, grated"
    ],
    "steps": [
      "Place English muffin cut side up in a toaster oven or on a baking sheet under the broiler, and toast until lightly browned.",
      "Spread the mustard on each muffin half, then half the cheese, the apple, and finally the other half of the cheese. Broil until cheese is melted."
    ],
    "phase": "follikel"
  },
  {
    "title": "Couscous stuffed bellpeppers with basil sauce",
    "kcal": 649,
    "protein": 15,
    "carbs": 26,
    "fat": 42,
    "time": 4500,
    "ingredients": [
      "1 cup low-sodium chicken broth",
      "2 teaspoon ground cumin",
      "3/4 cup couscous",
      "1 cup chickpeas, rinsed and drained",
      "1/4 cup dried currants",
      "1 packed cup baby spinach leaves, chopped",
      "4 oz feta cheese, crumbled",
      "1/4 cup extra-virgin olive oil, plus more for drizzling",
      "Kosher salt and freshly ground black pepper",
      "4 medium red bell peppers or poblano peppers, see alternate cooking instructions",
      "Hot water, as needed",
      "1 packed cup fresh basil leaves",
      "1/2 cup creme fraiche",
      "3 tablespoon extra-virgin olive oil",
      "1 tablespoon water",
      "1 garlic clove, coarsely chopped",
      "2 teaspoon fresh lemon juice",
      "1/4 teaspoon sugar",
      "1/4 teaspoon salt, plus extra, as needed",
      "1/4 teaspoon freshly ground black pepper, plus extra, as needed"
    ],
    "steps": [
      "Put an oven rack in the center of the oven. Preheat the oven to 400 degrees F.",
      "Filling: In a small pot, bring the chicken broth and cumin to a boil over medium-high heat. Remove the pan from the heat and stir in the couscous. Cover the pan until the couscous is tender and all of the liquid has been absorbed, about 5 to 6 minutes. Put the couscous in a large bowl and add the beans, currants, spinach, feta and 1/4 cup olive oil. Season with salt and pepper, to taste. Stir until all the ingredients are combined.",
      "Slice the tops off the peppers and remove all the ribs and seeds. If necessary, cut a very thin slice from the base to help the peppers stand up. Stuff the peppers with the filling and drizzle the tops with olive oil. Put the peppers in an 8 by 8-inch square baking dish. Fill the baking dish with 3/4-inch hot water and bake until the filling is golden and the peppers are cooked through, about 55 to 60 minutes.",
      "Sauce: In a blender, combine the basil, creme fraiche, olive oil, water, garlic, lemon juice, sugar, salt, and pepper. Blend until smooth. Adjust the seasoning with salt and pepper, to taste.",
      "Remove the peppers from the oven and arrange on serving plates. Spoon the sauce around the peppers and serve.",
      "----",
      "If using slow-cooker, skip the chicken broth and add the dry couscous and cumin directly to the bowl with the rest of the filling.  Cook in the slow cooker for 4 hours on High.",
      "----",
      "If using poblanos, instead preheat the oven to 475. Halve and clean the poblanos, cover in oil, salt, and pepper, and roast the halves for 11-13 minutes, until slightly softened. Remove from oven, but leave oven on.",
      "When filling is ready, pack into the poblano halves. Return to the oven for 5 minutes, until the peppers are softened. Remove from oven and let sit for two minutes, then drizzle with sauce and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Salad with egg, nuts, and veggies",
    "kcal": 397,
    "protein": 11,
    "carbs": 17,
    "fat": 33,
    "time": 1500,
    "ingredients": [
      "1 large egg",
      "2 ounce green beans, trimmed",
      "1/4 avocado",
      "1 ounce baby spinach",
      "1 small endive",
      "1/4 cup grape tomatoes",
      "2 tablespoon pecans",
      "Coarse salt and ground pepper",
      "2 tablespoon fresh lemon juice",
      "1 tablespoon olive oil",
      "1 teaspoon grainy mustard"
    ],
    "steps": [
      "Hard cook egg: Place egg in a saucepan; cover with cold water. Bring just to a boil; cover and remove from heat. Let stand 12 minutes, then run under cold water to stop cooking. Peel egg and quarter.",
      "In the same saucepan, bring 2 inches salted water to a boil. Add green beans and cook until crisp-tender, 3 to 5 minutes. Immediately run under cold water to stop cooking.",
      "In a small bowl, whisk together lemon juice, oil, and mustard; season with salt and pepper. Store this dressing in a small airtight container.",
      "Just before serving, dice avocado and add it to your premade salad, along with egg. Toss with dressing."
    ],
    "phase": "luteal"
  },
  {
    "title": "Pesto millet grits with tomato ragout",
    "kcal": 534,
    "protein": 30,
    "carbs": 81,
    "fat": 13,
    "time": 3000,
    "ingredients": [
      "2 clove garlic",
      "2 cup fresh basil, lightly packed",
      "2 tbsp olive oil",
      "1/2 tsp black pepper",
      "1/2 tsp salt",
      "3 cup milk",
      "1 cup uncooked millet grits",
      "1 tbsp olive oil",
      "8 oz white button mushrooms, sliced",
      "1 large shallot, finely chopped",
      "2 clove garlic, pressed",
      "2 10oz containers grape tomatoes",
      "1 15oz can cannellini beans, drained and rinsed",
      "1 tbsp capers, drained",
      "1 tbsp balsamic vinegar",
      "1/2 tsp crushed red pepper flakes",
      "2 oz mozzarella, grated or shredded",
      "3 tbsp fresh basil leaves, thinly sliced"
    ],
    "steps": [
      "Adapted recipe to use grits. May not be entirely correct on cooking times!",
      "1. Preheat oven to 350F. For pesto, press garlic into bowl of food processor. Add basil, black pepper, and salt. Process until basil is coarsely chopped. Slowly add oil and process until incorporated. Set aside.",
      "2. For grits, follow package instructions substituting milk for water. Mix in pesto when done cooking. Remove from heat and set aside.",
      "3. Meanwhile for ragout, heat oil over medium heat in 11 or 12 inch skillet. Add mushrooms and shallots. Cook and stir for 3 minutes or until mushrooms start to brown. Add garlic and cook an additional 1 minute or until fragrant. Move mushroom mixture to side of skillet. Add tomatoes; cook, covered, 4-5 minutes or until tomato skins start to split. Carefully break up tomatoes and mix with mushrooms. Reduce heat to medium-low add remaining ragout ingredients, except cheese and basil. Cook 4-5 minutes or until heated through.",
      "4. Serve grits in bowl, top with ragout and sprinkle with cheese and basil."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Coconut shrimp with tropical rice",
    "kcal": 357,
    "protein": 29,
    "carbs": 39,
    "fat": 9,
    "time": 1800,
    "ingredients": [
      "1 cup water",
      "3/4 cup coconut water",
      "3/4 cup basmati or other long-grain rice",
      "1 lime, zested and juiced separately",
      "1/2 cup carrots",
      "2 tablespoon red onion, finely chopped",
      "1/4 teaspoon kosher salt",
      "freshly ground pepper",
      "1 pound large shrimp, peeled and deveined",
      "1 large egg",
      "1 cup sweetened shredded coconut",
      "3/4 cup panko breadcrumbs",
      "2 tablespoon cilantro, chopped"
    ],
    "steps": [
      "Preheat the oven to 425°. Line a rimmed baking sheet with foil and set a wire rack on top; coat with cooking spray.",
      "Combine 1 cup water, the coconut water, and rice in a medium saucepan and bring to a boil. Reduce the heat to medium low; cover and simmer 8 minutes. Remove from the heat; add the carrots, red onion, lime zest, half the lime juice, salt, and pepper (do not stir). Cover and let sit 10 minutes, then fluff with a fork to combine.",
      "Meanwhile, season the shrimp with salt and pepper. Beat the egg and 2 tablespoons water in a bowl. Combine the coconut and panko in another bowl. Dip the shrimp in the egg mixture, then the coconut panko mixture, gently pressing to adhere; transfer to the prepared rack. Bake until the shrimp are cooked through, about 10 minutes, then turn on the broiler and broil the shrimp until golden brown, 1 to 2 minutes.",
      "Add the cilantro to the rice mixture and toss, then top with shrimp and remaining lime juice."
    ],
    "phase": "follikel"
  },
  {
    "title": "Shakshuka with chickpeas",
    "kcal": 452,
    "protein": 24,
    "carbs": 46,
    "fat": 19,
    "time": 2400,
    "ingredients": [
      "2 tablespoon extra-virgin olive oil",
      "1 onion, chopped",
      "3 clove garlic, thinly sliced",
      "1 can chickpeas, drained and rinsed",
      "2 teaspoon cumin",
      "Kosher salt and freshly ground pepper",
      "2 14.5oz cans petite diced tomatoes with green chiles",
      "1/3 cup water",
      "8 eggs",
      "2 tablespoon cilantro, chopped",
      "2 pieces pita bread",
      "1 tbsp za'atar seasoning",
      "1/2 cup plain nonfat Greek yogurt",
      "1/2 cup hummus"
    ],
    "steps": [
      "Heat the olive oil in a large skillet over medium heat. Add the onion and garlic and cook, stirring, until softened, about 5 minutes. Add the chickpeas, cumin and a pinch each of salt and pepper; stir well to coat. Add the tomatoes and water. Bring to a simmer and cook, stirring occasionally, until the sauce thickens, about 20 minutes.",
      "Make wells in the sauce, one per egg, and crack an egg into each. Sprinkle the eggs with herbs, and lightly season. Cover and cook until whites are just set but yolks are still runny, about 5 minutes. (The eggs will continue cooking after you remove them from the oven.)",
      "Meanwhile, divide the pitas into eighths and open up the halves. Spray with a thin layer of olive oil, then season with salt and za'atar. Toast at 375F for 6-8 minutes, until crispy.",
      "Combine the yogurt, hummus and a pinch of salt in a small bowl.",
      "Serve the shakshuka in bowls, ideally not breaking the yolks. Top with hummus sauce, and add chips on the side."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mediterranean Grain Salad",
    "kcal": 308,
    "protein": 10,
    "carbs": 33,
    "fat": 16,
    "time": 2100,
    "ingredients": [
      "1/4 cup farro",
      "Coarse salt and ground pepper",
      "1 cup grape tomatoes, halved",
      "1/2 cup fresh parsley, chopped",
      "1/2 small shallot, minced",
      "1 tablespoon red-wine vinegar",
      "2 teaspoon olive oil",
      "1 ounce fresh goat cheese, crumbled"
    ],
    "steps": [
      "Bring small pot of lightly salted water to a boil, rinse farro and add to boiling water, and cook for 30 minutes or until tender but chewy. Or cook according to package direction.",
      "Drain farro and place in a small mixing bowl. Add tomatoes, parsley, shallot, vinegar, and oil. Season with salt and pepper, and toss. Top with cheese."
    ],
    "phase": "luteal"
  },
  {
    "title": "Vegetable and tofu pad thai",
    "kcal": 443,
    "protein": 18,
    "carbs": 59,
    "fat": 16,
    "time": 1800,
    "ingredients": [
      "8 ounce dried wide flat rice noodles",
      "1/4 cup fresh lime juice",
      "3 tablespoon soy sauce",
      "1 tablespoon Sriracha",
      "1 tablespoon packed dark-brown sugar",
      "2 tablespoon vegetable oil",
      "2 eggs, lightly beaten",
      "14 oz firm tofu, drained, thinly sliced, and patted dry",
      "1 tbsp rice flour",
      "2 carrots, peeled and shredded",
      "2 clove garlic, minced",
      "8 green onions, white and green parts separated and thinly sliced",
      "Coarse salt",
      "2 tablespoon roasted salted peanuts, chopped",
      "1/4 cup cilantro"
    ],
    "steps": [
      "Cook noodles according to package instructions; drain. (Ideally, do this while the egg/tofu is cooking, so the noodles don't sit for long and stick together; if needed, you can always delay starting the veggies if noodles are taking a while to get ready.)",
      "In a small bowl, whisk together lime juice, soy sauce, chili sauce, and brown sugar.",
      "In a large nonstick skillet, heat 1/2 teaspoon oil over medium-high, tilting to coat pan. Add eggs, swirl to coat bottom, and cook until just set, about 1 minute. Transfer eggs to a cutting board, loosely roll up, and cut crosswise into thin strips.",
      "Toss tofu in rice flour. Add 4 teaspoons oil to skillet and heat. Add tofu in a single layer and cook until golden brown on both sides, 7 minutes, flipping halfway through. Transfer to cutting board with egg for temporary storage; lightly salt.",
      "Add 1 1/2 teaspoons oil, carrots, garlic, and scallion whites to skillet and cook until softened, 5 minutes. Add lime-juice mixture and bring to a simmer. Add noodles and cook, stirring frequently, 1 minute. Add eggs and tofu and gently toss to combine. Season to taste with salt. Divide among four plates and top with peanuts, cilantro, and scallion greens. Serve with lime wedges."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Wasabi Salmon with Miso-Sesame Sauce",
    "kcal": 258,
    "protein": 28,
    "carbs": 9,
    "fat": 10,
    "time": 5280,
    "ingredients": [
      "1 1/2 tablespoon red miso paste",
      "1/4 cup soy milk",
      "1 1/2 teaspoon sesame seeds, toasted",
      "1 1/2 tablespoon ginger, minced",
      "1 teaspoon cayenne pepper",
      "1/4 cup sake",
      "2 tablespoon tamari",
      "2 tablespoon wasabi paste or powder",
      "4 4-ounce salmon fillets"
    ],
    "steps": [
      "In a small bowl, combine miso paste, soy milk, and sesame seeds. Stir until the miso is completely dissolved. Set aside.",
      "Combine ginger, cayenne pepper, sake, tamari, and wasabi in a zippered plastic bag; blend well.Add salmon; seal and toss to coat. Marinate for 1 hour.",
      "Preheat oven to 400 degrees. Place salmon on a greased baking sheet, discarding marinade. Bake until fish flakes easily with a fork, about 13 minutes.",
      "Remove salmon. Transfer to a warm serving plate. Drizzle miso sauce over fillets. Serve warm."
    ],
    "phase": "follikel"
  },
  {
    "title": "Egg sauce",
    "kcal": 204,
    "protein": 9,
    "carbs": 21,
    "fat": 9,
    "time": 420,
    "ingredients": [
      "1 tbsp butter",
      "1 tbsp flour",
      "3/4 cup milk",
      "2 eggs, hard-boiled and diced",
      "1/4 tsp salt",
      "1/8 tsp black pepper",
      "2 slices toast"
    ],
    "steps": [
      "1. Melt the butter in a small saucepan. Mix in the flour, salt and pepper. Cook over low heat. Stir until mixture is smooth. Remove from heat and stir in milk.",
      "2. Heat to boiling. Then, stir the mixture constantly for one minute. Add the diced egg to the mixture. Serve with toast, english muffin, or boiled potatoes."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Black-eyed pea burgers with summer squash slaw",
    "kcal": 470,
    "protein": 16,
    "carbs": 63,
    "fat": 18,
    "time": 1500,
    "ingredients": [
      "1 15oz can black-eyed peas, drained and rinsed",
      "1 cup quick-cooking oats",
      "2/3 cup fresh parsley, loosely packed",
      "1/2 cup jarred roasted red peppers, drained, DO NOT pat dry",
      "2 large shallots, cut into chunks",
      "1 egg",
      "1 tsp adobo sauce, from a can of chipotle peppers in adobo sauce",
      "salt and pepper, to taste",
      "2 tbsp olive oil",
      "4 tbsp low-fat Greek yogurt",
      "2 tsp adobo sauce",
      "1 small zucchini, julienned",
      "1 yellow squash, julienned",
      "3 green onions, thinly sliced",
      "4 leaves green leaf lettuce",
      "4 hamburger buns"
    ],
    "steps": [
      "1. For burgers, place black-eyed peas in a food processor; pulse until coarsely chopped. Remove some of the peas. Add oats, parsley, roasted red peppers, shallots, egg, adobo sauce, and salt and pepper to the processor bowl. Pulse until finely chopped. Add removed peas back and hand-mix. Place in the refrigerator to rest for 10 minutes.",
      "2. Meanwhile, mix all slaw ingredients in a bowl.",
      "3. Form black-eyed pea mixture into 1/2-inch thick patties (1 patty per serving). Heat oil in a 12-inch skillet over medium heat 1-3 minutes or until shimmering. Cook patties 3-5 minutes per side or until deep golden brown.",
      "4. To assemble, place lettuce onto bun bottom; top with burger, slaw and bun top. Serve excess slaw, if any, on the side.",
      "-------",
      "If not using jarred roasted red pepper, you can manually roast red pepper: slice into flattish chunks, rub with oil, and broil 4 minutes per side."
    ],
    "phase": "luteal"
  },
  {
    "title": "Korean scallion pancakes with vegetable salad",
    "kcal": 480,
    "protein": 16,
    "carbs": 71,
    "fat": 17,
    "time": 2100,
    "ingredients": [
      "1/3 cup teriyaki sauce with honey",
      "1 1/2 tbsp rice vinegar",
      "2 medium carrots, peeled and julienned",
      "1 medium seedless cucumber, julienned, avoiding core",
      "1 cup fresh bean sprouts",
      "1/3 cup dry-roasted salted peanuts, coarsely chopped",
      "2 cup all-purpose flour",
      "4 green onions, with tops, thinly sliced",
      "2 clove garlic, pressed",
      "1/2 tsp salt",
      "1/8 tsp salt",
      "1/2 tsp black pepper",
      "1/2 tsp sugar",
      "1 3/4 cup cold water",
      "2 eggs, lightly beaten",
      "1 tsp toasted sesame oil",
      "4 tsp canola oil, divided"
    ],
    "steps": [
      "1. For salad, combine sauce and vinegar in medium mixing bowl; whisk until well blended. Cut vegetable Julienned strips into 2 inch pieces. Add carrots, cucumber and sprouts to mixing bowl; toss to coat. Set aside.",
      "2. For pancakes, combine flour, green onions, garlic, salt, pepper, and sugar in a large mixing bowl; mix well. Add water, eggs, and sesame oil; mix until ingredients are incorporated (do not overmix). Add 1/2 tsp of the canola oil to an 8-inch non-stick saute pan (do not use stainless cookware); heat over medium heat 1-3 minutes or until shimmering. Pour 1/3 cup batter into pan, immediately tilting and swirling pan to cover bottom. Turn when pancake starts to bubble and edges are golden brown. Cook an additional 45-60 seconds or until bottom of pancake is golden brown; remove from heat.",
      "3. Repeat with remaining batter, adding an additional 1/2 tsp of the canola oil after each pancake. Top pancakes with salad and drizzle with remaining sauce from mixing bowl. Sprinkle with peanuts."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Sweet, Spicy & Salty Candied Pecans",
    "kcal": 217,
    "protein": 3,
    "carbs": 11,
    "fat": 20,
    "time": 900,
    "ingredients": [
      "1/2 cup Confectioners sugar",
      "3/4 teaspoon kosher salt",
      "1/2 teaspoon cayenne pepper",
      "2 cup pecans",
      "4 teaspoon water"
    ],
    "steps": [
      "Preheat the oven to 350°F. Line a baking sheet with parchment paper.",
      "In a medium bowl, whisk together the Confectioners sugar, kosher salt and cayenne pepper.",
      "Add the pecans to the sugar mixture, along with 4 teaspoons of water. Stir until the sugar is dissolved into a sticky glaze. (If the mixture is still too powdery after stirring for a while, it's okay to add a few drops of water -- just don't add too much!)",
      "Transfer the pecans to the prepared baking sheet and arrange in a single layer. Do your best to make sure they are evenly spread out and the nuts are not touching each other. Scrape out every last bit of glaze from the bowl and drizzle over the nuts. Bake for 10-12 minutes, until the pecans are crusty on top and caramelized and golden on the bottom. Immediately slide the parchment off of the hot baking sheet and allow the pecans to cool completely on the countertop. Once cool, remove the pecans from the parchment, breaking apart any clusters if necessary, and store in an airtight container.",
      "Note: Make sure you're using parchment paper and not wax paper. Wax paper is not nonstick."
    ],
    "phase": "follikel"
  },
  {
    "title": "Panko-crusted tofu with black bean salad",
    "kcal": 340,
    "protein": 16,
    "carbs": 30,
    "fat": 20,
    "time": 1800,
    "ingredients": [
      "1/2 small red onion, diced",
      "1 cup fresh cilantro, loosely packed, coarsely chopped",
      "1 cup grape tomatoes, quartered lengthwise",
      "2 tbsp lime juice",
      "1 15oz can unsalted black beans, drained and rinsed",
      "1 avocado, diced",
      "1 tbsp Chipotle Rub",
      "1/4 tsp salt",
      "14 oz extra-firm tofu, drained and patted dry",
      "1/4 tsp salt",
      "1 1/2 cup panko",
      "1 tbsp Chipotle Rub",
      "1/3 cup all-purpose flour",
      "1 egg, lightly beaten",
      "2 tbsp canola oil, divided",
      "Lime wedges, optional, for serving"
    ],
    "steps": [
      "1. For salad, combine onion, cilantro, tomatoes, lime juice, beans, rub, and salt in a large mixing bowl. Mix gently. Add avocado and gently stir into salad and set aside.",
      "2. Slice tofu crosswise into eight slices (two slices per serving). Sprinkle with salt; set aside. Combine panko and rub in the bowl of a food processor. Pulse briefly to combine. Place flour in a shallow dish. Place egg in a second shallow dish. Place panko mixture in third shallow dish. Lightly dredge each tofu slice in flour, shaking off excess; dip into egg and then into panko, coating evenly.",
      "3. Heat 1/2 of the oil in a 10-inch skillet over medium-high heat 1-3 minutes or until shimmering. Place half of the tofu slices into skillet. Cook 2 minute or until golden brown. Turn tofu over and cook 2 minute or until golden brown. Remove tofu from skillet; repeat with remaining oil and tofu slices. Serve tofu with salad. Garnish with lime wedges and additional cilantro, if desired.",
      "Note: the Chipotle Rub this recipe calls for is a Pampered Chef product"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Farro Fagioli Minestrone",
    "kcal": 380,
    "protein": 14,
    "carbs": 48,
    "fat": 15,
    "time": 2700,
    "ingredients": [
      "2 medium carrots, peel and finely diced",
      "2 medium stalks celery, finely diced",
      "1 large onion, finely chopped",
      "1 tbsp rosemary oil",
      "4 garlic cloves, pressed",
      "2 tbsp fresh thyme, finely chopped",
      "4 cup kale, stalk removed and coarsely chopped",
      "3 cup vegetable stock",
      "3 cup water",
      "2 14.5oz cans diced tomatoes, undrained",
      "1 cup uncooked farro",
      "1 14.5oz can kidney beans, drained and rinsed",
      "1 tsp sugar",
      "1 tsp salt",
      "1/2 tsp black pepper, coarsely ground",
      "2 oz Parmesan cheese, grated",
      "4 tbsp rosemary oil"
    ],
    "steps": [
      "1. Heat oil in 12-qt stockpot over medium-high heat 1-3 minutes or until shimmering. Add carrots, celery, onion, pressed garlic and thyme to stockpot; cook and stir 1-2 minutes or until onion is translucent.",
      "2. Add kale, stock, water, tomatoes and farro to stockpot; cook, uncovered, 5-6 minutes or until simmering. Reduce heat to medium-low. Cook, covered, 20-25 minutes or until farro is tender. Stir in beans, sugar, salt, and black pepper.",
      "3. To serve, ladle soup into serving bowls. Top with Parmesan cheese; drizzle with remaining oil."
    ],
    "phase": "luteal"
  },
  {
    "title": "Spanish frittata with mixed greens salad",
    "kcal": 390,
    "protein": 18,
    "carbs": 33,
    "fat": 22,
    "time": 2100,
    "ingredients": [
      "1 tsp olive oil",
      "3 medium red potatoes, thinly sliced",
      "6 eggs",
      "3/4 tsp salt",
      "1 medium onion, coarsely chopped",
      "3 clove garlic, pressed",
      "1 6.5oz jar artichoke hearts (quartered and marinated), patted dry and coarsely chopped",
      "1/2 cup sun-dried tomatoes (in oil), drained, patted dry and thinly sliced",
      "3 oz manchego cheese, shredded",
      "1/2 tsp black pepper, coarsely ground",
      "2 tbsp fresh parsley, chopped",
      "2 tbsp sherry vinegar",
      "2 tbsp honey",
      "1 tbsp olive oil",
      "1 tsp Dijon mustard",
      "6 cup mixed salad greens"
    ],
    "steps": [
      "1. Preheat oven to 375F. Heat oil in a oven-safe non-stick 10-inch skillet (do not use stainless cookware) over medium high heat 1-3 minutes or until shimmering. Arrange potatoes evenly over bottom of skillet, overlapping as necessary. Cook potatoes undisturbed 4-5 minutes or until golden brown. Turn potatoes over; cook an additional 3-4 minutes or until light golden brown.",
      "2. meanwhile, combine eggs and salt in a mixing bowl; whisk until frothy. Add onion and garlic to potatoes in skillet; cook and stir 1 minute. Reduce heat to medium. Top potato mixure evenly with artichokes, sun-dried tomatoes and cheese. Slowly pour egg mixture over vegetables. Cook, uncovered, 1-2 minutes or until sides and bottom are light golden brown.",
      "3. Bake, uncovered, 8-10 minutes or until center is set but still moist and internal temperature reaches 155F. Carefully remove skillet from oven. Cover and let stand 5 minutes (temperature will rise to 168F).",
      "4. Meanwhile, for salad, combine vinegar, honey, oil and mustard in large mixing bowl; whisk until blended. Add mixed greens; toss gently to coat. Cut frittata into six slices (1 per serving) using a non-metal utensil. Serve frittata with salad; sprinkle with black pepper and parsley, if desired.",
      "Note: white cheddar cheese can be substituted for the manchego, if desired"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Roasted root vegetables with creamy grits",
    "kcal": 380,
    "protein": 14,
    "carbs": 49,
    "fat": 15,
    "time": 3300,
    "ingredients": [
      "1/2 tbsp olive oil",
      "1 large turnip, peeled and cut into 1/2 inch pieces",
      "3 small red onions, cut into wedges",
      "2 medium parsnips, peeled and sliced on the bias into 1/4 inch slices",
      "3 medium carrots, peel and sliced on the bias into 1/4 inch slices",
      "2 1/2 tbsp olive oil",
      "2 tbsp fresh thyme",
      "3 clove garlic, pressed",
      "2 tsp sugar",
      "3/4 tsp salt",
      "1/2 tsp black pepper, coarsely ground",
      "4 1/2 cup milk",
      "1 sprig fresh rosemary",
      "1 cup millet grits",
      "1 oz Parmesan cheese, grated",
      "2 oz sharp white cheddar cheese, shredded",
      "1/2 tsp salt",
      "1/4 tsp black pepper, coarsely ground"
    ],
    "steps": [
      "1. Preheat oven to 450F. Brush a large sheet pan with 1/2 tbsp oil (for full recipe); set aside.",
      "2. Combine turnip, onions, parsnips, carrots, remaining oil, thyme, garlic, sugar, salt, and black pepper in large mixing bowl; mix well. Spread vegetable mixure evenly over prepared sheet pan; roast 35-40 minutes or until edges of vegetables are golden brown. Remove sheet pan from oven; keep vegetables warm.",
      "3. For grits, combine milk and rosemary sprig in 3-qt saucepan; heat over medium heat until milk comes to a simmer. Remove saucepan from heat; cover and let stand 5 minutes. Using tongs, remove and discard rosemary sprig from milk. Return saucepan to stovetop. Cook grits according to package directions using milk. Remove from heat. Stir incheeses, salt, and black pepper; mix well. To serve, divide grits among serving plates; top with roasted vegetables."
    ],
    "phase": "follikel"
  },
  {
    "title": "Farmer's market vegetable pot pie",
    "kcal": 480,
    "protein": 15,
    "carbs": 58,
    "fat": 22,
    "time": 3000,
    "ingredients": [
      "1 pie crust",
      "1 tsp olive oil",
      "1/2 lb Yukon gold potatoes, unpeeled, diced into 1/4 inch pieces",
      "1/2 medium onion, finely chopped",
      "1/2 cup cauliflower, cut into small florets",
      "2 oz fresh green beans, trimmed and cut into 1 inch pieces",
      "1 1/2 medium carrots, peeled, diced into 1/4 inch pieces",
      "4 oz cremini mushrooms, cut into quarters",
      "1/2 cup frozen peas",
      "1/2 tsp salt",
      "1/4 tsp black pepper, coarsely ground",
      "1 tbsp sherry vinegar",
      "1 tbsp all-purpose flour",
      "3/4 cup milk",
      "2 1/2 oz Boursin cheese",
      "1/8 cup fresh parsley, finely chopped"
    ],
    "steps": [
      "Preheat oven to 400F. Thaw pie crust if needed. If using a crust *under* the pie (rather than an overcrust), pre-bake as directed (10-12 minutes). It won't really cook at all with the filling, so get it completely to the desired doneness here. Leave oven on when finished.",
      "Heat oil in medium pot over medium high heat. Add potatoes, cauliflower, and onion; cook and stir 1 minute. Reduce heat to medium-low. Add carrots and green beans; cook, covered 5 minutes, stirring occasionally. Add mushrooms; cook, covered 5-7 minutes or until potatoes are tender, stirring occasionally. Stir in peas, salt and pepper, and bring them to heat. Deglaze with the vinegar.",
      "Add flour to pot, and stir to distribute. Slowly add milk, stirring as you go. Add boursin and stir until it's melted thru. Stir in parsley.",
      "Pour filling into a deep dish pie plate, and top with pie crust. (Or pour into the pre-baked under-crust.) Bake 15 minutes or until golden brown and filling starts to bubble. Let stand 5 minutes before serving."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Barley risotto verde",
    "kcal": 405,
    "protein": 20,
    "carbs": 51,
    "fat": 15,
    "time": 3000,
    "ingredients": [
      "4 cup low-sodium vegetable broth",
      "4 cup water",
      "4 shallots, finely chopped",
      "4 clove garlic, pressed",
      "1 cup medium pearled barley (not quick-cooking)",
      "1 cup dry white wine",
      "1 clove garlic",
      "2 cup fresh basil (loosely packed)",
      "1 1/2 cup baby spinach",
      "1/2 cup fresh parsley (loosely packed)",
      "1 tbsp olive oil",
      "1/2 tsp salt",
      "1/2 tsp ground black pepper",
      "4 oz Parmesan cheese, grated",
      "2 oz goat cheese, crumbled",
      "1/4 cup fresh chives, snipped"
    ],
    "steps": [
      "1. In a 3-qt saucepan, bring broth and water to a simmer over medium heat. Reduce heat to low. Meanwhile, spray a 12-inch skillet (non-stick recommended) with olive oil; heat over medium-high heat 1-3 minutes or until shimmering. Add shallots; saute 1-2 minutes or until tender. Add garlic into skillet; cook 30-45 seconds or until fragrant. Add barley; cook 1 minute, stirring constantly with a wooden spoon. Add wine; cook 1-2 minutes or until wine is evaporated, stirring frequently.",
      "2. Using a ladle, add 1 cup of the hot broth mixture to skillet. Cook 4-5 minutes or until liquid is absorbed, stirring occasionally. Repeat with remaining broth mixture in 1-cup increments, cooking and stirring 4-5 minutes after each addition or until all of the liquid has been added and mixture is creamy (about 28-35 minutes). Remove skillet from heat.",
      "3. Meanwhile, place remaining garlic, basil, spinach, parsley, oil, salt and black pepper in a food processor. Process until finely chopped, scraping down bowl as needed. Add herb mixture and Parmesan cheese to skillet; mix well. Divide risotto among serving plates; top with goat cheese and chives."
    ],
    "phase": "luteal"
  },
  {
    "title": "French onion potato tart",
    "kcal": 380,
    "protein": 14,
    "carbs": 36,
    "fat": 20,
    "time": 3600,
    "ingredients": [
      "1 lb Yukon gold potatoes, thinly sliced",
      "2 medium onions, thinly sliced",
      "2 tsp sugar",
      "2 tbsp balsamic vinegar",
      "5 oz Gruyere cheese, grated",
      "2 clove garlic, pressed",
      "1/4 cup plain dry bread crumbs (or semolina?)",
      "1/2 package frozen puff pastry sheets (1 sheet), thawed",
      "1 oz Parmesan cheese, grated",
      "1 1/2 tbsp fresh rosemary, finely chopped",
      "3/4 tsp salt",
      "1/2 tsp coarsely ground black pepper",
      "2 tbsp fresh parsley, snipped"
    ],
    "steps": [
      "1. Preheat oven to 400F. Spray 12-inch skillet (nonstick recommended) with canola oil; heat over medium-high heat 1-3 minutes or until shimmering. Add onions and sugar to skillet; cook, uncovered, 8-10 minutes or until onions are light brown, stirring often. Add vinegar; cook 2 minutes, stirring occasionally. Remove skillet from heat.",
      "2. Meanwhile, in a 2-qt mixing bowl, combine Gruyere cheese and garlic; set aside. Sprinkle a medium sheet pan (about 9x14) with bread crumbs. Unfold pastry sheet onion lightly floured pastry mat. Using a rolling pin, roll out pastry into a 14x9 inch rectangle. Place pastry onion prepared sheet pan, pressing up sides.",
      "3. Sprinkle pastry with Parmesan cheese. Arrange half of the potatoes over pastry, slightly overlapping. Sprinkle potatoes with half EACH of the rosemary, salt, pepper, and Gruyere cheese mixture. Top with remaining potatoes, rosemary, salt and pepper. Sprikley with onions and remaining Gruyere cheese mixture. Bake 35-40 minutes or until edges of pastry are golden brown. Remove sheet pan from oven to a cooling rack. Cut tart into 12 pieces (for full recipe); sprinkle with parsley."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Wild mushroom and cauliflower lasagna",
    "kcal": 974,
    "protein": 46,
    "carbs": 72,
    "fat": 56,
    "time": 13800,
    "ingredients": [
      "2 tablespoon olive oil",
      "1 small yellow onion, finely diced",
      "2 clove garlic, finely chopped",
      "Pinch red pepper flakes",
      "3 cup canned plum tomatoes, and their juices",
      "2 tablespoon fresh basil, chopped",
      "3 tablespoon fresh flat-leaf parsley, chopped",
      "Salt and freshly ground black pepper",
      "Honey",
      "1 medium head cauliflower",
      "2 tablespoon olive oil",
      "Salt and freshly ground black pepper",
      "4 tablespoon unsalted butter",
      "1/4 cup flour",
      "5 cup whole milk, heated, divided",
      "1/8 teaspoon freshly grated nutmeg",
      "1/2 cup romano cheese, grated",
      "1 pound part-skim ricotta cheese",
      "1 large egg",
      "3/4 cup fresh flat-leaf parsley, finely chopped, divided, plus more for garnish",
      "3 teaspoon fresh thyme, finely chopped",
      "1/2 cup romano cheese, grated, plus more for finishing",
      "Kosher salt and freshly ground black pepper",
      "3 tablespoon olive oil",
      "3 clove garlic, smashed",
      "1 1/2 pound assorted mushrooms (shiitake, portobello, cremini), coarsely chopped",
      "2 shallots, finely diced",
      "1 ounce dried porcini mushrooms, soaked in boiling water for 30 minutes",
      "16 lasagna noodles, cooked for 5 minutes in boiling salted water, drained and rinsed with cold water",
      "1 1/4 pound fontina cheese, coarsely grated"
    ],
    "steps": [
      "For the tomato sauce: Heat the oil in a medium saucepan over medium-high heat. Add the onions and cook until soft. Add the garlic and red pepper flakes and cook for 30 seconds. Add the tomatoes, breaking them up with a wooden spoon, and the basil and cook until thickened and the tomatoes soften and break down. season with salt and pepper.",
      "Transfer to a blender and blend until smooth. Return the mixture to the saucepan, add the basil and chopped parsley, season with salt, pepper, and honey, if needed.",
      "For the cauliflower sauce: Preheat the oven to 350 degrees F. Remove the florets from the head of cauliflower and put in a small roasting pan. Drizzle with olive oil and season with salt and pepper. Add 1 1/2 cups water to the bottom of the pan, cover with foil, and cook until very tender, about 1 hour. Remove and increase the oven temperature to 375 degrees F.",
      "Melt the butter in a medium saucepan over medium heat. Whisk in the flour and cook for 30 seconds. Slowly whisk in 4 cups of the milk, increase the heat and bring to a boil, whisking constantly. Cook until thickened, about 5 minutes. Add the cauliflower, reduce the heat to low, and cook for 5 minutes longer. Remove from the heat and let cool slightly. Transfer the mixture to a blender (in batches) and puree until smooth. Strain the mixture into a clean saucepan through a medium mesh strainer and bring to a simmer over low heat. Whisk in the nutmeg, cheese, and salt and pepper, to taste. Cook for 1 minute. Add some of the remaining warm milk, if needed.",
      "For the lasagna: Increase the oven to 375 degrees F. Combine the ricotta, egg, 1/2 cup parsley, 1 teaspoon thyme, and romano cheese in a bowl and season with salt and pepper. Cover and refrigerate until ready to use.",
      "Heat the olive oil in a large saute pan over high heat. Add the garlic cloves and cook for 1 minute. Add the mushrooms and cook until they begin to soften. Add the shallots and cook until golden brown and completely dry. Drain the porcini mushrooms, reserving the soaking liquid, coarsely chop, and add to the mushrooms in the pan and cook for 1 minute. Deglaze with the porcini soaking liquid and cook until completely reduced. Stir in the remaining 2 teaspoons thyme, remaining 1/4 cup parsley, and season with salt and pepper. Remove from the heat.",
      "To assemble: Ladle some of the tomato sauce into the bottom of a 10 by 14 by 2 1/2-inch baking dish. Ladle some of the cauliflower mornay sauce over the tomato sauce. Top with 4 noodles. Top the noodles with some of the ricotta mixture, then some mushrooms, fontina, and romano. Season with salt and pepper. Repeat to make 4 layers. Ladle the cauliflower mornay sauce over the top of the noodles, making sure to cover the noodles completely with the sauce, and sprinkle with more of the romano cheese. Put the lasagna pan on a baking sheet, cover with foil, and bake for 30 minutes. Remove the foil and continue baking until bubbly and the top is golden brown, 30 to 40 minutes longer. Remove from the oven, sprinkle the top with parsley, and let rest 15 minutes before serving. Cut into squares and serve additional tomato sauce on the side.",
      "Recipe courtesy of Bobby Flay",
      "Read more at: http://www.foodnetwork.com/recipes/bobby-flay/wild-mushroom-and-cauliflower-lasagna-recipe.html?oc=linkback"
    ],
    "phase": "follikel"
  },
  {
    "title": "Hot cereal with apple butter and walnuts",
    "kcal": 296,
    "protein": 12,
    "carbs": 52,
    "fat": 6,
    "time": 600,
    "ingredients": [
      "1 cup fat-free milk",
      "3 tablespoon hot wheat cereal (not instant)",
      "3 tablespoon apple butter",
      "1 teaspoon light-brown sugar",
      "1 tablespoon chopped walnuts"
    ],
    "steps": [
      "Cook hot cereal according to package directions.",
      "Top cereal with apple butter, sugar, and walnuts."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mexican potato omelet",
    "kcal": 294,
    "protein": 16,
    "carbs": 11,
    "fat": 21,
    "time": 3000,
    "ingredients": [
      "2 tablespoon olive oil",
      "1 red-skinned potato (6 ounces), well scrubbed, halved, and thinly sliced",
      "3 garlic cloves, finely chopped",
      "2 scallions, thinly sliced",
      "Coarse salt and ground pepper",
      "8 large eggs",
      "1 1/4 cup plum tomatoes, coarsely chopped (about 2 tomatoes)",
      "2 oz pepper jack cheese, shredded",
      "2 tablespoon chopped cilantro",
      "1/2 teaspoon fresh lime juice"
    ],
    "steps": [
      "Heat 1 tablespoon oil in a 10-inch broiler-proof skillet over medium-low heat. Add potato, cover, and cook, stirring occasionally, until golden brown and tender, about 10 minutes. Stir in garlic and all but 1 tablespoon of the scallions; season with salt and pepper and cook 1 minute.",
      "In a large bowl, beat eggs until well combined. Add 1/4 cup each tomato and cheese; stir to combine. Add remaining oil to pan, and pour egg mixture over the potatoes.",
      "Preheat broiler with rack 4 inches from the heat. Meanwhile, cook eggs on the stovetop, lifting the edges to allow uncooked egg to flow underneath, until the center is almost set, 8 to 10 minutes. Sprinkle remaining 1/4 cup cheese over the top, then broil in the oven until set, about 2 minutes.",
      "In a small bowl, make a salsa by combining the remaining tomatoes, scallions, cilantro, and lime juice. Run a metal spatula around the edges of the pan and slide the omelette onto a platter. Serve cut into wedges with salsa."
    ],
    "phase": "luteal"
  },
  {
    "title": "Gazpacho Soup",
    "kcal": 444,
    "protein": 5,
    "carbs": 25,
    "fat": 37,
    "time": 4800,
    "ingredients": [
      "2 slices country-style bread, about 1 inch thick, crusts removed",
      "2 medium cucumbers, peeled, seeded and diced",
      "4 lb tomatoes, peeled, seeded and diced",
      "2 clove garlic, peeled and chopped",
      "1/2 red bell pepper, diced",
      "1/2 small white onion, diced",
      "1/4 cup sherry vinegar",
      "1 cup extra virgin olive oil",
      "Kosher salt, to taste",
      "Freshly ground black pepper, to taste"
    ],
    "steps": [
      "In a small bowl, soak the bread slices in water for about 20 minutes. Squeeze out water with your hands and set aside.",
      "In a blender, add the cucumbers, tomatoes, garlic, pepper, onion, vinegar and olive oil. Puree on high until the mixture is smooth. If there are lots of solid chunks, keep blending until the mixture is completely liquefied. You can strain the mixture through a fine-mesh sieve into a large pitcher, but this step is optional. Sease with salt and pepper to taste. Chill for at least 1 hour.",
      "Serve by pouring into chilled bowls or glasses, garnish with finishing salt and a drizzle of olive oil.",
      "Recipe offered courtesy of Terri Dien"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Eggs with mushrooms and tomatoes",
    "kcal": 394,
    "protein": 25,
    "carbs": 38,
    "fat": 18,
    "time": 1620,
    "ingredients": [
      "4 slices country bread, toasted",
      "1 teaspoon olive oil",
      "1 cup grape tomatoes, halved",
      "1/2 tsp kosher salt",
      "1/2 tsp black pepper",
      "1 pound mushrooms, sliced",
      "1 tablespoon fresh thyme",
      "8 large eggs",
      "1 ounce Parmesan, shaved",
      "2 tablespoon chopped fresh chives"
    ],
    "steps": [
      "Toast the bread.",
      "Then, do the following two things simultaneously:",
      "* Fry the eggs. As each pair of eggs is fried, put them on top of the bread.",
      "* Heat the oil in a large nonstick skillet over medium-high heat. Add the tomatoes, mushroom, and thyme, season with salt and pepper, and cook until tender, 5-7 minutes. Distribute this on top of the eggs (and around the plate, as there will be too much to stack).",
      "Finally, sprinkle with parmesan and chives."
    ],
    "phase": "follikel"
  },
  {
    "title": "Fruit and cheese breakfast",
    "kcal": 383,
    "protein": 12,
    "carbs": 24,
    "fat": 29,
    "time": 300,
    "ingredients": [
      "1 apple",
      "1 oz cheddar cheese",
      "1/8 cup peanut butter"
    ],
    "steps": [
      "Gather ingredients. Eat."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mustard, Avocado, and Dill on a Whole-Wheat Muffin With Boiled Egg",
    "kcal": 354,
    "protein": 15,
    "carbs": 30,
    "fat": 19,
    "time": 600,
    "ingredients": [
      "2 whole-wheat English muffins, split and toasted",
      "2 teaspoon whole-grain mustard",
      "1 avocado, sliced",
      "fresh dill, for serving",
      "2 eggs"
    ],
    "steps": [
      "Fill a sauce pan with 1/2 inch of water. Bring to a boil. Add eggs, reduce heat to medium, cover, and cook for 6 1/2 minutes (for any number of eggs). Immediately place in cold water bath. Peel carefully when cooled.",
      "Top the English muffin with the mustard, avocado, and dill, dividing evenly. Serve with the eggs."
    ],
    "phase": "luteal"
  },
  {
    "title": "Savory Oatmeal and Soft-Cooked Egg",
    "kcal": 264,
    "protein": 13,
    "carbs": 28,
    "fat": 11,
    "time": 600,
    "ingredients": [
      "1/2 cup quick-cooking oats",
      "Coarse salt and ground pepper",
      "Nonstick cooking spray",
      "1 large egg",
      "2 tablespoon sharp cheddar, shredded",
      "1 tablespoon scallion greens, thinly sliced"
    ],
    "steps": [
      "In a small saucepan, bring 1 cup water to a boil. Add oats and pinch of salt; stir, reduce heat, and simmer until tender, about 5 minutes. Meanwhile, heat a small nonstick pan over medium. Coat lightly with cooking spray. Add egg and cook until white is set and yolk is still runny, about 3 minutes. Season egg to taste with salt and pepper. Serve oatmeal in a bowl topped with cheese, egg, and scallion greens."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Adult Lunchable with Veggies, Egg, and Boursin",
    "kcal": 384,
    "protein": 11,
    "carbs": 32,
    "fat": 24,
    "time": 300,
    "ingredients": [
      "1 serving water crackers",
      "1/3 medium cucumber, sliced on the bias",
      "1/3 cup grape tomatoes",
      "1 egg, hard cooked and peeled",
      "1/4 package Boursin cheese",
      "1 cup fresh fruit"
    ],
    "steps": [
      "Pack all ingredients in small containers or a segmented lunch box. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Seitan and three-color pepper stir-fry bento",
    "kcal": 504,
    "protein": 24,
    "carbs": 85,
    "fat": 17,
    "time": 1620,
    "ingredients": [
      "1/2 tbsp olive oil",
      "3 tbsp green onion, roughly chopped",
      "2 tsp fresh ginger, peeled and finely chopped",
      "1/3 medium red bell pepper, cut into 1/2-inch chunks",
      "1/3 medium green bell pepper, cut into 1/2-inch chunks",
      "1/3 medium yellow bell pepper, cut into 1/2-inch chunks",
      "salt",
      "2 oz seitan, cut into 1/2-inch chunks",
      "black pepper, to taste",
      "1/2 tbsp soy sauce",
      "lettuce leaves (to use as bento dividers), washed and dried",
      "1 large green cabbage leaf",
      "1 2-inch length English cucumber, sliced into thin rounds",
      "1/2 tsp sea salt",
      "1 tbsp lemon juice",
      "4 florets broccoli",
      "4 cherry tomatoes",
      "1 cup cooked sushi rice"
    ],
    "steps": [
      "For Seitan:",
      "1. Heat the oil in a frying pan over medium heat. Add the green onion and ginger and stir-fry for 1-2 minutes until the oil is fragrant. Turn the heat up to the highest setting and add the peppers to the pan. Stir-fry with a spatula or long chopsticks. Sprinkle in some salt--this draws out moisture from the vegetables and cooks them a bit faster. Continue stir-frying for 4-5 minutes, until the peppers are cooked.",
      "2. Push the vegetables to the sides of the pan, and add the seitan to the exposed bottom. Leave for a couple of minutes, then turn over to cook the other side. Stir everything together, and add black pepper and soy sauce.",
      "For instant cabbage and cucumber pickles:",
      "1. cut out the tough vein of the cabbage leaf, and slice the rest into strips. Sprinkle the cabbage and cucumber with the salt and massage well with your hands until the vegetables go limp. Let rest for at least 5 minutes. Add a squeeze of lemon juice.",
      "2. Squeeze out any excess moisture before packing into a bento box. I like to put the pickles in a bento divider cup or cupcake liner to prevent the flavors from mingling with other flavors in the box.",
      "For Blanched Broccoli:",
      "1. Put just enough water in a small pan to cover the broccoli. Bring the water to a boil, add a pinch of salt, and put in the broccoli florets. Boil for 2-3 minutes, drain the water, and run cold tap water over the broccoli to cool quickly and fix the bright green color. Drain well. Use broccoli and cherry tomatoes to fill in gaps in the bento box."
    ],
    "phase": "ovulation"
  },
  {
    "title": "The best angel food cake",
    "kcal": 150,
    "protein": 4,
    "carbs": 33,
    "fat": 0,
    "time": 12000,
    "ingredients": [
      "1 1/2 cup egg whites (10-12 large), room temperature",
      "1 1/2 cup superfine sugar, divided",
      "1 cup sifted cake flour",
      "1 tsp cream of tartar",
      "1/4 tsp salt",
      "2 tsp vanilla extract or vanilla paste",
      "1 1/2 tsp lemon juice",
      "1/2 tsp almond extract"
    ],
    "steps": [
      "1. Adjust an oven rack to the lower-middle position and heat oven to 325 degrees. Have ready an ungreased large tube pan (9-inch diameter, 16-cup capacity), preferably with a removable bottom. If the pan bottom is not removable, line it with parchment or wax paper.",
      "2. In a small bowl, whisk the flour with 3/4 cup sugar. Place remaining 3/4 cup sugar in another small bowl next to the mixer.",
      "3. In the bowl of a standing mixer, or with a handheld mixer, beat egg whites at low speed until just broken up and beginning to froth. Add cream of tartar and salt and beat at medium speed until whites form very soft, billowy mounds. With the mixer still at medium speed, beat in 3/4 cup sugar, 1 tablespoon at a time, until all sugar is added and whites are shiny and form soft peaks. Add vanilla, lemon juice, and almond extract and beat until just blended.",
      "4. Place flour-sugar mixture in a sifter set over waxed paper. Sift flour-sugar mixture over egg whites about 3 tablespoons at a time, and gently fold it in, using a large rubber spatula. Sift any flour-sugar mixture that falls onto the paper back into the bowl with the whites.",
      "5. Gently scrape batter into pan, smooth the top, and give pan a couple of raps on the counter to release any large air bubbles.",
      "6. Bake until the cake is golden brown and the top springs back when pressed firmly, 50 to 60 minutes.",
      "7. If cake pan has prongs around the rim for elevating the cake, invert pan onto them. If not, invert pan over the neck of a bottle or funnel so that air can circulate all around it. Let the cake cool completely, 2 to 3 hours.",
      "8. To unmold, run a knife around edges, being careful not to separate the golden crust from the cake. Slide cake out of pan and cut the same way around removable bottom to release, or peel off parchment or wax paper, if used.",
      "9. Place the cake, bottom-side up, on a platter. Cut slices by sawing gently with a serrated knife. Serve the cake the day it is made.",
      "Read more: http://www.livestrong.com/recipes/the-best-angel-food-cake-cooks-illustrated/#ixzz4PHieOlr4"
    ],
    "phase": "luteal"
  },
  {
    "title": "Spring Chickpea Pasta Salad",
    "kcal": 479,
    "protein": 18,
    "carbs": 83,
    "fat": 13,
    "time": 30,
    "ingredients": [
      "1 cup canned chickpeas, rinsed and drained",
      "1 Tbsp extra-virgin olive oil",
      "1 1/2 Tbsp lemon juice",
      "1 clove garlic, minced",
      "1 tsp fresh rosemary, finely chopped",
      "1 Tbsp fresh parsley, finely chopped",
      "1/2 tsp salt",
      "freshly ground black pepper",
      "1 cup uncooked small pasta (such as tiny bowties/farfalline/small elbow macaroni/orzo)",
      "1/2 cup cherry tomatoes, halved or quartered",
      "1/2 cup snowpeas, cut bite-sized",
      "1 oz fresh goat cheese (or feta cheese)",
      "salt",
      "pepper",
      "4 radishes, halved and thinly sliced"
    ],
    "steps": [
      "Combine all the marinated chickpea ingredients and toss well. Let marinate, covered, in the refrigerator overnight or up to 4-5 days.",
      "Cook the pasta in salted water. Add the snow peas at the last minute or two to cook them too. Drain the pasta well.",
      "Toss the still hot pasta with the marinated chickpeas, including the marinade, and all remaining ingredients. Taste and season if needed. Let cool completely."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Salt block cucumber salad",
    "kcal": 93,
    "protein": 1,
    "carbs": 7,
    "fat": 7,
    "time": 780,
    "ingredients": [
      "4 small Persian cucumbers (or substitute English cucumber), cut into 1/4-inch-thick slices",
      "2 tbsp extra-virgin olive oil",
      "1 garlic clove, minced",
      "1/4 small red onion, finely chopped",
      "1/4 tsp black pepper, freshly ground",
      "1 tbsp rice wine vinegar (or white wine vinegar)",
      "2 tbsp fresh dill, chopped"
    ],
    "steps": [
      "Arrange the cucumber slices in a single layer on the salt block, as though setting up a checkers board (you will have to do this in batches). Let sit for 2 minutes, then flip the slices and let cure for 1 more minute. Remove the cucumber slices from the block and put in a clean, lint-free kitchen towel. Wrap the towel around the cucumber slices and wring purposefully but gently to remove any excess moisture. Put the cucumbers in a serving bowl. Wipe off the block and repeat the process with the remaining cucumber slices.",
      "Whisk together remaining ingredients in a small mixing bowl. Pour over cucumbers. Toss gently and serve."
    ],
    "phase": "follikel"
  },
  {
    "title": "Salt-baked walnut brioche scones",
    "kcal": 371,
    "protein": 7,
    "carbs": 31,
    "fat": 25,
    "time": 5580,
    "ingredients": [
      "1 1/2 cup all-purpose flour",
      "1/2 cup sugar",
      "1 1/2 tsp baking powder",
      "1 pinch fine salt (Himalayan salt is preferred)",
      "6 tbsp unsalted butter, softened, cut into 12 pieces",
      "6 extra-large egg yolks",
      "1/4 cup heavy cream",
      "1 cup walnuts, chopped"
    ],
    "steps": [
      "Place the tempered salt block on a heavy baking sheet and place on the middle rack of the oven. Turn on the oven to 350F, and heat the block for 1 hour.",
      "In the work bowl of a food processor equipped with a steel blade, combine the flour, sugar, baking powder and salt. Process in short pulses to combine. Add the butter and process in 2 to 3 pulses until it is dispersed evenly.Add the egg yolks and cream and process until the mixture becomes a cohesive dough, about 40 seconds. Add the walnuts and process in pulses until combined, but not so much that the walnuts become finely ground.",
      "Turn the dough out onto a clean work surface and pat into a 9-inch circle about 3/4-inch thick. Cut into 8 wedges. Arrange the cut scones on the hot salt block and bake until puffed and browned, about 18 minutes.",
      "Remove from the salt block with a spatula and let cool on a rack for 5 minutes before serving."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Basic bento: tofu and egg",
    "kcal": 453,
    "protein": 20,
    "carbs": 51,
    "fat": 20,
    "time": 900,
    "ingredients": [
      "3.5 oz extra-firm tofu, drained and pressed",
      "1/2 tablespoon sesame oil",
      "1/2 tablespoon soy sauce",
      "1/2 tablespoon rice vinegar",
      "1/2 tablespoon water",
      "3/4 cup cooked sushi rice",
      "1 egg, hard-cooked",
      "1 medium carrot",
      "1/4 cup green beans",
      "sesame seeds",
      "salt"
    ],
    "steps": [
      "The night before, cut tofu into 1 inch cubes. Combine marinade ingredients in a plastic bag and mix well. Add tofu. Gently mix to cover all of the tofu. Marinated overnight in the refrigerator (at least 30 minutes if in a hurry).",
      "Preheat oven or toaster oven to 350F. Line a baking sheet with parchment or a silpat. Remove tofu from marinade (discard liquid). Place on baking sheet leaving some space between pieces. Bake for 20-30 minutes.",
      "Cook rice and egg. Flash-broil the vegetables with some salt; rinse with cold water to stop the cooking.",
      "Halve and season the egg. Sprinkle sesame seeds on the rice."
    ],
    "phase": "luteal"
  },
  {
    "title": "Petite vegetable frittatas",
    "kcal": 205,
    "protein": 17,
    "carbs": 3,
    "fat": 13,
    "time": 1920,
    "ingredients": [
      "1 red bell pepper, diced",
      "1 yellow bell pepper, diced",
      "1 zucchini, diced",
      "1 small onion, diced",
      "1 cup Parmesan cheese",
      "8 eggs, beaten together",
      "2 tbsp fresh chives",
      "salt and pepper to taste",
      "olive oil, for drizzling"
    ],
    "steps": [
      "Preheat oven to 350 degrees. In a large 10 inch skillet heat the olive oil over medium high heat. Sauté the diced zucchini, onion and red and yellow bell peppers for about 5 minutes until they are slightly soft. Season with salt and pepper. Add the sautéed vegetables to the bottom of a regular sized muffin pan.",
      "In another bowl, whisk together 8 eggs and season with salt and pepper and add the chopped chives and parmesan. Fill the remaining area in the muffin tin with the egg, gently stirring the ingredients together. Bake in the oven for 10-12 minutes until the eggs are completely set."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Roasted Shrimp, Endive, and Red Onion Salad",
    "kcal": 360,
    "protein": 27,
    "carbs": 17,
    "fat": 18,
    "time": 3000,
    "ingredients": [
      "1/2 tbsp olive oil",
      "4 endive, halved lengthwise",
      "2 medium red onion, each cut into 6 wedges",
      "1/2 lb shrimp, deveined and peeled",
      "2 tbsp extra-virgin olive oil",
      "2 tbsp fresh sage, chopped",
      "1 tbsp lemon juice",
      "1 1/2 tbsp red wine vinegar",
      "1 tsp dijon mustard",
      "1/2 tsp salt",
      "1/4 tsp pepper"
    ],
    "steps": [
      "Preheat oven to 400F. Lightly oil a large rimmed baking sheet, and place endive and onion on it, cut side down. Roast for 20 minutes.",
      "Meanwhile, whisk vinaigrette ingredients in a large bowl.",
      "When roasting is done, gently flip vegetables and add shrimp, then return to oven for another 15 minutes, until shrimp is just cooked and vegetables are golden-brown and tender.",
      "Add veggies and shrimp to bowl with vinaigrette, gently toss. Serve, drizzling any remaining vinaigrette."
    ],
    "phase": "follikel"
  },
  {
    "title": "Udon noodle soup",
    "kcal": 610,
    "protein": 20,
    "carbs": 69,
    "fat": 30,
    "time": 3000,
    "ingredients": [
      "2 large eggs",
      "2 clove garlic, minced or pressed",
      "1 1-inch piece ginger, grated or finely minced",
      "2 scallions, thinly sliced, white and green parts separated",
      "1 carrot, diced",
      "2 tbsp sweet white miso paste",
      "1 tbsp hoisin sauce",
      "4 cup water",
      "6 oz baby bok choy, roughly chopped",
      "1/2 lb fresh udon noodles",
      "1/2 lime, juiced",
      "1 tbsp sesame oil",
      "3 tbsp peanuts, roasted",
      "salt and pepper"
    ],
    "steps": [
      "Cook & peel the eggs:\nBoil the eggs to a soft yolk, about 6 1/2 minutes. Cool, peel, and set aside.",
      "Cook the aromatics:\nWhile the eggs cook, in a large pot, heat 2 teaspoons of olive oil on medium-high until hot.Add the garlic, ginger and white bottoms of the scallions. Cook, stirring constantly, 30 seconds to 1 minute, or until fragrant. Add the carrot and cook, stirring occasionally, 2 to 3 minutes, or until slightly softened.",
      "Start the soup:\nWhile the eggs continue to cook, add the miso paste, hoisin sauce and 5 cups of water to the pot of aromatics. Heat to boiling on high. Once boiling, reduce the heat to medium and cook, stirring occasionally, 7 to 9 minutes, or until reduced in volume by about ¼. Add the bok choy and season with salt and pepper. Cook, stirring occasionally, 4 to 6 minutes, or until the bok choy stems have softened and the leaves have wilted.",
      "Finish the soup:\nTo the pot, add the noodles (carefully separating with your hands before adding), sesame oil and the lime juice. Cook, stirring occasionally, 2 to 4 minutes, or until thoroughly combined and heated through. Turn off the heat; season with salt and pepper to taste.",
      "Plate your dish:\nDivide the finished soup between 2 bowls. Halve the peeled eggs lengthwise and season with salt and pepper. Top the soup with the seasoned eggs. Garnish with the peanuts and green tops of the scallions. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Oaxaca Cheese & Plantain Tortas with Tangelo & Radish Salad",
    "kcal": 790,
    "protein": 28,
    "carbs": 114,
    "fat": 28,
    "time": 2700,
    "ingredients": [
      "2 Sandwich Rolls",
      "4 Ounces Queso Oaxaca",
      "3 Radishes",
      "1 Black Plantain",
      "1 Romaine Heart",
      "1 Tangelo",
      "2 Roasted Piquillo Peppers",
      "1 Shallot",
      "1 Tablespoon Sugar",
      "1 Tablespoon Red Wine Vinegar"
    ],
    "steps": [
      "Prepare the ingredients:\nPeel the plantain; Halve the rolls.Peel and thinly slice the shallot.Peel the plantain; cut on an angle into ¼-inch-thick pieces.Thinly slice the cheese.Cut off and discard the ends of the radishes; thinly slice into rounds.Peel and large dice the tangelo.Cut off and discard the root end of the romaine; roughly chop the leaves.Finely chop the peppers.",
      "Marinate the shallot:\nIn a medium bowl, combine the shallot, sugar and vinegar; drizzle with olive oil and season with salt and pepper. Set aside to marinate, stirring occasionally, for at least 10 minutes. Season with salt and pepper to taste.",
      "Cook the plantain:\nWhile the shallot marinates, in a large pan (nonstick, if you have one), heat 1 teaspoon of olive oil on medium-high until hot. Add the plantain and season with salt and pepper. Cook 3 to 4 minutes on the first side, or until browned. Flip and cook 2 to 3 minutes, or until browned and softened. Transfer to a paper towel-lined plate and immediately season with salt and pepper. Wipe out the pan.",
      "Assemble the tortas:\nPlace the rolls on a clean, dry work surface. Top the roll bottoms with the cheese, cooked plantain, peppers and marinated shallot (reserving the liquid). Season with salt and pepper. Complete the tortas with the roll tops.",
      "Cook the tortas:\nIn the same pan, heat 2 teaspoons of olive oil on medium until hot. Add the tortas. Place a heavy-bottomed pot (or pan) on top of the tortas; press down. Cook, occasionally pressing down on the pot, 2 to 3 minutes per side, or until lightly browned and slightly flattened. Transfer to a cutting board.",
      "Make the salad & plate your dish:\nIn a large bowl, combine the radishes, tangelo and romaine; season with salt and pepper. Add the reserved shallot marinating liquid and a drizzle of olive oil; toss to thoroughly combine. Season with salt and pepper to taste. Cut the cooked tortas in half on an angle. Divide the tortas and salad between 2 dishes. Enjoy!"
    ],
    "phase": "luteal"
  },
  {
    "title": "Mushroom & Broccoli Casserole with Baked Pastry",
    "kcal": 640,
    "protein": 17,
    "carbs": 69,
    "fat": 36,
    "time": 3600,
    "ingredients": [
      "1/2 oz dried porcini mushrooms",
      "1/2 lb broccoli, cut into florets, stem diced",
      "6 oz oyster mushrooms, roughly chopped",
      "2 carrots, small diced",
      "2 green onions, small diced and separated",
      "1 stalk celery, small diced",
      "1 tsp fresh thyme",
      "3 tbsp flour",
      "2 tbsp butter",
      "1 oz cheddar cheese, shredded",
      "1 pie crust"
    ],
    "steps": [
      "Preheat the oven to 400°F. Wash and dry the fresh produce. In a bowl, combine the dried porcini mushrooms and 1 1/2 cups of hot water; let stand for at least 10 minutes, then remove (reserving the water) and roughly chop.",
      "Toss broccoli florets with olive oil, salt, and pepper, and roast in the oven for 12-14 minutes, until lightly browned and tender. Remove from the oven, leaving it on.",
      "While the broccoli roasts, in a large pot, heat 2 teaspoons of olive oil on medium-high until hot. Add the carrots, celery, oyster mushrooms, chopped porcini mushrooms, thyme, and scallion whites. Season with salt and pepper. Cook, stirring occasionally, 12 to 14 minutes, or until softened.",
      "Add the butter to the pan and cook, stirring frequently, 30 seconds to 1 minute, or until melted. Add the flour and cook, stirring frequently, 30 seconds to 1 minute, or until lightly browned. Slowly stir in the reserved mushroom water. Cook, stirring occasionally, 2 to 4 minutes, or until the mixture is slightly thickened. Add the roasted broccoli and stir to combine. Turn off the heat and season with salt and pepper to taste.",
      "Transfer the finished filling to a baking dish. Top with pie crust. Bake as directed by pie crust instructions (probably 12 minutes), until crust is golden brown. When five minutes remain, top with shredded cheese and return to oven. Let stand for at least 2 minutes before serving. Top with scallion greens."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Penne & Arrabbiata Sauce with Roasted Carrot & Tangelo Salad",
    "kcal": 750,
    "protein": 28,
    "carbs": 117,
    "fat": 20,
    "time": 2700,
    "ingredients": [
      "1/2 Pound Penne Rigate Pasta",
      "1 14-Ounce Can Whole Peeled Tomatoes",
      "4 Ounces Fresh Mozzarella Cheese",
      "2 Carrots",
      "2 Cloves Garlic",
      "1 Tangelo",
      "1 Ounce Castelvetrano Olives",
      "1/4 Cup Grated Parmesan Cheese",
      "1/4 Teaspoon Crushed Red Pepper Flakes"
    ],
    "steps": [
      "Preheat the oven to 450°F. Wash and dry the fresh produce. Heat a medium pot of salted water to boiling on high. Peel the carrots; cut crosswise into 2-inch pieces, then lengthwise into 1/2-inch-thick wedges. Peel and roughly chop the garlic. Place the tomatoes in a bowl; gently break apart with your hands. Tear the mozzarella cheese into bite-sized pieces. Peel the tangelo. Separate the segments and cut in half crosswise. Using the flat side of your knife, smash the olives; remove and discard the pits, then roughly chop.",
      "Place the carrots on a sheet pan. Drizzle with olive oil and season with salt and pepper; toss to thoroughly coat. Arrange in a single, even layer. Roast, stirring halfway through, 14 to 16 minutes, or until browned and tender when pierced with a fork. Remove from the oven and set aside in a warm place.",
      "While the carrots roast, in a large pan (nonstick, if you have one), heat 1 teaspoon of olive oil on medium-high until hot. Add the garlic and season with salt and pepper. Cook, stirring constantly, 30 seconds to 1 minute, or until fragrant. Add as much of the red pepper flakes as you'd like, depending on how spicy you'd like the dish to be. Cook, stirring constantly, 30 seconds to 1 minute, or until fragrant. Add the tomatoes and season with salt and pepper. Cook, stirring occasionally, 9 to 10 minutes, or until thickened and saucy. Turn off the heat. Season with salt and pepper to taste.",
      "While the sauce cooks, add the pasta to the pot of boiling water. Cook 10 to 12 minutes, or until just shy of al dente (still slightly firm to the bite). Reserving 1/2 cup of the pasta cooking water, drain thoroughly.",
      "In a medium bowl, combine the roasted carrots, tangelo and olives. Drizzle with olive oil and season with salt and pepper to taste. Divide between 2 dishes.",
      "To the pan of sauce, add the cooked pasta and half the reserved cooking water. Cook on medium-high, stirring vigorously, 1 to 2 minutes, or until the pasta is thoroughly coated. (If the sauce seems dry, gradually add the remaining cooking water to achieve your desired consistency.) Add the mozzarella cheese. Cook, stirring frequently, 1 to 2 minutes, or until thoroughly combined and the cheese has melted. Turn off the heat and season with salt and pepper to taste. Divide the finished pasta between 2 separate dishes. Garnish with the parmesan cheese. Serve with the salad on the side. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Smoky Seared Cod with Roasted Potatoes & Dates",
    "kcal": 670,
    "protein": 34,
    "carbs": 69,
    "fat": 31,
    "time": 3000,
    "ingredients": [
      "2 Cod Fillets",
      "2 Cloves Garlic",
      "2 Ounces Baby Greens",
      "1 Pink Lemon",
      "1 Pound Russet Potatoes",
      "2 Tablespoons Butter",
      "2 Tablespoons Red Wine Vinegar",
      "1 Shallot",
      "1 Tablespoon Sugar",
      "3 Tablespoons Roasted Almonds",
      "1/2 Ounce Deglet Noor Dates",
      "1 1/2 Tablespoons Smoky Cod Spice Blend (Rice Flour or potato starch & Smoked Paprika)"
    ],
    "steps": [
      "Preheat the oven to 450°F. Wash and dry the fresh produce. Cut the potatoes into 1/4-inch-thick rounds. Peel and thinly slice the shallot. Peel and roughly chop the garlic. Roughly chop the dates. Quarter and deseed the lemon. Roughly chop the baby greens. Roughly chop the almonds.",
      "Place the potatoes on a sheet pan. Drizzle with 2 teaspoons of olive oil and season with salt and pepper; toss to thoroughly coat. Arrange in a single, even layer and roast, flipping halfway through, 18 to 20 minutes, or until lightly browned and tender when pierced with a fork. Remove from the oven and carefully transfer to a large bowl. Set aside in a warm place.",
      "While the potatoes roast, in a small pot, combine the shallot, sugar, vinegar and ¼ cup of water; season with salt and pepper. Heat to boiling on high. Once boiling, cook, stirring occasionally, 1 to 2 minutes, or until the sugar has dissolved. Set aside to cool, stirring occasionally, for at least 10 minutes. Season with salt and pepper to taste.",
      "While the shallot cools, place the spice blend on a plate. Pat the cod fillets dry with paper towels; season with salt and pepper on both sides. Coat 1 side of each seasoned fillet in the spice blend (tapping off any excess). In a medium pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium-high until hot. Add the fillets, coated sides down, and cook 3 to 5 minutes on the first side, or until browned. Flip the fillets and cook 1 to 2 minutes, or until lightly browned.",
      "Add the butter, garlic, dates and 1/4 cup of water to the pan; season with salt and pepper. Cook, occasionally spooning the sauce over the fillets, 2 to 3 minutes, or until the cod is coated and cooked through. Turn off the heat and top with the juice of 2 lemon wedges. Season with salt and pepper to taste.",
      "Reserving 2 tablespoons of the shallot pickling liquid, drain the pickled shallot. To the bowl of roasted potatoes, add the baby greens, pickled shallot, reserved pickling liquid, the juice of the remaining lemon wedges and a drizzle of olive oil. Gently toss to combine and season with salt and pepper to taste. Divide the finished vegetables between 2 dishes. Top with the finished cod fillets and sauce. Garnish with the almonds. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Kale & White Cheddar Quesadillas with Radishes & Fried Eggs",
    "kcal": 585,
    "protein": 29,
    "carbs": 50,
    "fat": 29,
    "time": 2400,
    "ingredients": [
      "4 tsp olive oil",
      "1/2 bunch kale, stems discarded and leaves roughly chopped",
      "1 clove garlic, minced or pressed",
      "1/4 cup water",
      "3/4 tsp taco seasoning",
      "1/2 lime, juiced",
      "3 oz white cheddar Cheese",
      "2 large flour tortillas",
      "1/2 lime, juiced",
      "2 tbsp Creme Fraiche",
      "2 tsp olive oil, plus more for drizzling on radishes",
      "1/4 tsp taco seasoning",
      "3 Radishes, halved lengthwise then thinly sliced crosswise",
      "2 Eggs"
    ],
    "steps": [
      "In a large pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium until hot. Add the garlic and kale; season with salt and pepper. Cook, stirring frequently, 1 to 2 minutes, or until the kale is slightly wilted. Add water and taco seasoning, depending on how spicy you’d like the dish to be; season with salt and pepper. Cook, stirring frequently, 3 to 5 minutes, or until the kale has wilted and the water has cooked off. Turn off the heat. Stir in the juice of 2 lime wedges; season with salt and pepper to taste.",
      "While the kale cooks, in a bowl, combine the crème fraîche and the juice of the remaining lime; season with salt and pepper to taste.",
      "Place the tortillas on a clean, dry work surface. Divide half the cheese between the two tortillas, only covering half of each tortilla; top with the cooked kale and remaining cheese. Season with salt and pepper. Fold over the tortilla to complete. Wipe out the pan used to cook the kale. Add 2 teaspoons of olive oil and heat on medium-high until hot. Add the quesadillas and cook 2 to 3 minutes per side, or until the tortillas are browned and the cheese has melted. Divide between 2 dishes; immediately season with salt. Set aside in a warm place. Wipe out the pan.",
      "In the same pan, heat 2 teaspoons of olive oil on medium until hot. Crack the eggs into the pan, keeping them separate. Season with salt and as much of the remaining spice blend as you'd like, depending on how spicy you'd like the dish to be. Cook 4 to 5 minutes, or until the whites are set and the yolks are cooked to your desired degree of doneness. Turn off the heat.",
      "Place the radishes in a bowl; drizzle with olive oil and season with salt and pepper. Toss to thoroughly coat. Top the cooked quesadillas with the fried eggs and seasoned radishes. Serve with the lime crème fraîche on the side. Enjoy!"
    ],
    "phase": "luteal"
  },
  {
    "title": "Baked Tofu Banh Mi Salad",
    "kcal": 627,
    "protein": 34,
    "carbs": 50,
    "fat": 32,
    "time": 90000,
    "ingredients": [
      "28 oz extra-firm tofu, cut into 1/2″ – 1″ pieces",
      "1 cup lite soy sauce",
      "4 tbsp sesame oil",
      "4 tbsp rice wine vinegar",
      "1 tbsp sugar",
      "1 scallion, finely chopped",
      "1/2 cup mayo",
      "1/4 cup reserved tofu marinade (plus more if needed)",
      "1 tbsp sriracha (or more/less to taste)",
      "2 carrots, peeled and thinly sliced on an angle",
      "2/3 English cucumber, halved, seeds scraped out and thinly sliced at an angle",
      "1 bunch radishes, quartered",
      "6 tbsp rice vinegar",
      "2 tsp sea salt",
      "1/2 tsp sugar",
      "8 oz French bread, cut into 1″ cubes (needs to be stale, if bread is too fresh, leave cubes on the counter overnight to stale)",
      "1/4 cup fresh cilantro, stems removed",
      "2 tbsp black sesame seeds, for sprinkling"
    ],
    "steps": [
      "*Components can all be made ahead of time*",
      "For tofu: Combine all tofu ingredients in a zip top bag and marinate 4-24 hours (ok, but really, if you’ve only got 30 minutes, that’s fine, too). Preheat oven to 350F. Drain tofu reserving the marinade. Place cubes on a parchment paper lined baking sheet and bake for 30 minutes or until tofu begins to brown in places where it’s exposed. Allow to cool.",
      "For dressing: Whisk all ingredients together in a small bowl, adding more marinade, if needed, to create a drizzleable consistency. Store in the fridge until ready to use.",
      "For veggies: Combine all ingredients and “marinate” in the fridge for 12-24 hours.",
      "To assemble salad: In a large bowl, layer half (each) of the bread, dressing, veggies, tofu and cilantro. Repeat. Top with sesame seeds. Toss just before serving."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Mexican caprese salad",
    "kcal": 427,
    "protein": 22,
    "carbs": 16,
    "fat": 31,
    "time": 600,
    "ingredients": [
      "1 cup grape tomatoes, halved",
      "1 avocado, halved and cut into strips or wedges",
      "1 large fresh mozzarella ball, halved and sliced into wedges",
      "2 teaspoon taco seasoning",
      "2 tablespoon Taco Sauce",
      "2 tablespoon fresh cilantro, chopped"
    ],
    "steps": [
      "Cut the tomatoes, avocado, and mozzarella ball into wedges. Place the tomatoes into a bowl and sprinkle with Taco Seasoning. Toss to coat. Then arrange the tomatoes, avocados, and mozzarella on a platter or large plate.",
      "Drizzle Taco Sauce over the top. Then sprinkle with fresh cilantro over the caprese salad. Salt and pepper if needed."
    ],
    "phase": "follikel"
  },
  {
    "title": "Chocolate covered strawberry quick oatmeal",
    "kcal": 270,
    "protein": 7,
    "carbs": 44,
    "fat": 9,
    "time": 420,
    "ingredients": [
      "1 cup water",
      "1/2 cup quick oats",
      "pinch salt",
      "2 tbsp semi-sweet chocolate morsels",
      "1/2 cup fresh fruit, chopped"
    ],
    "steps": [
      "Cook the oatmeal as directed (add water and a pinch of salt, microwave for two minutes). Stir in chocolate and fruit."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Golden-crusted Brussels sprouts",
    "kcal": 106,
    "protein": 7,
    "carbs": 10,
    "fat": 6,
    "time": 1500,
    "ingredients": [
      "24 small Brussels sprouts, trimmed and halved",
      "1 tbsp extra-virgin olive oil",
      "Salt",
      "Black pepper",
      "1/3 cup Parmesan, grated"
    ],
    "steps": [
      "Gently coat the brussels sprouts with oil, salt, and pepper. Add oil to a medium-size pan, and bring up to medium heat, then add sprouts, cut side down. Cover and cook for 5 minutes, until the sprouts are tender and only very slightly browned.",
      "Uncover, turn heat up to medium-high, and cook for a few minutes, until cut sides are golden and caramelized. Flip and cook for another minute or two, to get some browning on the round side. Season to taste, then serve immediately, topping with parmesan."
    ],
    "phase": "luteal"
  },
  {
    "title": "Sweet and Spicy Tofu with Jasmine Rice and Crispy Shallot",
    "kcal": 780,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 30,
    "ingredients": [
      "1/2 cup white Jasmine rice",
      "1 shallot, peeled and thinly sliced",
      "2 tbsp rice flour",
      "4 oz sweet peppers, halved lengthwise, seeds/ribs removed, thinly sliced crosswise",
      "1 zucchini, large diced",
      "2 green onions, thinly sliced, whites and greens separated",
      "7 oz tofu",
      "2 clove garlic, roughly chopped",
      "1 lime, halved",
      "2 tsp golden mountain sauce",
      "1 Thai chili (or jalapeno), thinly sliced into rounds",
      "1 tbsp honey, warmed to room temperature",
      "1/2 tbsp fresh cilantro, chopped",
      "1/2 tbsp fresh mint, chopped"
    ],
    "steps": [
      "Remove the honey from the refrigerator to bring to room temperature.",
      "Cook the **rice**: In a small saucepan, combine the rice, a big pinch of salt, and 1 cup of water. Heat to boiling on high. Once boiling, cover and reduce the heat to low. Cook 12 to 14 minutes, or until the water has been absorbed and the rice is tender. Turn off the heat and fluff the cooked rice with a fork.",
      "Mix **shallot**, **rice flour**, salt, and pepper in a bowl. Toss to thoroughly coat. In a large pan, heat a thin layer of oil on medium-high until hot. Once the oil is hot enough that a piece of shallot sizzles immediately when added to the pan, add the coated shallot in a single layer (tapping off any excess flour before adding). Cook, stirring frequently, 2 to 3 minutes, or until browned and crispy. Transfer to a paper towel-lined plate; immediately season with salt and pepper. Rinse and wipe out the pan.",
      "In the same pan, heat 2 teaspoons of olive oil on medium-high until hot. Add the **zucchini** and **sweet peppers**. Cook, stirring occasionally, 3 to 4 minutes, or until lightly browned. Turn off the heat; stir in the green tops of the **scallions**. Season with salt and pepper to taste. Transfer to a bowl; set aside in a warm place. Wipe out the pan.",
      "In the same pan, heat 2 teaspoons of olive oil on medium-high until hot. Add the **tofu**; season with salt and pepper. Cook, frequently breaking the tofu apart with a spoon, 3 to 4 minutes, or until browned. Add the **garlic**, white bottoms of the **scallions**, **honey**, **soy sauce**, the juice of half the **lime**, 2 tablespoons of water, and as much of the **chili pepper** as you’d like, depending on how spicy you’d like the dish to be. Cook, stirring frequently, 1 to 2 minutes, or until thoroughly combined and the tofu is warmed through.",
      "Dish up the rice, top with tofu and vegetables. Garnish with the fried shallot, cilantro and mint. Top with juice of remaining lime wedges."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Olive and Pepper Grilled Cheese Sandwiches",
    "kcal": 590,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 1800,
    "ingredients": [
      "4 slices Sourdough Bread",
      "4 oz White Cheddar Cheese, shredded",
      "2 oz Castelvetrano Olives, pitted and finely chopped",
      "2 oz Pickled peppadew peppers, finely chopped",
      "1/2 cup Cherry Tomatoes, halved",
      "2 cup lettuce",
      "1 clove Garlic, minced",
      "3/4 tbsp Red Wine Vinegar",
      "3 tbsp Creme Fraiche"
    ],
    "steps": [
      "1. Place the tomatoes in a bowl and season with salt and pepper. In another medium bowl, combine the olives and peppers. Drizzle with olive oil and season with salt and pepper to taste.",
      "2. Place the bread slices on a work surface. Divide half the cheddar cheese between 2 of the bread slices; top with the olive/pepper filling and remaining cheddar cheese. Season with salt and pepper. Complete the sandwiches with the remaining bread slices.",
      "3. In a medium pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium until hot. Add the sandwiches and cook 3 to 5 minutes per side, or until the bread is golden brown and the cheese has melted. (If the pan seems dry, add 1 teaspoon of olive oil before flipping the sandwiches.) Transfer to a cutting board.",
      "4. While the sandwiches cook, in a bowl, combine the creme fraiche, vinegar, and as much of the garlic paste as you’d like. Drizzle with olive oil and season with salt and pepper to taste.",
      "5. Just before serving, place the lettuce in a large bowl. Add enough of the dressing to coat the lettuce (you may have extra dressing). Toss to combine; season with salt and pepper to taste. To the bowl of seasoned tomatoes, add a drizzle of olive oil; season with salt and pepper to taste. Cut the cooked sandwiches in half on an angle. Divide the sandwiches and dressed lettuce between 2 dishes. Top the lettuce with the tomatoes. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Tofu katsu onigirazu",
    "kcal": 611,
    "protein": 25,
    "carbs": 88,
    "fat": 23,
    "time": 3600,
    "ingredients": [
      "14 oz firm tofu, pressed",
      "soy sauce",
      "1 egg, lightly beaten",
      "1 cup panko breadcrumbs",
      "all purpose flour",
      "canola oil",
      "4 nori sheets",
      "4 cup cooked sushi rice",
      "1 avocado, sliced",
      "1 oz baby spinach",
      "mayonnaise",
      "Sriracha"
    ],
    "steps": [
      "Cook rice: \n1. However much cooked rice you need, start with half that of dry rice.\n2. Rinse rice to remove starchy coating.\n3. Mix with ~1.7x water and a heavy pinch of salt.\n4. Boil until done, 20ish minutes.",
      "For the tofu:\n1. Set the oven to 400° F and line a baking tray with baking paper. \n2. Toast panko breadcrumbs in a small pan until golden (they will gain more colour in the oven). \n3. Cut tofu into thin blocks; ideally equal to # of servings, but if the tofu blocks are narrow, twice that. Sprinkle tofu with some soy sauce or you can season the flour with plenty of salt instead. \n4. Drag tofu in flour making sure that the entire surface area has been coated. Dip the tofu in the egg and finally drag it in the pre-toasted breadcrumbs. \n5. Brush a bit of oil on the baking paper underneath the tofu and bake for about 10 minutes per side, flipping halfway thru.",
      "To assemble:",
      "1. Cut a square of cling film slightly larger than your nori sheet. Place it on the table, place the nori sheet on top with the shiny side down and rotated 45° in relation to the cling film.\n2. Wet your hands (keep a small bowl of water handy to wet your hands) and grab a handful of rice. Place it in the middle of the sheet and using your hands form it into a compacted square (about 9 cm / 3.5 ” by 9 cm / 3.5 “). Try to make that layer as even and compacted as possible. Season well with salt. (Ideally, use an onigirazu mold.)\n3. Top with tofu, mayo, then veggies, and finally a second layer of rice.\n4. Fold the nori corners over the stack, using the cling film to help keep it together without tearing, until you get a small packet.\n5. Finally gather all the cling film over the stack and tie on the top. Put something moderately heavy (like a breadboard) on the onigirazu and set it aside to let the seaweed soften a little. Cut in half with a sharp knife."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Super veggie onigirazu",
    "kcal": 338,
    "protein": 8,
    "carbs": 53,
    "fat": 12,
    "time": 1200,
    "ingredients": [
      "1 sheet of nori",
      "3/4 cup cooked sushi rice",
      "mayonnaise, to taste",
      "Dijon mustard, to taste",
      "1 egg, hard cooked",
      "2 small leaves of romaine lettuce",
      "1/2 small carrot, peeled and julienned",
      "1/8 English cucumber, thinly sliced",
      "1/8 cup red onion, thinly sliced and halved",
      "1/4 large avocado, sliced",
      "1/8 small red cabbage, thinly sliced",
      "1 slice large tomato",
      "Kosher salt and freshly ground black pepper, to taste"
    ],
    "steps": [
      "1. Place a square piece of plastic wrap on your work surface and then place the sheet of nori (shiny side down) with a corner pointing up, on top of the plastic wrap.",
      "2. Form a thin layer of rice into the shape of a square in the center of the nori sheet, with the flat sides facing up/down and side-to-side (see video). It helps to wet your fingers when your shaping the rice.",
      "3. Spread the mayo and mustard on top of the rice and sprinkle with salt and pepper. Then pile on the veggies. Spoon some more rice on top of the veggies and form into another square. Tightly, but gently fold up the corners of the nori so that it completely covers the rice. Then fold up two corners of the plastic wrap to cover the nori and hold it in place. Place a piece of julienned carrot perpendicular to the way the ingredients run on top so that you know which direction to slice the onigirazu. Then fold up the last two sides of plastic wrap and set aside for at least 5 minutes and up to overnight.",
      "4. When ready to serve, slice the onigirazu along the length of the carrot you placed on the outside, remove the plastic wrap and enjoy."
    ],
    "phase": "luteal"
  },
  {
    "title": "Oregano halloumi with orzo salad",
    "kcal": 588,
    "protein": 28,
    "carbs": 28,
    "fat": 40,
    "time": 1080,
    "ingredients": [
      "12 oz dried orzo",
      "1 tsp dried oregano",
      "3 tbsp olive oil",
      "9 oz halloumi, sliced",
      "7 oz cherry tomatoes, halved",
      "1/4 cup pitted black olives, chopped",
      "5 oz basil pesto"
    ],
    "steps": [
      "Bring a large pan of salted water to the boil and cook the orzo following pack instructions. Meanwhile, mix the oregano in a small bowl with the oil and brush some over the halloumi. Heat a large, non-stick frying pan and cook the halloumi for a few mins each side until golden and soft.",
      "Drain the cooked orzo and mix with the tomatoes, olives and pesto. Season to taste. Spoon onto a serving plate and top with the halloumi."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Cucumber, Avocado, and Miso Spinach Rice Bowl",
    "kcal": 600,
    "protein": 18,
    "carbs": 97,
    "fat": 32,
    "time": 3600,
    "ingredients": [
      "1/2 cup dry sushi rice",
      "2 clove black garlic, minced",
      "2 eggs, soft-boiled",
      "1 avocado, medium diced",
      "1/3 english cucumber, halved and thinly sliced",
      "3 tbsp mirin, divided",
      "1 tbsp rice vinegar, divided",
      "2 tsp sambal oelek",
      "4 oz spinach",
      "2 tsp sweet white miso paste",
      "1 tbsp sesame oil",
      "1 poblano pepper (or cubanelle), cut into large strips or rings",
      "1/4 cup tempura mix",
      "1 tsp furikake"
    ],
    "steps": [
      "Cook sushi rice according to package directions, then add half the mirin and the black garlic.",
      "Mix cucumber, half the mirin, half the vinegar, salt and pepper, and sambal oelek to taste. Marinate for at least ten minutes, stirring occasionally.",
      "Mix avocado with half the vinegar, salt, and pepper. Marinate while the rest of the meal cooks.",
      "In a medium bowl, whisk together the miso paste, sesame oil, and 1 teaspoon of warm water. In a large pan, saute spinach in olive oil over medium-high heat, 1-2min until wilted. Transfer to a strainer and squeeze out excess water, then add to the bowl of miso dressing. If needed, season with salt and pepper to taste. Wipe out the pan.",
      "Prepare the tempura batter. In the same pan, heat a thin layer of oil on medium-high until hot. Once hot enough that a drop of batter sizzles immediately when added, working in batches, thoroughly coat the pepper in the batter (letting any excess drip off) and carefully add to the pan. Cook 2 to 4 minutes per side, or until golden brown. Transfer to a paper towel-lined plate; immediately season with salt.",
      "Divide the cooked rice between 2 bowls. Top with the marinated cucumber (including any marinating liquid), miso spinach, pepper tempura, seasoned avocado, and peeled eggs. Garnish with the furikake."
    ],
    "phase": "follikel"
  },
  {
    "title": "Spicy poblano pepper and cheese tortas",
    "kcal": 800,
    "protein": 28,
    "carbs": 78,
    "fat": 38,
    "time": 3000,
    "ingredients": [
      "2 Sandwich Rolls, halved",
      "4 oz Monterey Jack Cheese, grated",
      "1 Avocado",
      "1 Lime, divided",
      "1 Poblano Pepper, seeded and thinly sliced crosswise",
      "1 Vidalia Onion, thinly sliced and divided",
      "2 oz Pickled Goathorn Peppers, roughly chopped",
      "1 large carrot, shredded",
      "3 Radishes, halved and thinly sliced"
    ],
    "steps": [
      "Mash **avocado** with **half the lime juice**, a drizzle of olive oil, and salt and pepper. Set aside.",
      "Caramelize the **onions**; when softened, add **poblano** and cook 3-4 minutes on medium-high heat until lightly-browned and softened. Season to taste.",
      "Mix the **carrot** and **radish** in a bowl. Add the **lime zest** and other half of the **lime juice**, plus 2 tsp of **olive oil**, and salt and pepper to taste. Marinate at least 10 minutes.",
      "Divide **half the Monterey Jack cheese** between the roll bottoms; top with the **onion/poblano**, **goathorn peppers**, and **remaining Monterey Jack cheese**. Season with salt and pepper.  Spread **mashed avocado** on the roll tops, then assemble sandwiches.",
      "Heat a drizzle of oil in a pan over medium heat. Add the tortas and press, 2-3 minutes per side until cheese has melted. Transfer to a cutting board and cut in half on an angle. Serve with carrot/radish slaw on the side."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Chirashi-Style Rice Bowls",
    "kcal": 670,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 2700,
    "ingredients": [
      "3/4 cup Sushi Rice",
      "6 oz Shiitake Mushrooms, stems removed",
      "1 Avocado, medium diced",
      "1/2 lb Broccoli, cut into bite-size florets",
      "1/2 tbsp rice vinegar",
      "2 Rainbow Carrots, thinly sliced at an angle",
      "1 1/2 Tbsp Rice Vinegar",
      "1 1/2 Tbsp Sugar",
      "1 Tbsp Gochujang",
      "1 Tbsp Mirin",
      "1 Tbsp Soy Sauce",
      "1 tsp Furikake",
      "1/4 cup Tempura Mix"
    ],
    "steps": [
      "Preheat the oven to 450°. Place **diced avocado** in a bowl with **vinegar** and salt.",
      "In a small pot, combine the **rice**, a **big pinch of salt**, and **1 ½ cups of water**. Heat to boiling on high. Once boiling, cover and reduce the heat to low. Cook 15 to 17 minutes, or until the water has been absorbed and the rice is tender. Turn off the heat and fluff the cooked rice with a fork.",
      "While the rice cooks, place the **broccoli** on a sheet pan. Drizzle with olive oil and season with salt and pepper. Toss to thoroughly coat. Arrange in a single, even layer. Roast 14 to 16 minutes, or until browned and tender when pierced with a fork. Remove from the oven. Transfer to a large bowl. Set aside in a warm place.",
      "While the broccoli roasts, in a medium pan (nonstick, if you have one), combine the **carrots**, **sugar**, **remaining vinegar**, a **big pinch of salt**, and **¼ cup of water**. Heat to boiling on high. Once boiling, cook, stirring occasionally, 30 seconds to 1 minute, or until the sugar has dissolved. Turn off the heat. Stir in **as much of the gochujang** as you'd like, depending on how spicy you'd like the dish to be. Transfer to a bowl. Set aside to cool, stirring occasionally, for at least 10 minutes. Rinse and wipe out the pan.",
      "While the carrots cool, in a large bowl, combine the **tempura mix** and **¼ cup of cold water**; whisk until smooth. Season with salt and pepper. In the same pan, heat a thin layer of oil on medium-high until hot. Once the oil is hot enough that a drop of batter sizzles immediately when added to the pan, working in batches, thoroughly coat the **mushrooms** in the batter (letting any excess drip off) and carefully add to the pan. Cook 2 to 4 minutes per side, or until golden brown. Transfer to a paper towel-lined plate; immediately season with salt.",
      "To the bowl of **roasted broccoli**, add the **mirin** and **soy sauce**. Toss to thoroughly coat; season with salt and pepper to taste. Divide the **cooked rice** and dressed broccoli between 2 bowls. Top with the **pickled carrots** (reserving the pickling liquid), **seasoned avocado**, and **tempura mushrooms**. Drizzle with the **reserved pickling liquid**. Garnish the rice with the **furikake**."
    ],
    "phase": "luteal"
  },
  {
    "title": "Sweet & Savory Korean Rice Cakes",
    "kcal": 790,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 30,
    "ingredients": [
      "1/2 lb Korean Rice Cakes",
      "2 Cage-Free Farm Eggs",
      "4 oz Shiitake Mushrooms, stems removed, thinly sliced",
      "1 bunch Yu Choy, base removed, roughly chopped",
      "1 Jalapeño Pepper, remove seeds, thinly slice",
      "1 Plum, medium diced and seasoned with salt",
      "1 White Endive, base removed, thinly sliced",
      "1/2 bunch Garlic Chives",
      "3 Tbsps  Roasted Peanuts",
      "2 Tbsps  Black Bean Sauce",
      "2 Tbsps  Butter",
      "2 Tbsps  Crème Fraîche",
      "1 1-Inch Piece Ginger, finely chopped"
    ],
    "steps": [
      "Soft cook the **eggs**. (Bring ½\" water to boil, add eggs, turn down to medium, cover, cook for 6½ minutes. Immediately remove and cool in ice bath.)",
      "While the **eggs** cook, in a large pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium-high until hot. Add the **mushrooms**; cook, stirring occasionally, 3 to 4 minutes, or until lightly browned. Add the **yu choy**; season with salt and pepper. Cook, stirring occasionally, 2 to 3 minutes, or until wilted. Add the **endive**; season with salt and pepper. Cook, stirring occasionally, 1 to 2 minutes, or until softened. Transfer to a bowl; season with salt and pepper to taste.",
      "In the same pan, heat 1 teaspoon of olive oil on medium-high until hot. Add the **ginger**, **seasoned plum**, and as much of the **jalapeño** as you’d like, depending on how spicy you’d like the dish to be; season with salt and pepper. Cook, stirring occasionally, 1 to 2 minutes, or until softened. Add **¾ cup of water**; season with salt and pepper. Cook, stirring occasionally and gently smashing the plum with a spoon, 8 to 9 minutes, or until the plum has broken down. Add the **black bean sauce** and **2 tablespoons of water**. Cook, stirring frequently, 1 to 2 minutes, or until combined. Turn off the heat. Season with salt and pepper to taste.",
      "Once the sauce has cooked for about 10 minutes, add the **rice cakes** to the pot of boiling water. Cook 2 to 3 minutes, or until tender. Reserving **½ cup of the rice cake cooking water**, drain thoroughly. Transfer to the pan of **sauce**; add the **cooked vegetables**, **crème fraîche**, **butter**, **half the garlic chives**, and **half the reserved rice cake cooking water**. Cook on medium-high, stirring frequently, 1 to 2 minutes, or until coated and thoroughly combined. (If the sauce seems dry, gradually add the remaining rice cake cooking water to achieve your desired consistency.) Turn off the heat; season with salt and pepper to taste.",
      "Transfer the **peeled eggs** to a cutting board and halve lengthwise; season with salt and pepper. Divide the **finished rice cakes** between 2 dishes. Top with the seasoned eggs. Garnish with the **peanuts** and **remaining garlic chives**."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Salsa Scramble",
    "kcal": 243,
    "protein": 13,
    "carbs": 5,
    "fat": 19,
    "time": 900,
    "ingredients": [
      "2 large eggs",
      "1/4 cup fresh salsa",
      "2 tbsp fresh cilantro, chopped",
      "2 tsp olive oil"
    ],
    "steps": [
      "Scramble the eggs, then add salsa and cilantro."
    ],
    "phase": "follikel"
  },
  {
    "title": "Cheesy mushroom omelette",
    "kcal": 332,
    "protein": 21,
    "carbs": 4,
    "fat": 26,
    "time": 900,
    "ingredients": [
      "1/2 tbsp olive oil",
      "3 cremini mushrooms (3 ≈ 2oz), sliced",
      "1 oz cheddar cheese, grated",
      "1 tbsp fresh parsley, chopped",
      "2 eggs, beaten"
    ],
    "steps": [
      "Heat the olive oil in a small non-stick frying pan. Tip in the mushrooms and fry over a high heat, stirring occasionally for 2-3 mins until golden. Lift out of the pan into a bowl and mix with the cheese and parsley.",
      "Place the pan back on the heat and swirl the eggs into it. Cook for 1 min or until set to your liking, swirling with a fork now and again.",
      "Spoon the mushroom mix over one half of the omelette. Using a spatula or palette knife, flip the omelette over to cover the mushrooms. Cook for a few moments more, lift onto a plate and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Black Forest Bircher (overnight oats)",
    "kcal": 268,
    "protein": 11,
    "carbs": 111,
    "fat": 23,
    "time": 600,
    "ingredients": [
      "1 small pear, grated",
      "1/4 cup rolled oats",
      "1/2 tbsp unsweetened cocoa powder",
      "1/4 cup Greek yogurt",
      "2 tbsp milk",
      "1/2 tbsp honey, plus extra to serve (optional)",
      "1/2 cup cherries, halved and pitted",
      "2 tbsp Greek yogurt",
      "1 oz semisweet chocolate chips"
    ],
    "steps": [
      "Combine the pears, oats, cocoa powder, yogurt, milk and honey in a bowl. Divide between two bowls (or containers if you’re taking it to work).",
      "Top each serving with some cherries, 1 tbsp yogurt and a little extra honey, if you like. Top with chocolate chips. Eat straight away or chill in the fridge for up to 2 days."
    ],
    "phase": "luteal"
  },
  {
    "title": "Almond muffin in a minute",
    "kcal": 327,
    "protein": 12,
    "carbs": 23,
    "fat": 23,
    "time": 240,
    "ingredients": [
      "1/4 cup almond meal/flour",
      "1 tsp granulated sugar",
      "1/4 tsp baking powder",
      "1 dash salt",
      "1/2 tsp vanilla extract",
      "1 large egg",
      "1 tsp olive oil"
    ],
    "steps": [
      "Place all dry ingredients in a coffee mug. Stir to combine.",
      "Add the vanilla, egg, and oil. Stir until thoroughly combined.",
      "Microwave for 1 minute. Use a knife if necessary to help remove the muffin from the cup, slice, butter, eat."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Pesto Cavatelli w/ Mushrooms and Spicy Breadcrumbs",
    "kcal": 639,
    "protein": 20,
    "carbs": 74,
    "fat": 30,
    "time": 2100,
    "ingredients": [
      "6 oz cavatelli pasta",
      "2 clove garlic, finely chopped",
      "4 oz cremini Mushrooms, thinly sliced",
      "1/4 cup Basil & Cashew Pesto",
      "1/4 tsp Crushed Red Pepper Flakes",
      "1/4 cup Panko",
      "1 Tbsp  mascarpone cheese",
      "1 oz Roasted Piquillo Peppers, diced",
      "1 Zucchini, halved and thinly sliced"
    ],
    "steps": [
      "Heat a medium pot of salted water to boiling on high.",
      "In a medium pan, heat 2 teaspoons of olive oil on medium-high until hot. Add the **breadcrumbs** and half the **chopped garlic**; season with salt and pepper. Cook, stirring frequently, 2 to 3 minutes, or until golden brown. Turn off the heat and add the red pepper flakes, salt, and pepper. Transfer to a plate. Wipe out the pan.",
      "While the breadcrumbs toast, add the **pasta** to the pot of boiling water. Cook, stirring occasionally, 9 to 11 minutes, or until al dente (still slightly firm to the bite). Turn off the heat. Reserving ½ cup of the pasta cooking water, drain thoroughly and return to the pot.",
      "While the pasta cooks, in the same pan, heat 2 teaspoons of olive oil on medium-high until hot. Add the **sliced mushrooms** in an even layer and cook, without stirring, 3 to 4 minutes, or until lightly browned. Continue to cook, stirring occasionally, 1 to 2 minutes, or until browned. Add the **sliced zucchini** and remaining **chopped garlic**; season with salt and pepper. Cook, stirring frequently, 4 to 5 minutes, or until lightly browned. Turn off the heat and season with salt and pepper to taste.",
      "To the pot of **cooked pasta**, add the **cooked vegetables**, **mascarpone cheese**, and half the reserved pasta cooking water. Cook on medium-high, stirring vigorously, 1 to 2 minutes, or until coated. If the pasta seems dry, gradually add the remaining pasta cooking water to achieve your desired consistency. Turn off the heat. Stir in the **pesto** and **chopped peppers** until thoroughly combined. Season with salt and pepper to taste. Serve the finished pasta garnished with the spicy breadcrumbs."
    ],
    "phase": "follikel"
  },
  {
    "title": "Black bean mini burgers",
    "kcal": 234,
    "protein": 10,
    "carbs": 40,
    "fat": 6,
    "time": 1380,
    "ingredients": [
      "1 15oz can black beans, drained and chopped up finely in food processor",
      "1/3 cup bread crumbs",
      "1 medium onion, finely chopped and sauteed until translucent",
      "2 tbsp cilantro, finely chopped",
      "1 tsp taco seasoning",
      "1/8 cup tempura mix",
      "1 tbsp vegetable oil",
      "salsa, for dipping"
    ],
    "steps": [
      "Mix all the ingredient, except the oil,very well with your hands to a paste-like consistency and form into mini-burgers, pressing each one together firmly. Pan-fry in oil over low heat, turning gently so they don't fall apart. Pack some salsa as a dip."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mini hamburger bento (Select a mini burger recipe too)",
    "kcal": 348,
    "protein": 9,
    "carbs": 62,
    "fat": 7,
    "time": 30,
    "ingredients": [
      "1 serving mini burger recipe",
      "1 2-inch length of carrot, sliced into 1/4 inch rounds",
      "1/2 oz cheese",
      "1/2 medium red onion, very thinly sliced",
      "salt",
      "1/4 cup parsley, loosely packed, finely chopped",
      "black pepper",
      "1 tsp rice vinegar",
      "1 pinch sugar",
      "1/4 cup snow peas",
      "1 cup cooked short-grain white rice",
      "sesame salt, for sprinkling"
    ],
    "steps": [
      "1. Make or reheat mini burgers, pack into bento box to cool.\n2. For carrots: cut out decorative flowers with a small bento cutter. Boil in salted water for 5 minutes or until the carrot slices are tender. Let cool before adding to the bento box.\n3. For cheese (optional): cut out decorative flowers from sliced cheese. Alternatively, cut into small cubes.\n4. For red onion salad: sprinkle the onion with a pinch of salt and massage the salt well into the onion with your hands. Squeeze the onion to expel as much moisture as possible. In a bowl, mix the onion, parsley, vinegar, and sugar. Season with pepper to taste. Pack into a cupcake liner or bento divider cup.\n5. For snow peas: Blanch in boiling water for a few minutes until crisp-tender. Drain and cool rapidly under running water. Drain well before adding to bento box.\n6. For rice: Pack rice into the bento box and sprinkle with the sesame salt."
    ],
    "phase": "luteal"
  },
  {
    "title": "Avocado, olive tapenade, and chedder toast",
    "kcal": 387,
    "protein": 11,
    "carbs": 22,
    "fat": 29,
    "time": 300,
    "ingredients": [
      "1 slice bread, toasted",
      "1 tbsp olive tapenade",
      "1 slice cheddar cheese",
      "1/2 avocado, sliced",
      "1 tsp olive oil",
      "Flaky sea salt, for serving",
      "Crushed red pepper, for serving"
    ],
    "steps": [
      "Spread toast with tapenade. Top with cheddar and avocado, pressing down to secure the avocado slices. Drizzle with the oil and sprinkle with flaky sea salt and red pepper flakes."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Cozy bean and egg skillet for two",
    "kcal": 357,
    "protein": 18,
    "carbs": 46,
    "fat": 14,
    "time": 720,
    "ingredients": [
      "1 tbsp olive oil",
      "1 clove garlic, pressed",
      "1 tsp fresh thyme, plus more for garnish",
      "1/2 can pinto beans, rinsed",
      "1/2 cup water",
      "1/4 tsp Kosher salt",
      "1/4 tsp Freshly ground black pepper",
      "2 eggs",
      "2 slices toast"
    ],
    "steps": [
      "Heat the oil in a small skillet over medium-high heat. Add the garlic and thyme and cook until the garlic is fragrant, about 45 seconds. Stir in the beans, water, and pepper (if the beans are unsalted, add a little salt, too). Turn the heat up to high and cook, stirring here and there and smashing the beans with your spatula, until the beans are saucy and the liquid is creamy, 2 to 4 minutes.",
      "Using your spatula, make wells in the beans, one for each egg. Crack the eggs into the wells one at a time, then cover and cook until the whites are set but the yolks still jiggle when you shake the pan a bit, 1 to 2 minutes.",
      "Taste, garnish with thyme leaves and season with a little more salt and pepper. Eat right away with toasted and oiled bread, if you want."
    ],
    "phase": "follikel"
  },
  {
    "title": "Whipped eggs on toast",
    "kcal": 436,
    "protein": 16,
    "carbs": 28,
    "fat": 28,
    "time": 900,
    "ingredients": [
      "2 eggs",
      "2 slices bread",
      "1 tablespoon dijon mustard",
      "1 tablespoon mayonnaise",
      "1/2 tablespoon fresh chives, finely chopped"
    ],
    "steps": [
      "Lightly toast bread. Preheat oven to 325F.",
      "Carefully separate eggs, keeping yolks whole.",
      "Add a pinch of salt to the whites, then beat into soft peaks. Spoon into puffy mounds on center of toasts; shape a hollow in the top and slip a yolk into each.",
      "Bake for 4-5 minutes, spoon 1 tablespoon of dressing over yolks, then bake 4-5 minutes more, or until whites are beginning to turn golden and yolks set to your liking.",
      "Sprinkle with the chives and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Peach & Pickled Pepper Grilled Cheese",
    "kcal": 620,
    "protein": 27,
    "carbs": 48,
    "fat": 34,
    "time": 1500,
    "ingredients": [
      "4 slices white sandwich bread",
      "1/2 oz sweet piquante peppers, roughly chopped",
      "1 peach, pitted and thinly sliced",
      "2 oz fontina cheese, thinly sliced",
      "2 oz white cheddar cheese, thinly sliced",
      "1 tbsp butter",
      "1 clove garlic",
      "3 cup salad greens, washed and torn",
      "3 oz radishes, halved and thinly sliced",
      "1/2 tbsp dijon mustard",
      "1/2 tbsp mayonnaise",
      "1 tsp olive oil",
      "1 tbsp apple cider vinegar",
      "salt and pepper",
      "1 oz goat cheese"
    ],
    "steps": [
      "Assemble sandwiches with **bread**, **cheese**, **peach**, and **peppers**. Season with salt and pepper. Melt **butter** over medium heat, and cook sandwiches 2-4 minutes per side until golden brown. When finished, rub with **garlic clove** and season if desired.",
      "While the sandwiches cook, whisk together the **mustard**, **mayo**, **vinegar**, **olive oil**, and a pinch of **salt and pepper**. Toss the **lettuce**, **radish**, and **goat cheese** with the dressing. Serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Black bean and zucchini enchiladas",
    "kcal": 690,
    "protein": 26,
    "carbs": 85,
    "fat": 22,
    "time": 2700,
    "ingredients": [
      "1/4 cup dried White Jasmine Rice",
      "1/2 tbsp Mexican spice blend",
      "1/2 cup water",
      "2 tsp olive oil",
      "1 Zucchini, medium diced",
      "1/2 15-Ounce Can Black Beans, drained and rinsed",
      "1 Tbsp White Wine Vinegar",
      "2 Scallions, thinly slice, white and green parts separated",
      "2 Tbsp Tomato Paste",
      "2 Tbsp Ancho Chile Paste",
      "1/2 cup water",
      "1/4 cup Sour Cream Or Mexican Crema",
      "4 small flour tortillas",
      "2 oz White Cheddar Cheese, grated"
    ],
    "steps": [
      "Preheat the oven to 450°F. In a small pot, combine the **rice**, a big pinch of salt, the **spice blend**, and **water**. Heat to boiling on high. Once boiling, reduce the heat to low. Cover and cook, without stirring, 12 to 14 minutes, or until the water has been absorbed and the rice is tender. Turn off the heat and fluff with a fork. Transfer to a large bowl.",
      "While the rice continues to cook, in a large pan (nonstick, if you have one), heat **olive oil** on medium-high until hot. Add the diced **zucchini** in an even layer. Cook, without stirring, 3 to 4 minutes, or until lightly browned. Season with salt and pepper. Continue to cook, stirring frequently, 2 to 3 minutes, or until softened. Transfer to the bowl of cooked rice. Add the **beans**, **vinegar**, and a drizzle of olive oil. Season with salt and pepper and stir to combine. Wipe out the pan.",
      "In the same pan, heat a drizzle of olive oil on medium-high until hot. Add the sliced **white bottoms of the scallions**; season with salt and pepper. Cook, stirring frequently, 30 seconds to 1 minute, or until slightly softened. Add the **tomato paste** and **chile paste**. Cook, stirring frequently, 1 to 2 minutes, or until thoroughly combined. Add **water** (carefully, as the liquid may splatter). Cook, stirring constantly, 30 seconds to 1 minute, or until slightly thickened. Turn off the heat. Stir in the **sour cream or crema** and season with salt and pepper to taste.",
      "Spread a thin layer of sauce into the bottom of a baking dish. Place the **tortillas** on a work surface. Divide the filling among the tortillas; tightly roll up each tortilla around the filling. Transfer to the baking dish in an even layer, seam side down. Evenly top with the remaining sauce and **grated cheese**. Season with salt and pepper.",
      "Bake the enchiladas 7 to 9 minutes, or until lightly browned and the cheese is melted. Remove from the oven. Let stand at least 2 minutes before serving. Garnish the baked enchiladas with the sliced **green tops of the scallions**. Enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Banh Mi Sandwiches with Roasted Broccoli",
    "kcal": 770,
    "protein": 18,
    "carbs": 87,
    "fat": 41,
    "time": 2400,
    "ingredients": [
      "1/2 lb Broccoli, cut into small florets",
      "1/2 lb Cremini Mushrooms, quartered",
      "1 1-Inch Piece Ginger, peeled and finely chopped",
      "1/4 cup Mayonnaise",
      "1 Tbsp Sambal Oelek",
      "3 oz Radishes, thinly sliced into half-moons",
      "6 oz Carrots, grated",
      "1 Tbsp Sugar",
      "2 Tbsp Rice Vinegar",
      "2 Small Baguettes, halved",
      "1/2 tsp Black sesame seeds",
      "1/2 tsp White Sesame Seeds",
      "Olive oil",
      "Salt",
      "Black pepper"
    ],
    "steps": [
      "Place an oven rack in the center of the oven, then preheat to 450°F. Line a sheet pan with aluminum foil. Place **broccoli** on the sheet pan. Drizzle with olive oil and season with salt and pepper; toss to coat. Arrange in an even layer. Roast 19 to 21 minutes, or until lightly browned and tender when pierced with a fork. Leaving the oven on, transfer the roasted broccoli to a bowl. Reserving the sheet pan, remove and discard the foil.",
      "To make the spicy mayonnaise, in a bowl, combine the **mayonnaise** and as much of the **sambal oelek** as you’d like, depending on how spicy you’d like the dish to be. Season with salt and pepper to taste. In a medium bowl, combine the sliced **radishes**, **grated carrots**, **sugar**, and **vinegar**; season with salt and pepper. Set aside to marinate, stirring occasionally, for at least 10 minutes. Season with salt and pepper to taste.",
      "While the vegetables marinate, in a medium pan (nonstick, if you have one), heat 2 tablespoons of olive oil on medium-high until hot. Add the quartered **mushrooms** in an even layer. Cook, without stirring, 2 to 3 minutes, or until lightly browned and slightly softened; season with salt and pepper. Continue to cook, stirring occasionally, 2 to 3 minutes, or until softened. Add the chopped **ginger**; season with salt and pepper. Cook, stirring frequently, 1 to 2 minutes, or until softened. Turn off the heat and season with salt and pepper to taste.",
      "Place the halved **baguettes** cut side up on the sheet pan used to roast the broccoli. Drizzle with olive oil and season with salt and pepper. Toast in the oven 5 to 7 minutes, or until the edges are lightly browned. Carefully transfer to a work surface.",
      "While the baguettes toast, reserving the liquid, drain the marinated vegetables. Set aside. Add the reserved marinating liquid and **sesame seeds** to the bowl of roasted broccoli; stir to coat. Season with salt and pepper to taste.",
      "Build the sandwiches using the toasted baguettes, spicy mayonnaise, cooked mushrooms, and marinated vegetables. Serve the sandwiches with the dressed broccoli. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Roasted Sweet Potato Quesadillas",
    "kcal": 666,
    "protein": 23,
    "carbs": 79,
    "fat": 27,
    "time": 2400,
    "ingredients": [
      "1 sweet potato, sliced into ¼\" rounds",
      "1/2 tbsp mexican spice",
      "2 cup salad greens",
      "1/2 avocado, sliced",
      "1 shallot, thinly sliced",
      "1 tbsp sugar",
      "1 lime, divided and juiced",
      "1/4 cup water",
      "3 oz white cheddar cheese, grated",
      "1 jalapeño (preferably pickled), roughly chopped",
      "2 tbsp cotija cheese, grated",
      "2 oz sweet piquante peppers, rough chopped",
      "4 flour tortillas"
    ],
    "steps": [
      "Preheat oven to 450°F. Prepare a baking sheet with foil. Place **sweet potato** slices in a single layer, then drizzle with olive oil, salt, pepper, and **mexican spice**. Roast 18-20 minutes, until brown and tender.",
      "In a small pot, combine **shallot**, **sugar**, 3/4 of the **lime juice**, **1/4 cup of water**, and salt and pepper. Heat to boiling on high; once boiling, cook 1-2 minutes, stirring occasionally, until the sugar has dissolved. Set aside to cool for at least 10 minutes.",
      "Prepare the avocado: slice it, then place in a bowl. Squeeze remaining ¼ of lime juice over it, season with salt and pepper, and lightly toss. Set aside to season.",
      "When the sweet potato is done roasting, prepare the quesadillas. Top one half of each **tortilla** with half the **cheddar**, the **sweet potatoes**, the **piquante peppers**, and the **jalapeño**, finishing with the remaining cheddar. Fold in half.",
      "In a large pan, heat 2 tsp of oil on medium. Cook the quesadillas 2-3 minutes per side, until lightly browned and the cheese is melted.",
      "To prepare the salad, put the salad greens in a salad bowl, and top with the pickled shallots and half the pickling liquid. (The rest is unused.) Drizzle with olive oil, salt, and pepper, and toss to combine. Top with avocado and **cotija** when serving."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Baked macaroni and cheese",
    "kcal": 608,
    "protein": 26,
    "carbs": 47,
    "fat": 36,
    "time": 30,
    "ingredients": [
      "8 ounce elbow macaroni",
      "3 tablespoon unsalted butter",
      "3 tablespoon all-purpose flour",
      "1 tablespoon ground mustard",
      "1 teaspoon smoked paprika",
      "1/2 cup onion, diced small",
      "3 cup whole milk",
      "1 large egg",
      "9 ounce sharp cheddar cheese, grated",
      "1 teaspoon kosher salt",
      "1/2 teaspoon black pepper, freshly ground",
      "3 ounce sharp cheddar cheese, grated",
      "3 tablespoon unsalted butter, melted",
      "1 cup panko breadcrumbs"
    ],
    "steps": [
      "Heat the oven to 350 degrees F.",
      "Place dry pasta in a 4-quart pot and barely cover with cold water. Bring just to a boil over high heat, stirring occasionally, then test for doneness. You’re looking for al dente, that is the noodles should put up some resistance to the tooth but not so much that it gums up in your back teeth. Drain pasta in a colander but do not rinse.",
      "Meanwhile, melt the butter in a 3-quart saucier or saucepan over medium heat. Whisk in the flour and cook until the mixture is pale blond, stirring occasionally, about 3 minutes. Whisk in the mustard, paprika and onion and cook another minute. Whisk in the milk and cook over medium-high heat, whisking often for 7 to 8 minutes, or until slightly thickened. Remove from the heat.",
      "Lightly beat the egg in a small bowl then drizzle in about half a cup of the milk mixture, whisking constantly. Then, whisk the egg mixture into to the milk mixture. (This common maneuver called “tempering” prevents curdling of the egg by slowly increasing their temperature. Skip this and you’ll be making scrambled eggs.) Stir in the cheese, 1 teaspoon salt and the pepper. Fold in the macaroni then move to a 4-quart casserole or soufflé dish.",
      "Sprinkle with the remaining cheese, then toss the breadcrumbs with the melted butter and distribute evenly over the top. Bake for 30 minutes, cool for 5 minutes, then serve to a grateful world."
    ],
    "phase": "luteal"
  },
  {
    "title": "Cavatelli and kale with fried rosemary and walnuts",
    "kcal": 831,
    "protein": 22,
    "carbs": 81,
    "fat": 50,
    "time": 2100,
    "ingredients": [
      "1 bunch Rosemary, stems removed",
      "1/4 cup Walnuts, roughly chopped",
      "6 oz dried cavatelli pasta",
      "2 tsp olive oil",
      "1 Shallot, peeled and thinly sliced",
      "2 clove Garlic, peeled and roughly chopped",
      "1 bunch Kale, washed, stems removed, roughly chopped",
      "1/4 tsp Crushed Red Pepper Flakes",
      "2 Tbsp White wine vinegar",
      "1/4 cup Heavy Cream",
      "2 Tbsp Butter",
      "1/2 cup reserved pasta cooking water",
      "2 Tbsp Parmesan, grated"
    ],
    "steps": [
      "Heat a medium pot of salted water to boiling on high.",
      "Fry the rosemary & walnuts: \nIn a large pan, heat a thin layer of oil on medium-high until hot. Once the oil is hot enough that a rosemary leaf sizzles immediately when added to the pan, add the rosemary and walnuts. Cook, stirring frequently, 2 to 3 minutes, or until the rosemary is crispy and the walnuts are golden brown. Leaving any oil in the pan, transfer the fried rosemary and walnuts to a paper towel-lined plate. Immediately season with salt and pepper.",
      "Add the pasta to the pot of boiling water; cook according to package instructions or until al dente (still slightly firm to the bite). Reserving 1/2 cup of the pasta cooking water, drain thoroughly.",
      "Cook the kale:\nAdd 2 teaspoons of olive oil, the shallot, and the garlic to the pan; season with salt and pepper. Cook on medium-high, stirring occasionally, 2 to 3 minutes, or until softened and fragrant. Add the kale and as much of the red pepper flakes as you’d like, depending on how spicy you’d like the dish to be; season with salt and pepper. Cook, stirring frequently, 3 to 4 minutes, or until the kale has wilted. Add the vinegar (be careful, as the liquid may splatter) and cook, stirring constantly, 30 seconds to 1 minute, or until the liquid has cooked off. Add the heavy cream and cook, stirring constantly, 30 seconds to 1 minute, or until thoroughly combined. Turn off the heat and season with salt and pepper to taste.",
      "Add the cooked pasta, butter, and half the reserved pasta cooking water to the pan of cooked kale. Cook on medium-high, stirring vigorously, 1 to 2 minutes, or until the pasta is thoroughly coated. (If the pasta seems dry, gradually add the remaining cooking water to achieve your desired consistency.) Turn off the heat and season with salt and pepper to taste. Divide the finished pasta between 2 dishes. Drizzle with olive oil. Top with the fried rosemary and walnuts. Garnish with the cheese. Enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Falafel with Spicy Feta Sauce and Vegetable Salad",
    "kcal": 588,
    "protein": 24,
    "carbs": 46,
    "fat": 35,
    "time": 32700,
    "ingredients": [
      "8 oz dried chickpeas",
      "1/2 oz fresh parsley",
      "1/2 oz fresh cilantro",
      "6 green onions, sliced",
      "3 clove garlic, sliced",
      "1 tbsp kosher salt",
      "1 1/2 tsp ground cumin",
      "3/4 tsp ground coriander",
      "1/4 tsp cayenne pepper",
      "8 oz feta cheese (block form)",
      "1 clove garlic, chopped",
      "1/2 teaspoon dried oregano",
      "1/2 teaspoon red pepper flakes",
      "1/4 cup olive oil",
      "2 tablespoon water",
      "1 teaspoon lemon juice",
      "1/2 cup red onion, thinly sliced",
      "1 cup cherry tomatoes, halved",
      "1 cup English cucumber, thinly sliced into half-moons",
      "2 oz kalamata olives, pitted and roughly chopped",
      "2 tbsp olive oil",
      "1 tbsp red wine vinegar"
    ],
    "steps": [
      "Rinse chickpeas and place in a large bowl. Cover with enough cold water to allow chickpeas to triple in volume. Cover and let stand at room temperature overnight.",
      "The next day, rinse chickpeas and let drain thoroughly in a strainer while preparing remaining ingredients.",
      "Combine all falafel ingredients in the bowl of a food processor. Process until finely ground, about 30 seconds, stopping to scrape down the sides of the bowl as necessary.",
      "Transfer mixture to a medium bowl and cover. Refrigerate for 20 minutes before forming falafel. Prepare sauce while mixture is resting.",
      "Scoop two heaping tablespoons per falafel and gently form into a slightly flattened ball. Place falafel on the airfry basket, being careful not to press down.",
      "Select AIRFRY/450°F/SUPER CONVECTION/15 minutes and press START to preheat oven.\nCook in rack position 4 until lightly browned and cooked through, about 15 minutes.",
      "--------",
      "Meanwhile, combine feta, garlic, oregano and pepper flakes in the bowl of a food processor. Process until feta is broken down and smooth, about 30 seconds. Scrape down the sides of the bowl.",
      "With the machine running, add the olive oil through the feed tube and process until incorporated. Combine water and lemon juice in a small bowl. With the machine running, add the lemon juice mixture through the feed tube and process until a sauce forms. Set aside.",
      "-------",
      "In a large bowl, whisk together olive oil and red wine vinegar. Season to taste with salt and black pepper. Add red onion, tomatoes, cucumber, and olives to bowl. Toss to combine.",
      "Serve falafel immediately with salad, topping both with spicy feta sauce and serving remainder on the side of the plate."
    ],
    "phase": "follikel"
  },
  {
    "title": "Pickled Beet & Hard-Boiled Egg Sandwiches with Smoky Mayonnaise",
    "kcal": 760,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 3300,
    "ingredients": [
      "2 Eggs",
      "2 Tbsp  Mayonnaise",
      "1 1/2 Tbsp  Capers, roughly chopped",
      "1 clove Garlic, pressed",
      "1/8 tsp Smoked Paprika",
      "2 Carrots, quartered lengthwise and cut crosswise into 2-inch pieces",
      "1 Red Beet, see instructions for prep",
      "1/4 cup Red Wine Vinegar",
      "1 Shallot, peeled and thinly sliced",
      "3/4 cup water",
      "2 Ciabatta Rolls, halved",
      "1 tbsp Dill, roughly chopped",
      "1/4 cup Crumbled Feta Cheese",
      "2 oz Baby arugula"
    ],
    "steps": [
      "Preheat the oven to 475°F. Heat a small pot of water to boiling on high. Once boiling, add the **eggs** and cook for exactly 10 minutes. Drain thoroughly and rinse under cold water for 30 seconds to 1 minute to stop the cooking process. When cool enough to handle, carefully peel the cooked eggs. Transfer to a cutting board and thinly slice; season with salt and pepper. Wipe out the pot.",
      "While the eggs cook, prep remaining ingredients. For the **beet**: On a paper towel-lined cutting board, peel and thinly slice. In a bowl, combine the **mayonnaise**, **capers**, **paprika**, and as much of the **garlic**  as you'd like. Season with salt and pepper to taste.",
      "Place the **carrots** on a sheet pan. Drizzle with olive oil and season with salt and pepper; toss to thoroughly coat. Arrange in a single, even layer. Roast, stirring halfway through, 14 to 16 minutes, or until tender when pierced with a fork. Remove from the oven.",
      "While the carrots roast, in the same pot, combine the **beet**, **vinegar**, **shallot**, and **water**. Season with salt and pepper. Heat to boiling on high. Once boiling, cover and cook, stirring occasionally, 8 to 10 minutes, or until tender when pierced with a fork. Turn off the heat. Season with salt and pepper to taste.",
      "While the carrots continue to roast, place the **rolls** on a clean, dry work surface. Spread a layer of the **smoky mayonnaise** onto the cut sides of the rolls. Reserving the **pickling liquid**, drain the pickled beet. Divide the **beet**, sliced **eggs**, **cheese**, and as much of the **dill** as you'd like between the roll bottoms. Season with salt and pepper. Complete the sandwiches with the roll tops. In a medium pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium until hot. Add the sandwiches. Place a heavy-bottomed pot (or pan) on top of the sandwiches; press down. Cook, occasionally pressing down on the pot, 2 to 3 minutes per side, or until lightly browned and slightly flattened. Transfer to a cutting board and cut in half on an angle.",
      "While the sandwiches cook, to make the dressing, place the **reserved pickling liquid** in a bowl; slowly whisk in 1 tablespoon of olive oil until well combined. Season with salt and pepper to taste. In a large bowl, combine the **baby greens** and **roasted carrots**; season with salt and pepper. Add enough of the dressing to coat the salad (you may have extra dressing); toss to combine. Season with salt and pepper to taste. Divide the cooked sandwiches and salad between 2 dishes. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Butternut Squash & Fontina Calzones with Apple & Arugula Salad",
    "kcal": 800,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 3300,
    "ingredients": [
      "1 1/2 lb Plain Pizza Dough",
      "1 15-Ounce Can Crushed Tomatoes",
      "3 oz Fontina Cheese, shredded or medium diced",
      "4 clove Garlic, minced",
      "3 oz Arugula",
      "1 Honeycrisp Apple, cored and cut into matchsticks",
      "1 bunch Lacinato Kale, stems removed, roughly chop leaves",
      "1 Butternut Squash, medium diced, see instructions",
      "1 Lemon, quartered",
      "2 Tbsps Semolina Flour",
      "1/2 cup Grated Parmesan Cheese",
      "1 tsp Calzone Spice Blend (Italian Seasoning & Ground Nutmeg)"
    ],
    "steps": [
      "1. Prepare the ingredients:\nRemove the **dough** from the refrigerator. Preheat the oven to 475°F. Wash and dry the fresh produce. Cut off and discard the **squash** ends; using a knife, peel, then separate the neck and bulb. Halve the bulb; scoop out and discard the pulp and seeds, then medium dice the squash. Toss **apple** matchsticks with the juice of 1 **lemon wedge**.",
      "2. Make the filling: \nIn a large pan (nonstick, if you have one), heat 1 tablespoon of olive oil on medium-high until hot. Add the **squash**; season with salt and pepper. Cook, stirring occasionally, 8 to 10 minutes, or until browned and tender. Add the **kale**, **spice blend** and **half the garlic**; season with salt and pepper. Cook, stirring occasionally, 2 to 4 minutes, or until the kale has wilted. Add ⅓ of the **tomatoes**. Cook, stirring frequently, 30 seconds to 1 minute, or until well combined. Remove from heat; season with salt and pepper to taste.",
      "3. Assemble the calzones:\nSprinkle **half the flour** onto a work surface. Divide the **dough** into 4 equal-sized portions; using your hands, gently stretch into ¼-inch-thick rounds. (If the dough is resistant, let rest for 5 minutes.) Divide the filling (you may have extra) between the rounds; top with the **Fontina cheese** and **half the Parmesan cheese**. Season with salt and pepper. Fold each round in half over the filling. Using your fingers or a fork, press or crimp the edges of the dough to seal.",
      "4. Bake the calzones:\nSprinkle the **remaining flour** onto a large sheet pan. Carefully transfer the calzones to the prepared sheet pan; lightly drizzle or brush the tops with olive oil. Bake 16 to 18 minutes, or until browned on top. Remove from the oven and let stand for 2 minutes. Transfer to a serving dish.",
      "5. Make the tomato sauce:\nWhile the calzones bake, wipe out the pan used to make the filling. Add 2 teaspoons of olive oil and heat on medium until hot. Add the **remaining garlic** and season with salt and pepper. Cook, stirring frequently, 30 seconds to 1 minute, or until fragrant. Add the **remaining tomatoes** and ¼ cup of **water**. Cook, stirring occasionally, 2 to 3 minutes, or until thickened and saucy; season with salt and pepper to taste. Transfer to a serving dish.",
      "6. Make the salad & serve your dish:\nWhile the calzones continue to bake, to make the dressing, in a bowl, combine the **remaining Parmesan cheese** and the juice of the **remaining lemon wedges**. Slowly whisk in 2 tablespoons of olive oil until well combined; season with salt and pepper to taste. Just before serving, in a bowl, combine the **arugula** and **apple**. Add enough of the dressing to coat (you may have extra). Toss to mix; season with salt and pepper to taste. Transfer to a serving dish. Serve with the baked calzones and tomato sauce. Enjoy!"
    ],
    "phase": "luteal"
  },
  {
    "title": "Egg, cucumber, and smoked gouda spread sandwiches",
    "kcal": 543,
    "protein": 20,
    "carbs": 48,
    "fat": 30,
    "time": 2040,
    "ingredients": [
      "2 Persian cucumbers, thinly sliced on an angle",
      "1 Tbsp sugar",
      "1/2 Tbsp apple cider vinegar",
      "2 eggs",
      "2 small baguettes or rolls, cut in half and some inner bread removed",
      "2 oz smoked Gouda cheese, grated",
      "2 Tbsp mayonnaise",
      "1/2 Tbsp Southern Spice Blend",
      "1 oz pickled jalapenos, chopped",
      "1 Tbsp Dijon mustard",
      "1/2 Tbsp apple cider vinegar",
      "1 Tbsp olive oil",
      "1 persimmon (pear or apple can be substituted), cored and thinly sliced",
      "3 cup lettuce"
    ],
    "steps": [
      "Place an oven rack in the center of the oven, then preheat to 450°F. Fill a small pot 3/4 of the way up with water; cover and heat to boiling on high. Place cucumber slices in a bowl. Add the sugar and the vinegar; season with salt and pepper. Toss to thoroughly coat. Set aside to marinate, stirring occasionally, at least 10 minutes. Taste, then season with salt and pepper if desired.",
      "While the cucumbers marinate, carefully add the eggs to the pot of boiling water. Cook 9 minutes. Drain thoroughly and rinse under cold water 30 seconds to 1 minute to stop the cooking process. When cool enough to handle, peel the cooked eggs. Transfer to a cutting board. Thinly slice, then season with salt and pepper.",
      "Meanwhile, place the halved baguettes on a sheet pan, cut side up. Drizzle with olive oil. Toast 4 to 5 minutes, or until lightly browned around the edges. Transfer to a work surface.",
      "Meanwhile, in a bowl, combine the mayonnaise, grated cheese, the spice blend, and as much of the chopped pepper as you’d like, depending on how spicy you’d like the dish to be. Season with salt and pepper; stir to combine. Taste, then season with salt and pepper if desired.",
      "Assemble the sandwiches using the toasted baguettes, smoked gouda spread, marinated cucumbers (discarding any liquid), and sliced eggs. Carefully halve the sandwiches on an angle. To make the dressing, in a large bowl, combine the mustard and remaining vinegar; season with salt and pepper. Slowly whisk in olive oil. Add lettuce and persimmon. Toss to coat. Serve the sandwiches with the salad on the side. Enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Indian-style paneer and creamy tomato curry",
    "kcal": 727,
    "protein": 28,
    "carbs": 80,
    "fat": 34,
    "time": 2100,
    "ingredients": [
      "1/2 cup long-grain white rice, uncooked",
      "1 cup water",
      "4 oz paneer cheese, medium diced",
      "2 clove garlic, roughly chopped",
      "1 1-inch piece ginger, finely chopped",
      "1 zucchini, halved lengthwise, then thinly slice crosswise",
      "2 tbsp tomato paste",
      "2 tbsp savory tomato chutney",
      "1 15.5oz can chickpeas, *undrained*",
      "1/4 cup heavy cream"
    ],
    "steps": [
      "1. In a small pot, combine the rice, a big pinch of salt, and water. Heat to boiling on high. Once boiling, reduce heat to low. Cover and cook, without stirring, 12 to 14 minutes, or until the water has been absorbed and the rice is tender. Turn off the heat and fluff with a fork.",
      "2. While the rice cooks, in a large pan (nonstick, if you have one), heat a thin layer of oil on medium. Once the oil is hot enough that a piece of cheese sizzles immediately when added, add the diced cheese in an even layer. Cook stirring halfway through (carefully, as the cheese may pop), 4 to 6 minutes, or until lightly browned and crispy. Transfer to a paper towel-lined plate and immediately season with salt. Wipe out the pan.",
      "3. In the same pan, heat a drizzle of olive oil on medium-high until hot. Add the sliced zucchini, season with salt and pepper. Cook, stirring occasionally, 2-3 minutes, or until slightly softened. Add the garlic and ginger and cook, stirring frequently, for about 1 minute, or until fragrant.",
      "4. Add the tomato paste and chutney to the pan. Cook, stirring frequently, 30 seconds to 1 minute, or until thoroughly combined. Add the chickpeas and juice (careful, as the liquid may splatter); season with salt and pepper. Cook stirring occasionally, 5 to 6 minutes, or until slightly thickened.",
      "5. Add the cream and browned cheese. Cook, stirring frequently, 30 seconds to 1 minute, or until thoroughly combined. Turn off the heat. Season with salt and pepper to taste. Serve the curry over the cooked rice. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Smoky Brussels Sprouts & Black Bean Tacos",
    "kcal": 740,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 2100,
    "ingredients": [
      "4 flour tortillas",
      "1 can black beans, drained and rinsed",
      "1 lb sweet potatoes, sliced thin for roasting",
      "1/2 lb brussels sprouts, shredded",
      "2 scallions, diced, greens and whites divided",
      "1 tbsp light brown sugar",
      "2 tsp chipotle chili paste",
      "1/4 cup sour cream",
      "1 tbsp rice vinegar"
    ],
    "steps": [
      "Preheat the oven to 450°. Toss **potatoes** with oil, salt, and pepper, and roast for 22 minutes (until browned and tender).",
      "Add oil to a large pan. When hot, add the **brussels sprouts**, **chili paste**, salt, and pepper. Saute, stirring occasionally, until browned and tender, about 5 minutes. Transfer to bowl.",
      "Add more oil to pan, then add **scallion whites** and **brown sugar**, and season. Cook 30s-1min, until lightly browned and softened. Add the **beans** and 1/8 cup water. Cook 3-4min, stirring occasionally and mashing the beans as they soften until the mixture is thickened. Taste and season if needed.",
      "Combine the **sour cream** and **vinegar**, seasoning to taste.",
      "Warm the **tortillas**, fill with beans and brussels sprouts, and top with seasoned sour cream and scallion greens. Serve with potatoes on the side."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Japanese egg salad sandwich (tamago sando)",
    "kcal": 408,
    "protein": 24,
    "carbs": 30,
    "fat": 20,
    "time": 1800,
    "ingredients": [
      "12 large eggs, hard-boiled",
      "1 green onion, very thinly sliced",
      "1 tablespoon Kewpie mayonnaise, plus more for spreading on bread",
      "1 tablespoon creme fraiche",
      "1 1/2 teaspoon rice wine vinegar",
      "1 1/2 teaspoon Dijon mustard, plus more for spreading on bread",
      "Kosher salt",
      "Flaky sea salt, such as Maldon",
      "8 slices milk bread, brioche or white sandwich bread"
    ],
    "steps": [
      "Cook eggs.",
      "Meanwhile, prepare the dressing: In a small bowl, stir together the scallion, mayonnaise, crème fraîche, vinegar and mustard. Season to taste with salt.",
      "On a cutting board, dice the hard-boiled eggs into 1/4 inch pieces, and gently fold them into the dressing.",
      "Slice the medium-boiled eggs in half lengthwise. Sprinkle salt on the cut side.",
      "Lay out your bread for each sandwich, thinly slathering mustard on the inside of one slice and mayonnaise on the other. Arrange the egg halves vertically down the center of each slice of mustard-slathered bread, yolk side down, pointy bit pointing out and round bases touching in the middle.",
      "Gently divide the egg salad among the sandwiches, over and around the halved eggs. Using an offset spatula, spread the egg salad evenly toward the crusts in all directions until bread is covered.",
      "Top with the remaining slices of bread, mayonnaise side down. Using a serrated knife, carefully slice the crusts off on the left and the right sides of each sandwich. (These should be the 2 sides that are parallel to the halved eggs.) Halve the sandwiches vertically (cutting thru the halved-egg line), creating a beautiful exposed cross section.",
      "Serve immediately or refrigerate up to 24 hours."
    ],
    "phase": "luteal"
  },
  {
    "title": "Scallops over Truffled Mushroom Risotto",
    "kcal": 760,
    "protein": 14,
    "carbs": 77,
    "fat": 42,
    "time": 3600,
    "ingredients": [
      "3 1/2 cup chicken stock",
      "1 clove garlic, peeled and thinly sliced",
      "1 shallot, minced",
      "3/4 cup arborio rice",
      "1/4 cup dry white wine",
      "8 oz cremini mushrooms, sliced into 1/4-inch thick pieces",
      "1 lemon, zested and juiced",
      "1/4 oz fresh parsley, chopped",
      "8 oz scallops, tough muscle removed if needed",
      "2 tbsp butter",
      "1/4 cup parmesan cheese, grated",
      "1 tbsp butter",
      "5 tsp truffle oil",
      "vegetable oil",
      "salt",
      "pepper"
    ],
    "steps": [
      "Bring stock to a boil in a medium pot. Once boiling, reduce to a low simmer. Meanwhile, prep remaining ingredients.",
      "Heat a drizzle of oil in a large pan over medium-high heat. Add mushrooms and season with salt and pepper. Cook, stirring occasionally, until browned and crisp, 6-8 minutes. Add garlic and shallot. Cook, stirring, until softened, 1 minute. Add rice; stir until translucent, 1-2 minutes. Add wine; stir until liquid has mostly absorbed. Add stock 1/2 cup at a time and stirring until liquid has mostly absorbed—until rice is al dente and mixture is creamy, 25-30 minutes. TIP: Depending on the size of your pan, you may need a little more or a little less liquid.",
      "After about half of stock is used in risotto, pat scallops* dry with paper towels and season generously all over with salt and pepper. Heat a drizzle of oil in a large pan over medium-high heat. Add scallops and cook until browned and cooked through, 3-5 minutes per side. Turn off heat; remove from pan and set aside, covered. Wipe out pan.",
      "Melt 2 tbsp butter in same pan over medium heat. Cook, stirring, until foamy and flecked with amber brown bits, 2-4 minutes. Stir in half the chopped parsley and a squeeze of lemon juice. Immediately transfer to a small bowl. Once risotto is done, stir in Parmesan, 1 tbsp plain butter, a squeeze of lemon juice, and lemon zest and truffle oil to taste.",
      "Season risotto with salt, pepper, and more lemon juice to taste. • Divide between bowls; top with scallops. Drizzle with as much brown butter as you like and any remaining truffle oil to taste. Garnish with remaining chopped parsley. Serve with any remaining lemon wedges on the side."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Dark chocolate raspberry breakfast bake",
    "kcal": 441,
    "protein": 15,
    "carbs": 76,
    "fat": 10,
    "time": 1500,
    "ingredients": [
      "1/3 cup rolled oats",
      "2 Tbsp all-purpose flour",
      "2 Tbsp unsweetened cocoa powder",
      "1/4 tsp baking powder",
      "pinch of salt",
      "1/8 cup milk",
      "1/8 cup applesauce",
      "1 tbsp maple syrup",
      "1 tsp vanilla",
      "1/4 cup raspberries, fresh or frozen",
      "1/2 Tbsp dark chocolate, coarsely chopped"
    ],
    "steps": [
      "Preheat your oven to 350°F (176°C), and lightly coat an individual sized ramekin or oven-safe bowl with cooking spray or oil.",
      "In a medium-sized mixing bowl, whisk together the oats, flour, cocoa powder, baking powder, and salt. Add the almond milk, and vanilla, and mix until well combined. Fold in the raspberries and dark chocolate chunks, reserving a few to sprinkle on the top.",
      "Transfer the batter to your greased ramekin and top it with the remaining chocolate chunks . Bake for 20-25 minutes, depending on desired consistency.",
      "Remove your bake from oven and allow to cool for about 5 minutes before adding any additional toppings and digging in!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Oatmeal cookie dough breakfast bake",
    "kcal": 475,
    "protein": 14,
    "carbs": 56,
    "fat": 23,
    "time": 1500,
    "ingredients": [
      "1 Tbsp peanut butter",
      "1/4 cup unsweetened applesauce",
      "1/2 tsp vanilla extract",
      "1/4 tsp baking powder",
      "1/4 tsp salt",
      "1/4 cup rolled oats",
      "1/8 cup flour (or almond meal)",
      "1 Tbsp chocolate chips"
    ],
    "steps": [
      "Preheat your oven to 350°F (175°C) and prep a baking tray surface with oil or a baking sheet.",
      "In a small bowl, combine the almond butter, applesauce, maple syrup, baking powder, and salt. Mix well until fully combined. Add the oats, almond meal, and chocolate chips, mixing until you’re left with a sticky dough.",
      "Transfer dough to the baking sheet, one \"lump\" per serving, topping with a few extra chocolate chips and a sprinkle of sea salt, if desired. Bake for 18-20 minutes, until the center has set and the bake has reached your desired consistency."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Broccoli and Mozzarella Pizza",
    "kcal": 742,
    "protein": 34,
    "carbs": 134,
    "fat": 30,
    "time": 2400,
    "ingredients": [
      "1/2 lb pizza dough",
      "8 oz tomato sauce",
      "1/2 lb broccoli, roughly chopped",
      "2 clove garlic, roughly chopped",
      "1 Tbsp capers",
      "1 shallot, thinly sliced",
      "4 oz mozzarella, shredded or torn into bite-sized pieces",
      "1 oz roasted red peppers, roughly chopped",
      "1/2 cup part-skim ricotta",
      "1 1/2 tsp calabrian chile paste"
    ],
    "steps": [
      "1. Remove the **dough** from the refrigerator to bring to room temperature. Preheat the oven to 475F. In a small pot, heat **tomato sauce** over medium-high heat. Reduce to a simmer and cook until slightly reduced and thickened.",
      "2. In a medium pan, heat 2 teaspoons of olive oil on medium-high until hot. Add the **chopped broccoli**, season with salt and pepper. Cook, stirring occasionally, 3-4 minutes or until slightly softened. Add the **chopped garlic** and **capers**. Cook, stirring frequently, 1-2 minutes or until softened. Turn off the heat.",
      "3. Lightly oil a sheet pan or sprinkle generously with semolina. Using your hands, gently stretch the **dough** to 1/4-inch thickness. Carefully transfer to the sheet pan. Leaving a 1-inch border around the edges, spread enough of the **tomato sauce** onto the prepared dough to coat (you may have extra). Evenly top with the **cooked broccoli**, **sliced shallot**, **mozzarella cheese**, and **chopped peppers**. Season with salt and pepper. Bake, rotating the sheet pan half way through, 17-19 minutes or until the cheese is melted and the crust is golden brown. Remove from oven and let stand at least 2 minutes.",
      "4. While the pizza bakes, in a bowl, combine the **ricotta cheese**, a drizzle of olive oil, and as much of the chile paste as you'd like, depending on how spicy you'd like the dish to be. Season with salt and pepper.",
      "5. Transfer the **baked pizza** to a cutting board, evenly top with the **spicy ricotta**. Cut the pizza into equal-sized pieces. Enjoy!"
    ],
    "phase": "luteal"
  },
  {
    "title": "Roasted broccoli and fregola sarda pasta",
    "kcal": 602,
    "protein": 28,
    "carbs": 54,
    "fat": 26,
    "time": 2100,
    "ingredients": [
      "2 eggs, hard cooked, peeled, and sliced into rounds",
      "1/2 cup fregola sarda pasta",
      "3/4 lb broccoli (preferably Italian broccoli), cut into small florets",
      "1/2 red onion, large diced",
      "1 tbsp za'atar seasoning",
      "1 tbsp lemon juice",
      "1 tbsp tahini",
      "1 tbsp water",
      "1/2 tbsp olive oil",
      "1 clove garlic, minced",
      "3 tbsp sliced almonds, toasted",
      "1 oz parmesan cheese, grated",
      "2 tbsp fresh mint, leaves picked, roughly torn"
    ],
    "steps": [
      "1. Preheat oven to 450F. Place **broccoli** and **onion** on a sheet pan. Drizzle with olive oil and season with salt, pepper, and **za'atar seasoning**; toss to coat. Arrange in an even layer. Roast 20-22 minutes, or until browned and tender when pierced with a fork. Remove from the oven.",
      "2. Meanwhile, cook the fregola sarda (15 minutes, or per package directions) and hard-boil the eggs. Once the broccoli/onion is done, toast the almonds (350F for 5min)",
      "3. While everything is cooking, combine **lemon juice**, **tahini**, **water**, **olive oil**, and **garlic** in a large bowl. Whisk until smooth. Season with salt and pepper to taste.",
      "4. As they're cooked, add the pasta, broccoli/onion, chopped almonds, and parmesan to the bowl of dressing.  Stir to combine. Taste and adjust seasonings if needed.",
      "5. Serve **finished pasta** topped with **eggs**. Garnish with the **mint leaves**. Enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Single Serve Mug Coffee Cake",
    "kcal": 189,
    "protein": 5,
    "carbs": 29,
    "fat": 6,
    "time": 30,
    "ingredients": [
      "1 teaspoon granulated sugar",
      "2 1/2 tablespoon all purpose flour",
      "1/8 teaspoon salt",
      "1/4 teaspoon baking powder",
      "1 tablespoon plain nonfat greek yogurt",
      "1 tablespoon whole milk",
      "Dash of vanilla",
      "1 tablespoon walnuts, finely chopped",
      "1/2 tablespoon brown sugar",
      "1/4 teaspoon ground cinnamon"
    ],
    "steps": [
      "Spray a mug or a ramekin with nonstick cooking spray. Add sugar, flour, salt, baking powder, oil, milk, and vanilla and stir until combined. Sprinkle brown sugar and cinnamon on top.",
      "Microwave for 45 seconds (my microwave is 1100 watts - if yours is less you may need to microwave it longer, do so in 15 second increments).",
      "Enjoy warm!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Mediterranean egg salad",
    "kcal": 382,
    "protein": 15,
    "carbs": 40,
    "fat": 18,
    "time": 30,
    "ingredients": [
      "8 slices bread, toasted",
      "2 tbsp pine nuts, toasted",
      "2 tbsp olive oil",
      "1 tbsp za'atar",
      "2 tsp lemon juice",
      "4 eggs, hard-cooked and chopped",
      "1/2 cup green olives, chopped",
      "2 tbsp fresh cilantro, roughly chopped",
      "2 tbsp red onion, minced",
      "Salt",
      "Black pepper"
    ],
    "steps": [
      "While the eggs are cooking, toast the pine nuts and bread.",
      "Whisk together oil, za'atar, and lemon juice. Toss with eggs, olives, cilantro, onion, and pine nuts; season with salt and pepper to taste. Serve on toast."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mediterranean pasta salad",
    "kcal": 484,
    "protein": 15,
    "carbs": 54,
    "fat": 23,
    "time": 2700,
    "ingredients": [
      "8 oz dried pasta",
      "1/2 cucumber, medium diced",
      "2 cup cherry tomatoes, halved",
      "1 carrot, small diced",
      "1/4 cup fresh basil, chopped",
      "4 oz fresh goat cheese, crumbled",
      "black pepper, to taste",
      "1/4 cup extra virgin olive oil",
      "3 tbsp white wine vinegar (use distilled vinegar for more migraine safe option)",
      "1 tsp honey",
      "1 1/2 tsp dried oregano",
      "1 small shallot, minced",
      "1 tsp dijon mustard",
      "1/2 tsp kosher salt",
      "1/4 tsp crushed red pepper"
    ],
    "steps": [
      "Cook pasta as directed until al dente, then drain and rinse under cold water to stop cooking.",
      "While pasta is cooking, whisk together dressing ingredients, then mix pasta and all remaining ingredients with it. Serve immediately.",
      "If serving chilled, reserve the vegetables until just before serving, to preserve crispness. Chill at least two hours in the fridge."
    ],
    "phase": "luteal"
  },
  {
    "title": "Boursin broccoli soup",
    "kcal": 381,
    "protein": 8,
    "carbs": 30,
    "fat": 26,
    "time": 30,
    "ingredients": [
      "1/4 cup butter",
      "2 large shallots, chopped",
      "2 large carrots, chopped small (2 large chopped=1 cup)",
      "1/4 cup all purpose flour",
      "3 cup vegetable broth",
      "1 1/2 cup whole milk",
      "1 head broccoli, chopped into florets",
      "5 oz Boursin Garlic & Herb cheese",
      "3/4 teaspoon kosher salt",
      "1/2 teaspoon black pepper"
    ],
    "steps": [
      "In a large, heavy pot melt the butter over medium heat and stir in chopped shallots and carrots. Saute for about 2 minutes until they are fragrant and more tender, stirring often. Add flour and coat the vegetables. Pour in about 1/4-1/2 cup of broth and whisk till the flour gets incorporated and smooth. Then add the rest of the broth as well as the whole milk. Bring to a low simmer for 8-10 minutes, allowing it to thicken. Do not start to boil, otherwise your milk might curdle (especially if using a low fat option instead).",
      "Add the broccoli florets and cook for another 5 minutes until softened. Off the heat, stir in Boursin cheese until smooth and creamy. Taste and adjust any seasonings, like salt and pepper if needed."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Broccoli rice casserole",
    "kcal": 452,
    "protein": 11,
    "carbs": 50,
    "fat": 21,
    "time": 30,
    "ingredients": [
      "2 cup cooked brown rice",
      "2 tablespoon unsalted butter, divided",
      "2 medium shallots, peeled and chopped",
      "1 garlic clove, peeled and minced",
      "2 tablespoon all purpose flour",
      "1 cup whole milk",
      "1/2 cup vegetable or chicken stock",
      "12 oz broccoli, chopped into small florets and stem medium diced",
      "5 oz Boursin cheese",
      "1/2 cup panko",
      "2 tsp olive oil",
      "kosher salt and fresh pepper to taste"
    ],
    "steps": [
      "Cook rice. Preheat oven to 400 degrees.",
      "Roast broccoli for 8-10 minutes. (Alternately, saute broccoli stems 5min in the pot you'll use in the next step, then remove and set aside. Blanch florettes for 1min.)",
      "In a large pot, heat half the butter over medium high heat. Add shallots and garlic and cook for about a minute, until fragrant. Add flour and stir to combine. Slowly add in your broth, then your milk, integrating each pour. Whisk in your Boursin cheese block. Season if needed.",
      "Stir in rice and broccoli, then place mixture into an 8x8 casserole dish (or something similar). Cook for about 15-20 minutes.",
      "While the casserole cooks, melt the rest of the butter in a small pan over medium-low heat, and brown panko with it. Season to taste. Top the casserole when serving."
    ],
    "phase": "follikel"
  },
  {
    "title": "Overnight Chia Pudding",
    "kcal": 334,
    "protein": 12,
    "carbs": 26,
    "fat": 21,
    "time": 30,
    "ingredients": [
      "1/4 cup chia seeds",
      "1 cup milk",
      "1 tsp vanilla",
      "1 tsp honey or sugar",
      "2 tbsp peanut butter",
      "1/2 cup fruit, diced"
    ],
    "steps": [
      "Whisk chia seeds, milk, vanilla, and honey until combined. Let rest a few minutes, whisk again as it begins to thicken, then chill overnight.",
      "Stir in remaining ingredients before serving."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Creamy Summer Veggie Risotto",
    "kcal": 593,
    "protein": 16,
    "carbs": 81,
    "fat": 24,
    "time": 30,
    "ingredients": [
      "1/2 cup grape tomatoes, halved",
      "1 shallot, finely chopped",
      "2 clove garlic, roughly chopped",
      "1 cup carnaroli rice",
      "3 1/2 cup water",
      "2 tbsp mascarpone cheese",
      "2 tbsp butter",
      "1 oz parmesan, grated",
      "1 jalapeño pepper, seeded and diced",
      "4 oz sweet peppers, seeded and medium diced",
      "1 bunch chives, small diced"
    ],
    "steps": [
      "Mix the tomatoes in a bowl with salt and pepper, and leave to the side to season for at least ten minutes.",
      "In a medium pot, heat a drizzle of olive oil over medium-high heat, then cook shallot and garlic, seasoning, for 1 minute, until slightly softened. Add the rice, stirring requently for 1-2 minutes, until lightly browned. Add water, season, and heat to boiling on high; once boiling, reduce to medium-high and cook 16-18 minutes, stirring occasionally, until liquid is mostly absorbed and rice is al dente.",
      "Meanwhile, when risotta has about 10 minutes left, heat a drizzle of olive oil in a medium pan over medium-high heat, then cook sweet peppers and jalapeño for 2-3 minutes, until slightly softened. Add tomatoes, and cook for another 2-3 minutes. Season as needed.",
      "When risotto is done, add the butter, mascarpone, and half the parmesan, stirring until combined. Adjust seasoning if needed. Serve, topped with vegetables, remaining parmesan, and chives."
    ],
    "phase": "luteal"
  },
  {
    "title": "Potato and kale hash with baked eggs and hot sauce",
    "kcal": 520,
    "protein": 22,
    "carbs": 41,
    "fat": 31,
    "time": 2100,
    "ingredients": [
      "3/4 lb golden potatoes, medium diced",
      "1 red bell pepper, medium diced",
      "2 clove garlic, roughly chopped",
      "2 green onions, thinly sliced, white and green parts separated",
      "1 bunch kale, stems removed and roughly chopped",
      "2 eggs",
      "2 oz cheddar cheese, grated",
      "1 tbsp hot sauce"
    ],
    "steps": [
      "Place an oven rack inthe center of the oven; preheat to 450F. Fill a medium pot 3/4 of the way up with salted water; cover and heat to boiling on high. Once boiling, add the **diced potatoes** to the pot. Cook 6 to 7 minutes, or until slightly tender when pierced with a fork. Drain thoroughly.",
      "In an oven-safe medium pan, heat 1 tbsp olive oil on medium-high until hot. Add the **parboiled potatoes** in an even layer (carefully, as the oil may splatter). Cook, without stirring, 3-4 minutes or until lightly browned and crispy.",
      "Add the **diced peppers**, **garlic**, and **white part of the green onions** to the pan; season with salt and pepper. Cook, stirring frequently, 2-3 minutes, or until softened. Add the **chopped kale** and a drizzle of olive oil to the pan; season with salt and pepper. Cook, stirring frequently, 3-4 minutes, or until slightly wilted. Turn off the heat, taste, then season with salt and pepper, if desired.",
      "Using a spoon, create 2 wells inthe center of the hash. Crack an **egg** into each well; season with salt and pper. Evenly top the hash with the grated cheese. Bake in the oven 5-7 minutes, or until egg whites are set and the yolks are cooked to your desired degree of doneness. Remove from the oven. Let stand at least 2 minutes before serving.",
      "Serve the **baked eggs and hash** garnished with the **green tops of the green onions** and as much of the **hot sauce** as you'd like. Enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Goat Cheese Sandwich with Arugula & Cucumber",
    "kcal": 298,
    "protein": 11,
    "carbs": 38,
    "fat": 10,
    "time": 600,
    "ingredients": [
      "2 slices sandwich bread",
      "1/8 English cucumber, thinly sliced, enough to cover sandwich",
      "1/2 oz arugula",
      "1 oz fresh goat cheese",
      "1 tbsp sweet chili jam"
    ],
    "steps": [
      "Spread goat cheese on one slice of bread and sweet chili jam/sauce on the other side. Add cucumber and arugula, then assemble the sandwich and eat!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Cheesy portobello mushroom caps",
    "kcal": 570,
    "protein": 20,
    "carbs": 63,
    "fat": 26,
    "time": 2100,
    "ingredients": [
      "1 zucchini, cut crosswise into 1/2-inch-thick half-moons",
      "2 portobello mushrooms, stems and gills removed",
      "1 tsp Italian seasoning, divided",
      "2 tbsp olive oil",
      "salt & pepper",
      "4 serving [marinara sauce](http://www.xanthir.com/recipes/showrecipe.php?id=id34)",
      "4 oz dried spaghetti",
      "1/4 cup panko",
      "1/2 tbsp butter",
      "2 oz mozzarella cheese, shredded"
    ],
    "steps": [
      "Preheat oven to 425F. Bring a large pot of salted water to a boil. Start the marinara sauce.",
      "Toss **zucchini** with olive oil, half the **italian seasoning**, salt and pepper, and place on half a baking sheet. Brush both sides of each **portobello mushroom** with olive oil, and season all over with salt, pepper, and remaining **italian seasoning**. Arrange mushrooms gill sides down on empty side of same baking sheet. Roast on top rack until tender, 14-16 minutes.",
      "Meanwhile, prepare marinara sauce.",
      "Once water is boiling, add **spaghetti** to pot. Cook until al dente, 9-11 minutes (or according to package directions). Reserve **1/2 cup pasta cooking water**, then drain and return to pot.",
      "Meanwhile, melt butter in a small pan over medium-high heat. Add **panko**, and lightly season. Cook stirring frequently, until golden brown, 3-5 minutes. Remove from heat.",
      "Add zucchini and most of the marinara, reserving 1/8 cup per serving, to spaghetti. Stir well, adding pasta water as necessary, until pasta is coated.",
      "Heat broiler to high. Flip portobello mushrooms over on baking sheet to expose gills. Top with reserved marinara, then mozzarella, and broil 2-4 minutes, until cheese is lightly browned.",
      "Divide spaghetti between plates and top with cheesy mushrooms. Sprinkle with toasted breadcrumbs and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Sweet Potato Bowl with Creamy Tahini Dressing",
    "kcal": 561,
    "protein": 10,
    "carbs": 63,
    "fat": 14,
    "time": 3300,
    "ingredients": [
      "1/4 cup tahini",
      "1 clove garlic, minced",
      "2 teaspoon granulated sugar (or honey)",
      "1/4 cup distilled white vinegar",
      "1 tablespoon toasted sesame oil",
      "1 tablespoon olive oil",
      "2 teaspoon ground ginger",
      "kosher salt as needed",
      "cold water to thin out, if needed",
      "2 tbsp olive oil",
      "4 medium sweet potatoes cut into ½ inch cubes",
      "1 tbsp olive oil",
      "12 oz broccoli florets",
      "kosher salt and pepper",
      "2 cup cooked brown rice",
      "3 green onions chopped",
      "1 carrots, chopped",
      "2 tbsp sesame seeds, toasted"
    ],
    "steps": [
      "Preheat oven to 425F and prepare a sheet pan (can cover with parchment paper for easy clean up). Toss chopped sweet potatoes with olive oil, salt and pepper and spread out on the baking sheet. Bake for 20 minutes, then flip/toss the potatoes so they'll brown evenly. You can prepare the broccoli by also tossing with olive oil, salt and pepper but it will be added to the sheet later.",
      "Make the tahini sauce by combining all the ingredients in a food processor or just by whisking together in a bowl. Add water until desired consistency is reached. Taste and see if it needs salt - some tahini are more salty than others. Set aside at room temp.",
      "After 20 minutes, toss the sweet potatoes and add the broccoli to the same sheet pan another 20 minutes (40 minutes total). If you're roasting any other veggies, like the carrots, you can add them here as well or just leave them raw.",
      "Place all the veggies in a bowl with your desired base and top with tahini sauce, green onion, and toasted sesame seeds."
    ],
    "phase": "luteal"
  },
  {
    "title": "Italian garden veggie soup",
    "kcal": 596,
    "protein": 18,
    "carbs": 82,
    "fat": 25,
    "time": 3000,
    "ingredients": [
      "1 yellow onion, medium diced",
      "6 oz carrots, sliced into 1/4-inch thick rounds",
      "1 tbsp Italian seasoning",
      "2 clove garlic, minced",
      "1 14-oz can diced tomatoes",
      "3 cup vegetable stock",
      "1/2 cup pearl couscous",
      "1/2 bunch kale, about 4 oz, stems removed and leaves roughly chopped",
      "1 sandwich roll or small baguette, halved lengthwise",
      "2 tbsp butter",
      "1/2 tsp garlic powder",
      "salt and pepper",
      "1/4 cup Parmesan, grated",
      "1 tsp red pepper flakes"
    ],
    "steps": [
      "Heat a large drizzle of olive oil in a large pot over medium-high heat. Add **onion** and **carrots**; season with salt and pepper. Cook stirring occasionally until veggies are lightly browned and slightly softened, 4-6 minutes.",
      "Stir **Italian seasoning** and **garlic** into pot with veggies. Cook until fragrant, 30 seconds. Add **diced tomatoes**, **stock**, and a big pinch of salt. Bring to a boil, then reduce to a simmer. Cook until carrots are just softened, 5-7 minutes.",
      "Once carrots are just softened, stirr in **couscous** and **kale**. Cook until couscous is tender and kale has wilted, 8-10 minutes. Taste and season generously with salt and pepper.",
      "While the soup cooks, place butter in a small microwave-safe bowl; microwave until softened, 10-15 seconds. Stir in **garlic powder** and season with salt and pepper. Toast baguette halves, the spread cut sides with **garlic butter**. Halve each piece on a diagonal.",
      "Divide soup between bowls. Sprinkle with **Parmesan** and a pinch of **chili flakes** to taste. Serve with garlic bread on the side."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Perfectly Pillowly Cinnamon Rolls",
    "kcal": 440,
    "protein": 8,
    "carbs": 72,
    "fat": 14,
    "time": 9900,
    "ingredients": [
      "1/2 cup whole milk",
      "24 g Unbleached Bread Flour",
      "2/3 cup whole milk",
      "300 g Unbleached Bread Flour",
      "1 teaspoon salt",
      "2 tablespoon granulated sugar",
      "2 teaspoon instant yeast",
      "4 tablespoon unsalted butter, softened",
      "1 tablespoon butter, melted",
      "107 g light brown sugar, packed",
      "14 g Unbleached Bread Flour",
      "3 teaspoon ground cinnamon",
      "1/16 teaspoon salt",
      "1 1/2 tablespoon butter, melted, for brushing tops",
      "1 1/2 tablespoon butter, melted, for icing",
      "1/2 teaspoon vanilla extract",
      "1/16 teaspoon salt",
      "170 g confectioners' sugar, sifted",
      "1 to 2 tablespoons milk (or cream/buttermilk), enough to thin to desired consistency"
    ],
    "steps": [
      "**To make the tangzhong:** Combine both the ingredients in a small saucepan, and whisk until no lumps remain.",
      "Place the saucepan over medium heat and cook the mixture, stirring regularly, until thickened, paste-like, and the spoon or spatula leaves lines on the bottom of the pan. This should take 1 to 3 minutes, depending on the strength of your burner.",
      "Remove from the heat and transfer to a large mixing bowl, the bowl of a stand mixer, or the bucket of a bread machine (whatever you plan to knead the dough in).",
      "**To make the dough:** Weigh your flour; or measure it by gently spooning it into a cup, then sweeping off any excess. Add the cold milk, then the flour and remaining ingredients to the mixing bowl in the order listed; the heat from the tangzhong will help to warm the cold milk.",
      "Mix — by hand, on low speed of a stand mixer with the dough hook attachment, or in a bread machine set to the dough cycle — to bring the dough together. Next, knead the dough until it’s smooth, elastic, and tacky. This will take up to 15 minutes by hand, 10 to 12 minutes on medium-low speed of a mixer, or the length of the dough cycle in a bread machine.",
      "Shape the dough into a ball, place it in a bowl, and cover the bowl with plastic wrap or a reusable cover.",
      "Let the dough rise until puffy but not necessarily doubled in bulk, about 60 to 90 minutes (depending on the warmth of your kitchen).",
      "**To make the filling:** While the dough is rising, put the melted butter into a medium bowl and add the remaining ingredients, stirring until the mixture is the texture of damp sand. Set aside.",
      "Lightly grease a baking sheet, or line it with parchment paper.",
      "**To assemble the rolls:** Transfer the dough to a lightly greased work surface and press it into a 10” x 12” rectangle that’s about 1/2” thick. For evenly shaped rolls, try to pat the dough into an actual rectangle (with corners), rather than an oval.",
      "Sprinkle the filling over the dough, covering all but a 1/2” strip along one long side.",
      "Starting with the filling-covered long side, roll the dough into a log.",
      "Score the dough lightly into eight equal 1 1/2” to 2” pieces; this will make large, saucer-sized cinnamon rolls — their generous size is part of their charm. Cut the dough at the score marks. Dental floss will give you the cleanest cut: pull off a long piece of floss, loop it underneath the log at the score mark, and pull the ends in opposite directions to cut the dough. Repeat until you've cut all of the rolls. If you don’t have dental floss, a bench knife or sharp knife will work.",
      "Place the rolls onto the prepared baking sheet, spacing them so there’s at least 2” between each one and they’re 2” away from the edges of the pan; a 3-2-3 arrangement works well. To prevent them from unraveling while they rise and bake, tuck the ends of the spirals underneath the rolls so that they’re held in place.",
      "Cover the rolls with lightly greased plastic wrap or a reusable cover and let them rise for 30 to 60 minutes (depending on the warmth of your kitchen). The rolls should be puffy and the dough shouldn’t bounce back immediately when gently pressed.",
      "About 20 minutes before you’re ready to bake, position a rack in the top third of the oven. Preheat the oven to 375°F.",
      "Bake the rolls for 14 to 18 minutes, until they’re a light golden brown and a digital thermometer inserted into the center of one roll reads 190°F. Bake for the lesser amount of time for extra-soft rolls, and the longer amount of time for rolls with a bit more color and slightly firmer texture.",
      "Remove the rolls from the oven, place the pan on a rack, and brush the hot rolls with 1 1/2 tablespoons (21g) of the melted butter. Let the rolls cool for 10 to 15 minutes before icing.",
      "**To make the icing:** Combine the remaining 1 1/2 tablespoons (21g) melted butter with the remaining icing ingredients in a medium bowl, mixing with a spatula until smooth. Milk makes a lovely frosting; using cream in place of milk creates an extra layer of richness, while substituting buttermilk adds subtle tang, a nice counterpoint to the icing's overall sweetness.",
      "Ice the rolls and serve immediately. If you’re planning to serve the rolls later, wait to ice them until just before serving. Store icing at room temperature, tightly covered, until you’re ready to use it.",
      "Store completely cooled rolls, un-iced and well wrapped, for a couple of days at room temperature; or freeze for up to 1 month."
    ],
    "phase": "follikel"
  },
  {
    "title": "Vegetable Tortilla Roll-ups",
    "kcal": 209,
    "protein": 5,
    "carbs": 21,
    "fat": 12,
    "time": 9000,
    "ingredients": [
      "8 ounce whipped cream cheese",
      "1/4 cup homemade ranch dressing mix or 1 packet store-bought",
      "1 teaspoon dried dill weed or 1 tablespoon minced fresh dill",
      "2 cup finely chopped vegetables such as broccoli, cauliflower, carrots, bell peppers, or olives",
      "8 (8-inch) flour tortillas"
    ],
    "steps": [
      "In a medium bowl, combine cream cheese, mayonnaise, ranch dressing mix, and dill weed. Fold in vegetables and shredded cheese.",
      "Working with one tortilla at a time, spread about ½ cup of the cream cheese mixture evenly over the tortilla, going all the way to the edge. Roll the tortilla tightly and wrap in plastic.",
      "Continue with the remaining tortillas until all have been assembled and wrapped in plastic. Refrigerate for at least 2 hours or overnight. To serve, trim any unfilled ends away. Slice each tortilla into 8 equal pieces. Serving = 1/2 tortilla"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Crunchy chickpea pita pockets",
    "kcal": 735,
    "protein": 19,
    "carbs": 65,
    "fat": 23,
    "time": 1800,
    "ingredients": [
      "1/2 14-oz can chickpeas, drained and rinsed",
      "1/2 tbsp flour",
      "1 tbsp za'atar (or Shawarma spice blend)",
      "4 oz grape tomatoes, halved",
      "1/4 English cucumber, sliced into half moons",
      "1 tbsp fresh dill, roughly chopped",
      "1/2 cup feta cheese, crumbled",
      "2 tbsp hummus",
      "2 tbsp sour cream",
      "2 pitas"
    ],
    "steps": [
      "Heat a 1/4-inch layer of oil in a medium pan over medium-high heat. Sprinkle **chickpeas** with **flour**; toss to evenly coat.",
      "Once oil is hot enough that a pinch of flour sizzles when added to the pan, add chickpeas and cover, cook uncovering to stir once or twice, until crispy, 4-7 minutes. Transfer chickpeas to a paper-towel-lined plate; season with **za'atar**, salt, and pepper.",
      "While chickpeas cook, in a large bowl, toss together **tomatoes**, **cucumber**, **dill**, **feta**, and a drizzle of olive oil. Season with salt and pepper to taste.",
      "Toast **pitas** until warm and pliable. Halve each pita crosswise to create pockets. Spread **hummus** and **sour cream** inside of each pita pocket. Fill with chickpeas and salad. Serve pita pockets with any leftover chickpeas and/or salad on the side."
    ],
    "phase": "luteal"
  },
  {
    "title": "Cheese Board Bento",
    "kcal": 504,
    "protein": 19,
    "carbs": 38,
    "fat": 33,
    "time": 30,
    "ingredients": [
      "1/2 oz parmesan cheese, broken into rustic bite-sized pieces",
      "1/2 oz cheddar cheese, broken into rustic bite-sized pieces",
      "1/4 cup castelvetrano olives",
      "1/2 cup grapes",
      "1/2 apples, cut into wedges or large pieces",
      "2 tsp lemon juice",
      "1/4 cup Marcona almonds"
    ],
    "steps": [
      "Toss apple pieces with lemon juice to prevent browning. Arrange ingredients in bento box."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Vegetable Fried Rice with Broccoli, Carrots, & Spicy Pepper Sauce",
    "kcal": 590,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 1200,
    "ingredients": [
      "1/2 cup jasmine rice",
      "1/2 lb broccoli, roughly chopped",
      "2 medium carrots, thinly sliced at an angle",
      "1 1-inch piece ginger, peeled and finely chopped",
      "2 scallions, thinly sliced, separate white and green parts",
      "1 Tbsp white wine vinegar",
      "1 Tbsp honey",
      "1 bird's eye chile pepper, thinly sliced",
      "2 Tbsp soy sauce",
      "3 Tbsp sweet chili sauce",
      "2 clove black garlic, peeled and roughly chopped",
      "2 eggs"
    ],
    "steps": [
      "In a medium pot, combine the **rice**, a big pinch of salt, and 1 cup of water. Heat to boiling on high. Once boiling, reduce the heat to low. Cover and cook, without stirring, 12 to 14 minutes, or until the water has been absorbed and the rice is tender. Turn off the heat and fluff with a fork.",
      "In a medium pan (nonstick, if you have one), heat 2 teaspoons of olive oil on medium-high until hot. Add the chopped **broccoli**; season with salt and pepper. Cook, stirring occasionally, 4 to 5 minutes, or until slightly softened. Add the sliced **carrots**; season with salt and pepper. Cook, stirring occasionally, 4 to 5 minutes, or until slightly softened. Add the chopped **ginger** and sliced **white bottoms of the scallions**. Cook, stirring occasionally, 2 to 3 minutes, or until softened. Transfer to a large bowl; cover with aluminum foil to keep warm. Wipe out the pan.",
      "While the vegetables cook, in a bowl, whisk together the **vinegar** and **honey**. Stir in the sliced **pepper**. Season with salt and pepper.",
      "In the same pan, heat 1 tablespoon of olive oil on medium-high until hot. Add the **cooked rice** in an even layer. Cook, without stirring, 3 to 4 minutes, or until slightly crispy. Turn off the heat; stir in the **soy sauce**, **sweet chili sauce**, and **chopped garlic**. Transfer to the bowl of cooked vegetables; stir to combine. Season with salt and pepper to taste. Cover with the foil to keep warm. Rinse and wipe out the pan.",
      "In the same pan, heat 2 teaspoons of olive oil on medium-high until hot. Keeping them separate, crack the **eggs** into the pan; season with salt and pepper. Cook 3 to 5 minutes, or until the whites are set and the yolks are cooked to your desired degree of doneness. Turn off the heat. Serve the fried rice topped with the fried eggs and as much of the sauce as you’d like, depending on how spicy you’d like the dish to be. Garnish with the **sliced green tops of the scallions**. Enjoy!"
    ],
    "phase": "follikel"
  },
  {
    "title": "Seared tilapia and lemon-caper sauce",
    "kcal": 522,
    "protein": 31,
    "carbs": 49,
    "fat": 24,
    "time": 2100,
    "ingredients": [
      "4 oz orzo pasta, dried",
      "2 tsp olive oil",
      "1 zucchini, quartered and cut crosswise into 1/2-inch pieces",
      "4 oz sweet peppers, cut off and discard stems, remove cores, then thinly slice lengthwise",
      "2 clove garlic, peeled and roughly chopped",
      "2 fillets tilapia",
      "1 tbsp weeknight hero spice blend",
      "2 tsp olive oil",
      "2 tbsp butter",
      "1 tbsp capers",
      "1 lemon, halved",
      "2 tbsp fromage blanc, or Greek yogurt",
      "1 tbsp fresh parsley, roughly chopped"
    ],
    "steps": [
      "Fill a medium pot with salted water; cover and heat to boiling on high. Add the **pasta** to the pot of boiling water and cook, uncovered, 7 to 9 minutes, or until tender. Turn off the heat. Drain thoroughly and return to the pot.",
      "While the pasta cooks in a medium pan (nonstick, if you have one), heat **2 tsp olive oil** over medium-high until hot. Add the **zucchini** in an even layer. Cook, without stirring, 2 to 3 minutes or until lightly browned.",
      "Add the **peppers** and **garlic**; season with salt and pepper. Cook, stirring occasionally, 2 to 3 minutes, or until the vegetables are slightly softened. Transfer to the pot of cooked pasta and stir to combine. Cover to keep warm. Wipe out the pan.",
      "Pat the **fish** dry with paper towels; season both sides well with salt, pepper and enough of the spice blend to coat (you may not need the full amount). In the same pan, heat **2 tsp olive oil** on medium-high until hot. Add the seasoned fish and cook 3 to 4 minutes, or until browned. Flip and cook 2 minutes.",
      "To the pan, add the **butter**, **capers**, and **the juice of half the lemon** (carefully, as the liquid may splatter). Cook, constantly spooning the sauce over the fish, 1 to 2 minutes, or until the fish is coated and cooked through. Turn off the heat.",
      "To the pot of **cooked pasta and vegetables**, add the **fromage blanc** and **the juice of the remaining lemon half**; stir to combine. Taste, then season with salt and pepper if desired.",
      "Serve the finished pasta topped with the cooked fish and pan sauce. Garnish with **parsley**. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Gyoza bento",
    "kcal": 426,
    "protein": 30,
    "carbs": 48,
    "fat": 11,
    "time": 2100,
    "ingredients": [
      "3 gyoza (or other small dumpling)",
      "1/2 cup sushi rice, cooked",
      "1 large eggs",
      "3/4 tsp sugar",
      "1/4 tsp mirin",
      "1 pinch salt",
      "1/8 tsp soy sauce",
      "1 chikuwa, thawed",
      "1/4 Persian cucumbers, see instructions for prep note",
      "1/4 cup broccoli, blanched",
      "3 grape tomatoes",
      "soy sauce, or other dipping sauce",
      "furikake"
    ],
    "steps": [
      "Fill up half of the bento box with Japanese rice. Let it cool so that hot/warm rice will not warm up other cool food.",
      "Pan fry leftover gyoza or bake in a toaster oven until it's warm. Allow to cool.",
      "Mix together tamagoyaki ingredients until combined. See for cooking instructions: https://www.xanthir.com/recipes/showrecipe.php?id=id451",
      "Slice cucumber lengthwise into thin sticks to fit inside chikuwa. Put cucumber inside chikuwa then slice at an angle into 3-4 pieces.",
      "Pack cooled gyoza, tamagoyaki, and chikuwa cucumber. Fill empty spaces with blanched broccoli and tomatoes.",
      "Sprinkle furikake on top of slightly cooled rice.",
      "Pack soy sauce or other dipping sauce in a sauce container.",
      "Cool down completely before closing the bento box."
    ],
    "phase": "luteal"
  },
  {
    "title": "Pan fried tofu and soba noodle bento",
    "kcal": 430,
    "protein": 31,
    "carbs": 53,
    "fat": 14,
    "time": 30,
    "ingredients": [
      "1 oz soba noodles, uncooked",
      "1 tsp soy sauce, divided",
      "2 tsp sesame seeds",
      "1/2 tsp toasted sesame oil",
      "white pepper",
      "1 Tbsp all-purpose flour or potato starch",
      "1 tsp garlic powder",
      "3 1/2 oz extra-firm tofu, cut into 1/2-inch cubes",
      "1/2 tsp soy sauce",
      "black pepper",
      "1 Tbsp water",
      "1/2 tsp soy sauce",
      "1/2 cup broccoli florets, blanched",
      "1 Tbsp grated carrots",
      "1/2 Tbsp finely minced fresh ginger",
      "1/4 cup frozen shelled edamame, thawed"
    ],
    "steps": [
      "1. Cook noodles according to package directions. Drain, rinse with cold water, and drain again. Toss with 1 tsp soy sauce, sesame seeds, and sesame oil; season with white pepper to taste.",
      "2. Stir together flour and garlic powder in medium bowl; add tofu, and toss to coat. Season with black pepper to taste.",
      "3. Spray skillet with olive oil cooking spray; heat over medium-high heat, add tofu, and sauté 5 minutes, or until golden brown. Transfer to plate; sprinkle with soy sauce.",
      "4. Return skillet to heat. Add water and remaining soy sauce, then broccoli, carrots, and ginger. Cover, and simmer 3 minutes, or until broccoli is warmed through.",
      "5. To assemble: Pack soba noodles in 1 section of bento box or portable container. Pack tofu and broccoli mixture in other sections. Fill in last section with edamame. Refrigerate, uncovered, until all ingredients are chilled thoroughly. Cover box, and refrigerate until ready to serve."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Black bean plantain bowls",
    "kcal": 610,
    "protein": 13,
    "carbs": 110,
    "fat": 13,
    "time": 2700,
    "ingredients": [
      "1/2 15oz-can black beans, drained and rinsed",
      "2 tbsp cilantro, finely minced",
      "1/2 medium navel orange, zested and juiced",
      "1 clove garlic, grated",
      "1/2 tbsp red wine vinegar",
      "1/4 tsp ground coriander",
      "1/4 tsp dried oregano",
      "1 tsp maple syrup",
      "1 tsp extra virgin olive oil",
      "Salt, to taste",
      "1 ripe plantain, peeled and sliced into coins",
      "1/2 cup Jasmine rice, uncooked",
      "1 tbsp Oil, for cooking",
      "2 clove garlic, thinly sliced",
      "Pickled red onion",
      "Avocado",
      "Lime wedges, optional"
    ],
    "steps": [
      "Add the beans, cilantro, orange zest, garlic, coriander and oregano to a mixing bowl. Squeeze over with the juice from the orange then add the red wine, maple syrup, extra virgin olive oil and a generous pinch of salt. Toss to coat and allow to marinate in the fridge.",
      "Preheat the oven to 400F, then peel and slice your plantains into 1/2 inch pieces. Place the slices on a parchment lined baking sheet and spray or brush both sides with avocado oil. Place the plantains in the oven to cook for 15 minutes, then flip and roast for another 5-8 minutes until golden. Salt them as they come out of the oven. Optional, but a squeeze of lime juice before serving.",
      "Meanwhile, in a small pot add rice, a big pinch of salt, and 1 cup water to a boil. Stir, reduce heat to lower and cover. Cook, without stirring, for 12-14 minutes or until all water is absorbed and rice is tender.",
      "Optional, but as the plantains cook you can crisp up your rice for added texture. Start by warming a large skillet over medium heat. Drizzle oil in the pan and allow to warm through. Add the sliced garlic and allow to lightly brown for about 2 minutes. Remove the garlic then add the rice to the pan. With a spatula, flatten the rice into an even layer and allow it to cook undisturbed for about 5 minutes or until you see the rice become lightly golden. Add the garlic back on top of the rice with a pinch of salt and then break it up into chunks with your spatula.",
      "To serve, layer the rice and plantains together then top with the black bean salad. You can also add sliced avocado and some pickled red onion then drizzle a little bit of the orange marinade on top."
    ],
    "phase": "follikel"
  },
  {
    "title": "Elote-style vegetable tostadas",
    "kcal": 612,
    "protein": 8,
    "carbs": 57,
    "fat": 40,
    "time": 2700,
    "ingredients": [
      "1/4 cup jasmine rice, uncooked",
      "1/2 cup water",
      "1 lime, zested then cut in quarters",
      "olive oil",
      "1 zucchini, medium diced",
      "2 small flour tortillas",
      "1 tbsp olive oil",
      "1 medium red onion, medium diced",
      "1 poblano pepper, medium diced",
      "1/2 tbsp Mexican spice blend",
      "2 clove garlic, roughly chopped",
      "1/4 cup mayonnaise",
      "2 tbsp Cotija cheese, grated",
      "Salt and pepper, to taste"
    ],
    "steps": [
      "Preheat conventional or toaster oven to 450F.",
      "In a small pot, combine the **rice**, a big pinch of **salt**, and **water**. Heat to boiling on high. Once boiling, reduce heat to low. Cover and cook, without stirring, 12-14 minutes or until the water has been absorbed and the rice is tender. Turn off the heat and fluff with a fork. Stir in the **lime zest** and the juice of **1 quarter of the lime**. Cover to keep warm.",
      "Meanwhile, in a large pan, heat **1 tablespoon olive oil** over medium heat until hot. Add the **diced zucchini** in an even layer. Cook, without stirring, for 2-3 minutes (Rachel's note - may take longer since you're not overheating your pan). Season with salt and pepper. Continue to cook, stirring occasionally, 3-4 minutes, or until slightly softened. Transfer to a large bowl, cover to keep warm. Wipe out the pan.",
      "Meanwhile, place the **tortillas** on a sheet pan. Drizzle with **olive oil** and season with salt and pepper. Turn to coat; arrange in an even layer. Bake in the oven for 6-8 minutes or until lightly browned and crispy. Remove from oven.",
      "In the same pan, heat **2 teaspoons olive oil** on medium until hot. Add the diced **onion** and **pepper**; season with salt and pepper. Cook, stirring occasionally, 4-5 minutes, or until lightly browned and softened. Add the **spice blend** and the **chopped garlic**. Cook, stirring constantly, 1-2 minutes, or until combined. Transfer to the bowl of **cooked zucchini**.",
      "To the bowl of **cooked vegetables**, add the **mayonnaise** and the **juice of half the lime**. Stir to combine. Taste, then season with salt and pepper if desired.",
      "Assemble the tostadas with the **toasted tortillas**, **lime rice**, and **finished vegetables**. Serve garnished with the **cheese**. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Grilled halloumi and vegetables",
    "kcal": 424,
    "protein": 16,
    "carbs": 21,
    "fat": 32,
    "time": 1500,
    "ingredients": [
      "12 oz halloumi",
      "2 red bell peppers, see instructions",
      "2 large zucchini, sliced diagonally into 1/4- to 1/3-inch-thick rounds",
      "2 Japanese eggplant, sliced diagonally into 1/4- to 1/3-inch-thick rounds",
      "1 bunch green onions, trimmed",
      "Salt and pepper",
      "Olive oil",
      "3 tsp za'atar"
    ],
    "steps": [
      "Prepare a hot grill (400F). Cut halloumi into 8-12 slabs (for 4 servings), about 1/3- to 1/2-inch thick. Cut peppers into wide pieces, slicing from top to bottom along the natural indentations. Discard seeds. Cut pieces in half crosswise.",
      "Season all vegetables with salt and pepper. Brush vegetables and halloumi with olive oil.",
      "Grill vegetables until tender and nicely charred, turning occasionally. If you'd like, use an outdoor grill pan to keep them from slipping through the grate. Scallions will be ready after 3 to 4 minutes. Peppers, zucchini, and eggplant take about 10 minutes. Arrange on a platter.",
      "Grill halloumi, turning occasionally, for 2-6 minutes, until grill marks appear. When you press on the cheese, it should give but it should not be runny.",
      "Remove cheese to the platter with vegetables. Sprinkles with za'atar and serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Grilled Veggies and Gnocchi with Salsa Verde",
    "kcal": 480,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 1800,
    "ingredients": [
      "1/4 cup fresh parsley",
      "1/4 cup fresh basil",
      "1/4 cup extra-virgin olive oil",
      "2 tsp capers",
      "1 tbsp lemon juice",
      "2 anchovy fillets",
      "1 clove garlic",
      "salt",
      "12 oz fresh gnocchi",
      "4 cup cherry tomatoes",
      "2 small red onions, cut into 2\" pieces",
      "6 portobello mushrooms, cut into 2\" pieces",
      "2 tbsp extra-virgin olive oil",
      "salt",
      "freshly ground black pepper"
    ],
    "steps": [
      "Preheat grill to 400F.",
      "In a food processor, combine parsley, basil, oil, capers, lemon juice, anchovies, and garlic. Blend until smooth, season to taste with salt, and chill until ready to serve.",
      "Toss the gnocchi and veggies with oil, salt, and pepper, then move to a grill pan. (The larger the better, so they have more exposed surface area.) Grill for 8 minutes, toss, then 8 minutes more, toss, then a final 5 minutes if needed (it probably will be). Ideally, gnocchi should start to dry out/crisp a little.",
      "Divide among bowls and top with the salsa verde."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Katsu-style eggplant with stir-fried green beans and sweet peppers",
    "kcal": 670,
    "protein": 19,
    "carbs": 93,
    "fat": 26,
    "time": 2640,
    "ingredients": [
      "2 tsp olive oil",
      "1 eggplant, cut lengthwise into 1/2-inch planks and lightly salted",
      "2 eggs, beaten smooth",
      "1 tbsp water",
      "1/2 cup all-purpose flour",
      "1 cup panko breadcrumbs",
      "1 tbsp olive oil",
      "1/2 cup jasmine rice",
      "1 cup water",
      "1 tsp rice vinegar",
      "1 tsp sesame oil",
      "2 tbsp tonkatsu sauce (or 2:1 ketchup and Worcestershire sauce)",
      "4 oz sweet peppers, cut into quarters lengthwise, stems, ribs, and seeds removed",
      "6 oz green beans, trimmed",
      "1 1-inch piece ginger, finely chopped",
      "1/4 cup water",
      "2 tbsp peanuts, roughly chopped",
      "2 tbsp cilantro, roughly chopped"
    ],
    "steps": [
      "Preheat the oven to 475F. Drizzle a sheet pan with **olive oil**.",
      "Prepare eggs+water, flour, and panko on separate plates; season each of them. Working 1 piece at a time, thoroughly coat the **eggplant** in the **flour** (tapping off any excess), then in the **beaten eggs** (letting any excess drip off), then in the **breadcrumbs** (pressing to adhere). Transfer the breaded eggplant to the prepared sheet pan in a single layer. Drizzle with **olive oil**. Bake the **breaded eggplant**, flipping halfway through, 22 to 24 minutes, or until browned and crispy. Remove from the oven.",
      "While the eggplant bakes, cook the rice 12-14 min. When done, fluff with a fork, and set aside in a warm place.",
      "Prepare the sauce: In a bowl, combine the **vinegar**, **sesame oil**, and **tonkatsu sauce**.",
      "While the eggplant continues to bake, in a large pan, heat 2 teaspoons of olive oil on medium heat until hot. Add the **peppers** and **green beans**; season with salt and pepper. Cook, stirring frequently, 2 to 3 minutes, or until lightly browned and slightly softened. Add the **ginger** and **water**. Cook, stirring frequently, 3 to 4 minutes or until fragrant and the vegetables have softened. Turn off the heat. Stir in the **peanuts**. Season with salt and pepper to taste.",
      "Divide the **cooked rice** between 2 dishes. Top with the **cooked vegetables** and **baked eggplant**. Drizzle with some of the **sauce**. Garnish with **cilantro**. Serve with any remaining sauce on the side.",
      "-------",
      "**Grilling:**",
      "Prep the eggplant as directed. Halve the peppers (or leave them whole, if they're small enough to be troublesome on the grill) and oil+season them. Oil+season the green beans and mix with ginger. If you have a veggie grilling pan, use it; otherwise put the green beans on some foil, enough to form a slight bowl so their water and oil won't drip.",
      "Heat grill to 400F. Place all veggies on the grill, with eggplant on the cooler side, and pepper and green beans on the hotter side.",
      "Cook peppers for about 6 min, flipping halfway, until tender. Cook green beans for 9 min, stirring every 3 min. Cook eggplants 15 min, flipping halfway, until panko is well-browned and the eggplant is tender.",
      "Roughly chop the peppers; halve the green beans if desired. Serve as directed above."
    ],
    "phase": "follikel"
  },
  {
    "title": "Black bean and delicata squash bowls",
    "kcal": 526,
    "protein": 14,
    "carbs": 85,
    "fat": 9,
    "time": 2400,
    "ingredients": [
      "1/2 cup brown rice, uncooked",
      "1 cup water",
      "1 oz pickled jalapenos, roughly chopped",
      "1 delicata squash, halved lengthwise, seeds and ends discarded, and sliced into 1/2-inch half moons",
      "1 tsp olive oil",
      "1 tsp Mexican spice blend",
      "1 serving [guacamole](https://www.xanthir.com/recipes/showrecipe.php?id=28)",
      "4 oz grape tomatoes, halved",
      "1 lime, zested and juiced",
      "1/2 tsp olive oil",
      "2 clove garlic, roughly chopped",
      "1/2 can black beans, drained",
      "1 tsp Mexican spice blend",
      "3 tbsp water",
      "1 tbsp creme fraiche",
      "2 tbsp pumpkin seeds, toasted, for garnish"
    ],
    "steps": [
      "1. Preheat oven to 450F. Line a sheet pan with parchment paper.",
      "2. Bring **rice**, **water**, and a big pinch of **salt** to a boil in a medium pot over high heat. Once boiling, give it a stir, reduce heat to low, cover and cook for 30-35 minutes.",
      "3. Toss **squash** with 1 teaspoon olive oil, **spice blend**, and salt and pepper to taste. Arrange in an even layer on prepared sheet pan. Roast 21-23 minutes or until browned and tender when pierced with a fork. Remove from oven.",
      "4. In a small bowl combine **guacamole** and the juice of **up to 1 lime half** to get a thinner consistency than normal. In another bowl, combine **tomatoes**, **lime zest**, and the juice of **1 lime half**. Season with salt and pepper. Set aside to marinate, stirring occasionally, at least 10 minutes.",
      "5. In a medium pan, heat 1/2 tsp olive oil on medium until hot. Add the **chopped garlic**. Cook, stirring constantly, 30 seconds to 1 minute or until softened. Add the **drained beans**, **water**. Season with salt and pepper. Cook, stirring occasionally, 3 to 4 minutes or until combined. Turn off heat and stir in **creme fraiche**. Taste, then season with salt and pepper if desired.",
      "6. To the pot of **cooked rice**, add **as much of the chopped pepper as you like**, depending on how spicy you'd like the dish to be. Add salt and pepper to taste.",
      "7. Serve the **finished rice** toped with the **roasted squash**, **cooked beans**, **marinated tomatoes** (including any liquid), and **seasoned guacamole**. Garnish with the **toasted pumpkin seeds**. Enjoy!"
    ],
    "phase": "ovulation"
  },
  {
    "title": "Creamy Lemon Spinach-Ricotta Ravioli",
    "kcal": 640,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 3000,
    "ingredients": [
      "1 bell pepper, halved",
      "1 roma tomato, cut into wedges (4-6 per tomato)",
      "2 tbsp butter, divided",
      "2 clove garlic, thinly sliced",
      "9 oz ravioli (spinach and ricotta)",
      "1/4 tsp vegetable stock concentrate",
      "1 tbsp lemon juice",
      "2 tbsp cream cheese",
      "2 tbsp sour cream",
      "1/4 cup parmesan cheese"
    ],
    "steps": [
      "1. Preheat oven to 400F. Toss **bell pepper** and **tomatoes** with oil, salt, and pepper, and roast 20-25 minutes, until softened and lightly charred. Transfer to a cutting board and thinly slice.",
      "2. When veggies are half done, bring a pot of water to boil. Add **ravioli**, and simmer until al dente and floating, 4-5 minutes. Reserve 1/2 cup pasta water, drain the rest, and set ravioli aside.",
      "3. Melt half the **butter** in pan and saute **garlic** until softened, 2-3 minutes. Add 1/4 cup reserved pasta water, **stock**, **cream cheese**, **sour cream**, and remaining **butter**. Whisk until combined and creamy, then add veggies. Add **lemon** juice and season to taste.",
      "4. Add ravioli to sauce, gently toss until thoroughly coated. Serve, topping with parmesan."
    ],
    "phase": "luteal"
  },
  {
    "title": "Sweet potato fajitas",
    "kcal": 609,
    "protein": 17,
    "carbs": 73,
    "fat": 29,
    "time": 2100,
    "ingredients": [
      "2 sweet potatoes, cut into 1/2-inch thick wedges",
      "1 tsp fajita or southwest seasoning",
      "1 yellow onion, divided, sliced/diced",
      "1 green bell pepper",
      "1 roma tomato, small diced",
      "1 tbsp fresh cilantro, roughly chopped",
      "1 lime, zested and juiced (probably won't need all the juice)",
      "2 tbsp sour cream",
      "4 small flour tortillas",
      "1/2 cup pepper jack cheese, shredded",
      "1 oz pickled jalapeno"
    ],
    "steps": [
      "1. Adjust rack to top position and preheat oven to 425F. Toss **sweet potato wedges** with a large drizzle of olive oil and **fajita seasoning**. Season with salt if the fajita seasoning doesn't include salt. Cook for 25-30 minutes, until slightly crispy.",
      "2. Small dice 1/4 cup (for 2 servings) of the onion for the salsa. Slice the rest.",
      "3. Heat a drizzle of oil in a large pan over medium heat. Add **sliced onion** and **green pepper**. Cook stirring occasionally, until softened and lightly charred, 8-10 minutes. Season with salt and pepper. Remove pan from heat.",
      "3. While veggies cook, in a small bowl, combine **tomato**, **cilantro**, **diced onion**, and a squeeze of **lime juice**. Season with salt and pepper. In a separate bowl, combine **sour cream**, **lime zest**, and a squeeze of **lime juice** to make it slightly thinner if needed. Season with salt and pepper.",
      "4. Heat tortillas using desired method. Divide tortillas between plats and fill with **sweet potatoes**, **veggies**, **pepper jack**, **salsa**, **lime sour cream**, and as much **pickled jalapeno** as you like. Enjoy!",
      "Note: Southwest seasoning can be made with 2 parts garlic powder, 1 part cumin, and 1 part chili powder."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Halloumi with pistachio rice",
    "kcal": 645,
    "protein": 20,
    "carbs": 54,
    "fat": 39,
    "time": 2700,
    "ingredients": [
      "1 tbsp butter",
      "1/2 shallot, minced",
      "1 clove garlic, minced",
      "1/4 oz pistachios",
      "1/2 tbsp shawarma spice blend or za'atar",
      "1/2 cup jasmine rice",
      "3/4 cup water",
      "1 tsp vegetable bouillon",
      "1 Persian cucumber, sliced into half moons",
      "4 oz grape tomatoes, halved lengthwise",
      "1/2 shallot, thinly sliced",
      "1/2 lemon, zested and juiced",
      "2 tbsp sour cream",
      "1 clove garlic, minced",
      "4 oz halloumi, sliced into thick planks",
      "1/2 tbsp Shawarma spice blend or za'atar",
      "1 tbsp butter",
      "1 tsp hot sauce",
      "1/4 oz pistachios",
      "Salt and pepper, to taste"
    ],
    "steps": [
      "Melt **butter** in small pot over medium high heat. Add **minced shallot**, **garlic**, **pistachios**, **spice blend**, and a pinch of salt. Cook, stirring, 1 minute.",
      "Stir in **rice**, **water**, **bouillon**, and a big pinch of salt. Bring to a boil, then cover and reduce heat to low. Cook until rice is tender 15-18 minutes. Keep covered off heat until ready to serve.",
      "In a medium bowl, combine **cucumber**, **tomatoes**, and **sliced shallot** to taste. Toss with a **drizzle of olive oil**, a **big squeeze of lemon juice**, a **pinch of lemon zest**, **salt** and **pepper**.",
      "In a small bowl, combine **sour cream** with **garlic** to taste. Season with **salt**. Stir in **water** 1 tsp at a time until mixture reaches a drizzling consistency.",
      "Place **cheese** on a plate; season all over with **spice blend**. Shake off any excess spice blend. Heat a **drizzle of oil** in a large, preferably nonstick, pan over medium-high heat. Add seasoned **cheese** and cook until browned, 1-2 minutes per side.",
      "Fluff **rice** with a fork; stir in **butter**. Taste and adjust seasonings if needed. Divide **rice** between shallow bowls. Top with **salad** and **cheese**. Drizzle cheese with **garlicky white sauce** and **hot sauce** to taste. Sprinkle with **remaining pistachios**. Serve with **lemon wedges** on the side if desired."
    ],
    "phase": "follikel"
  },
  {
    "title": "Kimchi jeon",
    "kcal": 702,
    "protein": 18,
    "carbs": 98,
    "fat": 24,
    "time": 1320,
    "ingredients": [
      "1 cup fully-fermented kimchi, thinly sliced",
      "1 scallion, cut into about 2-inch pieces, if white part is thick, cut in half lengthwise",
      "1/4 medium onion, thinly sliced",
      "cooking oil with high smoke point for pan frying",
      "1 cup all-purpose flour, or buchimgaru (Korean pancake premix)",
      "1/4 cup sweet rice flour or potato starch, substitute with additional AP flour if unavailable",
      "2 tablespoon juice/liquid from kimchi, may need a little more, See note on water below",
      "1 egg, lightly beaten",
      "1 cup icy cold water, Use more water if juice/liquid from kimchi is unavailable and not using an egg. Flour to liquid should be about 1:1 ratio in total.",
      "1 tablespoon soy sauce",
      "1 teaspoon rice vinegar",
      "1 tablespoon water",
      "1/2 teaspoon sugar",
      "pinch of black pepper"
    ],
    "steps": [
      "In a large bowl, combine the **flour (or pancake mix)** with the **liquid from kimchi** and **egg**, and **water**, a little bite at a time. Do not over mix. Add a little more water if the batter is too thick. The batter should flow easily from a spoon. Stir in the **kimchi**, **scallions**, and **onion**.",
      "In a small bowl, combine all **dipping sauce ingredients**.",
      "Heat one tablespoon of **oil** in a non-stick pan over medium heat. Ladle the mixture into the pan, and spread it evenly into a thin round shape. Cook until the edges turn light golden brown, about 3 minutes. Turn it over, and add more **oil** to the sides of the pan. Gently swirl the pan to distribute the oil under the pancakes. Press the pancake down with a spatula. Cook until the other side is nicely browned and crispy, 2 to 3 minutes.",
      "Repeat the process until there is no remaining batter. Serve hot with a dipping sauce, if desired.",
      "-----",
      "Tips for making kimchi pancakes:\n1. Use juice/liquid from kimchi if at all possible.\n2. Use icy cold water.\n3. The batter should be thin enough to flow easily from a spoon.\n4. Spread the batter thin when pan frying.\n5. Use a generous amount of oil.\n6. Increase the heat a little to crisp up the pancakes at the end of pan-frying."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Strawberry Almond Oat Bars",
    "kcal": 226,
    "protein": 4,
    "carbs": 28,
    "fat": 9,
    "time": 2700,
    "ingredients": [
      "3/4 cup strawberry jam",
      "2 Tbsp chia seeds",
      "1 cup rolled oats",
      "1 cup almond flour",
      "1/2 cup unsweetened applesauce",
      "1/4 cup brown sugar",
      "1 Tbsp butter, melted",
      "1/4 tsp salt"
    ],
    "steps": [
      "Stir chia seeds into jam and let sit at least 5 minutes.",
      "Preheat your oven to 325F (162C) and prepare an 8×8 (20x20cm) baking dish by lining it with a sheet of aluminum foil or parchment paper, leaving a few inches of overhang on the sides to allow for easy removal.",
      "Add the oats and almond flour to a high-speed blender or food processor and process on high for about 10 seconds, or until the oats have broken down into the consistency of a fine flour. Add the remaining crust ingredients and continue processing for about 20 – 30 seconds until a sticky dough begins to form. Make sure to stop and scrape down the sides of your blender/processor as necessary.\nTransfer 2/3 of the dough into your prepared baking pan, using your fingers or a spatula to ensure that it is pressed down tightly and evenly. It might be a little stubborn, so just take your time and spread it as best you can – it doesn’t have to be perfect. Spoon the chia jam over the surface, and use a spatula or knife to spread it evenly, making sure to only go within 1/4 of the edge to prevent the jam from burning. Top with remaining dough by dropping it on top in in a few separate globs, and then using your spatula to spread them out.",
      "Bake for 35 – 40 minutes, until the center has set and the bars begin to turn golden brown. Remove from the oven and let them cool in the pan for about 15 minutes before transferring them to a wire rack to cool completely. Use a sharp knife to cut them into individual bars and store them in an airtight container at room temperature for up to 5 days."
    ],
    "phase": "luteal"
  },
  {
    "title": "Middle Eastern chickpea bowls",
    "kcal": 750,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 3000,
    "ingredients": [
      "1 tbsp butter",
      "2 tbsp red onion, minced, see below for remaining onion prep",
      "1 clove garlic, minced",
      "1/2 oz pistachios, divided, roughly chopped",
      "1/2 tbsp Shawarma spice",
      "1/2 cup long grain white rice",
      "3/4 cup water",
      "1 tsp vegetable stock concentrate",
      "1 medium red onion, halved and cut into 1/2-inch thick wedges",
      "4 oz grape tomatoes",
      "1 14-oz can chickpeas, drained, rinsed, and patted very dry",
      "olive oil",
      "1/2 tbsp Shawarma spice",
      "4 tbsp sour cream",
      "1 clove garlic, minced",
      "1 tbsp butter",
      "2 tbsp cilantro, finely chopped",
      "1 lemon, zested and juiced",
      "1 tsp hot sauce",
      "salt",
      "pepper"
    ],
    "steps": [
      "Adjust rack to top position and preheat oven to 425F. Melt 1 tbsp **butter** in a small pot over medium-high heat. Add **minced onion**, **garlic**, **half the pistachios**, **Shawarma spice**, and a pinch of **salt**.  Cook, stirring, 1 minute. Stir in **rice**, **water**, **stock concentrate**, and a big pinch of **salt**. Bring to a boil, then cover and reduce heat to low. Cook until rice is tender 12-14 minutes. Keep covered off heat.",
      "Meanwhile, toss **onion wedges**, **tomatoes**, and **chickpeas** on a baking sheet with a large drizzle of **olive oil**, **Shawarma spice**, **pepper**, and a few pinches of **salt**. Roast on top rack, tossing halfway through, until veggies are tender and lightly charred and chickpeas are crispy, 18-20 minutes.",
      "While veggies and chickpeas roast, in a small bowl, combine **sour cream** and remaining **garlic** to taste. Season with salt. Stir in **water** 1 tsp at a time until mixture reaches a drizzling consistency.",
      "Fluff **rice** with fork; stir in 1 tbsp **butter** and half the **cilantro**. Season with **salt** and **pepper**. Once veggies and chickpeas are done, remove from oven and toss with **lemon zest**.",
      "Divide **rice** between shallow bowls. Top with **veggies** and **chickpeas**. Drizzle with **garlicky white sauce** and **hot sauce** to taste. Sprinkle with remaining **pistachios** and **cilantro**. Top with **lemon juice** to taste. Serve and enjoy!"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Bibim guksu",
    "kcal": 594,
    "protein": 16,
    "carbs": 96,
    "fat": 16,
    "time": 1500,
    "ingredients": [
      "6 oz somyeon or somen noodles",
      "1 small cucumber, julienned",
      "1 small carrot, grated or julienned",
      "2 oz red cabbage, thinly sliced",
      "2 oz lettuce, thinly sliced",
      "1/2 cup kimchi, thinly sliced",
      "1 egg, hard cooked, peeled, and halved",
      "1 tbsp sesame oil",
      "2 tsp sesame seeds",
      "1/4 cup Asian pear, grated",
      "2 tbsp gochujang",
      "2 tbsp rice vinegar",
      "1 tbsp soy sauce",
      "1 1/2 tbsp coarse gochugaru",
      "1 tsp honey or sugar",
      "1/2 tbsp sesame oil",
      "1 clove garlic, pressed",
      "1 1/2 tbsp water"
    ],
    "steps": [
      "In a large bowl, set up an ice bath by partially filling it with a combination of cold water and ice. Set aside. Note: this dish is meant to be a cold noodle dish and you get better results using an ice bath rather than just rinsing under tap water.",
      "Cook egg and prepare vegetables if needed. Bring a large saucepan of water to a boil over high heat. Add **somyeon**. Cook according to package directions, using tongs to constantly stir and move noodles around to prevent them from sticking to each other. Drain noodles and immediately transfer noodles to ice bath. Swish noodles around in the ice water to loosen them up a bit, then let noodles sit in the ice bath while you prepare the sauce.",
      "Mix all **sauce ingredients** together in a bowl. The sauce can be prepared ahead of time, and it will keep well for up to 2 weeks.",
      "Place **noodles** in the middle of each serving bowl and nicely arrange the cold **vegetables** over the noodles. Drizzle the **sesame oil** over, sprinkle with the **sesame seeds**, and place a half of **boiled egg** on top. The **sauce** can be served on top or separately."
    ],
    "phase": "follikel"
  },
  {
    "title": "Lemon poppy seed overnight oats",
    "kcal": 379,
    "protein": 15,
    "carbs": 55,
    "fat": 12,
    "time": 4200,
    "ingredients": [
      "1/4 cup rolled oats",
      "1/2 tbsp chia seeds",
      "1 tsp poppy seeds",
      "pinch of kosher salt",
      "1/2 cup milk",
      "2 tbsp plain Greek yogurt",
      "1/2 tbsp maple syrup",
      "1/2 lemon, zested and juiced",
      "1/4 cup fresh or frozen blueberries, for serving"
    ],
    "steps": [
      "To an airtight container, add the **rolled oats**, **chia seeds**, **poppy seeds**, and **salt**, then stir to combine. To the same container, add the **milk**, **yogurt**, **maple syrup**, and **lemon zest and juice**, and stir well to combine. Allow the mixture to sit for 10 minutes, then stir well to prevent the chia from clumping. Seal the container and place in the fridge for at least 1 hour or overnight.",
      "When ready to serve, stir well, then top with **blueberries**. The oats can be store in the fridge for up to 4 days."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Chocolate chip cookie dough overnight oats",
    "kcal": 377,
    "protein": 13,
    "carbs": 49,
    "fat": 16,
    "time": 4200,
    "ingredients": [
      "1/3 cup rolled oats",
      "1/2 tbsp chia seeds",
      "pinch of kosher salt",
      "1/2 cup whole milk",
      "2 tbsp plain Greek yogurt",
      "1 tbsp almond butter",
      "1 tsp brown sugar",
      "1/2 tsp vanilla extract",
      "1 tbsp chocolate chips",
      "1/4 Banana, sliced, optional for serving"
    ],
    "steps": [
      "To an airtight container, add the **oats**, **chia seeds**, and **salt**, then stir to combine. Pour in **milk**, **yogurt**, **almond butter**, **maple syrup**, **vanilla**, and **chocolate chips** then stir again making sure the chia seeds don't clump. Allow the mixture to sit for 5 minutes, stir once more, then store in the fridge for up to 4 days. Top with **banana** before serving."
    ],
    "phase": "luteal"
  },
  {
    "title": "BBQ Vegetable Salad",
    "kcal": 441,
    "protein": 16,
    "carbs": 74,
    "fat": 10,
    "time": 1800,
    "ingredients": [
      "1 bunch lacinato kale, stems removed and leaves thinly sliced",
      "Salt and black pepper",
      "1 head romaine, thinly sliced",
      "1/2 bunch cilantro, leaves and tender stems thinly sliced",
      "1/2 cup barbeque sauce",
      "1/4 cup lime juice",
      "1 15-oz can white beans, drained and rinsed",
      "2 peaches (ripe and firm), cut into 1-inch-thick wedges",
      "1 red onion, cut into 1/2-inch-thick wedges through the root",
      "1 lb grilling vegetables",
      "Safflower oil",
      "1 handful tortilla chips, crushed"
    ],
    "steps": [
      "Heat the grill to medium-high. In a large shallow bowl or platter, sprinkle the **kale** with a pinch each of **salt and pepper**. Squeeze with your hands until shiny and softened. Add the **romaine** and **cilantro** and toss to coat. Set aside.",
      "In a small bowl, stir together the **barbeque sauce** and **lime juice**. Season to taste with salt and pepper. In a separate small bowl, stir together the **beans** and 1/2 tbsp per serving of the **barbeque-lime mixture**. On a sheet pan or large bowl, toss the **peaches**, **onion**, and **vegetables** with enough oil to coat. Season with salt and pepper.",
      "Clean and grease the grates. Grill the peaches and vegetables until charred and tender, 2-10 minutes, depending on the density and size of the vegetables. Return to the bowl or sheet pan and head back inside.",
      "Drizzle some of the **dressing** over the **greens**, then arrange the **grilled vegetables**, **peaches**, **beans**, and **chips** on top. Drizzle with more **dressing**. Eat right away, with any remaining dressing and additional chips alongside."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Grilled tofu tacos",
    "kcal": 561,
    "protein": 19,
    "carbs": 60,
    "fat": 30,
    "time": 1800,
    "ingredients": [
      "2 tbsp safflower oil, plus more for oiling grates",
      "1 tbsp garlic, minced",
      "1 tsp Old Bay seasoning",
      "1 canned chipotle pepper in adobo, minced",
      "1 tbsp adobo sauce",
      "1 lb firm tofu, drained, halved lengthwise and each half cut into 4 equal rectangles (for full pound)",
      "Salt and pepper",
      "1/3 cup sour cream",
      "1/4 cup whole milk",
      "1/4 cup fresh cilantro, chopped",
      "8 flour tortillas",
      "1 cup Cabbage, shredded",
      "1/2 cup Pico de gallo",
      "1 avocado, sliced",
      "Lime wedges"
    ],
    "steps": [
      "In a medium nonstick skillet, heat **oil** over medium. Add **garlic** and cook, stirring, until fragrant, 30 seconds. Add **Old Bay**, **chipotle pepper** and the **adobo sauce**; cook, stirring, 1 minute. Turn off heat and add tofu; season with salt and pepper and toss to evenly coat. Let marinate, turning occasionally, for 15 minutes.",
      "Meanwhile, heat a grill to medium and lightly oil the grates.",
      "In a small bowl, stir to combine **sour cream**, **milk**, and **a little chopped cilantro**.",
      "Arrange **tofu** on grill and cook, basting with any remaining marinade and turning occasionally, until golden and nicely charred all over, 5 minutes. Meanwhile, warm **tortillas**.",
      "Divide **tofu** among **tortillas** and drizzle with some of the **sour cream mixture**. Top each taco with **cabbage**, **pico de gallo**, **avocado**, **remaining cilantro**, and **lime** to taste."
    ],
    "phase": "follikel"
  },
  {
    "title": "Mushroom and herb shepherd's pie",
    "kcal": 676,
    "protein": 17,
    "carbs": 68,
    "fat": 38,
    "time": 3900,
    "ingredients": [
      "16 oz Yukon gold potatoes, diced into 1/2-inch pieces",
      "8 oz button mushrooms, trimmed and quartered",
      "6 oz carrots, finely diced",
      "1/2 yellow onion, diced",
      "1 tbsp butter",
      "1 1/2 tsp fresh thyme, finely chopped",
      "1 tsp garlic powder",
      "1 tbsp flour",
      "1.5 oz tomato paste",
      "3/4 cup water",
      "2 tsp vegetable stock concentrate",
      "2 tbsp sour cream",
      "1/2 cup white cheddar, shredded, divided",
      "2 tbsp butter",
      "Olive oil",
      "Salt and pepper"
    ],
    "steps": [
      "Place **potatoes** in a large pot with enough salted water to cover by 2 inches. Bring to a boil and cook until tender, 15-20 minutes. Reserve **1/2 cup potato cooking liquid** then drain and return potatoes to pot. Keep covered off heat until ready to mash.",
      "While potatoes cook, heat a large drizzle of olive oil in a medium, preferably ovenproof, pan over medium-high heat. Add **mushrooms** and a big pinch of salt. Cook, stirring occasionally until lightly browned, 5 minutes.  Add a drizzle of olive oil to pan then stir in **carrots**, **onion**, and salt. Cook, stirring, until veggies are softened, 5-7 minutes more.",
      "Stir **butter** into pan with **veggies** until melted, then add **thyme**, **garlic powder**, and **flour**. Cook, stirring, 1 minute. Stir in **tomato paste** until incorporated, 1 minutes. Pour in **water** and **stock concentrate**, scraping up any browned bits from bottom of pan. Bring to a boil, then reduce to a low simmer and cook until sauce has thickened, 2-3 minutes. Season with salt and pepper to taste. Turn off heat. If you pan isn't ovenproof, transfer mixture now to a baking dish.",
      "Mash drained **potatoes** with **sour cream**, **half the cheddar** and **butter** until smooth and creamy, adding splashes of **reserved potato cooking liquid** as needed. Season with salt and pepper.",
      "Heat broiler to high. Once filling has thickened, spoon **mashed potatoes** on top. Spread into an even layer, leaving a 1-inch border around edge of pan. Sprinkle potatoes with **remaining cheddar**. Broil until cheese is lightly browned, 3-4 minutes. Watch carefully to avoid burning. Let rest as least 5 minutes, then divide between plates and serve."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Mexicali black bean soup",
    "kcal": 620,
    "protein": 0,
    "carbs": 0,
    "fat": 0,
    "time": 1500,
    "ingredients": [
      "1 medium yellow onion, diced",
      "2 green onions, thinly sliced, separate whites from greens",
      "1 tbsp southwest spice",
      "1 Roma tomato, diced",
      "1.5 oz tomato paste",
      "1 tbsp BBQ sauce",
      "1 1/2 tbsp taco seasoning",
      "2 cup vegetable stock",
      "1 14oz can black beans, drained and liquid reserved",
      "1/4 cup reserved bean liquid",
      "olive oil",
      "salt and pepper",
      "2 tbsp sour cream",
      "1/4 tsp smoked paprika",
      "1 1/2 oz tortilla chips",
      "1/2 cup cheddar, shredded"
    ],
    "steps": [
      "Heat a large drizzle of oil in a large pot over medium-high heat. Add **onion** and **scallion whites**. Cook stirring until softened, 3-4 minutes. Add **southwest spice**, stir until fragrant, 30 seconds. Stir in **diced tomato**, **tomato paste**, **BBQ sauce** and **taco seasoning**, cook until slightly darkened in color, 1 minute.",
      "Stir in **vegetable stock**, **beans** and **reserved bean liquid** into pot. Bring to a boil and cook, stirring occasionally, until thickened 5-8 minutes. Taste and season with salt and pepper. Turn off heat.",
      "Meanwhile, in a small bowl, mix **sour cream** and **smoked paprika**. Season to taste with salt and pepper.",
      "Divide soup between bowls and top with **scallion greens**, **cheddar**, **smoky sour cream**, and as many **crushed tortilla chips** as you'd like. Serve with remaining **whole tortilla chips** on the side."
    ],
    "phase": "luteal"
  },
  {
    "title": "Tofu poke bowl",
    "kcal": 639,
    "protein": 25,
    "carbs": 81,
    "fat": 16,
    "time": 1200,
    "ingredients": [
      "2 oz white onion, thinly sliced",
      "6.5 oz deep-fried firm tofu cutlet (atsuage)",
      "1 Tbsp toasted sesame oil",
      "3 Tbsp soy sauce",
      "1/2 Tbsp rice vinegar, (unseasoned)",
      "1 tsp Sambal Oelek Chili Paste",
      "1 carrot, julienned or grated",
      "1/4 English cucumber, thinly sliced",
      "3 oz radish, thinly sliced",
      "3 oz red cabbage, cored and thinly sliced",
      "2 green onions, thinly sliced",
      "1/2 avocado, sliced",
      "1 lime, juiced",
      "2 servings cooked Japanese short-grain brown rice (typically 1 2/3 cups per donburi serving)",
      "2 Tbsp shelled edamame",
      "1/2 tsp toasted black sesame seeds",
      "1/2 tsp toasted white sesame seeds"
    ],
    "steps": [
      "Open the package of 1 block deep-fried firm tofu cutlet (atsuage) and remove any moisture with a paper towel. Cut the tofu into bite-sized pieces, about 12 pieces for the whole block. Heat toasted sesame oil in a large frying pan over medium heat and add the white onion. Sauté until the onion is coated with oil. Then, add the tofu cubes. Once the tofu is coated with oil, add soy sauce, rice vinegar, and Sambal Oelek Chili Paste. Reduce the heat to medium-low and coat the tofu with the sauce. Turn off the heat and remove it from the stove once the tofu is well-coated with the sauce.",
      "Prepare toppings and squeeze the lime juice over the avocado to prevent browning. Place brown rice in individual large bowls. Place the bulky ingredients on top first, such as the pan-fried tofu, avocado, and red cabbage. Then, divide and add the rest of the ingredients: The carrot, cucumber, radish, cabbage, and edamame. Sprinkle sesame seeds and the chopped green onions on top."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Grilled eggplant sandwich",
    "kcal": 576,
    "protein": 12,
    "carbs": 61,
    "fat": 34,
    "time": 1500,
    "ingredients": [
      "2 tablespoon olive oil",
      "1 garlic clove, minced",
      "2 ciabatta rolls, split",
      "4 slices eggplant (1/2 inch thick)",
      "1 medium heirloom tomato, cut into 1/2-inch slices",
      "1/4 teaspoon salt",
      "1/8 teaspoon pepper",
      "1/2 package Boursin",
      "6 fresh basil leaves"
    ],
    "steps": [
      "Mix oil and garlic; brush onto cut sides of rolls and both sides of vegetables. Sprinkle vegetables with salt and pepper.",
      "Grill eggplant, covered, over medium heat until tender, 4-5 minutes per side. Grill tomato, covered, until lightly browned, 1-2 minutes per side. Grill rolls, cut side down, until toasted, 1-2 minutes.",
      "Spread roll bottoms with goat cheese. Top with basil, eggplant and tomato; close sandwiches."
    ],
    "phase": "follikel"
  },
  {
    "title": "Avocado Breakfast Flatbreads with Pickled White Beans",
    "kcal": 568,
    "protein": 22,
    "carbs": 82,
    "fat": 24,
    "time": 1260,
    "ingredients": [
      "1/2 15oz can cannellini beans, drained and rinsed",
      "1 tbsp extra virgin olive oil (plus extra for drizzling)",
      "2 scallions, thinly sliced (separate the whites and greens)",
      "2 clove garlic, minced",
      "Kosher salt",
      "1 avocado, cubed",
      "1/4 cup cilantro leaves, minced",
      "1/4 cup parsley leaves, minced",
      "1/4 cup pickled jalapeños, diced",
      "1 tbsp brine from a jar of pickled jalapeños",
      "1 lime, Juiced and zested",
      "Cracked black pepper",
      "2 whole wheat pitas"
    ],
    "steps": [
      "Heat the oil in a small sauté pan over medium-low heat. When hot, add the white portion of the scallions and garlic with a pinch of salt. Sauté for 2-3 minutes or until the garlic becomes slightly golden in color.",
      "Combine the fried scallions and garlic with all other ingredients (besides the pitas) in a medium mixing bowl.",
      "Heat up/lightly toast the pitas. Spoon the avocado-bean mixture into them."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Banana Nut Chia Pudding",
    "kcal": 423,
    "protein": 10,
    "carbs": 48,
    "fat": 21,
    "time": 600,
    "ingredients": [
      "1 banana",
      "3/4 cup whole milk",
      "1/3 cup Greek yogurt",
      "1 1/2 tbsp maple syrup",
      "2 tbsp raw pecans",
      "1 tsp vanilla paste or extract",
      "1 tsp ground cinnamon",
      "1/4 tsp ground cardamom",
      "1/3 cup chia seeds",
      "2 tbsp brown sugar, packed",
      "1/3 cup pecans",
      "1/2 tsp cinnamon",
      "Kosher salt"
    ],
    "steps": [
      "To a blender cup, add the banana, milk, yogurt, maple syrup, pecans, vanilla, cinnamon, cardamom and a pinch of salt. Blend everything until completely smooth, scraping down the sides of the blender cup as needed.",
      "To a large storage container, add the chia seeds then pour in the blended banana milk. Whisk the mixture together well, cover and let the mixture set for 5 minutes. Whisk again to help remove any clumps that may have formed then cover again and allow to refrigerate for at least an hour before using.",
      "In a mini-food processor, add the brown sugar, pecans, cinnamon and a pinch of salt. Pulse the mixture together until it becomes crumbly to your liking.",
      "To serve, layer a spoonful of the crumble in a small cup, then add the chia pudding on top. Top with another spoonful of the crumble mix and extra banana slices as desired."
    ],
    "phase": "luteal"
  },
  {
    "title": "Soba salad with grilled mushrooms and tofu",
    "kcal": 508,
    "protein": 24,
    "carbs": 70,
    "fat": 19,
    "time": 1500,
    "ingredients": [
      "Salt",
      "14 oz extra-firm tofu",
      "3 limes, juiced (about 6 tablespoons)",
      "3 tablespoon neutral oil, such as grapeseed, plus more for greasing",
      "3 tablespoon white miso",
      "3 tablespoon maple syrup",
      "8 ounce mushrooms (any type), trimmed into large, bite-size pieces",
      "8 ounce soba noodles",
      "8 ounce sugar snap peas or snow peas, halved lengthwise",
      "1 serrano chile, finely chopped",
      "2 tablespoon toasted sesame seeds",
      "1 cup basil, cilantro or mint leaves, or a combination, torn if large"
    ],
    "steps": [
      "Step 1\nHeat a grill to medium-high. Bring a large pot of salted water to a boil. Meanwhile, cut the tofu in half lengthwise, then slice crosswise into 6 sections. (You’ll have 12 squares total.) Pat the tofu dry. In a large bowl, use a fork to stir together the lime juice, oil, miso and maple syrup until smooth. Add the tofu and turn to coat. On a sheet pan, toss the mushrooms with enough oil to coat, about 2 tablespoons; season generously with salt.",
      "Step 2\nWhen the water’s boiling, add the soba noodles and cook according to package directions. Drain, rinse under cold water until cool, then shake the colander to remove as much water as possible. Set aside.",
      "Step 3\nClean and grease the grates. Grill the tofu (closed if using a gas grill) until it releases from the grates and grill marks appear, 3 to 5 minutes per side. Return the tofu to the bowl of dressing. While the tofu’s grilling, grill the mushrooms, turning occasionally, until browned and tender, 10 to 15 minutes. Return the mushrooms to the sheet pan and head back inside.",
      "Step 4\nTo the bowl of tofu, add the soba, snap peas, mushrooms, chile, sesame seeds and basil. Use your hands to toss gently. Season to taste with salt if needed.2032"
    ],
    "phase": "menstruation"
  },
  {
    "title": "Cheesy Cabbage Tteokbokki",
    "kcal": 567,
    "protein": 16,
    "carbs": 90,
    "fat": 17,
    "time": 1200,
    "ingredients": [
      "4 eggs",
      "1 tablespoon granulated sugar",
      "3 tablespoon gochujang",
      "1 tablespoon soy sauce",
      "1 garlic clove, finely grated",
      "3 tablespoon unsalted butter",
      "2 large shallots, thinly sliced crosswise into rings",
      "Salt",
      "1 cup water, cold tap water",
      "1 pound fresh or frozen tteok",
      "1/2 cup shredded cheese, such as sharp Cheddar or low-moisture mozzarella",
      "5 ounce green cabbage, shredded (5 oz=about 2 cups)"
    ],
    "steps": [
      "Soft-boil eggs.",
      "In a small bowl, stir together the sugar, gochujang, soy sauce and garlic. Set aside.",
      "In a large pan, melt the butter over medium-high heat. Add the shallots, season generously with salt and cook, stirring constantly, until the edges of the shallots are really brown, 5 to 7 minutes. Stir in the gochujang mixture and cook, stirring for a few seconds, just until the sauce loses its raw edge.",
      "Stir in cold tap water and add the tteok, making sure to separate them if stuck together. Bring to a simmer over medium-high and cook until the sauce thickens and the tteok are heated through but still chewy, 4 to 6 minutes. (Add a minute or two if using frozen rice cakes.)",
      "Scatter over the cheese, followed by the cabbage. Cover to let the cheese melt; the cabbage will steam slightly and lose some of its raw edge. Transfer to bowls or plates, then halve the soft-boiled eggs and arrange them over top."
    ],
    "phase": "follikel"
  },
  {
    "title": "Grilled loaded nachos",
    "kcal": 680,
    "protein": 24,
    "carbs": 61,
    "fat": 41,
    "time": 2700,
    "ingredients": [
      "1 medium tomato, large diced",
      "1 tablespoon extra-virgin olive oil",
      "1/2 tsp kosher salt",
      "1 tsp extra-virgin olive oil, divided",
      "1/2 medium red onion, large diced",
      "1 poblano chiles, large diced",
      "1 jalapeño chiles, large diced",
      "1/2 15oz can black beans, drained and rinsed",
      "1 tsp extra-virgin olive oil",
      "1 tbsp lime juice",
      "1 tbsp fresh cilantro, chopped",
      "salt & pepper",
      "2 ounce Monterey Jack cheese, shredded",
      "2 ounce sharp cheddar cheese, shredded",
      "3 ounce tortilla chips",
      "2 scallions, thinly sliced",
      "Salsa for serving, optional"
    ],
    "steps": [
      "Toss tomatoes with oil, salt, and black pepper to taste in large bowl. Let stand for at least 15 minutes or up to 1 hour.",
      "Heat grill to 400F.",
      "Toss all veggies (tomatoes, onions, peppers) with oil, salt, and pepper. Grill in a veggie basket for 10 minutes, tossing halfway. When finished, toss with beans, lime juice, and cilantro.",
      "In a large grill basket, layer half the chips, half the beans/veggies, half the cheese, and half the green onion, then the second half of each. Return to grill for 15 minutes.",
      "Serve with salsa."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Hiyashi Chuka Ramen",
    "kcal": 360,
    "protein": 17,
    "carbs": 48,
    "fat": 11,
    "time": 1800,
    "ingredients": [
      "1/2 tsp ginger, grated",
      "3 tbsp soy sauce",
      "2 tbsp rice vinegar",
      "2 tbsp chicken stock",
      "1 tbsp water",
      "4 tsp sugar",
      "2 tsp toasted sesame oil",
      "1/4 tsp chili oil",
      "2 large eggs",
      "1/2 tbsp sugar",
      "1 pinch salt",
      "olive oil",
      "2 persian cucumbers, matchsticked",
      "1/4 cup cherry tomatoes, halved",
      "1/4 lb mushrooms, sliced thin",
      "2 stick real or imitation crabmeat, shredded",
      "2 servings ramen noodles",
      "1 tsp toasted white sesame seeds",
      "Japanese karashi hot mustard (optional)",
      "pickled red ginger (optional, beni shoga or kizami beni shoga)"
    ],
    "steps": [
      "Mix all dressing ingredients in a small saucepan. Bring to a simmer then turn off the heat, ensuring the sugar is fully dissolved. Cool the sauce in an ice bath, or make ahead and refrigerate.",
      "Beat egg with seasoning, then fry into a thin, flat omelette. Let cool, then cut in half, and then into thin strips.",
      "Lightly saute the mushrooms.",
      "Boil water in a medium pot for the noodles. Separate the noodles by hand, then add to the water and cook per package directions. Drain and cold rinse to stop cooking.",
      "Plate noodles, then arrange ingredients over them, and top with sauce. Add sesame seeds, and mustard/ginger on the side if desired."
    ],
    "phase": "luteal"
  },
  {
    "title": "Sweet and Spicy Tofu With Soba Noodles",
    "kcal": 543,
    "protein": 24,
    "carbs": 70,
    "fat": 20,
    "time": 1800,
    "ingredients": [
      "21 oz firm tofu, drained and pressed while prepping",
      "2 tablespoon canola oil",
      "1 tablespoon sesame oil",
      "8 oz dried soba noodles",
      "1 tablespoon sesame oil",
      "4 clove garlic, smashed",
      "1 tablespoon ginger, peeled and thinly sliced",
      "4 green onions, white and green parts separated, cut into 2-inch matchsticks",
      "1/3 cup soy sauce",
      "3 tablespoon dark brown sugar",
      "1 teaspoon black pepper",
      "Pinch of red-pepper flakes",
      "4 Persian cucumbers, thinly sliced",
      "4 radishes, thinly sliced",
      "1/4 cup fresh cilantro, chopped",
      "1 lime, cut in wedges, for serving"
    ],
    "steps": [
      "Step 1\nBring a small pot of water to a boil for the soba noodles.",
      "Step 2\nCut tofu into 1-inch cubes. Heat a cast-iron skillet over medium-high heat. Add the vegetable oil and sesame oil. When the oil shimmers, add the tofu in a single layer, in batches if needed and cook until golden on all sides, turning as needed when the tofu releases easily from the pan, about 8 to 10 minutes total. Lift the tofu out of the pan with a spatula and transfer to a new paper-towel-lined plate.",
      "Step 3\nMeanwhile, cook the soba in boiling water for 5 to 8 minutes (or according to package directions), until just al dente, stirring frequently. Drain and rinse in cold water until the noodles no longer feel sticky.",
      "Step 4\nAdd garlic, ginger and whites of the onions to the skillet, along with the remaining sesame oil, reduce the heat to medium, and cook until the oil is fragrant, stirring constantly, about 1 minute.",
      "Step 5\nAdd cooked and drained soba noodles to the pan, along with soy sauce, sugar, black pepper, red pepper and reserved green onions; toss together until the noodles are coated. Gently toss in the tofu until all the pieces are covered in the sauce.",
      "Step 6\nRemove from the heat, and sprinkle cucumber, radish and cilantro on top. Serve warm or at room temperature, with lime."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Chinese Stir-Fried Tomatoes and Eggs",
    "kcal": 466,
    "protein": 16,
    "carbs": 36,
    "fat": 30,
    "time": 1200,
    "ingredients": [
      "6 eggs",
      "Kosher salt",
      "1/2 teaspoon sesame oil",
      "1 tablespoon Shaoxing rice wine or dry sherry",
      "1 teaspoon potato starch",
      "1 teaspoon sugar",
      "2 tablespoon ketchup",
      "1 pound tomatoes, or 1 14.5-ounce can of diced tomatoes in juice",
      "4 tablespoon vegetable oil",
      "3 scallions, sliced",
      "1 teaspoon ginger, minced",
      "1 1/2 cup cooked rice, for serving"
    ],
    "steps": [
      "Step 1\nIn a mixing bowl, beat the eggs well with 1 teaspoon salt, sesame oil and rice wine or sherry. In a small bowl, stir together the cornstarch and 2 tablespoons water until well combined, then stir in the sugar and ketchup.",
      "Step 2\nIf using fresh tomatoes, core and cut them into ½-inch wide wedges.",
      "Step 3\nHeat a wide nonstick skillet over high heat with 3 tablespoons of vegetable oil. When the oil shimmers, add most of the scallions, saving some to garnish. Cook, stirring, until very aromatic, about 20 seconds. Add the eggs, and cook, stirring well with a spatula or chopsticks, until just set but still runny, about 45 seconds. Pour the eggs back into the mixing bowl, and wipe out the pan.",
      "Step 4\nReheat the pan over high heat with the remaining tablespoon of oil. When it is hot, add the ginger and cook until aromatic, about 15 seconds. Add the tomatoes and salt to taste; cook, stirring occasionally, until the flesh has softened but still has some shape and the juices have begun to form a sauce, 2 to 3 minutes. (If using canned tomatoes, add the juice as well and cook about 4 minutes, to reduce it to a saucelike consistency.)",
      "Step 5\nReduce the heat to medium. Give the cornstarch-ketchup mixture a stir in its bowl, then stir it into the pan. Cook, stirring, until the sauce returns to a boil and thickens. Taste and adjust seasoning with salt, sugar or more ketchup — you want a savory, tart-sweet sauce. Stir the eggs in the bowl to cut up the curds a bit, then return them to the pan. Cook, stirring, for a few seconds to finish cooking the eggs and to combine. Top with the reserved scallions, and serve with steamed rice."
    ],
    "phase": "follikel"
  },
  {
    "title": "Chocolate protein powder mix",
    "kcal": 98,
    "protein": 18,
    "carbs": 2,
    "fat": 1,
    "time": 30,
    "ingredients": [
      "170 g unflavored whey protein isolate powder",
      "28 g unsweetened cocoa powder",
      "30 g sugar",
      "1/4 teaspoon fine sea salt",
      "1/2 teaspoon vanilla powder, optional"
    ],
    "steps": [
      "Whisk whey protein powder, cocoa, sugar, salt, and vanilla, if using, together in a bowl; transfer to a storage container with a tight-fitting lid."
    ],
    "phase": "ovulation"
  },
  {
    "title": "Chocolate protein shake",
    "kcal": 172,
    "protein": 22,
    "carbs": 0,
    "fat": 5,
    "time": 30,
    "ingredients": [
      "1 cup whole milk",
      "1 cup water",
      "70 g protein powder mix",
      "1/2 cup ice"
    ],
    "steps": [
      "Place ingredients into a blender jar in the order listed. Blend until smooth. Serve."
    ],
    "phase": "luteal"
  },
  {
    "title": "Shredded Tofu and Shiitake Stir-Fry",
    "kcal": 562,
    "protein": 27,
    "carbs": 58,
    "fat": 29,
    "time": 30,
    "ingredients": [
      "14 oz firm tofu, drained",
      "2 tablespoon soy sauce",
      "1 tablespoon Chinese Shaoxing",
      "1/2 lime, juiced",
      "2 teaspoon toasted sesame oil",
      "2 tablespoon vegetable oil",
      "7 ounce shiitake mushrooms, stems removed and caps thinly sliced",
      "1/4 cup sliced scallion",
      "1 stalk lemongrass, trimmed, outer leaves removed, inner core finely chopped (optional)",
      "1 tablespoon ginger, grated",
      "1 garlic clove, grated",
      "1 small red chile, seeded and finely chopped",
      "Salt, as needed",
      "1/2 cup shelled edamame, (defrosted if using frozen)",
      "1/4 cup fresh cilantro or chives, chopped",
      "1 1/2 cup cooked white rice, for serving"
    ],
    "steps": [
      "Step 1\nUsing the coarse holes of a box grater, shred the tofu. Spread tofu out on a clean kitchen towel to drain while you prepare the sauce and mushrooms.",
      "Step 2\nIn a small bowl, whisk together soy sauce, Shaoxing, lime juice and sesame oil.",
      "Step 3\nHeat a large skillet over medium-high heat until it’s very hot, then add the peanut oil; it should thin out on contact. Once the oil is hot, add the mushrooms and cook, tossing occasionally, until most of the mushroom liquid has evaporated and mushrooms are browned and slightly crisp, 8 to 12 minutes. Stir in the scallion, lemongrass, ginger, garlic, chile and a pinch of salt. Cook until softened, about 2 minutes.",
      "Step 4\nCarefully transfer the tofu from the towel into the skillet. Toss in the edamame and the soy sauce mixture. Cook until mixture is heated through. Season with salt as needed. Remove from heat and stir in herbs. Serve with rice."
    ],
    "phase": "menstruation"
  },
  {
    "title": "Vegetarian Mushroom Shawarma Pitas",
    "kcal": 552,
    "protein": 20,
    "carbs": 54,
    "fat": 30,
    "time": 30,
    "ingredients": [
      "3/4 pound portobello mushroom caps, sliced ½-inch thick",
      "1 medium red onion, halved and cut into ⅓-inch wedges",
      "3 tablespoon extra-virgin olive oil",
      "2 teaspoon shawarma spice",
      "1 teaspoon salt",
      "1/2 teaspoon black pepper",
      "2 pitas",
      "2 packed cups very thinly sliced red cabbage (about 6 ounces)",
      "2 teaspoon extra-virgin olive oil",
      "3/4 cup 2% Greek yogurt",
      "3/4 teaspoon ground turmeric",
      "4 tablespoon Cilantro or mint, for serving"
    ],
    "steps": [
      "Step 1\nHeat the oven to 425 degrees. On a large rimmed sheet pan, drizzle the mushrooms and red onion with 3 tablespoons oil. Sprinkle with shawarma spice, salt and pepper; toss to coat. Arrange in an even layer and roast until tender and browned, about 20 minutes. Add the pitas directly to the oven rack to warm during the last 5 minutes of cooking.",
      "Step 2\nMeanwhile, toss cabbage with remaining oil in a medium bowl; toss to coat. Season generously with salt and pepper. In a small bowl, stir together yogurt and turmeric; season with salt and pepper.",
      "Step 3\nTo serve, slather yogurt over warm pitas. Top with cabbage, mushroom mixture and herbs, and serve immediately."
    ],
    "phase": "follikel"
  },
  {
    "title": "Tofu salad slaw with peanuts and nori",
    "kcal": 425,
    "protein": 30,
    "carbs": 18,
    "fat": 28,
    "time": 1800,
    "ingredients": [
      "1/4 cup creamy peanut butter",
      "2 tablespoon soy sauce",
      "2 tablespoon rice vinegar",
      "1 1-inch piece fresh ginger, finely chopped",
      "1 clove garlic, finely chopped",
      "Warm water",
      "12 ounce green or Napa cabbage, thinly sliced (or use bag of slaw blend)",
      "Salt",
      "2 14-oz packages tofu, drained and patted dry, shredded or torn into bite size pieces",
      "2 Persian cucumbers, thinly sliced",
      "1/2 cup roasted unsalted peanuts, roughly chopped",
      "3 scallions, thinly sliced",
      "1 0.17-ounce pack nori snacks"
    ],
    "steps": [
      "Step 1\nIn a liquid measuring cup or small bowl, stir together the **peanut butter**, **soy sauce**, **rice vinegar**, **ginger** and **garlic**. Add **warm water**, 1/2 tablespoon at a time, until saucy but still creamy.",
      "Step 2\nIn a large bowl, season the **cabbage** with a pinch of salt. Squeeze until wilted slightly. Add the **tofu**, **cucumbers** and **dressing**. Toss to combine. (Slaw can be made up to this point up to 1 day ahead.) Top with the **peanuts** and **scallions**. If packing ahead of time, put **nori** on the side to keep dry. When ready to serve, crush the nori in your hands and add to the salad."
    ],
    "phase": "ovulation"
  }
];

const MEAT_KEYS_OR = ["beef", "chicken", "pork", "lamb", "turkey", "bacon", "sausage", "ham", "veal", "steak"];
const FISH_KEYS_OR = ["shrimp", "salmon", "tuna", "fish", "shellfish", "crab", "lobster", "scallop"];
const DAIRY_KEYS_OR = ["cheese", "butter", "cream", "milk", "yogurt", "parmesan"];
const EGG_KEYS_OR = ["egg"];
const GLUTEN_KEYS_OR = ["flour", "bread", "pasta", "wheat", "noodle", "cracker", "panko", "breadcrumb"];

function convertOpenRecipeToAppRecipe(r, idx) {
  const phase = PHASES[r.phase];
  const allIngText = r.ingredients.join(" ").toLowerCase();
  const hasAny = (keys) => keys.some((k) => allIngText.includes(k));
  const meat = hasAny(MEAT_KEYS_OR);
  const fish = hasAny(FISH_KEYS_OR);
  const dairy = hasAny(DAIRY_KEYS_OR);
  const egg = hasAny(EGG_KEYS_OR);
  const gluten = hasAny(GLUTEN_KEYS_OR);

  const tags = [];
  if (r.protein >= 25) tags.push("High Protein");
  if (!meat && !fish && !dairy && !egg) tags.push("Vegan");
  if (fish) tags.push("Omega-3");
  if (r.time <= 30) tags.push("Schnell");
  if (tags.length === 0) tags.push("Ausgewogen");

  return {
    id: `openrecipe-{idx}`,
    title: r.title,
    cuisine: null,
    phase: r.phase,
    time: r.time,
    kcal: r.kcal,
    protein: r.protein,
    carbs: r.carbs,
    fat: r.fat,
    tags: tags.slice(0, 3),
    micronutrient: phase.focus[idx % phase.focus.length],
    ingredients: r.ingredients,
    steps: r.steps,
    why: `Klassisches Gericht aus einer offenen Rezeptsammlung, mit echten Original-N\u00e4hrwertangaben.`,
    color: phase.color,
    meat,
    fish,
    dairy,
    gluten,
    egg,
  };
}

function buildConvertedOpenRecipes() {
  return OPEN_RECIPE_DB.map((r, i) => convertOpenRecipeToAppRecipe(r, i));
}

function convertCycleRecipeToAppRecipe(dbRecipe, phaseKey) {
  const phase = PHASES[phaseKey];
  let kcal = 0,
    protein = 0,
    carbs = 0,
    fat = 0;
  let meatFlag = false,
    fishFlag = false,
    dairyFlag = false,
    eggFlag = false,
    glutenFlag = false;

  dbRecipe.zutaten.forEach((str) => {
    const lower = str.toLowerCase();
    if (DIET_CONFLICT_WORDS.meat.some((w) => lower.includes(w))) meatFlag = true;
    if (DIET_CONFLICT_WORDS.fish.some((w) => lower.includes(w))) fishFlag = true;
    if (DIET_CONFLICT_WORDS.dairy.some((w) => lower.includes(w))) dairyFlag = true;
    if (DIET_CONFLICT_WORDS.gluten.some((w) => lower.includes(w))) glutenFlag = true;
    if (/\bei\b|eier/.test(lower)) eggFlag = true;
    const food = FOOD_DB.find((f) => f.keys.some((k) => hasWholeWordMatch(lower, k)));
    if (food) {
      const parsed = parseIngredientString(str);
      const grams = resolveGrams(food, { num: parsed.amount, unit: parsed.unit });
      const scale = grams / 100;
      kcal += food.kcal * scale;
      protein += food.protein * scale;
      carbs += food.carbs * scale;
      fat += food.fat * scale;
    }
  });

  if (kcal === 0) {
    kcal = 380;
    protein = 15;
    carbs = 40;
    fat = 14;
  }

  const micronutrient = (dbRecipe.fokus || "").split(",")[0].trim() || phase.focus[0];
  const tags = [];
  if (Math.round(protein) >= 25) tags.push("High Protein");
  if (!meatFlag && !fishFlag && !dairyFlag && !eggFlag) tags.push("Vegan");
  tags.push(dbRecipe.mahlzeit);
  const uniqueTags = Array.from(new Set(tags)).slice(0, 3);

  return {
    id: `db-${dbRecipe.id}`,
    title: dbRecipe.titel,
    phase: phaseKey,
    time: (dbRecipe.vorbereitungszeit_min || 0) + (dbRecipe.kochzeit_min || 0),
    kcal: Math.round(kcal),
    protein: Math.round(protein),
    carbs: Math.round(carbs),
    fat: Math.round(fat),
    tags: uniqueTags.length > 0 ? uniqueTags : ["Ausgewogen"],
    micronutrient,
    ingredients: dbRecipe.zutaten,
    steps: dbRecipe.zubereitung,
    why: dbRecipe.fokus,
    color: phase.color,
    meat: meatFlag,
    fish: fishFlag,
    dairy: dairyFlag,
    gluten: glutenFlag,
    egg: eggFlag,
  };
}

function buildConvertedCycleRecipes() {
  return CYCLE_RECIPE_DB.map((r) => {
    const phaseKey = Object.keys(CYCLE_RECIPE_PHASE_MAP).find((k) => CYCLE_RECIPE_PHASE_MAP[k] === r.phase) || "follikel";
    return convertCycleRecipeToAppRecipe(r, phaseKey);
  });
}

// Deterministic pseudo-random pick so the daily suggestion stays stable while
// browsing (doesn't reshuffle on every re-render) but still varies day to day.
function seededPick(arr, seed) {
  if (!arr || arr.length === 0) return null;
  let hash = 0;
  const s = String(seed);
  for (let i = 0; i < s.length; i++) hash = (hash * 31 + s.charCodeAt(i)) >>> 0;
  return arr[hash % arr.length];
}

// Cycle-day (1-28) -> phase -> one random recipe per meal (Frühstück/Mittagessen/Abendessen).
function getDailyCycleRecipes(phaseKey, cycleDay) {
  const phaseLabel = CYCLE_RECIPE_PHASE_MAP[phaseKey];
  const result = {};
  CYCLE_RECIPE_MEALS.forEach((meal) => {
    const pool = CYCLE_RECIPE_DB.filter((r) => r.phase === phaseLabel && r.mahlzeit === meal);
    result[meal] = seededPick(pool, `${phaseLabel}-${meal}-${cycleDay}`);
  });
  return result;
}

const SYMPTOMS = [
  {
    id: "cramps",
    label: "Unterleibsschmerzen",
    labelEn: "Cramps",
    icon: HeartCrack,
    why: "Prostaglandine lösen Kontraktionen der Gebärmutter aus – das erzeugt die typischen Krämpfe.",
    whyEn: "Prostaglandins trigger contractions of the uterus – that's what causes the typical cramps.",
    ingredients: ["Ingwer", "Kurkuma", "Kürbiskerne (Magnesium)"],
    ingredientsEn: ["Ginger", "Turmeric", "Pumpkin seeds (magnesium)"],
    recipeId: "signature-cramps",
    matchTag: "Anti-Bloat",
  },
  {
    id: "cravings",
    label: "Heißhunger",
    labelEn: "Cravings",
    icon: Flame,
    why: "Sinkendes Progesteron & Serotonin lassen den Blutzucker schwanken und wecken Verlangen nach schnellen Kohlenhydraten.",
    whyEn: "Falling progesterone & serotonin cause blood sugar swings and trigger cravings for fast carbs.",
    ingredients: ["Kakaonibs", "Süßkartoffel", "Zimt"],
    ingredientsEn: ["Cacao nibs", "Sweet potato", "Cinnamon"],
    recipeId: "signature-cravings",
    matchTag: "Cravings",
  },
  {
    id: "fatigue",
    label: "Energietief",
    labelEn: "Low energy",
    icon: Zap,
    why: "Ein sinkender Eisenspiegel – besonders während der Blutung – senkt die Sauerstoffversorgung deiner Zellen.",
    whyEn: "A dropping iron level – especially during bleeding – reduces oxygen supply to your cells.",
    ingredients: ["Linsen", "Spinat", "Vitamin C (Zitrus)"],
    ingredientsEn: ["Lentils", "Spinach", "Vitamin C (citrus)"],
    recipeId: "signature-fatigue",
    matchTag: "Eisen-Booster",
  },
  {
    id: "bloating",
    label: "Blähungen",
    labelEn: "Bloating",
    icon: Wind,
    why: "Progesteron verlangsamt die Verdauung und begünstigt Wassereinlagerungen.",
    whyEn: "Progesterone slows digestion and promotes water retention.",
    ingredients: ["Fenchel", "Ingwer", "Kalium (Kürbis)"],
    ingredientsEn: ["Fennel", "Ginger", "Potassium (pumpkin)"],
    recipeId: "signature-bloating",
    matchTag: "Anti-Bloat",
  },
  {
    id: "headache",
    label: "Kopfschmerzen",
    labelEn: "Headache",
    icon: Brain,
    why: "Der Östrogenabfall kurz vor der Periode kann Spannungskopfschmerz oder Migräne triggern.",
    whyEn: "The drop in estrogen right before your period can trigger tension headaches or migraines.",
    ingredients: ["Magnesium", "Elektrolyte", "ausreichend Wasser"],
    ingredientsEn: ["Magnesium", "Electrolytes", "Enough water"],
    recipeId: "signature-headache",
    matchTag: "Magnesium",
  },
  {
    id: "mood",
    label: "Stimmungsschwankungen",
    labelEn: "Mood swings",
    icon: Meh,
    why: "Schwankende Serotoninspiegel durch den Hormonabfall beeinflussen direkt deine Stimmung.",
    whyEn: "Fluctuating serotonin levels caused by the hormone drop directly affect your mood.",
    ingredients: ["Omega-3 (Lachs)", "Walnüsse", "Vollkorn"],
    ingredientsEn: ["Omega-3 (salmon)", "Walnuts", "Whole grain"],
    recipeId: "signature-mood",
    matchTag: "Omega-3",
  },
];
function localizeSymptom(s, lang) {
  if (lang !== "en") return s;
  return { ...s, label: s.labelEn, why: s.whyEn, ingredients: s.ingredientsEn };
}

const MOOD_OPTIONS = [
  { id: "energized", label: "Energiegeladen", labelEn: "Energized", value: 4, icon: Zap },
  { id: "balanced", label: "Ausgeglichen", labelEn: "Balanced", value: 3, icon: Smile },
  { id: "irritable", label: "Gereizt", labelEn: "Irritable", value: 2, icon: Meh },
  { id: "tired", label: "Müde", labelEn: "Tired", value: 1, icon: Frown },
];
const MOOD_VALUE = Object.fromEntries(MOOD_OPTIONS.map((m) => [m.id, m.value]));
function moodLabel(m, lang) {
  return lang === "en" ? m.labelEn : m.label;
}

/* ------------------------------ AI mock logic ------------------------------ */
const JUNK_SWAPS = {
  pommes: { name: "Süßkartoffel-Wedges mit Avocado-Dip", nameEn: "Sweet potato wedges with avocado dip", match: 90, kcal: 340, protein: 8, carbs: 42, fat: 16, why: "Süßkartoffeln liefern Beta-Carotin & komplexe Kohlenhydrate statt leerer Transfette.", whyEn: "Sweet potatoes provide beta-carotene & complex carbs instead of empty trans fats." },
  fritten: { name: "Süßkartoffel-Wedges mit Avocado-Dip", nameEn: "Sweet potato wedges with avocado dip", match: 90, kcal: 340, protein: 8, carbs: 42, fat: 16, why: "Süßkartoffeln liefern Beta-Carotin & komplexe Kohlenhydrate statt leerer Transfette.", whyEn: "Sweet potatoes provide beta-carotene & complex carbs instead of empty trans fats." },
  pizza: { name: "Vollkorn-Flatbread mit Gemüse & Feta", nameEn: "Whole-grain flatbread with veggies & feta", match: 85, kcal: 420, protein: 18, carbs: 46, fat: 18, why: "Vollkorn & frisches Gemüse statt raffiniertem Mehl und stark verarbeitetem Käse.", whyEn: "Whole grain & fresh veggies instead of refined flour and heavily processed cheese." },
  chips: { name: "Geröstete Kichererbsen mit Paprika", nameEn: "Roasted chickpeas with paprika", match: 88, kcal: 220, protein: 10, carbs: 28, fat: 8, why: "Genauso knusprig wie Chips, aber reich an Ballaststoffen & pflanzlichem Protein.", whyEn: "Just as crunchy as chips, but rich in fibre & plant protein." },
  burger: { name: "Linsen-Burger mit Süßkartoffel-Bun", nameEn: "Lentil burger with sweet potato bun", match: 84, kcal: 460, protein: 22, carbs: 48, fat: 16, why: "Pflanzliches Protein & Ballaststoffe statt verarbeitetem Fleisch und Weißmehl.", whyEn: "Plant protein & fibre instead of processed meat and white flour." },
  nugget: { name: "Ofen-Hähnchenspieße mit Kräutern", nameEn: "Oven-baked chicken skewers with herbs", match: 82, kcal: 380, protein: 32, carbs: 14, fat: 18, why: "Im Ofen gegart statt frittiert – weniger Transfette, mehr Protein.", whyEn: "Oven-baked instead of fried – less trans fat, more protein." },
  döner: { name: "Bowl mit Hähnchen, Bulgur & Joghurt-Dip", nameEn: "Bowl with chicken, bulgur & yoghurt dip", match: 83, kcal: 450, protein: 30, carbs: 44, fat: 14, why: "Gleiche Aromen, aber ohne frittiertes Fett und Weißbrot.", whyEn: "Same flavours, without the fried fat and white bread." },
  currywurst: { name: "Linsen-Curry mit Naturjoghurt", nameEn: "Lentil curry with plain yoghurt", match: 80, kcal: 400, protein: 20, carbs: 40, fat: 14, why: "Curry-Aromen ohne stark verarbeitetes Fleisch und Zucker-Ketchup.", whyEn: "Curry flavours without heavily processed meat and sugary ketchup." },
};
function localizedSwap(swap, lang) {
  if (!swap) return swap;
  return lang === "en" ? { ...swap, name: swap.nameEn, why: swap.whyEn } : swap;
}
const JUNK_KEYWORDS = Object.keys(JUNK_SWAPS).concat(["frittiert", "fastfood", "fast food"]);

function detectJunk(lowerText) {
  return JUNK_KEYWORDS.find((k) => lowerText.includes(k)) || null;
}
function junkKeyFor(lowerText) {
  return Object.keys(JUNK_SWAPS).find((k) => lowerText.includes(k)) || "pommes";
}

const DIET_CONFLICT_WORDS = {
  meat: ["hähnchen", "huhn", "rind", "schwein", "fleisch", "wurst", "speck", "pute", "salami"],
  fish: ["lachs", "fisch", "garnele", "thunfisch", "meeresfrüchte", "shrimp"],
  dairy: ["käse", "milch", "joghurt", "sahne", "butter", "quark"],
  gluten: ["brot", "nudel", "pasta", "weizen", "kuchen", "brötchen"],
};
function checkDietConflict(lowerText, diet, lang) {
  const has = (cat) => DIET_CONFLICT_WORDS[cat].some((w) => lowerText.includes(w));
  const label = dietLabel(diet, lang);
  if (lang === "en") {
    if (diet === "vegan" && (has("meat") || has("fish") || has("dairy"))) return `Likely contains animal ingredients – doesn't fit your ${label} diet.`;
    if (diet === "vegetarian" && (has("meat") || has("fish"))) return `Likely contains meat or fish – doesn't fit your ${label} diet.`;
    if (diet === "pescetarian" && has("meat")) return `Likely contains meat – doesn't fit your ${label} diet.`;
    if (diet === "lactose_free" && has("dairy")) return `Likely contains dairy – look for lactose-free alternatives.`;
    if (diet === "gluten_free" && has("gluten")) return `Likely contains gluten – look for gluten-free alternatives.`;
    return null;
  }
  if (diet === "vegan" && (has("meat") || has("fish") || has("dairy"))) return "Enthält vermutlich tierische Zutaten – passt nicht zu deinem veganen Ernährungsstil.";
  if (diet === "vegetarian" && (has("meat") || has("fish"))) return "Enthält vermutlich Fleisch oder Fisch – passt nicht zu deinem vegetarischen Ernährungsstil.";
  if (diet === "pescetarian" && has("meat")) return "Enthält vermutlich Fleisch – passt nicht zu deinem pescetarischen Ernährungsstil.";
  if (diet === "lactose_free" && has("dairy")) return "Enthält vermutlich Milchprodukte – achte auf laktosefreie Alternativen.";
  if (diet === "gluten_free" && has("gluten")) return "Enthält vermutlich Gluten – achte auf glutenfreie Alternativen.";
  return null;
}
function checkDietConflicts(lowerText, diets, lang) {
  const list = Array.isArray(diets) ? diets : [diets];
  for (const d of list) {
    const msg = checkDietConflict(lowerText, d, lang);
    if (msg) return msg;
  }
  return null;
}

// Per-100g (or per-100ml) macro reference values for common foods, each with a realistic
// default serving size to assume when no explicit quantity is mentioned, and (where it
// makes more sense) a per-piece weight for "2 Eier" / "1 Banane" style phrasing.
const FOOD_DB = [
  { keys: ["hafer", "haferflocken"], kcal: 370, protein: 13, carbs: 59, fat: 7, defaultG: 50 },
  { keys: ["reis"], kcal: 130, protein: 2.7, carbs: 28, fat: 0.3, defaultG: 180 },
  { keys: ["nudel", "pasta", "spaghetti", "penne"], kcal: 158, protein: 5.8, carbs: 31, fat: 0.9, defaultG: 200 },
  { keys: ["süßkartoffel"], kcal: 86, protein: 1.6, carbs: 20, fat: 0.1, defaultG: 180 },
  { keys: ["kartoffel"], kcal: 87, protein: 2, carbs: 20, fat: 0.1, defaultG: 200 },
  { keys: ["quinoa"], kcal: 120, protein: 4.4, carbs: 21, fat: 1.9, defaultG: 180 },
  { keys: ["couscous", "bulgur"], kcal: 112, protein: 3.8, carbs: 23, fat: 0.2, defaultG: 180 },
  { keys: ["brot", "brötchen", "toast"], kcal: 265, protein: 9, carbs: 49, fat: 3.2, defaultG: 60, sliceG: 30 },
  { keys: ["hähnchen", "huhn", "hühnchen", "pute", "putenbrust"], kcal: 160, protein: 30, carbs: 0, fat: 4, defaultG: 150 },
  { keys: ["rind", "rinderhack", "hackfleisch", "hack", "bolognese"], kcal: 230, protein: 20, carbs: 0, fat: 16, defaultG: 150 },
  { keys: ["carbonara"], kcal: 280, protein: 14, carbs: 2, fat: 24, defaultG: 150 },
  { keys: ["pesto"], kcal: 300, protein: 4, carbs: 4, fat: 30, defaultG: 40 },
  { keys: ["alfredo"], kcal: 250, protein: 6, carbs: 5, fat: 24, defaultG: 100 },
  { keys: ["lachs", "fisch", "forelle", "kabeljau"], kcal: 150, protein: 21, carbs: 0, fat: 8, defaultG: 150 },
  { keys: ["thunfisch"], kcal: 130, protein: 29, carbs: 0, fat: 1, defaultG: 120 },
  { keys: ["garnele", "garnelen", "shrimp"], kcal: 99, protein: 24, carbs: 0.2, fat: 0.3, defaultG: 120 },
  { keys: ["ei", "eier"], kcal: 155, protein: 13, carbs: 1.1, fat: 11, defaultG: 110, pieceG: 55 },
  { keys: ["tofu", "tempeh"], kcal: 90, protein: 10, carbs: 2, fat: 5, defaultG: 150 },
  { keys: ["feta"], kcal: 264, protein: 14, carbs: 4, fat: 21, defaultG: 40 },
  { keys: ["käse", "cheddar", "gouda", "mozzarella"], kcal: 350, protein: 25, carbs: 1.3, fat: 28, defaultG: 30 },
  { keys: ["joghurt"], kcal: 59, protein: 10, carbs: 3.6, fat: 0.4, defaultG: 150 },
  { keys: ["quark"], kcal: 67, protein: 12, carbs: 4, fat: 0.2, defaultG: 150 },
  { keys: ["milch"], kcal: 64, protein: 3.4, carbs: 4.8, fat: 3.6, defaultG: 200 },
  { keys: ["banane"], kcal: 89, protein: 1.1, carbs: 23, fat: 0.3, defaultG: 120, pieceG: 120 },
  { keys: ["apfel"], kcal: 52, protein: 0.3, carbs: 14, fat: 0.2, defaultG: 180, pieceG: 180 },
  { keys: ["beeren", "himbeere", "blaubeere", "erdbeere"], kcal: 50, protein: 1, carbs: 12, fat: 0.3, defaultG: 100 },
  { keys: ["avocado"], kcal: 160, protein: 2, carbs: 9, fat: 15, defaultG: 150, pieceG: 150 },
  { keys: ["nuss", "nüsse", "cashew", "walnuss", "haselnuss", "pistazie"], kcal: 600, protein: 18, carbs: 20, fat: 52, defaultG: 30 },
  { keys: ["mandel"], kcal: 579, protein: 21, carbs: 22, fat: 50, defaultG: 30 },
  { keys: ["schokolade"], kcal: 530, protein: 6, carbs: 57, fat: 31, defaultG: 25 },
  { keys: ["kakao"], kcal: 400, protein: 8, carbs: 45, fat: 20, defaultG: 15 },
  { keys: ["olivenöl", "leinöl", "sonnenblumenöl", "rapsöl", "öl"], kcal: 884, protein: 0, carbs: 0, fat: 100, defaultG: 15 },
  { keys: ["honig", "ahornsirup", "sirup"], kcal: 304, protein: 0.3, carbs: 82, fat: 0, defaultG: 20 },
  { keys: ["zucker"], kcal: 400, protein: 0, carbs: 100, fat: 0, defaultG: 10 },
  { keys: ["sahne"], kcal: 300, protein: 2.4, carbs: 3.4, fat: 30, defaultG: 30 },
  { keys: ["sauce", "dressing", "mayo", "dip"], kcal: 300, protein: 1.5, carbs: 6, fat: 30, defaultG: 20 },
  { keys: ["salat"], kcal: 15, protein: 1.4, carbs: 2.9, fat: 0.2, defaultG: 80 },
  { keys: ["gemüse", "paprika", "zucchini", "brokkoli", "karotte", "tomate", "gurke", "spinat"], kcal: 30, protein: 2, carbs: 5, fat: 0.3, defaultG: 150 },
  { keys: ["kichererbsen"], kcal: 164, protein: 9, carbs: 27, fat: 2.6, defaultG: 150 },
  { keys: ["linsen"], kcal: 116, protein: 9, carbs: 20, fat: 0.4, defaultG: 150 },
  { keys: ["bohnen"], kcal: 127, protein: 9, carbs: 23, fat: 0.5, defaultG: 150 },
];

// Looks for a quantity + optional unit written directly before (or right after) the
// matched keyword, e.g. "150g Hähnchen", "2 Eier", "1 Schüssel Haferflocken", "Reis 200g".
function parseQuantityNear(lower, key) {
  const idx = lower.indexOf(key);
  if (idx === -1) return null;
  const unitPattern = "(g|gramm|ml|stück|scheiben?|el|tl|schüssel|portion|handvoll|tasse|glas)?";
  const before = lower.slice(Math.max(0, idx - 20), idx);
  const beforeMatch = before.match(new RegExp(`(\\d+(?:[.,]\\d+)?)\\s*${unitPattern}\\s*$`));
  if (beforeMatch) return { num: parseFloat(beforeMatch[1].replace(",", ".")), unit: beforeMatch[2] || null };
  const after = lower.slice(idx + key.length, idx + key.length + 15);
  const afterMatch = after.match(new RegExp(`^\\s*(\\d+(?:[.,]\\d+)?)\\s*${unitPattern}`));
  if (afterMatch) return { num: parseFloat(afterMatch[1].replace(",", ".")), unit: afterMatch[2] || null };
  return null;
}

// Whole-word matching for food keywords: a naive lower.includes("ei") would also match
// inside "ein", "kein", "mein", "weiß" etc. This checks that the matched substring is
// bounded by non-letters (or string start/end) on both sides, accounting for umlauts.
function hasWholeWordMatch(lowerText, key) {
  const isLetter = (c) => !!c && /[a-zäöüß]/i.test(c);
  let idx = lowerText.indexOf(key);
  while (idx !== -1) {
    const before = idx === 0 ? "" : lowerText[idx - 1];
    const after = lowerText[idx + key.length] || "";
    if (!isLetter(before) && !isLetter(after)) return true;
    idx = lowerText.indexOf(key, idx + 1);
  }
  return false;
}

function resolveGrams(food, qty) {
  if (!qty) return food.defaultG;
  const { num, unit } = qty;
  if (unit === "g" || unit === "gramm" || unit === "ml") return num;
  if (unit === "stück") return num * (food.pieceG || food.defaultG);
  if (unit && unit.startsWith("scheib")) return num * (food.sliceG || 30);
  if (unit === "el") return num * 15;
  if (unit === "tl") return num * 5;
  if (unit === "handvoll") return num * 30;
  if (unit === "schüssel" || unit === "portion" || unit === "tasse" || unit === "glas") return num * food.defaultG;
  // no unit given: a piece-based food ("2 Eier") is read as a count, everything else as grams
  return food.pieceG ? num * food.pieceG : num;
}

// Recipe ingredient strings look like "80g Basmatireis", "2 Stück Eier", "1 EL Olivenöl",
// "etwas Petersilie". Break each into {amount, unit, name} so it becomes individually editable.
function parseIngredientString(str) {
  let m = str.match(/^(\d+(?:[.,]\d+)?)\s*(g|kg|ml|l)\s+(.+)$/i);
  if (m) return { amount: parseFloat(m[1].replace(",", ".")), unit: m[2].toLowerCase(), name: m[3].trim() };
  m = str.match(/^(\d+(?:[.,]\d+)?)\s*(stück|el|tl|zehe(?:n)?|zweig(?:e)?|prise(?:n)?|scheiben?)\s+(.+)$/i);
  if (m) return { amount: parseFloat(m[1].replace(",", ".")), unit: m[2].toLowerCase(), name: m[3].trim() };
  m = str.match(/^etwas\s+(.+)$/i);
  if (m) return { amount: 1, unit: "Prise", name: m[1].trim() };
  return { amount: 1, unit: "Portion", name: str };
}

// Turns a recipe's flavour-text ingredient list into a structured, per-item macro breakdown:
// items that match our nutrition database get a real per-gram estimate; anything unmatched
// (herbs, spices, etc.) gets a fair share of whatever's left so the total still adds up to
// the recipe's own stated macros.
function ingredientsFromRecipe(recipe) {
  const parsed = (recipe.ingredients || []).map((str) => parseIngredientString(str));
  const withMacros = parsed.map((p) => {
    const lowerName = p.name.toLowerCase();
    const food = FOOD_DB.find((f) => f.keys.some((k) => hasWholeWordMatch(lowerName, k)));
    if (food) {
      const grams = resolveGrams(food, { num: p.amount, unit: p.unit });
      const scale = grams / 100;
      return {
        name: p.name,
        amount: Math.round(grams),
        unit: "g",
        kcal: Math.round(food.kcal * scale),
        protein: Math.round(food.protein * scale * 10) / 10,
        carbs: Math.round(food.carbs * scale * 10) / 10,
        fat: Math.round(food.fat * scale * 10) / 10,
        matched: true,
      };
    }
    return { name: p.name, amount: p.amount, unit: p.unit, kcal: 0, protein: 0, carbs: 0, fat: 0, matched: false };
  });

  const known = withMacros.reduce(
    (acc, i) => (i.matched ? { kcal: acc.kcal + i.kcal, protein: acc.protein + i.protein, carbs: acc.carbs + i.carbs, fat: acc.fat + i.fat } : acc),
    { kcal: 0, protein: 0, carbs: 0, fat: 0 }
  );
  const remainder = {
    kcal: Math.max(0, (recipe.kcal || 0) - known.kcal),
    protein: Math.max(0, (recipe.protein || 0) - known.protein),
    carbs: Math.max(0, (recipe.carbs || 0) - known.carbs),
    fat: Math.max(0, (recipe.fat || 0) - known.fat),
  };
  const unmatched = withMacros.filter((i) => !i.matched);
  if (unmatched.length > 0) {
    const share = 1 / unmatched.length;
    unmatched.forEach((i) => {
      i.kcal = Math.round(remainder.kcal * share);
      i.protein = Math.round(remainder.protein * share * 10) / 10;
      i.carbs = Math.round(remainder.carbs * share * 10) / 10;
      i.fat = Math.round(remainder.fat * share * 10) / 10;
    });
  } else if (withMacros.length > 0) {
    withMacros[0].kcal += remainder.kcal;
    withMacros[0].protein = Math.round((withMacros[0].protein + remainder.protein) * 10) / 10;
    withMacros[0].carbs = Math.round((withMacros[0].carbs + remainder.carbs) * 10) / 10;
    withMacros[0].fat = Math.round((withMacros[0].fat + remainder.fat) * 10) / 10;
  }

  return withMacros.map(({ matched, ...rest }) => ({ id: secureId("ing"), ...rest }));
}

// Derives an editable, multi-item ingredient breakdown straight from a dish's name/description
// (e.g. "Lachs mit Ofengemüse" -> Lachs + Gemüse), scaled so the items sum to the given totals.
// Used whenever we have an aggregate kcal/protein/carbs/fat (from Claude or elsewhere) but no
// (or an unusable) itemised ingredient list, so editing never gets stuck at a single opaque "1 Portion".
function ingredientsFromDishText(text, totals) {
  const lower = text.toLowerCase();
  const matches = [];
  FOOD_DB.forEach((food) => {
    const hitKey = food.keys.find((k) => {
      if (!hasWholeWordMatch(lower, k)) return false;
      if (k === "kartoffel" && lower.includes("süßkartoffel")) return false;
      return true;
    });
    if (!hitKey) return;
    const grams = resolveGrams(food, parseQuantityNear(lower, hitKey));
    const scale = grams / 100;
    matches.push({
      name: capitalizeFirst(hitKey),
      amount: Math.round(grams),
      unit: "g",
      kcal: food.kcal * scale,
      protein: food.protein * scale,
      carbs: food.carbs * scale,
      fat: food.fat * scale,
    });
  });

  if (matches.length === 0) {
    return [{ id: secureId("ing"), name: capitalizeFirst(text) || "Mahlzeit", amount: 1, unit: "Portion", kcal: totals.kcal, protein: totals.protein, carbs: totals.carbs, fat: totals.fat }];
  }

  // Rescale so the itemised ingredients sum exactly to the dish's own stated totals.
  const sum = matches.reduce((acc, m) => ({ kcal: acc.kcal + m.kcal, protein: acc.protein + m.protein, carbs: acc.carbs + m.carbs, fat: acc.fat + m.fat }), { kcal: 0, protein: 0, carbs: 0, fat: 0 });
  const kcalF = sum.kcal > 0 ? totals.kcal / sum.kcal : 1;
  const proteinF = sum.protein > 0 ? totals.protein / sum.protein : 1;
  const carbsF = sum.carbs > 0 ? totals.carbs / sum.carbs : 1;
  const fatF = sum.fat > 0 ? totals.fat / sum.fat : 1;
  return matches.map((m) => ({
    id: secureId("ing"),
    name: m.name,
    amount: m.amount,
    unit: m.unit,
    kcal: Math.round(m.kcal * kcalF),
    protein: Math.round(m.protein * proteinF * 10) / 10,
    carbs: Math.round(m.carbs * carbsF * 10) / 10,
    fat: Math.round(m.fat * fatF * 10) / 10,
  }));
}

const INITIAL_RECIPES = [...buildConvertedCycleRecipes(), ...buildConvertedOpenRecipes()];

function capitalizeFirst(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function estimateMeal(text) {
  const lower = text.toLowerCase();
  const junk = detectJunk(lower);

  if (junk) {
    const hash = lower.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
    const kcal = 620 + (hash % 140);
    const protein = 9 + (hash % 5);
    const carbs = 52 + (hash % 12);
    const fat = 30 + (hash % 10);
    return {
      kcal,
      protein,
      carbs,
      fat,
      isJunk: true,
      junkKey: junkKeyFor(lower),
      ingredients: [{ name: capitalizeFirst(text.trim()) || "Mahlzeit", amount: 1, unit: "Portion", kcal, protein, carbs, fat }],
    };
  }

  let kcal = 0,
    protein = 0,
    carbs = 0,
    fat = 0,
    matchedAny = false;
  const ingredients = [];

  FOOD_DB.forEach((food) => {
    const hitKey = food.keys.find((k) => {
      if (!hasWholeWordMatch(lower, k)) return false;
      // avoid "Süßkartoffel" also triggering the separate plain "Kartoffel" entry
      if (k === "kartoffel" && lower.includes("süßkartoffel")) return false;
      return true;
    });
    if (!hitKey) return;
    matchedAny = true;
    const grams = resolveGrams(food, parseQuantityNear(lower, hitKey));
    const scale = grams / 100;
    const itemKcal = food.kcal * scale;
    const itemProtein = food.protein * scale;
    const itemCarbs = food.carbs * scale;
    const itemFat = food.fat * scale;
    kcal += itemKcal;
    protein += itemProtein;
    carbs += itemCarbs;
    fat += itemFat;
    ingredients.push({
      name: capitalizeFirst(hitKey),
      amount: Math.round(grams),
      unit: "g",
      kcal: Math.round(itemKcal),
      protein: Math.round(itemProtein * 10) / 10,
      carbs: Math.round(itemCarbs * 10) / 10,
      fat: Math.round(itemFat * 10) / 10,
    });
  });

  if (!matchedAny) {
    // Nothing recognisable in the text - fall back to one plausible average-meal estimate
    // instead of silently guessing on a fixed baseline (which was the source of the old
    // "always ~350 kcal no matter what you typed" bug).
    const hash = lower.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
    const fKcal = 380 + (hash % 140);
    const fProtein = 16 + (hash % 10);
    const fCarbs = 42 + (hash % 14);
    const fFat = 14 + (hash % 8);
    return {
      kcal: fKcal,
      protein: fProtein,
      carbs: fCarbs,
      fat: fFat,
      isJunk: false,
      junkKey: null,
      ingredients: [{ name: capitalizeFirst(text.trim()) || "Mahlzeit", amount: 1, unit: "Portion", kcal: fKcal, protein: fProtein, carbs: fCarbs, fat: fFat }],
    };
  }

  kcal = Math.max(60, Math.round(kcal));
  return { kcal, protein: Math.max(1, Math.round(protein)), carbs: Math.max(1, Math.round(carbs)), fat: Math.max(1, Math.round(fat)), isJunk: false, junkKey: null, ingredients };
}

function junkMatchScore(text) {
  const hash = text.toLowerCase().split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  return 16 + (hash % 20);
}

function phaseMatchScore(meal, phaseKey) {
  const kcal = Math.max(meal.kcal, 1);
  const proteinShare = (meal.protein * 4) / kcal;
  const carbShare = (meal.carbs * 4) / kcal;
  const fatShare = (meal.fat * 9) / kcal;

  // Rough ideal macro-energy split per phase (protein/carbs/fat as a share of kcal).
  const targets = {
    menstruation: { protein: 0.22, carbs: 0.48, fat: 0.3 },
    follikel: { protein: 0.3, carbs: 0.45, fat: 0.25 },
    ovulation: { protein: 0.25, carbs: 0.4, fat: 0.35 },
    luteal: { protein: 0.2, carbs: 0.5, fat: 0.3 },
  };
  const t = targets[phaseKey] || targets.follikel;
  const diff = Math.abs(proteinShare - t.protein) + Math.abs(carbShare - t.carbs) + Math.abs(fatShare - t.fat);
  const score = 96 - diff * 85;
  return Math.max(35, Math.min(98, Math.round(score)));
}

function matchReason(score, phaseKey, isJunk, lang) {
  const phase = PHASES[phaseKey];
  const phaseName = lang === "en" ? PHASE_TEXT_EN[phaseKey].name : phase.name;
  const focus0 = lang === "en" ? PHASE_TEXT_EN[phaseKey].focus[0] : phase.focus[0];
  if (lang === "en") {
    if (isJunk) return `Strongly inflammatory due to trans fats & refined carbs – barely fits your ${phaseName}.`;
    if (score >= 80) return `Strong match with your nutrient needs during the ${phaseName}.`;
    if (score >= 60) return `Solid choice – largely matches the focus of your ${phaseName}.`;
    return `Only partially fits the ${phaseName} – ideally add some ${focus0}.`;
  }
  if (isJunk) return `Stark entzündungsfördernd durch Transfette & raffinierte Kohlenhydrate – passt kaum zu deiner ${phaseName}.`;
  if (score >= 80) return `Starke Übereinstimmung mit deinem Nährstoffbedarf in der ${phaseName}.`;
  if (score >= 60) return `Solide Wahl – passt größtenteils zu den Schwerpunkten deiner ${phaseName}.`;
  return `Passt nur teilweise zur ${phaseName} – ergänze idealerweise mit ${focus0}.`;
}

/* --------------------------- Hormone-Balance-Score --------------------------- */
/* ------------------------------ Meal-time categories ------------------------------ */
const MEAL_TYPE_ORDER = ["breakfast", "lunch", "dinner", "snack"];
const MEAL_TYPE_ICON = { breakfast: "☕", lunch: "🍝", dinner: "🥗", snack: "🍎" };
const MEAL_TYPE_SPLIT = { breakfast: 0.3, lunch: 0.35, dinner: 0.25, snack: 0.1 };
function autoMealType() {
  const h = new Date().getHours();
  if (h < 11) return "breakfast";
  if (h < 15) return "lunch";
  if (h < 21) return "dinner";
  return "snack";
}

function computeHormoneScore(meals, goals, totals) {
  if (!meals || meals.length === 0) return 50;
  const avgMatch = Math.round(meals.reduce((s, m) => s + m.match, 0) / meals.length);
  let bonus = 0;
  const kcalRatio = goals.kcal ? totals.kcal / goals.kcal : 1;
  if (kcalRatio >= 0.85 && kcalRatio <= 1.15) bonus += 5;
  const junkCount = meals.filter((m) => m.isJunk).length;
  bonus -= junkCount * 8;
  return Math.max(10, Math.min(100, avgMatch + bonus));
}
function hormoneFeedback(score, phase, lang) {
  const primary = phase.focus[0];
  const combo = phase.focus.slice(0, 2).join(" & ");
  if (lang === "en") {
    if (score >= 80) return `${score}% – Optimal! You're perfectly supporting your body in the ${phase.name} with ${combo}.`;
    if (score >= 60) return `${score}% – Good progress. Focus a bit more on ${primary} to fully support your ${phase.name}.`;
    if (score >= 40) return `${score}% – Room to improve. Your meals could align better with ${combo} during your ${phase.name}.`;
    return `${score}% – Time to adjust. Try adding more ${primary}-rich foods.`;
  }
  if (score >= 80) return `${score}% – Optimal! Du versorgst deinen Körper in der ${phase.name} perfekt mit ${combo}.`;
  if (score >= 60) return `${score}% – Gut unterwegs. Achte noch etwas mehr auf ${primary}, um deine ${phase.name} optimal zu unterstützen.`;
  if (score >= 40) return `${score}% – Ausbaufähig. Deine Mahlzeiten könnten besser auf ${combo} in der ${phase.name} abgestimmt sein.`;
  return `${score}% – Zeit zum Nachsteuern. Versuche gezielt mehr ${primary}-reiche Lebensmittel einzubauen.`;
}

/* --------------------------------- Rewards --------------------------------- */
function computeRewards(logsByDate, cycleStartDate, profile, todayKey) {
  const loggedDates = Object.keys(logsByDate)
    .filter((dk) => (logsByDate[dk] || []).length > 0)
    .sort();

  let totalPoints = 0;
  let bestScore = 0;
  const scoreByDate = {};

  loggedDates.forEach((dk) => {
    const meals = logsByDate[dk];
    const cd = cycleDayForKey(dk, cycleStartDate);
    const pk = phaseForDay(cd);
    const g = computeGoals(profile, pk);
    const totals = meals.reduce(
      (acc, m) => ({ kcal: acc.kcal + m.kcal, protein: acc.protein + m.protein, carbs: acc.carbs + m.carbs, fat: acc.fat + m.fat }),
      { kcal: 0, protein: 0, carbs: 0, fat: 0 }
    );
    const score = computeHormoneScore(meals, g, totals);
    scoreByDate[dk] = score;
    if (score >= 80) totalPoints += 3;
    else if (score >= 60) totalPoints += 1;
    if (score > bestScore) bestScore = score;
  });

  let streak = 0;
  let cursor = todayKey;
  while (scoreByDate[cursor] != null && scoreByDate[cursor] >= 60) {
    streak++;
    cursor = addDaysToKey(cursor, -1);
  }

  const badges = [];
  if (streak >= 3) badges.push({ id: "streak3", labelKey: "badge_streak3", icon: Flame });
  if (streak >= 7) badges.push({ id: "streak7", labelKey: "badge_streak7", icon: Flame });
  if (streak >= 14) badges.push({ id: "streak14", labelKey: "badge_streak14", icon: Trophy });
  if (bestScore >= 90) badges.push({ id: "perfect", labelKey: "badge_perfect", icon: Award });
  if (totalPoints >= 15) badges.push({ id: "pro", labelKey: "badge_pro", icon: Trophy });

  return { totalPoints, streak, bestScore, badges };
}

function RewardsCard({ rewards, phase }) {
  const { t, lang } = useLang();
  return (
    <div className="rounded-2xl p-5 mb-5" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold flex items-center gap-1.5" style={{ color: "#121212" }}>
          <Trophy size={14} style={{ color: phase.color }} /> {t("rewards_title")}
        </p>
        <span className="text-[11px] font-semibold px-2.5 py-1 rounded-full" style={{ background: phase.tint, color: phase.color }}>
          {rewards.totalPoints} {t("rewards_points")}
        </span>
      </div>
      <div className="flex items-center gap-2 mb-3">
        <Flame size={18} style={{ color: rewards.streak > 0 ? phase.color : "#AFAFAF" }} />
        <p className="text-xs" style={{ color: "#545454" }}>
          {rewards.streak > 0 ? `${rewards.streak} ${t("rewards_streak_active")}` : t("rewards_streak_empty")}
        </p>
      </div>
      {rewards.badges.length > 0 ? (
        <div className="flex gap-2 flex-wrap">
          {rewards.badges.map((b) => {
            const BIcon = b.icon;
            return (
              <span key={b.id} className="flex items-center gap-1 text-[10px] font-medium px-2.5 py-1.5 rounded-full" style={{ background: phase.tint, color: phase.color }}>
                <BIcon size={11} /> {t(b.labelKey)}
              </span>
            );
          })}
        </div>
      ) : (
        <p className="text-[11px]" style={{ color: "#8A8A8A" }}>
          {t("rewards_no_badges")}
        </p>
      )}
    </div>
  );
}

function CycleRecipeDetailModal({ recipe, phase, onClose }) {
  const { t } = useLang();

  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  const totalMin = (recipe.vorbereitungszeit_min || 0) + (recipe.kochzeit_min || 0);

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.5)" }} onClick={onClose}>
      <div
        className="w-full max-w-md rounded-t-3xl sm:rounded-3xl"
        style={{ background: "#FFFFFF", maxHeight: "min(92vh, 92dvh)", overflowY: "auto", WebkitOverflowScrolling: "touch", overscrollBehavior: "contain" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-5 relative" style={{ background: phase.tint }}>
          <button onClick={onClose} className="absolute top-4 right-4 w-9 h-9 rounded-full flex items-center justify-center z-10" style={{ background: "rgba(0,0,0,0.15)" }} aria-label={t("close")}>
            <X size={17} style={{ color: "#121212" }} strokeWidth={2.5} />
          </button>
          <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-full inline-block mb-2" style={{ background: "#FFFFFF", color: phase.color }}>
            {t(mealTypeKeyFromDb(recipe.mahlzeit))}
          </span>
          <p className="font-display text-2xl leading-tight break-words pr-10" style={{ color: "#121212" }}>
            {recipe.titel}
          </p>
        </div>

        <div className="p-5">
          <div className="flex gap-4 text-xs mb-4" style={{ color: "#545454" }}>
            <span className="flex items-center gap-1"><Clock size={13} />{recipe.vorbereitungszeit_min} {t("prep_time")}</span>
            <span className="flex items-center gap-1"><Flame size={13} />{recipe.kochzeit_min} {t("cook_time")}</span>
            <span className="flex items-center gap-1 font-semibold" style={{ color: "#121212" }}>{totalMin} {t("total_time")}</span>
          </div>

          <div className="rounded-2xl p-4 mb-5" style={{ background: "#F5F5F5" }}>
            <p className="text-[11px] uppercase tracking-widest mb-1.5 flex items-center gap-1.5" style={{ color: phase.color }}>
              <Sparkles size={12} /> {t("focus_label")}
            </p>
            <p className="text-xs leading-relaxed" style={{ color: "#262626" }}>
              {recipe.fokus}
            </p>
          </div>

          <p className="text-xs font-semibold mb-2 flex items-center gap-1.5" style={{ color: "#121212" }}>
            <ListChecks size={14} style={{ color: phase.color }} /> {t("ingredients_label")}
          </p>
          <ul className="mb-5">
            {recipe.zutaten.map((ing, i) => (
              <li key={i} className="text-xs py-1.5 flex items-center gap-2" style={{ color: "#262626", borderBottom: i < recipe.zutaten.length - 1 ? "1px solid #EFEFEF" : "none" }}>
                <CircleDot size={7} style={{ color: phase.color }} className="shrink-0" />
                {ing}
              </li>
            ))}
          </ul>

          <p className="text-xs font-semibold mb-2 flex items-center gap-1.5" style={{ color: "#121212" }}>
            <ChefHat size={14} style={{ color: phase.color }} /> {t("preparation")}
          </p>
          <ol className="mb-5 space-y-2.5">
            {recipe.zubereitung.map((step, i) => (
              <li key={i} className="text-xs leading-relaxed flex gap-2.5" style={{ color: "#262626" }}>
                <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold" style={{ background: phase.tint, color: phase.color }}>
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>

          <button onClick={onClose} className="w-full py-3 rounded-xl text-sm font-semibold" style={{ background: "#F3ECE2", color: "#545454" }}>
            {t("close")}
          </button>
        </div>
      </div>
    </div>
  );
}

function ScoreGauge({ score, phase, compact }) {
  const { t, lang } = useLang();
  const size = compact ? 108 : 152;
  const inner = compact ? 88 : 124;
  return (
    <div className="rounded-2xl p-5 mb-5" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
      <div className="flex items-center gap-4">
        <div className="relative shrink-0" style={{ width: size, height: size }}>
          <div className="w-full h-full rounded-full flex items-center justify-center" style={{ background: `conic-gradient(${phase.color} ${score * 3.6}deg, #EFEFEF 0deg)` }}>
            <div className="rounded-full flex flex-col items-center justify-center" style={{ width: inner, height: inner, background: "#FFFFFF", boxShadow: "inset 0 0 0 1px #F0F0F0" }}>
              <span className={compact ? "font-display text-lg" : "font-display text-2xl"} style={{ color: "#121212" }}>
                {score}%
              </span>
            </div>
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold mb-1 flex items-center gap-1.5" style={{ color: "#121212" }}>
            <Gauge size={13} style={{ color: phase.color }} /> {t("hormone_score")}
          </p>
          <p className="text-[11px] leading-relaxed" style={{ color: "#545454" }}>
            {hormoneFeedback(score, phase, lang)}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ------------------------- Ingredient adjustment estimator ------------------------- */
const INGREDIENT_ESTIMATES = [
  { match: ["olivenöl", "öl"], kcal: 120, protein: 0, carbs: 0, fat: 14 },
  { match: ["käse"], kcal: 110, protein: 7, carbs: 1, fat: 9 },
  { match: ["sauce", "dressing", "mayo", "dip"], kcal: 90, protein: 1, carbs: 4, fat: 8 },
  { match: ["avocado"], kcal: 160, protein: 2, carbs: 8, fat: 15 },
  { match: ["honig", "sirup", "zucker"], kcal: 60, protein: 0, carbs: 15, fat: 0 },
  { match: ["nüsse", "mandel", "walnuss", "cashew"], kcal: 100, protein: 3, carbs: 3, fat: 9 },
  { match: ["sahne"], kcal: 100, protein: 1, carbs: 2, fat: 10 },
  { match: ["brot", "brötchen"], kcal: 130, protein: 4, carbs: 24, fat: 1 },
  { match: ["ei", "eier"], kcal: 80, protein: 7, carbs: 1, fat: 5 },
  { match: ["hähnchen", "huhn", "fleisch"], kcal: 165, protein: 28, carbs: 0, fat: 6 },
];
const DEFAULT_ADJUSTMENT = { kcal: 70, protein: 2, carbs: 6, fat: 3 };

function estimateAdjustmentDelta(text) {
  const lower = text.toLowerCase();
  const found = INGREDIENT_ESTIMATES.find((e) => e.match.some((m) => hasWholeWordMatch(lower, m)));
  return found ? { kcal: found.kcal, protein: found.protein, carbs: found.carbs, fat: found.fat } : DEFAULT_ADJUSTMENT;
}

/* ------------------------------ AI recipe engine (on-demand) ------------------------------ */
const EXTRA_TAGS = ["Cravings", "Schnell", "Anti-Bloat", "Eisen-Booster", "Antioxidantien", "Omega-3", "Magnesium"];

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function dietConstraints(diets) {
  const list = Array.isArray(diets) ? diets : [diets];
  return {
    noMeat: list.includes("vegan") || list.includes("vegetarian") || list.includes("pescetarian"),
    noFish: list.includes("vegan") || list.includes("vegetarian"),
    noDairy: list.includes("vegan") || list.includes("lactose_free"),
    noEgg: list.includes("vegan"),
    noGluten: list.includes("gluten_free"),
  };
}

function generateAIRecipe(phaseKey, diets) {
  const phase = PHASES[phaseKey];
  const { noMeat, noFish, noDairy, noEgg, noGluten } = dietConstraints(diets);

  let proteinPool = PROTEIN_POOL.filter((p) => (!noMeat || !p.meat) && (!noFish || !p.fish) && (!noEgg || !p.egg));
  if (proteinPool.length === 0) proteinPool = PROTEIN_POOL.filter((p) => !p.meat && !p.fish && !p.egg);
  const proteinOpt = pick(proteinPool);
  const proteinSource = proteinOpt.name;
  const meatFlag = proteinOpt.meat;
  const fishFlag = proteinOpt.fish;
  const eggFlag = proteinOpt.egg;

  // Superfood cap: roughly 1 in 10 generations reaches for Süßkartoffel/Quinoa, the rest
  // uses everyday staples (pasta, rice, potatoes, bread, wraps, gnocchi).
  const commonCarbOptions = noGluten ? COMMON_CARBS.filter((c) => !c.gluten) : COMMON_CARBS;
  const rareCarbOptions = noGluten ? RARE_CARBS.filter((c) => !c.gluten) : RARE_CARBS;
  const useRareCarb = rareCarbOptions.length > 0 && Math.random() < 0.1;
  const carb = useRareCarb ? pick(rareCarbOptions) : pick(commonCarbOptions);

  const veg = Math.random() < 0.1 ? RARE_VEG[0] : pick(COMMON_VEG);
  const fat = pick(FAT_POOL);
  const { style, cuisine } = pick(STYLE_POOL);

  const dairyItem = !noDairy && Math.random() > 0.5 ? pick(DAIRY_POOL) : null;

  const proteinAmt = meatFlag || fishFlag ? "140g" : eggFlag ? "2 Stück" : "150g";
  const fatAmt = fat === "Olivenöl" || fat === "Leinöl" ? "1 EL" : "20g";
  const herb = pick(HERB_POOL);

  const title = creativeTitle(style, carb.name, proteinSource, veg, Math.floor(Math.random() * 1000));

  const ingredients = [`80g ${carb.name}`, `${proteinAmt} ${proteinSource}`, `100g ${veg}`, `${fatAmt} ${fat}`];
  if (dairyItem) ingredients.push(`30g ${dairyItem}`);

  const steps = stepsForStyle(style, carb.name, proteinSource, veg, veg, fat, dairyItem, herb);

  const protein_g = meatFlag || fishFlag ? 34 : eggFlag ? 24 : 22;
  const carbs_g = 46 + (carb.gluten ? 8 : 0);
  const fat_g = 16 + (dairyItem ? 4 : 0);
  const kcal = protein_g * 4 + carbs_g * 4 + fat_g * 9;
  const micronutrient = pick(phase.focus);

  const dietLabel = (Array.isArray(diets) ? diets : [diets]).map((d) => DIET_LABELS[d]).join(" + ");
  const tags = new Set(["KI-Generiert", pick(EXTRA_TAGS)]);
  if (protein_g >= 30) tags.add("High Protein");
  if (noDairy && noEgg && noMeat && noFish) tags.add("Vegan");

  return {
    id: secureId("ai"),
    title: title || "KI-Rezept",
    cuisine,
    phase: phaseKey,
    time: 15 + Math.floor(Math.random() * 20),
    kcal: Math.round(kcal),
    protein: protein_g,
    carbs: carbs_g,
    fat: fat_g,
    tags: Array.from(tags),
    micronutrient,
    ingredients,
    steps,
    why: `${cleverWhyText(phase, proteinSource, carb.name, micronutrient)} Abgestimmt auf deinen Ernährungsstil "${dietLabel}".`,
    color: phase.color,
    meat: meatFlag,
    fish: fishFlag,
    dairy: !!dairyItem,
    gluten: carb.gluten,
    egg: eggFlag,
    aiGenerated: true,
  };
}

function pantryStepsForStyle(style, items, carbName, fat) {
  const itemList = items.join(", ");
  switch (style) {
    case "Pasta":
      return [
        `${carbName} in reichlich Salzwasser al dente kochen.`,
        `${itemList} klein schneiden und in einer Pfanne mit etwas ${fat} anbraten.`,
        `Abgetropfte Nudeln unterheben und gut durchschwenken.`,
        `Würzen und servieren.`,
      ];
    case "Stir-Fry":
      return [
        `${itemList} in dünne Streifen oder Stücke schneiden.`,
        `Bei hoher Hitze in einer Pfanne oder im Wok mit etwas ${fat} scharf anbraten.`,
        `${carbName} bzw. Sojasauce unterrühren und kurz mitbraten.`,
        `Sofort servieren.`,
      ];
    case "Suppe":
    case "Eintopf":
      return [
        `${itemList} waschen, schälen wo nötig und klein schneiden.`,
        `Kurz in etwas ${fat} andünsten.`,
        `Mit Brühe aufgießen, ${carbName} hinzufügen und 15-20 Minuten köcheln lassen.`,
        `Nach Belieben pürieren, würzen und heiß servieren.`,
      ];
    case "Curry":
      return [
        `${itemList} klein schneiden.`,
        `In einem Topf mit etwas ${fat} und Currygewürzen kurz anrösten.`,
        `${carbName} und etwas Kokosmilch oder Brühe hinzufügen und 15 Minuten köcheln.`,
        `Mit frischen Kräutern abschmecken und servieren.`,
      ];
    case "Salat":
      return [
        `${carbName} kochen und abkühlen lassen.`,
        `${itemList} waschen und klein schneiden bzw. roh oder blanchiert vorbereiten.`,
        `Alles in einer Schüssel mit ${fat} vermengen.`,
        `Mit Salz, Pfeffer und Zitronensaft abschmecken.`,
      ];
    case "Wrap":
      return [
        `${itemList} würzen und kurz anbraten bzw. vorbereiten.`,
        `${carbName} als Basis (z. B. Fladenbrot) vorbereiten.`,
        `Alles mit ${fat} füllen und einrollen.`,
        `Sofort servieren.`,
      ];
    case "Auflauf":
    case "Ofengericht":
      return [
        `Ofen auf 200°C Ober-/Unterhitze vorheizen.`,
        `${itemList} und ${carbName} in eine Auflaufform schichten.`,
        `Mit ${fat} beträufeln und würzen.`,
        `20-25 Minuten backen, bis alles gar ist.`,
      ];
    case "One-Pot-Gericht":
      return [
        `${itemList} in einem großen Topf mit etwas ${fat} anbraten.`,
        `${carbName} und etwas Flüssigkeit hinzufügen.`,
        `Alles zusammen köcheln lassen, bis der ${carbName} gar ist.`,
        `Abschmecken und servieren.`,
      ];
    default:
      // Bowl / Pfanne
      return [
        `${carbName} nach Packungsanweisung garen.`,
        `${itemList} klein schneiden und in einer Pfanne mit etwas ${fat} anbraten bzw. erhitzen.`,
        `Alles zusammen in einer Bowl anrichten.`,
        `Mit Gewürzen und Kräutern nach Wahl abschmecken.`,
      ];
  }
}

function shuffleArray(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function generateSinglePantryRecipe(phaseKey, diets, pantryInput, styleObj, seed) {
  const items = pantryInput
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) return null;
  const { style, cuisine } = styleObj;

  const phase = PHASES[phaseKey];
  const lowerAll = items.join(" ").toLowerCase();
  const has = (cat) => DIET_CONFLICT_WORDS[cat].some((w) => lowerAll.includes(w));
  const meatFlag = has("meat");
  const fishFlag = has("fish");
  const dairyFlag = has("dairy") || lowerAll.includes("feta") || lowerAll.includes("käse");
  const eggFlag = hasWholeWordMatch(lowerAll, "ei") || hasWholeWordMatch(lowerAll, "eier");
  const glutenFlag = has("gluten");

  const { noGluten } = dietConstraints(diets);
  const dietWarning = checkDietConflicts(lowerAll, diets, "de");

  // Everyday carb by default; Süßkartoffel/Quinoa only ever in the rare seed slot (1 in 10).
  const commonOptions = noGluten ? COMMON_CARBS.filter((c) => !c.gluten) : COMMON_CARBS;
  const rareOptions = noGluten ? RARE_CARBS.filter((c) => !c.gluten) : RARE_CARBS;
  const carb = seed % 10 === 9 && rareOptions.length > 0 ? rareOptions[seed % rareOptions.length] : commonOptions[seed % commonOptions.length];
  const fat = FAT_POOL[(seed * 3 + 1) % FAT_POOL.length];

  const titleTemplates = [
    `${style} mit ${items[0]}${items[1] ? ` & ${items[1]}` : ""}`,
    `${items[0]}-${style}${items[1] ? ` mit ${items[1]}` : ""}`,
    `Resteverwertung: ${items.slice(0, 2).join(" & ")}-${style}`,
  ];
  const title = titleTemplates[seed % titleTemplates.length];

  const fatAmt = fat === "Olivenöl" || fat === "Leinöl" ? "1 EL" : "20g";
  const ingredients = [...items.map((it) => `nach Bedarf ${it}`), `80g ${carb.name}`, `${fatAmt} ${fat}`];
  const steps = pantryStepsForStyle(style, items, carb.name, fat);

  const protein_g = meatFlag || fishFlag ? 30 + (seed % 6) : eggFlag ? 22 : 16 + (seed % 5);
  const carbs_g = 40 + (carb.gluten ? 8 : 0) + (seed % 8);
  const fat_g = 14 + (seed % 6);
  const kcal = protein_g * 4 + carbs_g * 4 + fat_g * 9;
  const micronutrient = phase.focus[seed % phase.focus.length];

  const tags = ["Resteverwertung", "KI-Generiert"];
  if (style === "Suppe" || style === "Eintopf") tags.push("Anti-Bloat");
  if (protein_g >= 30) tags.push("High Protein");

  return {
    id: secureId(`pantry-${seed}`),
    title,
    cuisine,
    phase: phaseKey,
    time: 15 + (seed % 4) * 5,
    kcal: Math.round(kcal),
    protein: protein_g,
    carbs: carbs_g,
    fat: fat_g,
    tags,
    micronutrient,
    ingredients,
    steps,
    why: `Nutzt genau das, was du zu Hause hast (${items.join(", ")}) kombiniert mit ${carb.name} als Alltagszutat, und liefert gleichzeitig ${micronutrient} für deine ${phase.name}.`,
    color: phase.color,
    meat: meatFlag,
    fish: fishFlag,
    dairy: dairyFlag,
    gluten: glutenFlag,
    egg: eggFlag,
    aiGenerated: true,
    pantry: true,
    dietWarning,
  };
}

function generatePantryRecipes(phaseKey, diets, pantryInput, count = 3) {
  const items = pantryInput
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) return [];
  const styles = shuffleArray(STYLE_POOL).slice(0, count);
  return styles.map((styleObj, i) => generateSinglePantryRecipe(phaseKey, diets, pantryInput, styleObj, i)).filter(Boolean);
}

/* ------------------------------ TDEE logic ------------------------------ */
const ACTIVITY_FACTORS = { sedentary: 1.2, moderate: 1.375, active: 1.55 };
const ACTIVITY_LABELS = { sedentary: "Sitzend", moderate: "Moderat aktiv", active: "Sehr aktiv" };
const ACTIVITY_LABELS_EN = { sedentary: "Sedentary", moderate: "Moderately active", active: "Very active" };
function activityLabel(a, lang) {
  return (lang === "en" ? ACTIVITY_LABELS_EN[a] : ACTIVITY_LABELS[a]) || a;
}

function computeGoals(profile, phaseKey) {
  const { height, weight, age, activity } = profile;
  const bmr = 10 * weight + 6.25 * height - 5 * age - 161;
  let kcal = bmr * (ACTIVITY_FACTORS[activity] || 1.375);
  const lutealBonus = phaseKey === "luteal" ? 150 : 0;
  kcal = Math.round(kcal + lutealBonus);
  const protein = Math.round(weight * 1.6);
  const fat = Math.round((kcal * 0.28) / 9);
  const carbs = Math.max(60, Math.round((kcal - protein * 4 - fat * 9) / 4));
  return { kcal, protein, carbs, fat, lutealBonus };
}

/* ------------------------------ Shopping list helpers ------------------------------ */
const SHOPPING_CATEGORIES = {
  "Gemüse & Obst": [
    "brokkoli", "spinat", "rote bete", "paprika", "zucchini", "karotte", "rosenkohl", "fenchel", "grünkohl", "blumenkohl",
    "aubergine", "champignon", "lauch", "kürbis", "banane", "beeren", "himbeere", "blaubeere", "zitrone", "avocado",
    "mango", "granatapfel", "ingwer", "knoblauch", "zwiebel", "tomate", "gurke", "rucola", "koriander", "kräuter",
  ],
  "Kühlregal": [
    "feta", "joghurt", "hüttenkäse", "parmesan", "mozzarella", "milch", "ei", "eier", "tofu", "tempeh", "lachs",
    "garnele", "thunfisch", "kabeljau", "hähnchen", "pute", "rind", "hackfleisch", "käse", "sahne", "butter",
  ],
  "Trockenwaren & Gewürze": [
    "quinoa", "reis", "hirse", "buchweizen", "nudel", "couscous", "bulgur", "brot", "hafer", "linsen", "kichererbse",
    "kokosmilch", "currypaste", "kreuzkümmel", "zimt", "kurkuma", "kakaonibs", "mandel", "walnuss", "cashew",
    "kürbiskern", "chiasamen", "sesam", "olivenöl", "leinöl", "honig", "ahornsirup", "salz", "pfeffer", "brühe",
    "edamame", "schokolade", "dattel",
  ],
};
function categorizeIngredient(text) {
  const lower = text.toLowerCase();
  for (const [cat, words] of Object.entries(SHOPPING_CATEGORIES)) {
    if (words.some((w) => lower.includes(w))) return cat;
  }
  return "Sonstiges";
}

/* --------------------------------- App --------------------------------- */
export default function App() {
  const [lang, setLang] = useLocalStorage("nicinsync_lang", "de");
  const t = useMemo(() => makeT(lang), [lang]);

  const [todayKey, setTodayKey] = useState(() => toKey(new Date()));
  useEffect(() => {
    const interval = setInterval(() => {
      const current = toKey(new Date());
      setTodayKey((prev) => (prev !== current ? current : prev));
    }, 60000);
    return () => clearInterval(interval);
  }, []);
  const [cycleStartDate, setCycleStartDate] = useLocalStorage("nicinsync_cycle_start", addDaysToKey(todayKey, -20));

  const cycleDay = cycleDayForKey(todayKey, cycleStartDate);
  const phaseKey = phaseForDay(cycleDay);
  const phase = localizePhase(PHASES[phaseKey], lang);

  const [tab, setTab] = useState("home");
  const [profile, setProfile] = useLocalStorage("nicinsync_profile", { name: "", height: 167, weight: 62, age: 28, activity: "moderate", diets: ["omnivore"] });
  const [profileOpen, setProfileOpen] = useState(false);
  const goals = useMemo(() => computeGoals(profile, phaseKey), [profile, phaseKey]);

  const [recipes, setRecipes] = useLocalStorage("nicinsync_recipes", INITIAL_RECIPES);
  const addRecipe = (r) => setRecipes((prev) => [r, ...prev]);
  const clearAllRecipes = () => setRecipes([]);

  // One-time migration: seed the 240 cycle-database recipes into every existing user's
  // library exactly once, merging them in (never overwriting recipes the user has since
  // generated via AI or the pantry mode).
  useEffect(() => {
    try {
      if (!window.localStorage.getItem("nicinsync_recipes_v2_seeded")) {
        setRecipes((prev) => {
          const existingIds = new Set(prev.map((r) => r.id));
          const toAdd = INITIAL_RECIPES.filter((r) => !existingIds.has(r.id));
          return [...toAdd, ...prev];
        });
        window.localStorage.setItem("nicinsync_recipes_v2_seeded", "1");
      }
    } catch (err) {
      console.error("Recipe seeding failed:", err);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Second migration: adds the 227 open-source recipes for users who already ran the
  // v2 migration above before this collection existed.
  useEffect(() => {
    try {
      if (!window.localStorage.getItem("nicinsync_open_recipes_seeded")) {
        setRecipes((prev) => {
          const existingIds = new Set(prev.map((r) => r.id));
          const toAdd = buildConvertedOpenRecipes().filter((r) => !existingIds.has(r.id));
          return [...toAdd, ...prev];
        });
        window.localStorage.setItem("nicinsync_open_recipes_seeded", "1");
      }
    } catch (err) {
      console.error("Open recipe seeding failed:", err);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [recipeQuery, setRecipeQuery] = useState("");
  const [recipeNavKey, setRecipeNavKey] = useState(0);
  function goToRecipe(title) {
    setRecipeQuery(title);
    setRecipeNavKey((k) => k + 1);
    setTab("recipes");
  }

  // ---- date-based meal logs (all keyed by local YYYY-MM-DD strings) ----
  // Every day starts empty - nothing is pre-logged, the list only fills as the user logs meals.
  const [selectedDate, setSelectedDate] = useState(todayKey);
  const [logsByDate, setLogsByDate] = useLocalStorage("nicinsync_logs", {});

  const selectedCycleDay = cycleDayForKey(selectedDate, cycleStartDate);
  const selectedPhaseKey = phaseForDay(selectedCycleDay);
  const selectedPhase = localizePhase(PHASES[selectedPhaseKey], lang);
  const selectedGoals = useMemo(() => computeGoals(profile, selectedPhaseKey), [profile, selectedPhaseKey]);
  const selectedMeals = logsByDate[selectedDate] || [];

  function addMeal(meal) {
    setLogsByDate((prev) => ({ ...prev, [selectedDate]: [meal, ...(prev[selectedDate] || [])] }));
  }
  function deleteMeal(id) {
    setLogsByDate((prev) => ({ ...prev, [selectedDate]: (prev[selectedDate] || []).filter((m) => m.id !== id) }));
  }
  function editMeal(id, changes) {
    setLogsByDate((prev) => ({
      ...prev,
      [selectedDate]: (prev[selectedDate] || []).map((m) => (m.id === id ? { ...m, ...changes } : m)),
    }));
  }

  const [scannerText, setScannerText] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [lastAiError, setLastAiError] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const [pendingMealType, setPendingMealType] = useState(null);

  const totals = useMemo(
    () =>
      selectedMeals.reduce(
        (acc, m) => ({ kcal: acc.kcal + m.kcal, protein: acc.protein + m.protein, carbs: acc.carbs + m.carbs, fat: acc.fat + m.fat }),
        { kcal: 0, protein: 0, carbs: 0, fat: 0 }
      ),
    [selectedMeals]
  );
  const selectedScore = useMemo(() => computeHormoneScore(selectedMeals, selectedGoals, totals), [selectedMeals, selectedGoals, totals]);

  // today-specific score for the dashboard, independent of which date is being browsed in the tracker
  const todayMeals = logsByDate[todayKey] || [];
  const todayTotals = useMemo(
    () => todayMeals.reduce((acc, m) => ({ kcal: acc.kcal + m.kcal, protein: acc.protein + m.protein, carbs: acc.carbs + m.carbs, fat: acc.fat + m.fat }), { kcal: 0, protein: 0, carbs: 0, fat: 0 }),
    [todayMeals]
  );
  const todayScore = useMemo(() => computeHormoneScore(todayMeals, goals, todayTotals), [todayMeals, goals, todayTotals]);

// Real AI-powered dish analysis via the Claude API (vision + text). Falls back to the
// local heuristic estimator (see estimateMeal/phaseMatchScore) if the request fails for
// any reason - network issue, malformed response, etc. - so the scanner always works.
// Tries the direct Anthropic endpoint first (this works automatically inside the Claude
// artifact preview, where Anthropic proxies auth for us). On a standalone deployment
// (e.g. your own Vercel site) that direct call has no credentials and will fail, so we
// fall back to our own serverless function at /api/analyze, which holds the API key
// safely on the server side (see api/analyze.js).
async function analyzeFoodWithAI({ text, imageDataUrl, phase, diets, lang }) {
  const dietList = diets && diets.length ? diets.map((d) => dietLabel(d, lang)).join(", ") : lang === "en" ? "no restrictions" : "keine Einschränkungen";
  const langInstruction = lang === "en" ? "Respond in English." : "Antworte auf Deutsch.";
  const instructions = `You are a nutrition assistant inside a cycle-based nutrition app.
Current cycle phase: ${phase.name}
Nutrient focus of this phase: ${phase.focus.join(", ")}
User's diet restrictions: ${dietList}

${imageDataUrl ? "Identify the dish shown in the attached photo" : `Analyze this dish, described by the user: "${text}"`} and estimate realistic nutrition (kcal, protein, carbs, fat in grams) for the portion shown/described.
Also break the dish down into its main individual ingredients (2-6 items) with a realistic amount and unit for each (e.g. "g", "ml", "Stück", "EL", "Portion") and that ingredient's own kcal/protein/carbs/fat contribution. The ingredient values should sum up to (approximately) the dish totals.
Rate 0-100 how well this dish fits the nutrient focus of the current cycle phase (match).
If it is clearly deep-fried or heavily processed fast food (fries, pizza, burger, chips, nuggets, etc.), set isJunk to true, cap match at 35, and suggest one specific, appealing, healthier swap.
If the dish conflicts with the user's diet restrictions above, explain briefly in dietWarning (${langInstruction.toLowerCase()}), otherwise set it to null.
Keep "reason" to exactly 1-2 short, complete sentences (max ~150 characters) - never trail off or leave a sentence unfinished. Same rule for "dietWarning" and the swap's "why". Ingredient names should be short (1-3 words, in ${lang === "en" ? "English" : "German"}).
${langInstruction}

Respond with ONLY a JSON object, no markdown formatting, no extra text before or after, in exactly this shape:
{"name":"...","kcal":0,"protein":0,"carbs":0,"fat":0,"isJunk":false,"match":0,"reason":"...","dietWarning":null,"ingredients":[{"name":"...","amount":0,"unit":"g","kcal":0,"protein":0,"carbs":0,"fat":0}],"swap":null}
If isJunk is true, "swap" must be {"name":"...","kcal":0,"protein":0,"carbs":0,"fat":0,"match":0,"why":"..."}, otherwise "swap" must be null.`;

  const parts = [{ text: instructions }];
  if (imageDataUrl) {
    const match = imageDataUrl.match(/^data:(image\/\w+);base64,(.+)$/);
    if (match) parts.unshift({ inlineData: { mimeType: match[1], data: match[2] } });
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 25000);
  let response;
  try {
    response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ role: "user", parts }] }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
  }
  if (!response.ok) {
    let detail = "";
    try {
      const errBody = await response.json();
      detail = `: ${JSON.stringify(errBody).slice(0, 400)}`;
    } catch (e) {
      /* body wasn't JSON */
    }
    throw new Error(`AI API error ${response.status}${detail}`);
  }
  const data = await response.json();
  const textBlock = data?.candidates?.[0]?.content?.parts?.find((p) => typeof p.text === "string");
  if (!textBlock) throw new Error("No text block in AI response");
  const cleaned = textBlock.text.replace(/```json|```/g, "").trim();
  const parsed = JSON.parse(cleaned);
  if (typeof parsed.kcal !== "number" || typeof parsed.match !== "number") throw new Error("Unexpected response shape");
  return parsed;
}

function buildMealFromText(rawText, mealType) {
    const text = sanitizeText(rawText.trim(), 120) || (lang === "en" ? "Meal" : "Mahlzeit");
    const lower = text.toLowerCase();
    const est = estimateMeal(text);
    const match = est.isJunk ? junkMatchScore(text) : phaseMatchScore(est, selectedPhaseKey);
    const swap = est.isJunk ? localizedSwap(JUNK_SWAPS[est.junkKey], lang) : null;
    const dietWarning = checkDietConflicts(lower, profile.diets, lang);
    return {
      id: secureId("meal"),
      name: text.charAt(0).toUpperCase() + text.slice(1),
      kcal: est.kcal,
      protein: est.protein,
      carbs: est.carbs,
      fat: est.fat,
      time: new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }),
      match,
      isJunk: est.isJunk,
      swap,
      dietWarning,
      adjustments: [],
      mealType,
      ingredients: (est.ingredients || []).map((ing) => ({ id: secureId("ing"), ...ing })),
    };
  }

  function quickAddMeal(text, mealType) {
    if (!text.trim()) return;
    addMeal(buildMealFromText(text, mealType));
  }

  async function handleAnalyze() {
    if (!scannerText.trim() && !imagePreview) return;
    setAnalyzing(true);
    const rawText = scannerText.trim();
    const fallbackText = rawText || (lang === "en" ? "Photographed meal" : "Fotografierte Mahlzeit");
    const mealType = pendingMealType || autoMealType();

    let aiResult = null;
    try {
      aiResult = await analyzeFoodWithAI({ text: rawText, imageDataUrl: imagePreview, phase: selectedPhase, diets: profile.diets, lang });
      setLastAiError(null);
    } catch (err) {
      console.warn("AI food analysis failed, using local estimate instead.", err);
      setLastAiError(String(err && err.message ? err.message : err));
    }

    let newMeal;
    if (aiResult) {
      const cleanName = sanitizeText(String(aiResult.name || fallbackText), 120);
      const isJunk = !!aiResult.isJunk;
      const swapRaw = isJunk && aiResult.swap ? aiResult.swap : null;
      newMeal = {
        id: secureId("meal"),
        name: cleanName.charAt(0).toUpperCase() + cleanName.slice(1),
        kcal: Math.max(1, Math.round(Number(aiResult.kcal) || 0)),
        protein: Math.max(0, Math.round(Number(aiResult.protein) || 0)),
        carbs: Math.max(0, Math.round(Number(aiResult.carbs) || 0)),
        fat: Math.max(0, Math.round(Number(aiResult.fat) || 0)),
        time: new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }),
        match: Math.max(0, Math.min(100, Math.round(Number(aiResult.match) || 50))),
        isJunk,
        swap: swapRaw
          ? {
              name: sanitizeText(String(swapRaw.name || ""), 80),
              kcal: Math.max(1, Math.round(Number(swapRaw.kcal) || 0)),
              protein: Math.max(0, Math.round(Number(swapRaw.protein) || 0)),
              carbs: Math.max(0, Math.round(Number(swapRaw.carbs) || 0)),
              fat: Math.max(0, Math.round(Number(swapRaw.fat) || 0)),
              match: Math.max(0, Math.min(100, Math.round(Number(swapRaw.match) || 80))),
              why: sanitizeText(String(swapRaw.why || ""), 400),
            }
          : null,
        dietWarning: aiResult.dietWarning ? sanitizeText(String(aiResult.dietWarning), 300) : null,
        matchReasonText: aiResult.reason ? sanitizeText(String(aiResult.reason), 500) : null,
        adjustments: [],
        mealType,
        aiAnalyzed: true,
        ingredients:
          Array.isArray(aiResult.ingredients) && aiResult.ingredients.length > 0
            ? aiResult.ingredients.slice(0, 8).map((ing) => ({
                id: secureId("ing"),
                name: sanitizeText(String(ing.name || "Zutat"), 40),
                amount: Math.max(0, Math.round(Number(ing.amount) || 0)) || 1,
                unit: sanitizeText(String(ing.unit || "g"), 12) || "g",
                kcal: Math.max(0, Math.round(Number(ing.kcal) || 0)),
                protein: Math.max(0, Math.round((Number(ing.protein) || 0) * 10) / 10),
                carbs: Math.max(0, Math.round((Number(ing.carbs) || 0) * 10) / 10),
                fat: Math.max(0, Math.round((Number(ing.fat) || 0) * 10) / 10),
              }))
            : ingredientsFromDishText(String(aiResult.name || fallbackText), {
                kcal: Math.max(1, Math.round(Number(aiResult.kcal) || 0)),
                protein: Math.max(0, Math.round(Number(aiResult.protein) || 0)),
                carbs: Math.max(0, Math.round(Number(aiResult.carbs) || 0)),
                fat: Math.max(0, Math.round(Number(aiResult.fat) || 0)),
              }),
      };
    } else {
      newMeal = buildMealFromText(fallbackText, mealType);
    }

    addMeal(newMeal);
    setScannerText("");
    setImagePreview(null);
    setAnalyzing(false);
  }

  function logSwap(swap) {
    addMeal({
      id: secureId("meal"),
      name: swap.name,
      kcal: swap.kcal,
      protein: swap.protein,
      carbs: swap.carbs,
      fat: swap.fat,
      time: new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }),
      match: swap.match,
      isJunk: false,
      swap: null,
      dietWarning: null,
      adjustments: [],
      mealType: autoMealType(),
      ingredients: [{ id: secureId("ing"), name: swap.name, amount: 1, unit: "Portion", kcal: swap.kcal, protein: swap.protein, carbs: swap.carbs, fat: swap.fat }],
    });
  }

  // ---- mood & symptom logs (per date) ----
  const moodSeed = useMemo(() => {
    const d1 = addDaysToKey(todayKey, -1);
    const d2 = addDaysToKey(todayKey, -2);
    const d3 = addDaysToKey(todayKey, -3);
    const d4 = addDaysToKey(todayKey, -4);
    const d8 = addDaysToKey(todayKey, -8);
    return {
      [todayKey]: { mood: "balanced", symptoms: ["bloating"] },
      [d1]: { mood: "tired", symptoms: ["fatigue", "cravings"] },
      [d2]: { mood: "irritable", symptoms: ["cramps"] },
      [d3]: { mood: "energized", symptoms: [] },
      [d4]: { mood: "tired", symptoms: ["headache"] },
      [d8]: { mood: "tired", symptoms: ["fatigue"] },
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [moodLogByDate, setMoodLogByDate] = useLocalStorage("nicinsync_mood_log", moodSeed);
  function setTodayMood(moodId) {
    setMoodLogByDate((prev) => ({ ...prev, [todayKey]: { ...(prev[todayKey] || { symptoms: [] }), mood: moodId } }));
  }
  function toggleTodaySymptom(symptomId) {
    setMoodLogByDate((prev) => {
      const entry = prev[todayKey] || { mood: null, symptoms: [] };
      const symptoms = entry.symptoms.includes(symptomId) ? entry.symptoms.filter((s) => s !== symptomId) : [...entry.symptoms, symptomId];
      return { ...prev, [todayKey]: { ...entry, symptoms } };
    });
  }

  // ---- shopping list ----
  const [shoppingList, setShoppingList] = useLocalStorage("nicinsync_shopping", []);
  function addRecipeToShoppingList(recipe) {
    setShoppingList((prev) => {
      const existingTexts = new Set(prev.map((i) => i.text.toLowerCase()));
      const additions = recipe.ingredients
        .filter((ing) => !existingTexts.has(ing.toLowerCase()))
        .map((ing) => ({ id: secureId("item"), text: ing, category: categorizeIngredient(ing), checked: false, recipeTitle: recipe.title }));
      return [...prev, ...additions];
    });
  }
  function toggleShoppingItem(id) {
    setShoppingList((prev) => prev.map((i) => (i.id === id ? { ...i, checked: !i.checked } : i)));
  }
  function removeShoppingItem(id) {
    setShoppingList((prev) => prev.filter((i) => i.id !== id));
  }
  function clearShoppingList() {
    setShoppingList([]);
  }
  function addCustomShoppingItem(text) {
    const clean = sanitizeText(text, 80);
    if (!clean) return;
    setShoppingList((prev) => {
      if (prev.some((i) => i.text.toLowerCase() === clean.toLowerCase())) return prev;
      return [...prev, { id: secureId("item"), text: clean, category: categorizeIngredient(clean), checked: false, recipeTitle: null }];
    });
  }

  // ---- saved (favorite) recipes ----
  const [favoriteIds, setFavoriteIds] = useLocalStorage("nicinsync_favorites", []);
  function toggleFavorite(id) {
    setFavoriteIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  // Turns a logged meal (from the Tracker) into a proper Recipe entry and favorites it
  // immediately, so dishes you've actually eaten and liked show up under Rezepte -> Favoriten.
  function saveMealAsFavoriteRecipe(meal) {
    const ingredientStrings = (meal.ingredients || [])
      .map((ing) => (!ing.unit || ing.unit === "Portion" ? ing.name : `${ing.amount}${ing.unit === "g" || ing.unit === "ml" ? ing.unit : ` ${ing.unit}`} ${ing.name}`))
      .filter(Boolean);
    const phaseObj = PHASES[selectedPhaseKey];
    const tags = [];
    if (meal.protein >= 20) tags.push("High Protein");
    if (meal.isJunk) tags.push("Cravings");
    if (tags.length === 0) tags.push("Ausgewogen");
    const newRecipe = {
      id: secureId("fav"),
      title: meal.name,
      cuisine: null,
      phase: selectedPhaseKey,
      time: 0,
      kcal: meal.kcal,
      protein: meal.protein,
      carbs: meal.carbs,
      fat: meal.fat,
      tags: tags.slice(0, 3),
      micronutrient: phaseObj.focus[0],
      ingredients: ingredientStrings.length > 0 ? ingredientStrings : [meal.name],
      steps: [lang === "en" ? "Logged from your food diary - no preparation steps recorded." : "Aus deinem Tagebuch gespeichert - keine Zubereitungsschritte hinterlegt."],
      why:
        lang === "en"
          ? "Saved from something you actually ate and liked."
          : "Gespeichert aus einer Mahlzeit, die du wirklich gegessen und für gut befunden hast.",
      color: phaseObj.color,
      meat: false,
      fish: false,
      dairy: false,
      gluten: false,
      egg: false,
    };
    addRecipe(newRecipe);
    setFavoriteIds((prev) => (prev.includes(newRecipe.id) ? prev : [...prev, newRecipe.id]));
  }

  // ---- one-tap logging shortcuts (e.g. "my usual breakfast") ----
  const [shortcuts, setShortcuts] = useLocalStorage("nicinsync_shortcuts", []);
  function addShortcut(shortcut) {
    if (!shortcut || !shortcut.label || !String(shortcut.label).trim()) {
      console.error("addShortcut(): missing label, ignoring", shortcut);
      return;
    }
    setShortcuts((prev) => [
      ...prev,
      {
        id: secureId("shortcut"),
        label: sanitizeText(String(shortcut.label), 60),
        kcal: Math.max(0, Math.round(Number(shortcut.kcal) || 0)),
        protein: Math.max(0, Math.round(Number(shortcut.protein) || 0)),
        carbs: Math.max(0, Math.round(Number(shortcut.carbs) || 0)),
        fat: Math.max(0, Math.round(Number(shortcut.fat) || 0)),
        ingredients: Array.isArray(shortcut.ingredients) && shortcut.ingredients.length > 0 ? shortcut.ingredients : null,
      },
    ]);
  }
  function removeShortcut(id) {
    setShortcuts((prev) => prev.filter((s) => s.id !== id));
  }
  function logShortcut(shortcut, mealType) {
    const match = phaseMatchScore({ kcal: shortcut.kcal, protein: shortcut.protein, carbs: shortcut.carbs, fat: shortcut.fat }, selectedPhaseKey);
    addMeal({
      id: secureId("meal"),
      name: shortcut.label,
      kcal: shortcut.kcal,
      protein: shortcut.protein,
      carbs: shortcut.carbs,
      fat: shortcut.fat,
      time: new Date().toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }),
      match,
      isJunk: false,
      swap: null,
      dietWarning: null,
      adjustments: [],
      mealType: mealType || pendingMealType || autoMealType(),
      ingredients:
        Array.isArray(shortcut.ingredients) && shortcut.ingredients.length > 0
          ? shortcut.ingredients.map((ing) => ({ ...ing, id: secureId("ing") }))
          : [{ id: secureId("ing"), name: shortcut.label, amount: 1, unit: "Portion", kcal: shortcut.kcal, protein: shortcut.protein, carbs: shortcut.carbs, fat: shortcut.fat }],
    });
    setPendingMealType(null);
  }

  // ---- rewards: streaks, points & badges for well-balanced days ----
  const rewards = useMemo(() => computeRewards(logsByDate, cycleStartDate, profile, todayKey), [logsByDate, cycleStartDate, profile, todayKey]);

  return (
    <LangContext.Provider value={{ lang, t }}>
    <div className="min-h-screen w-full flex justify-center" style={{ background: "#FAFAFA", fontFamily: "'Nunito', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fredoka:wght@400;500;600;700&family=Nunito:wght@400;500;600;700;800&display=swap');
        .font-display { font-family: 'Fredoka', sans-serif; }
        ::-webkit-scrollbar { display: none; }
      `}</style>

      <div className="w-full max-w-md min-h-screen relative pb-24" style={{ background: "#FAFAFA" }}>
        {tab === "home" && (
          <HomeTab
            phase={phase}
            phaseKey={phaseKey}
            cycleDay={cycleDay}
            todayKey={todayKey}
            setCycleStartDate={setCycleStartDate}
            onOpenProfile={() => setProfileOpen(true)}
            goToRecipe={goToRecipe}
            recipes={recipes}
            diets={profile.diets}
            hormoneScore={todayScore}
            userName={profile.name}
            rewards={rewards}
          />
        )}
        {tab === "tracker" && (
          <TrackerTab
            phase={selectedPhase}
            phaseKey={selectedPhaseKey}
            totals={totals}
            goals={selectedGoals}
            meals={selectedMeals}
            selectedDate={selectedDate}
            setSelectedDate={setSelectedDate}
            todayKey={todayKey}
            scannerText={scannerText}
            setScannerText={setScannerText}
            analyzing={analyzing}
            imagePreview={imagePreview}
            setImagePreview={setImagePreview}
            handleAnalyze={handleAnalyze}
            logSwap={logSwap}
            deleteMeal={deleteMeal}
            editMeal={editMeal}
            hormoneScore={selectedScore}
            shortcuts={shortcuts}
            addShortcut={addShortcut}
            removeShortcut={removeShortcut}
            logShortcut={logShortcut}
            pendingMealType={pendingMealType}
            setPendingMealType={setPendingMealType}
            quickAddMeal={quickAddMeal}
            saveMealAsFavoriteRecipe={saveMealAsFavoriteRecipe}
            lastAiError={lastAiError}
          />
        )}
        {tab === "recipes" && (
          <RecipesTab
            key={recipeNavKey}
            phase={phase}
            phaseKey={phaseKey}
            initialQuery={recipeQuery}
            recipes={recipes}
            addRecipe={addRecipe}
            clearAllRecipes={clearAllRecipes}
            diets={profile.diets}
            addRecipeToShoppingList={addRecipeToShoppingList}
            favoriteIds={favoriteIds}
            toggleFavorite={toggleFavorite}
            addShortcut={addShortcut}
          />
        )}
        {tab === "symptoms" && (
          <SymptomsTab
            phase={phase}
            goToRecipe={goToRecipe}
            recipes={recipes}
            todayKey={todayKey}
            cycleStartDate={cycleStartDate}
            moodLogByDate={moodLogByDate}
            setTodayMood={setTodayMood}
            toggleTodaySymptom={toggleTodaySymptom}
          />
        )}
        {tab === "shopping" && (
          <ShoppingListTab phase={phase} items={shoppingList} onToggle={toggleShoppingItem} onRemove={removeShoppingItem} onClear={clearShoppingList} onAdd={addCustomShoppingItem} />
        )}

        <BottomNav tab={tab} setTab={setTab} phase={phase} shoppingCount={shoppingList.filter((i) => !i.checked).length} />

        {profileOpen && (
          <ProfileModal
            profile={profile}
            phase={phase}
            onClose={() => setProfileOpen(false)}
            onSave={(p) => {
              setProfile(p);
              setProfileOpen(false);
            }}
            lang={lang}
            setLang={setLang}
          />
        )}
      </div>
    </div>
    </LangContext.Provider>
  );
}

/* ------------------------------ Bottom Nav ------------------------------ */
function BottomNav({ tab, setTab, phase, shoppingCount }) {
  const { t } = useLang();
  const items = [
    { id: "home", label: t("nav_dashboard"), icon: Home },
    { id: "tracker", label: t("nav_tracker"), icon: Salad },
    { id: "recipes", label: t("nav_recipes"), icon: BookOpen },
    { id: "shopping", label: t("nav_shopping"), icon: ShoppingCart },
    { id: "symptoms", label: t("nav_symptoms"), icon: Activity },
  ];
  return (
    <div className="fixed bottom-0 w-full max-w-md left-1/2 -translate-x-1/2 border-t" style={{ background: "#FFFFFF", borderColor: "#E2E2E2" }}>
      <div className="flex items-center gap-1 py-2 px-2 overflow-x-auto" style={{ scrollSnapType: "x proximity" }}>
        {items.map((it) => {
          const Icon = it.icon;
          const active = tab === it.id;
          return (
            <button
              key={it.id}
              onClick={() => setTab(it.id)}
              className="relative flex flex-col items-center gap-1 py-1.5 px-3 rounded-xl transition-colors shrink-0"
              style={{ color: active ? phase.color : "#A3A3A3", background: active ? phase.tint : "transparent", minWidth: 64, scrollSnapAlign: "center" }}
            >
              <Icon size={19} strokeWidth={active ? 2.4 : 1.8} />
              {it.id === "shopping" && shoppingCount > 0 && (
                <span className="absolute -top-0.5 right-2 min-w-[14px] h-[14px] px-[3px] rounded-full text-[8px] font-bold flex items-center justify-center text-white" style={{ background: "#8C3B47" }}>
                  {shoppingCount}
                </span>
              )}
              <span className="text-[9.5px] font-medium whitespace-nowrap">{it.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------ Profile Modal ------------------------------ */
function ProfileModal({ profile, phase, onClose, onSave, lang, setLang }) {
  const { t } = useLang();
  const [form, setForm] = useState(() => ({ ...profile }));
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const setNum = (key, min, max) => (nextVal) => {
    const n = Math.max(min, Math.min(max, nextVal));
    setForm((f) => ({ ...f, [key]: n }));
  };
  const setNumFromText = (key, min, max) => (e) => {
    const digits = e.target.value.replace(/[^0-9]/g, "");
    if (digits === "") {
      setForm((f) => ({ ...f, [key]: 0 }));
      return;
    }
    const n = Math.max(0, Math.min(max, Number(digits)));
    setForm((f) => ({ ...f, [key]: n }));
  };
  const setVal = (key) => (v) => setForm((f) => ({ ...f, [key]: v }));

  function toggleDiet(d) {
    setForm((f) => {
      const current = f.diets || ["omnivore"];
      if (d === "omnivore") return { ...f, diets: ["omnivore"] };
      let next = current.filter((x) => x !== "omnivore");
      if (next.includes(d)) {
        next = next.filter((x) => x !== d);
        if (next.length === 0) next = ["omnivore"];
      } else {
        next = [...next, d];
      }
      return { ...f, diets: next };
    });
  }

  const previewGoals = useMemo(() => computeGoals(form, phase.key), [form, phase.key]);

  function handleSave() {
    onSave({
      ...form,
      name: sanitizeText(form.name, 40),
      height: form.height || profile.height,
      weight: form.weight || profile.weight,
      age: form.age || profile.age,
    });
  }

  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.45)" }} onClick={onClose}>
      <div
        className="w-full max-w-md rounded-t-3xl sm:rounded-3xl p-6"
        style={{
          background: "#FFFFFF",
          maxHeight: "min(85vh, 85dvh)",
          overflowY: "auto",
          WebkitOverflowScrolling: "touch",
          overscrollBehavior: "contain",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-display text-xl" style={{ color: "#121212" }}>
            {t("profile_title")}
          </h2>
          <button onClick={onClose} className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: "#EFEFEF" }}>
            <X size={16} style={{ color: "#545454" }} />
          </button>
        </div>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("language")}
        </label>
        <div className="grid grid-cols-2 gap-1.5 mb-5">
          {[
            { id: "de", label: "Deutsch" },
            { id: "en", label: "English" },
          ].map((l) => (
            <button
              key={l.id}
              onClick={() => setLang(l.id)}
              className="text-[11px] px-2 py-2 rounded-lg border font-medium"
              style={{
                background: lang === l.id ? phase.color : "#FFFFFF",
                color: lang === l.id ? "#FFFFFF" : "#545454",
                borderColor: lang === l.id ? phase.color : "#E2E2E2",
              }}
            >
              {l.label}
            </button>
          ))}
        </div>

        <div className="mb-4">
          <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
            {t("your_name")}
          </label>
          <input
            type="text"
            value={form.name || ""}
            onChange={(e) => setVal("name")(e.target.value)}
            placeholder={t("name_placeholder")}
            className="w-full px-3 py-2.5 rounded-lg text-sm outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
          />
        </div>

        <div className="space-y-3 mb-4">
          <NumberField label={t("height_cm")} value={form.height} onStep={setNum("height", 100, 220)} onTextChange={setNumFromText("height", 100, 220)} step={1} />
          <NumberField label={t("weight_kg")} value={form.weight} onStep={setNum("weight", 30, 200)} onTextChange={setNumFromText("weight", 30, 200)} step={1} />
          <NumberField label={t("age_years")} value={form.age} onStep={setNum("age", 10, 100)} onTextChange={setNumFromText("age", 10, 100)} step={1} />
        </div>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("activity_level")}
        </label>
        <div className="grid grid-cols-3 gap-1.5 mb-4">
          {Object.keys(ACTIVITY_LABELS).map((k) => (
            <button
              key={k}
              onClick={() => setVal("activity")(k)}
              className="text-[11px] px-2 py-2.5 rounded-lg border font-medium text-center"
              style={{
                background: form.activity === k ? phase.color : "#FFFFFF",
                color: form.activity === k ? "#FFFFFF" : "#545454",
                borderColor: form.activity === k ? phase.color : "#E2E2E2",
              }}
            >
              {activityLabel(k, lang)}
            </button>
          ))}
        </div>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("diet_style")} <span style={{ color: "#8A8A8A", fontWeight: 400 }}>{t("diet_multiselect")}</span>
        </label>
        <div className="grid grid-cols-2 gap-1.5 mb-4">
          {DIET_ORDER.map((d) => {
            const active = (form.diets || []).includes(d);
            return (
              <button
                key={d}
                onClick={() => toggleDiet(d)}
                className="text-[11px] px-2 py-2 rounded-lg border font-medium flex items-center justify-center gap-1.5"
                style={{
                  background: active ? phase.color : "#FFFFFF",
                  color: active ? "#FFFFFF" : "#545454",
                  borderColor: active ? phase.color : "#E2E2E2",
                }}
              >
                {active && <Check size={11} />}
                {dietLabel(d, lang)}
              </button>
            );
          })}
        </div>

        <div className="rounded-2xl p-4 mb-5" style={{ background: phase.tint }}>
          <p className="text-[11px] uppercase tracking-widest mb-2" style={{ color: phase.color }}>
            {t("daily_goal")}
          </p>
          <p className="font-display text-2xl mb-1" style={{ color: "#121212" }}>
            {previewGoals.kcal} kcal
          </p>
          <p className="text-[11px]" style={{ color: "#545454" }}>
            {previewGoals.protein}g {t("protein")} · {previewGoals.carbs}g {t("carbs")} · {previewGoals.fat}g {t("fat")}
          </p>
          {previewGoals.lutealBonus > 0 && (
            <p className="text-[11px] mt-2 flex items-center gap-1" style={{ color: phase.color }}>
              <Sparkles size={11} /> +{previewGoals.lutealBonus} {t("luteal_bonus")}
            </p>
          )}
        </div>

        <div className="rounded-2xl p-4 mb-5" style={{ background: "#F6E1E3" }}>
          <p className="text-[11px] uppercase tracking-widest mb-2" style={{ color: "#8C3B47" }}>
            {t("privacy_title")}
          </p>
          <p className="text-[11px] leading-relaxed mb-3" style={{ color: "#545454" }}>
            {t("privacy_hint")}
          </p>
          {!confirmingDelete ? (
            <button onClick={() => setConfirmingDelete(true)} className="w-full py-2.5 rounded-xl text-xs font-semibold" style={{ background: "#8C3B47", color: "#FFFFFF" }}>
              {t("delete_my_data")}
            </button>
          ) : (
            <div className="flex gap-2">
              <button onClick={() => setConfirmingDelete(false)} className="flex-1 py-2.5 rounded-xl text-xs font-semibold" style={{ background: "#FFFFFF", color: "#545454" }}>
                {t("cancel")}
              </button>
              <button
                onClick={() => {
                  clearAllLocalData();
                  window.location.reload();
                }}
                className="flex-1 py-2.5 rounded-xl text-xs font-semibold"
                style={{ background: "#8C3B47", color: "#FFFFFF" }}
              >
                {t("confirm_delete")}
              </button>
            </div>
          )}
        </div>

        <div className="flex gap-2">
          <button onClick={onClose} className="flex-1 py-3 rounded-xl text-sm font-semibold" style={{ background: "#EFEFEF", color: "#545454" }}>
            {t("cancel")}
          </button>
          <button onClick={handleSave} className="flex-1 py-3 rounded-xl text-sm font-semibold" style={{ background: phase.color, color: "#FFFFFF" }}>
            {t("save")}
          </button>
        </div>
      </div>
    </div>
  );
}

function NumberField({ label, value, onStep, onTextChange, step }) {
  return (
    <div>
      <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
        {label}
      </label>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onStep(value - step)}
          className="w-10 h-10 rounded-lg flex items-center justify-center text-lg font-semibold shrink-0 border border-[#DADADA] text-[#121212] hover:bg-[#121212] hover:text-white hover:border-[#121212] transition-colors"
          aria-label={`${label} verringern`}
        >
          −
        </button>
        <input
          type="text"
          inputMode="numeric"
          value={value}
          onChange={onTextChange}
          className="flex-1 min-w-0 px-3 py-2.5 rounded-lg text-base font-semibold text-center outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
        />
        <button
          type="button"
          onClick={() => onStep(value + step)}
          className="w-10 h-10 rounded-lg flex items-center justify-center text-lg font-semibold shrink-0 border border-[#DADADA] text-[#121212] hover:bg-[#121212] hover:text-white hover:border-[#121212] transition-colors"
          aria-label={`${label} erhöhen`}
        >
          +
        </button>
      </div>
    </div>
  );
}

/* --------------------------------- Home --------------------------------- */
function HomeTab({ phase, phaseKey, cycleDay, todayKey, setCycleStartDate, onOpenProfile, goToRecipe, recipes, diets, hormoneScore, userName, rewards }) {
  const { t, lang } = useLang();
  const Icon = phase.icon;
  const angle = (cycleDay / CYCLE_LENGTH) * 360;
  const dialRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [pressing, setPressing] = useState(false);
  const pressTimerRef = useRef(null);

  const conic = `conic-gradient(
    ${PHASES.menstruation.color} 0deg ${(5 / CYCLE_LENGTH) * 360}deg,
    ${PHASES.follikel.color} ${(5 / CYCLE_LENGTH) * 360}deg ${(13 / CYCLE_LENGTH) * 360}deg,
    ${PHASES.ovulation.color} ${(13 / CYCLE_LENGTH) * 360}deg ${(16 / CYCLE_LENGTH) * 360}deg,
    ${PHASES.luteal.color} ${(16 / CYCLE_LENGTH) * 360}deg 360deg
  )`;

  const recommended = recipes.find((r) => r.phase === phaseKey && isDietCompatible(r, diets)) || recipes.find((r) => r.phase === phaseKey);
  const dailyRecipes = useMemo(() => getDailyCycleRecipes(phaseKey, cycleDay), [phaseKey, cycleDay]);
  const [openCycleRecipe, setOpenCycleRecipe] = useState(null);

  function handleDayChange(newDay) {
    setCycleStartDate(addDaysToKey(todayKey, -(newDay - 1)));
  }

  function dayFromPointer(clientX, clientY) {
    if (!dialRef.current) return cycleDay;
    const rect = dialRef.current.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const dx = clientX - cx;
    const dy = clientY - cy;
    let ang = Math.atan2(dx, -dy) * (180 / Math.PI);
    if (ang < 0) ang += 360;
    let day = Math.round((ang / 360) * CYCLE_LENGTH);
    if (day <= 0) day = CYCLE_LENGTH;
    if (day > CYCLE_LENGTH) day = CYCLE_LENGTH;
    return day;
  }

  function handlePointerDown(e) {
    const startX = e.clientX;
    const startY = e.clientY;
    setPressing(true);

    function onMoveDuringHold(ev) {
      const dx = ev.clientX - startX;
      const dy = ev.clientY - startY;
      if (Math.sqrt(dx * dx + dy * dy) > 12) cancelHold();
    }
    function onUpDuringHold() {
      cancelHold();
    }
    function cancelHold() {
      clearTimeout(pressTimerRef.current);
      window.removeEventListener("pointermove", onMoveDuringHold);
      window.removeEventListener("pointerup", onUpDuringHold);
      setPressing(false);
    }

    pressTimerRef.current = setTimeout(() => {
      window.removeEventListener("pointermove", onMoveDuringHold);
      window.removeEventListener("pointerup", onUpDuringHold);
      setPressing(false);
      setDragging(true);
      handleDayChange(dayFromPointer(startX, startY));
    }, 350);

    window.addEventListener("pointermove", onMoveDuringHold);
    window.addEventListener("pointerup", onUpDuringHold);
  }

  useEffect(() => {
    if (!dragging) return;
    function onMove(e) {
      handleDayChange(dayFromPointer(e.clientX, e.clientY));
    }
    function onUp() {
      setDragging(false);
    }
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dragging]);

  return (
    <div className="px-5 pt-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="text-xs tracking-widest uppercase" style={{ color: "#AFAFAF" }}>
            {t("greeting")}
          </p>
          <h1 className="font-display text-2xl" style={{ color: "#121212" }}>
            {userName ? `${t("hello")}, ${userName}` : "NicInSync"}
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onOpenProfile} className="w-10 h-10 rounded-full flex items-center justify-center" style={{ background: "#EFEFEF" }}>
            <Settings size={17} style={{ color: "#545454" }} />
          </button>
          <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ background: phase.tint }}>
            <Icon size={18} style={{ color: phase.color }} />
          </div>
        </div>
      </div>

      {/* Cycle dial */}
      <div className="flex flex-col items-center mb-6">
        <div
          ref={dialRef}
          onPointerDown={handlePointerDown}
          className="relative w-56 h-56 rounded-full flex items-center justify-center"
          style={{ background: conic, padding: 14, touchAction: "none", cursor: "pointer", transform: pressing ? "scale(1.03)" : "scale(1)", transition: "transform 0.2s ease" }}
        >
          <div className="w-full h-full rounded-full flex flex-col items-center justify-center" style={{ background: "#FAFAFA" }}>
            <span className="text-xs uppercase tracking-widest" style={{ color: "#AFAFAF" }}>
              {t("cycle_day")}
            </span>
            <span className="font-display text-5xl" style={{ color: phase.color }}>
              {cycleDay}
            </span>
            <span className="text-sm mt-1 font-medium" style={{ color: "#545454" }}>
              {phase.name}
            </span>
          </div>
          <div
            className="absolute w-6 h-6 rounded-full border-2 flex items-center justify-center"
            style={{
              marginLeft: -12,
              marginTop: -12,
              borderColor: "#FAFAFA",
              background: phase.color,
              top: "50%",
              left: "50%",
              transform: `rotate(${angle}deg) translate(0, -105px) rotate(-${angle}deg)`,
              transformOrigin: "0 0",
              boxShadow: dragging ? "0 0 0 6px rgba(0,0,0,0.08)" : pressing ? "0 0 0 4px rgba(0,0,0,0.05)" : "none",
            }}
          />
        </div>
        <p className="text-[11px] mt-3" style={{ color: "#AFAFAF" }}>
          {t("drag_dial_hint")}
        </p>
      </div>

      {/* Quick phase switch */}
      <div className="flex gap-2 mb-6 overflow-x-auto">
        {PHASE_ORDER.map((key) => {
          const p = PHASES[key];
          const PIcon = p.icon;
          const active = key === phaseKey;
          return (
            <button
              key={key}
              onClick={() => handleDayChange(Math.round((p.dayRange[0] + p.dayRange[1]) / 2))}
              className="flex items-center gap-1.5 px-3 py-2 rounded-full text-xs font-medium whitespace-nowrap border transition-all"
              style={{ background: active ? p.color : "#FFFFFF", color: active ? "#FFFFFF" : "#545454", borderColor: active ? p.color : "#E2E2E2" }}
            >
              <PIcon size={13} />
              {p.name}
            </button>
          );
        })}
      </div>

      <ScoreGauge score={hormoneScore} phase={phase} />
      <RewardsCard rewards={rewards} phase={phase} />

      {/* Daily meal recommendations from the cycle recipe database (1 per meal) */}
      <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "#AFAFAF" }}>
        {t("todays_recipe_picks")}
      </p>
      <div className="space-y-2.5 mb-6">
        {CYCLE_RECIPE_MEALS.map((meal) => {
          const r = dailyRecipes[meal];
          if (!r) return null;
          const mealIcon = meal === "Frühstück" ? "☕" : meal === "Mittagessen" ? "🍽️" : "🌙";
          return (
            <button
              key={meal}
              onClick={() => setOpenCycleRecipe(r)}
              className="w-full flex items-center gap-3 rounded-2xl p-3.5 text-left"
              style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}
            >
              <div className="w-11 h-11 rounded-full flex items-center justify-center text-lg shrink-0" style={{ background: phase.tint }}>
                {mealIcon}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[10px] uppercase tracking-wide font-semibold" style={{ color: phase.color }}>
                  {t(mealTypeKeyFromDb(meal))}
                </p>
                <p className="text-sm font-semibold truncate" style={{ color: "#121212" }}>
                  {r.titel}
                </p>
              </div>
              <ChevronRight size={16} style={{ color: "#AFAFAF" }} className="shrink-0" />
            </button>
          );
        })}
      </div>

      {openCycleRecipe && <CycleRecipeDetailModal recipe={openCycleRecipe} phase={phase} onClose={() => setOpenCycleRecipe(null)} />}

      {/* Recommended meal card */}
      {recommended && (
        <div className="rounded-2xl overflow-hidden mb-6" style={{ border: "1px solid #E2E2E2" }}>
          <div className="px-5 pt-4 pb-1" style={{ background: "#FFFFFF" }}>
            <p className="text-[11px] uppercase tracking-widest flex items-center gap-1.5" style={{ color: phase.color }}>
              <Sparkles size={12} /> {t("recommended_for")} {phase.name}
            </p>
          </div>
          <div className="p-5 pt-3" style={{ background: "#FFFFFF" }}>
            <div className="flex gap-4">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center shrink-0" style={{ background: `linear-gradient(135deg, ${recommended.color}, ${phase.soft})` }}>
                <Leaf size={24} className="text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-display text-lg leading-tight mb-1" style={{ color: "#121212" }}>
                  {recommended.title || "Rezept"}
                </p>
                <div className="flex gap-3 text-[11px]" style={{ color: "#8A8A8A" }}>
                  <span className="flex items-center gap-1"><Clock size={11} />{recommended.time} Min</span>
                  <span className="flex items-center gap-1"><Flame size={11} />{recommended.kcal} kcal</span>
                  <span className="flex items-center gap-1"><Beef size={11} />{recommended.protein}g</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => goToRecipe(recommended.title)}
              className="w-full mt-4 py-2.5 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5"
              style={{ background: phase.color, color: "#FFFFFF" }}
            >
              {t("to_recipe")} <ArrowRight size={13} />
            </button>
          </div>
        </div>
      )}

      {/* Phase info card */}
      <div className="rounded-2xl p-5 mb-6" style={{ background: phase.tint }}>
        <p className="text-sm leading-relaxed mb-4" style={{ color: "#262626" }}>
          {phase.desc}
        </p>
        <p className="text-xs uppercase tracking-widest mb-2" style={{ color: phase.color }}>
          {t("nutrient_focus")}
        </p>
        <div className="flex gap-2 flex-wrap">
          {phase.focus.map((f) => (
            <span key={f} className="text-xs font-medium px-3 py-1.5 rounded-full" style={{ background: "#FFFFFF", color: phase.color }}>
              {f}
            </span>
          ))}
        </div>
      </div>

      <div className="rounded-2xl p-4 flex items-center gap-3" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
        <Sparkles size={18} style={{ color: phase.color }} className="shrink-0" />
        <p className="text-xs leading-relaxed" style={{ color: "#545454" }}>
          {phase.mealTip}
        </p>
      </div>
    </div>
  );
}

/* -------------------------------- Tracker -------------------------------- */
function ProgressBar({ label, value, goal, color, unit = "g" }) {
  const pct = Math.min(100, Math.round((value / goal) * 100));
  return (
    <div className="mb-3">
      <div className="flex justify-between text-xs mb-1.5">
        <span className="font-medium" style={{ color: "#262626" }}>
          {label}
        </span>
        <span style={{ color: "#8A8A8A" }}>
          {value}{unit} / {goal}{unit}
        </span>
      </div>
      <div className="w-full h-2 rounded-full" style={{ background: "#E2E2E2" }}>
        <div className="h-2 rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

function DateStrip({ selectedDate, setSelectedDate, todayKey, phaseColor }) {
  const { t, lang } = useLang();
  const days = [];
  for (let i = 9; i >= 0; i--) days.push(addDaysToKey(todayKey, -i));

  return (
    <div className="mb-4">
      <div className="flex items-center gap-2 mb-2">
        <CalendarDays size={14} style={{ color: "#8A8A8A" }} />
        <p className="text-xs font-medium" style={{ color: "#545454" }}>
          {t("history_search")}
        </p>
        <input
          type="date"
          max={todayKey}
          value={selectedDate}
          onChange={(e) => e.target.value && setSelectedDate(e.target.value)}
          className="ml-auto text-[11px] px-2 py-1 rounded-lg outline-none bg-[#F5F5F5] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
          style={{ color: "#545454" }}
        />
      </div>
      <div className="flex items-center gap-1.5">
        <button onClick={() => setSelectedDate(addDaysToKey(selectedDate, -1))} className="w-7 h-7 rounded-full flex items-center justify-center shrink-0" style={{ background: "#EFEFEF" }}>
          <ChevronLeft size={14} style={{ color: "#545454" }} />
        </button>
        <div className="flex gap-1.5 overflow-x-auto">
          {days.map((d) => {
            const active = d === selectedDate;
            const isToday = d === todayKey;
            return (
              <button
                key={d}
                onClick={() => setSelectedDate(d)}
                className="flex flex-col items-center justify-center rounded-xl px-2.5 py-1.5 shrink-0 border"
                style={{
                  background: active ? phaseColor : "#FFFFFF",
                  color: active ? "#FFFFFF" : "#545454",
                  borderColor: active ? phaseColor : "#E2E2E2",
                  minWidth: 46,
                }}
              >
                <span className="text-[9px] uppercase">{isToday ? t("today") : formatDateLabel(d, lang).split(" ")[0]}</span>
                <span className="text-xs font-semibold">{formatDateLabel(d, lang).split(" ")[1]}</span>
              </button>
            );
          })}
        </div>
        <button
          onClick={() => {
            const next = addDaysToKey(selectedDate, 1);
            if (next <= todayKey) setSelectedDate(next);
          }}
          disabled={selectedDate >= todayKey}
          className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 disabled:opacity-30"
          style={{ background: "#EFEFEF" }}
        >
          <ChevronRight size={14} style={{ color: "#545454" }} />
        </button>
      </div>
    </div>
  );
}

function useSpeechToText(onResult, lang) {
  const recognitionRef = useRef(null);
  const [isListening, setIsListening] = useState(false);
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    const SR = typeof window !== "undefined" && (window.SpeechRecognition || window.webkitSpeechRecognition);
    if (!SR) {
      setSupported(false);
      return;
    }
    const recognition = new SR();
    recognition.lang = lang === "en" ? "en-US" : "de-DE";
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;
    recognition.onresult = (e) => {
      const transcript = e.results[0][0].transcript;
      onResult(transcript);
    };
    recognition.onend = () => setIsListening(false);
    recognition.onerror = () => setIsListening(false);
    recognitionRef.current = recognition;
    return () => {
      try {
        recognition.stop();
      } catch (err) {
        /* no-op */
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lang]);

  function toggle() {
    if (!recognitionRef.current) return;
    if (isListening) {
      recognitionRef.current.stop();
      setIsListening(false);
    } else {
      setIsListening(true);
      try {
        recognitionRef.current.start();
      } catch (err) {
        setIsListening(false);
      }
    }
  }

  return { toggle, isListening, supported };
}

function TrackerTab({
  phase,
  phaseKey,
  totals,
  goals,
  meals,
  selectedDate,
  setSelectedDate,
  todayKey,
  scannerText,
  setScannerText,
  analyzing,
  imagePreview,
  setImagePreview,
  handleAnalyze,
  logSwap,
  deleteMeal,
  editMeal,
  hormoneScore,
  shortcuts,
  addShortcut,
  removeShortcut,
  logShortcut,
  pendingMealType,
  setPendingMealType,
  quickAddMeal,
  saveMealAsFavoriteRecipe,
  lastAiError,
}) {
  const { t, lang } = useLang();
  const kcalPct = Math.min(100, Math.round((totals.kcal / goals.kcal) * 100));
  const isToday = selectedDate === todayKey;
  const fileInputRef = useRef(null);
  const [shortcutModalOpen, setShortcutModalOpen] = useState(false);
  const [shortcutPicker, setShortcutPicker] = useState(null); // shortcut object pending a meal-type choice
  const [openMealTypePage, setOpenMealTypePage] = useState(null);

  const mealsByType = useMemo(() => {
    const grouped = { breakfast: [], lunch: [], dinner: [], snack: [] };
    meals.forEach((m) => {
      const type = MEAL_TYPE_ORDER.includes(m.mealType) ? m.mealType : "snack";
      grouped[type].push(m);
    });
    return grouped;
  }, [meals]);

  function handleFileChange(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setImagePreview(reader.result);
    reader.readAsDataURL(file);
  }
  function clearImage() {
    setImagePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  const speech = useSpeechToText((transcript) => {
    setScannerText((prev) => (prev.trim() ? `${prev.trim()} ${transcript}` : transcript));
  }, lang);

  function openMealPage(type) {
    setOpenMealTypePage(type);
    setPendingMealType(type);
    setScannerText("");
    setImagePreview(null);
  }
  function closeMealPage() {
    setOpenMealTypePage(null);
    setPendingMealType(null);
  }

  if (openMealTypePage) {
    const type = openMealTypePage;
    const typeMeals = mealsByType[type];
    const typeKcal = typeMeals.reduce((a, m) => a + m.kcal, 0);
    const typeGoal = Math.round(goals.kcal * MEAL_TYPE_SPLIT[type]);

    return (
      <div className="px-5 pt-8">
        <button onClick={closeMealPage} className="flex items-center gap-1.5 mb-5 text-sm font-medium" style={{ color: "#545454" }}>
          <ChevronLeft size={18} /> {t("back")}
        </button>

        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 rounded-full flex items-center justify-center text-2xl shrink-0" style={{ background: "#F5F5F5" }}>
            {MEAL_TYPE_ICON[type]}
          </div>
          <div>
            <h1 className="font-display text-2xl leading-tight" style={{ color: "#121212" }}>
              {t(`meal_${type}`)}
            </h1>
            <p className="text-xs" style={{ color: "#8A8A8A" }}>
              {typeKcal} / {typeGoal} kcal
            </p>
          </div>
        </div>

        {lastAiError && (
          <div className="rounded-2xl p-4 mb-4" style={{ background: "#F6E1E3" }}>
            <p className="text-[11px] font-semibold mb-1" style={{ color: "#8C3B47" }}>
              ⚠️ KI-Fehler (zum Screenshot für Debugging):
            </p>
            <p className="text-[11px] font-mono break-words max-h-40 overflow-y-auto" style={{ color: "#8C3B47" }}>
              {lastAiError}
            </p>
          </div>
        )}

        {/* AI scanner, scoped to this meal */}
        <div className="rounded-2xl p-5 mb-5" style={{ background: phase.tint }}>
          <div className="flex items-center gap-2 mb-3">
            <Sparkles size={16} style={{ color: phase.color }} />
            <p className="text-sm font-semibold" style={{ color: "#121212" }}>
              {t("scanner_title")}
            </p>
          </div>
          <textarea
            autoFocus
            value={scannerText}
            onChange={(e) => setScannerText(sanitizeLiveInput(e.target.value, 300))}
            placeholder={t("scanner_placeholder")}
            rows={2}
            className="w-full rounded-xl px-3 py-2.5 text-sm mb-1 outline-none resize-none bg-white text-[#121212] border border-white focus:border-[#121212] transition-colors"
          />
          {speech.isListening && (
            <p className="text-[11px] mb-2 flex items-center gap-1.5" style={{ color: phase.color }}>
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: phase.color }} /> {t("listening")}
            </p>
          )}
          {!speech.isListening && <div className="mb-2" />}

          {imagePreview && (
            <div className="relative w-20 h-20 mb-3">
              <img src={imagePreview} alt="Foto-Vorschau" className="w-20 h-20 object-cover rounded-xl" style={{ border: "1px solid #E2E2E2" }} />
              <button onClick={clearImage} className="absolute -top-2 -right-2 w-6 h-6 rounded-full flex items-center justify-center" style={{ background: "#8C3B47" }} aria-label="Foto entfernen">
                <X size={12} className="text-white" />
              </button>
            </div>
          )}

          <input ref={fileInputRef} type="file" accept="image/*" capture="environment" className="hidden" onChange={handleFileChange} />

          <div className="flex gap-2">
            {speech.supported && (
              <button
                onClick={speech.toggle}
                className="flex items-center justify-center px-3 py-2.5 rounded-xl border shrink-0"
                style={{
                  background: speech.isListening ? phase.color : "#FFFFFF",
                  borderColor: speech.isListening ? phase.color : "#E2E2E2",
                }}
                aria-label="Per Sprache diktieren"
              >
                {speech.isListening ? <MicOff size={14} color="#FFFFFF" /> : <Mic size={14} color="#545454" />}
              </button>
            )}
            <button
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
              className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-medium border"
              style={{
                background: imagePreview ? phase.color : "#FFFFFF",
                color: imagePreview ? "#FFFFFF" : "#545454",
                borderColor: imagePreview ? phase.color : "#E2E2E2",
              }}
            >
              {imagePreview ? <ImagePlus size={14} /> : <Camera size={14} />}
              {imagePreview ? t("photo_change") : t("photo_take")}
            </button>
            <button
              onClick={handleAnalyze}
              disabled={analyzing || (!scannerText.trim() && !imagePreview)}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-semibold disabled:opacity-50"
              style={{ background: phase.color, color: "#FFFFFF" }}
            >
              {analyzing ? (
                t("analyzing")
              ) : (
                <>
                  <Sparkles size={14} /> {t("analyze_button")}
                </>
              )}
            </button>
          </div>
        </div>

        <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "#AFAFAF" }}>
          {t(`meal_${type}`)}
        </p>
        <div className="space-y-3">
          {typeMeals.length === 0 ? (
            <p className="text-xs text-center py-8" style={{ color: "#8A8A8A" }}>
              {t("no_meals_day")}
            </p>
          ) : (
            typeMeals.map((m) => (
              <MealCard key={m.id} meal={m} phaseKey={phaseKey} phase={phase} logSwap={logSwap} onDelete={deleteMeal} onEdit={editMeal} onSaveAsShortcut={addShortcut} onSaveAsFavoriteRecipe={saveMealAsFavoriteRecipe} />
            ))
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="px-5 pt-8">
      <h1 className="font-display text-2xl mb-1" style={{ color: "#121212" }}>
        {t("tracker_title")}
      </h1>
      <p className="text-[11px] mb-4 flex items-center gap-1.5" style={{ color: "#8A8A8A" }}>
        {isToday ? t("today") : formatDateLabel(selectedDate, lang)} · {phase.name}
        {goals.lutealBonus > 0 && (
          <span className="flex items-center gap-1" style={{ color: phase.color }}>
            <Sparkles size={11} /> +{goals.lutealBonus} {t("calorie_bonus")}
          </span>
        )}
      </p>

      <DateStrip selectedDate={selectedDate} setSelectedDate={setSelectedDate} todayKey={todayKey} phaseColor={phase.color} />

      <ScoreGauge score={hormoneScore} phase={phase} compact />

      {/* Calorie ring + macros */}
      <div className="rounded-2xl p-5 mb-5" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
        <div className="flex items-center justify-center gap-5 mb-5">
          <div className="text-center shrink-0" style={{ width: 64 }}>
            <p className="font-display text-xl leading-none" style={{ color: "#121212" }}>
              {totals.kcal}
            </p>
            <p className="text-[10px] uppercase tracking-wide mt-1" style={{ color: "#8A8A8A" }}>
              {t("eaten_label")}
            </p>
          </div>

          <div className="relative shrink-0" style={{ width: 152, height: 152 }}>
            <div className="w-full h-full rounded-full flex items-center justify-center" style={{ background: `conic-gradient(${phase.color} ${kcalPct * 3.6}deg, #EFEFEF 0deg)` }}>
              <div className="rounded-full flex flex-col items-center justify-center gap-0.5 px-3" style={{ width: 124, height: 124, background: "#FFFFFF", boxShadow: "inset 0 0 0 1px #F0F0F0" }}>
                <span className={`font-display leading-none whitespace-nowrap ${String(Math.max(0, goals.kcal - totals.kcal)).length >= 4 ? "text-2xl" : "text-3xl"}`} style={{ color: "#121212" }}>
                  {Math.max(0, goals.kcal - totals.kcal)}
                </span>
                <span className="text-[10px] font-medium leading-none" style={{ color: "#8A8A8A" }}>
                  kcal
                </span>
                <span className="text-[11px] uppercase tracking-wide leading-none mt-1" style={{ color: "#8A8A8A" }}>
                  {t("remaining_label")}
                </span>
              </div>
            </div>
          </div>

          <div className="text-center shrink-0" style={{ width: 64 }}>
            <p className="font-display text-xl leading-none" style={{ color: "#121212" }}>
              {goals.kcal}
            </p>
            <p className="text-[10px] uppercase tracking-wide mt-1" style={{ color: "#8A8A8A" }}>
              {t("goal_label")}
            </p>
          </div>
        </div>

        <ProgressBar label={t("protein")} value={totals.protein} goal={goals.protein} color="#B85C4A" />
        <ProgressBar label={t("carbs")} value={totals.carbs} goal={goals.carbs} color="#C6952E" />
        <ProgressBar label={t("fat")} value={totals.fat} goal={goals.fat} color="#6E8F6B" />
      </div>

      {/* Shortcuts for frequently eaten meals (e.g. the usual breakfast) */}
      <div className="mb-5">
        <p className="text-xs uppercase tracking-widest mb-2" style={{ color: "#AFAFAF" }}>
          {t("your_shortcuts")}
        </p>
        <div className="rounded-2xl overflow-hidden" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
          {shortcuts.length === 0 && (
            <p className="text-xs px-4 py-4" style={{ color: "#8A8A8A" }}>
              {t("no_shortcuts_yet")}
            </p>
          )}
          {shortcuts.map((s, i) => (
            <div key={s.id} className="flex items-center gap-3 p-3.5" style={{ borderTop: i === 0 ? "none" : "1px solid #EFEFEF" }}>
              <button onClick={() => setShortcutPicker(s)} className="flex items-center gap-3 flex-1 min-w-0 text-left">
                <div className="w-10 h-10 rounded-full flex items-center justify-center shrink-0" style={{ background: phase.tint }}>
                  <Zap size={16} style={{ color: phase.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold truncate" style={{ color: "#121212" }}>
                    {s.label}
                  </p>
                  <p className="text-[11px]" style={{ color: "#8A8A8A" }}>
                    {s.kcal} kcal · {s.protein}g P · {s.carbs}g C · {s.fat}g F
                  </p>
                </div>
              </button>
              <button onClick={() => removeShortcut(s.id)} className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: "#F5F5F5" }} aria-label="Remove shortcut">
                <Trash2 size={13} style={{ color: "#AFAFAF" }} />
              </button>
            </div>
          ))}
          <button
            onClick={() => setShortcutModalOpen(true)}
            className="w-full flex items-center gap-3 p-3.5 text-left"
            style={{ borderTop: shortcuts.length > 0 ? "1px solid #EFEFEF" : "none" }}
          >
            <div className="w-10 h-10 rounded-full flex items-center justify-center shrink-0" style={{ background: "#F5F5F5" }}>
              <Plus size={16} style={{ color: "#545454" }} />
            </div>
            <p className="text-sm font-semibold" style={{ color: "#545454" }}>
              {t("new_shortcut")}
            </p>
          </button>
        </div>
      </div>

      {shortcutModalOpen && (
        <ShortcutModal
          phase={phase}
          onClose={() => setShortcutModalOpen(false)}
          onSave={(s) => {
            try {
              addShortcut(s);
            } catch (err) {
              console.error("Failed to save shortcut:", err);
            } finally {
              setShortcutModalOpen(false);
            }
          }}
        />
      )}

      {shortcutPicker && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.5)" }} onClick={() => setShortcutPicker(null)}>
          <div className="w-full max-w-md rounded-t-3xl sm:rounded-3xl p-6" style={{ background: "#FFFFFF" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-1">
              <h2 className="font-display text-lg" style={{ color: "#121212" }}>
                {shortcutPicker.label}
              </h2>
              <button onClick={() => setShortcutPicker(null)} className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: "#EFEFEF" }}>
                <X size={16} style={{ color: "#545454" }} />
              </button>
            </div>
            <p className="text-xs mb-5" style={{ color: "#8A8A8A" }}>
              {t("choose_meal_type")}
            </p>
            <div className="grid grid-cols-2 gap-3">
              {MEAL_TYPE_ORDER.map((type) => (
                <button
                  key={type}
                  onClick={() => {
                    logShortcut(shortcutPicker, type);
                    setShortcutPicker(null);
                  }}
                  className="flex items-center gap-2.5 py-3.5 px-4 rounded-xl border"
                  style={{ background: "#FFFFFF", borderColor: "#E2E2E2" }}
                >
                  <span className="text-xl">{MEAL_TYPE_ICON[type]}</span>
                  <span className="text-sm font-semibold" style={{ color: "#121212" }}>
                    {t(`meal_${type}`)}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Logged meals, grouped by time of day like a real food diary */}
      <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "#AFAFAF" }}>
        {isToday ? t("logged_today") : `${t("logged_on")} ${formatDateLabel(selectedDate, lang)}`}
      </p>
      <div className="rounded-2xl overflow-hidden mb-5" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
        {MEAL_TYPE_ORDER.map((type, idx) => {
          const typeMeals = mealsByType[type];
          const typeKcal = typeMeals.reduce((a, m) => a + m.kcal, 0);
          const typeGoal = Math.round(goals.kcal * MEAL_TYPE_SPLIT[type]);
          return (
            <button
              key={type}
              onClick={() => openMealPage(type)}
              className="w-full flex items-center gap-3 p-4 text-left"
              style={{ borderTop: idx === 0 ? "none" : "1px solid #EFEFEF" }}
            >
              <div className="w-11 h-11 rounded-full flex items-center justify-center text-lg shrink-0" style={{ background: "#F5F5F5" }}>
                {MEAL_TYPE_ICON[type]}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold" style={{ color: "#121212" }}>
                  {t(`meal_${type}`)}
                </p>
                <p className="text-xs" style={{ color: "#8A8A8A" }}>
                  {typeKcal} / {typeGoal} kcal{typeMeals.length > 0 ? ` · ${typeMeals.length}` : ""}
                </p>
              </div>
              <div className="w-9 h-9 rounded-full flex items-center justify-center shrink-0" style={{ background: "#121212" }} aria-label={t("add_meal_aria")}>
                <Plus size={16} className="text-white" />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function MealCard({ meal, phaseKey, phase, logSwap, onDelete, onEdit, onSaveAsShortcut, onSaveAsFavoriteRecipe }) {
  const { t, lang } = useLang();
  const [showEdit, setShowEdit] = useState(false);
  const [shortcutSaved, setShortcutSaved] = useState(false);
  const [favoriteSaved, setFavoriteSaved] = useState(false);
  const good = meal.match >= 70;
  const warn = meal.isJunk;

  function handleSaveShortcut() {
    onSaveAsShortcut({ label: meal.name, kcal: meal.kcal, protein: meal.protein, carbs: meal.carbs, fat: meal.fat, ingredients: meal.ingredients });
    setShortcutSaved(true);
    setTimeout(() => setShortcutSaved(false), 1500);
  }

  function handleSaveAsFavorite() {
    onSaveAsFavoriteRecipe(meal);
    setFavoriteSaved(true);
    setTimeout(() => setFavoriteSaved(false), 1500);
  }

  return (
    <div className="rounded-2xl p-4" style={{ background: "#FFFFFF", border: warn ? "1px solid #E8B4A0" : "1px solid #E2E2E2" }}>
      <div className="flex justify-between items-start mb-2">
        <div className="pr-3">
          <p className="text-sm font-semibold" style={{ color: "#121212" }}>
            {meal.name}
          </p>
          <p className="text-[11px] flex items-center gap-1" style={{ color: "#8A8A8A" }}>
            {meal.time} · {meal.kcal} kcal
            {meal.aiAnalyzed && <Sparkles size={10} style={{ color: "#8A8A8A" }} />}
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <div
            className="px-2.5 py-1 rounded-full text-[11px] font-bold flex items-center gap-1"
            style={{ background: warn ? "#FBE3D6" : good ? "#E4EEDF" : "#F6E1E3", color: warn ? "#B25A2A" : good ? "#5C7A4E" : "#8C3B47" }}
          >
            {warn && <AlertTriangle size={11} />}
            {meal.match}% {t("match")}
          </div>
          <button
            onClick={handleSaveAsFavorite}
            className="w-7 h-7 rounded-full flex items-center justify-center"
            style={{ background: favoriteSaved ? "#F6E1E3" : "#EFEFEF" }}
            aria-label={t("save_as_favorite_recipe")}
          >
            {favoriteSaved ? <Check size={12} style={{ color: "#8C3B47" }} /> : <Heart size={12} style={{ color: "#545454" }} />}
          </button>
          <button
            onClick={handleSaveShortcut}
            className="w-7 h-7 rounded-full flex items-center justify-center"
            style={{ background: shortcutSaved ? "#E4EEDF" : "#EFEFEF" }}
            aria-label={t("save_as_shortcut")}
          >
            {shortcutSaved ? <Check size={12} style={{ color: "#5C7A4E" }} /> : <Zap size={12} style={{ color: "#545454" }} />}
          </button>
          <button onClick={() => setShowEdit(true)} className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: "#EFEFEF" }} aria-label={t("edit_meal")}>
            <Pencil size={12} style={{ color: "#545454" }} />
          </button>
          <button onClick={() => onDelete(meal.id)} className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: "#F6E1E3" }} aria-label={t("delete_meal")}>
            <Trash2 size={12} style={{ color: "#8C3B47" }} />
          </button>
        </div>
      </div>

      <div className="flex gap-3 text-[11px] mb-2 flex-wrap" style={{ color: "#8A8A8A" }}>
        <span className="flex items-center gap-1"><Beef size={11} />{meal.protein}g</span>
        <span className="flex items-center gap-1"><Wheat size={11} />{meal.carbs}g</span>
        <span className="flex items-center gap-1"><Nut size={11} />{meal.fat}g</span>
        {meal.ingredients && meal.ingredients.length > 1 && (
          <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold" style={{ background: "#F5F5F5", color: "#545454" }}>
            {meal.ingredients.length} {t("ingredients_label")}
          </span>
        )}
      </div>
      <p className="text-[11px] leading-relaxed" style={{ color: "#545454" }}>
        {meal.matchReasonText || matchReason(meal.match, phaseKey, warn, lang)}
      </p>

      {meal.adjustments && meal.adjustments.length > 0 && (
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {meal.adjustments.map((a) => (
            <span key={a.id} className="text-[10px] px-2 py-1 rounded-full" style={{ background: "#EFEFEF", color: "#545454" }}>
              {a.type === "add" ? "+ " : "− "}
              {a.text}
            </span>
          ))}
        </div>
      )}

      {meal.dietWarning && (
        <div className="mt-3 pt-3 flex items-start gap-2" style={{ borderTop: "1px dashed #E2E2E2" }}>
          <AlertTriangle size={13} className="mt-0.5 shrink-0" style={{ color: "#B25A2A" }} />
          <p className="text-[11px] leading-relaxed" style={{ color: "#B25A2A" }}>
            {meal.dietWarning}
          </p>
        </div>
      )}

      {meal.swap && (
        <div className="mt-3 pt-3 rounded-xl" style={{ borderTop: "1px dashed #E2E2E2" }}>
          <div className="flex items-start gap-2 mb-2">
            <Sparkles size={13} className="mt-0.5 shrink-0" style={{ color: "#5C7A4E" }} />
            <div>
              <p className="text-xs font-semibold" style={{ color: "#121212" }}>
                {t("cravings_swap")}: {meal.swap.name}
              </p>
              <p className="text-[11px] leading-relaxed mt-0.5" style={{ color: "#545454" }}>
                {meal.swap.why}
              </p>
            </div>
          </div>
          <button onClick={() => logSwap(meal.swap)} className="w-full py-2 rounded-lg text-[11px] font-semibold flex items-center justify-center gap-1" style={{ background: "#E4EEDF", color: "#5C7A4E" }}>
            <Check size={12} /> {t("log_swap_instead")} ({meal.swap.match}% {t("match")})
          </button>
        </div>
      )}

      {showEdit && (
        <EditMealModal
          meal={meal}
          phase={phase}
          onClose={() => setShowEdit(false)}
          onSave={(changes) => {
            onEdit(meal.id, changes);
            setShowEdit(false);
          }}
        />
      )}
    </div>
  );
}

// Used by "Zutat hinzufügen" - prefers a real per-gram FOOD_DB match (so amount stays
// meaningfully editable in grams) and only falls back to a flat "1 Portion" estimate
// for things not in the database (e.g. "extra Sauce").
function estimateNewIngredientRow(text) {
  const lower = text.toLowerCase();
  const food = FOOD_DB.find((f) => f.keys.some((k) => hasWholeWordMatch(lower, k)));
  if (food) {
    const hitKey = food.keys.find((k) => hasWholeWordMatch(lower, k));
    const grams = resolveGrams(food, parseQuantityNear(lower, hitKey));
    const scale = grams / 100;
    return {
      unit: "g",
      amount: Math.round(grams),
      perUnitKcal: food.kcal / 100,
      perUnitProtein: food.protein / 100,
      perUnitCarbs: food.carbs / 100,
      perUnitFat: food.fat / 100,
    };
  }
  const delta = estimateAdjustmentDelta(text);
  return { unit: "Portion", amount: 1, perUnitKcal: delta.kcal, perUnitProtein: delta.protein, perUnitCarbs: delta.carbs, perUnitFat: delta.fat };
}

function EditMealModal({ meal, phase, onClose, onSave }) {
  const { t } = useLang();
  const [ingredients, setIngredients] = useState(() => {
    const list =
      meal.ingredients && meal.ingredients.length > 0
        ? meal.ingredients
        : [{ id: secureId("ing"), name: meal.name, amount: 1, unit: "Portion", kcal: meal.kcal, protein: meal.protein, carbs: meal.carbs, fat: meal.fat }];
    return list.map((ing) => {
      const amt = ing.amount > 0 ? ing.amount : 1;
      return {
        id: ing.id || secureId("ing"),
        name: ing.name,
        unit: ing.unit || "g",
        amount: amt,
        perUnitKcal: (ing.kcal || 0) / amt,
        perUnitProtein: (ing.protein || 0) / amt,
        perUnitCarbs: (ing.carbs || 0) / amt,
        perUnitFat: (ing.fat || 0) / amt,
      };
    });
  });
  const [addText, setAddText] = useState("");

  const rows = useMemo(
    () =>
      ingredients.map((ing) => ({
        ...ing,
        kcal: Math.round(ing.perUnitKcal * ing.amount),
        protein: Math.round(ing.perUnitProtein * ing.amount * 10) / 10,
        carbs: Math.round(ing.perUnitCarbs * ing.amount * 10) / 10,
        fat: Math.round(ing.perUnitFat * ing.amount * 10) / 10,
      })),
    [ingredients]
  );

  const working = useMemo(
    () =>
      rows.reduce(
        (acc, r) => ({ kcal: acc.kcal + r.kcal, protein: acc.protein + r.protein, carbs: acc.carbs + r.carbs, fat: acc.fat + r.fat }),
        { kcal: 0, protein: 0, carbs: 0, fat: 0 }
      ),
    [rows]
  );

  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  function setAmount(id, newAmount) {
    setIngredients((prev) => prev.map((ing) => (ing.id === id ? { ...ing, amount: Math.max(0, newAmount) } : ing)));
  }
  function removeIngredient(id) {
    setIngredients((prev) => prev.filter((ing) => ing.id !== id));
  }
  function handleAddIngredient() {
    const clean = sanitizeText(addText, 60);
    if (!clean) return;
    const row = estimateNewIngredientRow(clean);
    setIngredients((prev) => [...prev, { id: secureId("ing"), name: clean, ...row }]);
    setAddText("");
  }
  function handleSave() {
    onSave({
      kcal: Math.max(0, Math.round(working.kcal)),
      protein: Math.max(0, Math.round(working.protein)),
      carbs: Math.max(0, Math.round(working.carbs)),
      fat: Math.max(0, Math.round(working.fat)),
      ingredients: rows.map(({ id, name, unit, amount, kcal, protein, carbs, fat }) => ({ id, name, unit, amount, kcal, protein, carbs, fat })),
      adjustments: [],
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.5)" }} onClick={onClose}>
      <div className="w-full max-w-md rounded-t-3xl sm:rounded-3xl p-6" style={{ background: "#FFFFFF", maxHeight: "min(90vh, 90dvh)", overflowY: "auto", WebkitOverflowScrolling: "touch", overscrollBehavior: "contain" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display text-lg leading-tight pr-3" style={{ color: "#121212" }}>
            {meal.name}
          </h2>
          <button onClick={onClose} className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: "#EFEFEF" }}>
            <X size={16} style={{ color: "#545454" }} />
          </button>
        </div>

        <div className="rounded-2xl p-4 mb-5 grid grid-cols-4 gap-2 text-center" style={{ background: phase.tint }}>
          <div>
            <p className="font-display text-lg" style={{ color: "#121212" }}>
              {working.kcal}
            </p>
            <p className="text-[9px] uppercase" style={{ color: "#545454" }}>
              kcal
            </p>
          </div>
          <div>
            <p className="font-display text-lg" style={{ color: "#121212" }}>
              {Math.round(working.protein)}g
            </p>
            <p className="text-[9px] uppercase" style={{ color: "#545454" }}>
              {t("protein")}
            </p>
          </div>
          <div>
            <p className="font-display text-lg" style={{ color: "#121212" }}>
              {Math.round(working.carbs)}g
            </p>
            <p className="text-[9px] uppercase" style={{ color: "#545454" }}>
              {t("carbs")}
            </p>
          </div>
          <div>
            <p className="font-display text-lg" style={{ color: "#121212" }}>
              {Math.round(working.fat)}g
            </p>
            <p className="text-[9px] uppercase" style={{ color: "#545454" }}>
              {t("fat")}
            </p>
          </div>
        </div>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("ingredients_label")}
        </label>
        <div className="space-y-2 mb-4">
          {rows.length === 0 && (
            <p className="text-xs" style={{ color: "#8A8A8A" }}>
              {t("no_ingredients_hint")}
            </p>
          )}
          {rows.map((r) => (
            <div key={r.id} className="flex items-center gap-2 p-2.5 rounded-lg" style={{ background: "#F5F5F5" }}>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold truncate" style={{ color: "#121212" }}>
                  {r.name}
                </p>
                <p className="text-[10px]" style={{ color: "#8A8A8A" }}>
                  {r.kcal} kcal
                </p>
              </div>
              <input
                type="text"
                inputMode="numeric"
                value={r.amount}
                onChange={(e) => {
                  const digits = e.target.value.replace(/[^0-9]/g, "");
                  setAmount(r.id, digits === "" ? 0 : Number(digits));
                }}
                className="w-14 px-2 py-1.5 rounded-lg text-xs text-center outline-none bg-white border border-white focus:border-[#121212] transition-colors"
              />
              <span className="text-[10px] shrink-0 w-8" style={{ color: "#8A8A8A" }}>
                {r.unit}
              </span>
              <button onClick={() => removeIngredient(r.id)} className="w-7 h-7 rounded-full flex items-center justify-center shrink-0" style={{ background: "#F6E1E3" }} aria-label={t("delete")}>
                <X size={12} style={{ color: "#8C3B47" }} />
              </button>
            </div>
          ))}
        </div>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("add_ingredient")}
        </label>
        <div className="flex gap-2 mb-5">
          <input
            value={addText}
            onChange={(e) => setAddText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAddIngredient()}
            placeholder={t("add_extra_placeholder")}
            className="flex-1 px-3 py-2 rounded-lg text-sm outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
          />
          <button
            onClick={handleAddIngredient}
            className="px-4 py-2 rounded-lg text-xs font-semibold shrink-0 flex items-center gap-1.5"
            style={{ background: "#5C7A4E", color: "#FFFFFF" }}
          >
            <Plus size={14} /> {t("add")}
          </button>
        </div>

        <div className="flex gap-2">
          <button onClick={onClose} className="flex-1 py-3 rounded-xl text-sm font-semibold" style={{ background: "#EFEFEF", color: "#545454" }}>
            {t("cancel")}
          </button>
          <button onClick={handleSave} className="flex-1 py-3 rounded-xl text-sm font-semibold" style={{ background: phase.color, color: "#FFFFFF" }}>
            {t("save")}
          </button>
        </div>
      </div>
    </div>
  );
}

function ShortcutModal({ phase, onClose, onSave }) {
  const { t } = useLang();
  const [label, setLabel] = useState("");
  const [macros, setMacros] = useState({ kcal: 400, protein: 15, carbs: 40, fat: 15 });

  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  function setMacro(key) {
    return (e) => {
      const digits = e.target.value.replace(/[^0-9]/g, "");
      setMacros((m) => ({ ...m, [key]: digits === "" ? 0 : Number(digits) }));
    };
  }

  function handleSave() {
    if (!label.trim()) return;
    onSave({ label: label.trim(), kcal: macros.kcal, protein: macros.protein, carbs: macros.carbs, fat: macros.fat });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.5)" }} onClick={onClose}>
      <div className="w-full max-w-md rounded-t-3xl sm:rounded-3xl p-6" style={{ background: "#FFFFFF", maxHeight: "min(90vh, 90dvh)", overflowY: "auto", WebkitOverflowScrolling: "touch", overscrollBehavior: "contain" }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display text-lg" style={{ color: "#121212" }}>
            {t("new_shortcut")}
          </h2>
          <button onClick={onClose} className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: "#EFEFEF" }}>
            <X size={16} style={{ color: "#545454" }} />
          </button>
        </div>
        <p className="text-[11px] mb-4" style={{ color: "#8A8A8A" }}>
          {t("shortcut_hint")}
        </p>

        <label className="text-xs font-medium block mb-1.5" style={{ color: "#545454" }}>
          {t("shortcut_name_label")}
        </label>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder={t("shortcut_name_placeholder")}
          className="w-full mb-4 px-3 py-2.5 rounded-lg text-sm outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
        />

        <div className="grid grid-cols-4 gap-2 mb-5">
          {["kcal", "protein", "carbs", "fat"].map((k) => (
            <div key={k}>
              <label className="text-[9px] uppercase block mb-1" style={{ color: "#8A8A8A" }}>
                {k === "kcal" ? "kcal" : t(k)}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={macros[k]}
                onChange={setMacro(k)}
                className="w-full px-2 py-2 rounded-lg text-sm font-semibold text-center outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
              />
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          <button onClick={onClose} className="flex-1 py-3 rounded-xl text-sm font-semibold" style={{ background: "#EFEFEF", color: "#545454" }}>
            {t("cancel")}
          </button>
          <button onClick={handleSave} disabled={!label.trim()} className="flex-1 py-3 rounded-xl text-sm font-semibold disabled:opacity-50" style={{ background: phase.color, color: "#FFFFFF" }}>
            {t("save")}
          </button>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------- Recipes -------------------------------- */
function RecipesTab({ phase, phaseKey, initialQuery, recipes, addRecipe, clearAllRecipes, diets, addRecipeToShoppingList, favoriteIds, toggleFavorite, addShortcut }) {
  const { t, lang } = useLang();
  const [query, setQuery] = useState(initialQuery || "");
  const [filter, setFilter] = useState("Alle");
  const [generating, setGenerating] = useState(false);
  const [openRecipeId, setOpenRecipeId] = useState(null);
  const [pantryText, setPantryText] = useState("");
  const [pantryGenerating, setPantryGenerating] = useState(false);
  const [pantrySuggestions, setPantrySuggestions] = useState([]);

  const [savedOnly, setSavedOnly] = useState(false);
  const [categoryFilters, setCategoryFilters] = useState([]); // array of { key, type, value, min, max }

  function toggleCategoryFilter(next) {
    setCategoryFilters((prev) => (prev.some((f) => f.key === next.key) ? prev.filter((f) => f.key !== next.key) : [...prev, next]));
  }
  function isCategoryActive(key) {
    return categoryFilters.some((f) => f.key === key);
  }

  const searching = query.trim().length > 0;
  const dietFiltered = recipes.filter((r) => isDietCompatible(r, diets));
  const base = savedOnly ? dietFiltered.filter((r) => favoriteIds.includes(r.id)) : searching || categoryFilters.length > 0 ? dietFiltered : dietFiltered.filter((r) => r.phase === phaseKey);

  const availableTags = useMemo(() => {
    const tags = new Set();
    base.forEach((r) => r.tags.forEach((t) => tags.add(t)));
    return ["Alle", ...Array.from(tags)];
  }, [base]);

  let filtered = base.filter((r) => (r.title || "").toLowerCase().includes(query.toLowerCase())).filter((r) => filter === "Alle" || r.tags.includes(filter));
  categoryFilters.forEach((cf) => {
    if (cf.type === "tag") filtered = filtered.filter((r) => r.tags.includes(cf.value));
    if (cf.type === "cuisine") filtered = filtered.filter((r) => r.cuisine === cf.value);
    if (cf.type === "diet") filtered = filtered.filter((r) => isDietCompatible(r, [cf.value]));
    if (cf.type === "kcal") filtered = filtered.filter((r) => r.kcal >= cf.min && r.kcal <= cf.max);
  });
  const openRecipe = recipes.find((r) => r.id === openRecipeId);

  const pantryItems = pantryText
    .split(/,|\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  const pantryMatches = useMemo(() => {
    if (pantryItems.length === 0) return [];
    const lowerItems = pantryItems.map((i) => i.toLowerCase());
    return recipes
      .filter((r) => isDietCompatible(r, diets))
      .map((r) => {
        const matchCount = lowerItems.filter((item) => r.ingredients.some((ing) => ing.toLowerCase().includes(item)) || (r.title || "").toLowerCase().includes(item)).length;
        return { recipe: r, matchCount };
      })
      .filter((x) => x.matchCount > 0)
      .sort((a, b) => b.matchCount - a.matchCount)
      .slice(0, 5);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pantryText, recipes, diets]);

  function handleGenerate() {
    setGenerating(true);
    setTimeout(() => {
      const newRecipe = generateAIRecipe(phaseKey, diets);
      addRecipe(newRecipe);
      setGenerating(false);
      setOpenRecipeId(newRecipe.id);
    }, 900);
  }

  function handlePantryGenerate() {
    if (!pantryText.trim()) return;
    setPantryGenerating(true);
    setTimeout(() => {
      const newRecipes = generatePantryRecipes(phaseKey, diets, pantryText, 3);
      newRecipes.forEach((r) => addRecipe(r));
      setPantrySuggestions(newRecipes);
      setPantryGenerating(false);
    }, 900);
  }

  return (
    <div className="px-5 pt-8">
      <div className="flex items-start justify-between gap-2 mb-1">
        <h1 className="font-display text-2xl" style={{ color: "#121212" }}>
          {t("recipes_title")}
        </h1>
        {recipes.length > 0 && (
          <button onClick={clearAllRecipes} className="shrink-0 text-[11px] font-semibold px-2.5 py-1.5 rounded-lg" style={{ background: "#F6E1E3", color: "#8C3B47" }}>
            {t("clear_all_recipes")}
          </button>
        )}
      </div>
      <p className="text-xs mb-1" style={{ color: "#8A8A8A" }}>
        {searching ? t("search_results_all_phases") : `${t("curated_for")} ${phase.name} (${base.length} ${t("recipes_count")})`}
      </p>
      <p className="text-[11px] mb-4" style={{ color: phase.color }}>
        {t("filtered_by")}: {diets.length > 0 ? diets.map((d) => dietLabel(d, lang)).join(" + ") : t("filter_all")}
      </p>

      <div className="flex gap-2 mb-5 p-1 rounded-full" style={{ background: "#EFEFEF" }}>
        <button
          onClick={() => {
            setSavedOnly(false);
            setCategoryFilters([]);
          }}
          className="flex-1 py-2 rounded-full text-xs font-semibold transition-colors"
          style={{ background: !savedOnly ? phase.color : "transparent", color: !savedOnly ? "#FFFFFF" : "#545454" }}
        >
          {t("discover_tab")}
        </button>
        <button
          onClick={() => {
            setSavedOnly(true);
            setCategoryFilters([]);
          }}
          className="flex-1 py-2 rounded-full text-xs font-semibold transition-colors flex items-center justify-center gap-1"
          style={{ background: savedOnly ? phase.color : "transparent", color: savedOnly ? "#FFFFFF" : "#545454" }}
        >
          {t("my_favorites_tab")} {favoriteIds.length > 0 && `(${favoriteIds.length})`}
        </button>
      </div>

      {!savedOnly && !searching && (
        <>
          <p className="text-sm font-semibold mb-3" style={{ color: "#121212" }}>
            {t("popular_categories")}
          </p>
          <div className="flex gap-3 mb-6 overflow-x-auto pb-1">
            {POPULAR_CATEGORY_CHIPS.map((c) => {
              const key = `tag:${c.value}`;
              const active = isCategoryActive(key);
              return (
                <button
                  key={c.value}
                  onClick={() => toggleCategoryFilter({ key, type: "tag", value: c.value })}
                  className="flex flex-col items-center gap-1.5 shrink-0"
                  style={{ width: 68 }}
                >
                  <div className="w-14 h-14 rounded-full flex items-center justify-center text-2xl" style={{ background: active ? phase.color : "#F5F5F5", border: active ? "none" : "1px solid #E2E2E2" }}>
                    {c.emoji}
                  </div>
                  <span className="text-[10px] font-medium text-center leading-tight" style={{ color: active ? phase.color : "#545454" }}>
                    {tagLabel(c.value, lang)}
                  </span>
                </button>
              );
            })}
          </div>

          <p className="text-sm font-semibold mb-3" style={{ color: "#121212" }}>
            {t("recipes_by_kcal")}
          </p>
          <div className="grid grid-cols-3 gap-2 mb-6">
            {KCAL_RANGE_CHIPS.map((r) => {
              const key = `kcal:${r.min}`;
              const active = isCategoryActive(key);
              return (
                <button
                  key={r.min}
                  onClick={() => toggleCategoryFilter({ key, type: "kcal", min: r.min, max: r.max })}
                  className="rounded-xl py-3 flex flex-col items-center gap-1"
                  style={{ background: active ? phase.color : "#F5F5F5", border: active ? "none" : "1px solid #E2E2E2" }}
                >
                  <span className="text-lg">{r.emoji}</span>
                  <span className="text-[10px] font-semibold" style={{ color: active ? "#FFFFFF" : "#121212" }}>
                    {r.min}-{r.max}
                  </span>
                  <span className="text-[9px]" style={{ color: active ? "#FFFFFF" : "#8A8A8A" }}>
                    kcal
                  </span>
                </button>
              );
            })}
          </div>

          <p className="text-sm font-semibold mb-3" style={{ color: "#121212" }}>
            {t("by_cuisine")}
          </p>
          <div className="flex gap-2 mb-6 overflow-x-auto pb-1">
            {CUISINE_CHIPS.map((cu) => {
              const key = `cuisine:${cu.value}`;
              const active = isCategoryActive(key);
              return (
                <button
                  key={cu.value}
                  onClick={() => toggleCategoryFilter({ key, type: "cuisine", value: cu.value })}
                  className="shrink-0 rounded-2xl px-4 py-3 flex items-center gap-2"
                  style={{ background: active ? phase.color : "#F5F5F5", border: active ? "none" : "1px solid #E2E2E2" }}
                >
                  <span className="text-lg">{cu.emoji}</span>
                  <span className="text-xs font-medium whitespace-nowrap" style={{ color: active ? "#FFFFFF" : "#121212" }}>
                    {tagLabel(cu.value, lang)}
                  </span>
                </button>
              );
            })}
          </div>

          <p className="text-sm font-semibold mb-3" style={{ color: "#121212" }}>
            {t("by_diet")}
          </p>
          <div className="flex gap-3 mb-6 overflow-x-auto pb-1">
            {DIET_ORDER.map((d) => {
              const key = `diet:${d}`;
              const active = isCategoryActive(key);
              return (
                <button
                  key={d}
                  onClick={() => toggleCategoryFilter({ key, type: "diet", value: d })}
                  className="flex flex-col items-center gap-1.5 shrink-0"
                  style={{ width: 68 }}
                >
                  <div className="w-14 h-14 rounded-full flex items-center justify-center text-2xl" style={{ background: active ? phase.color : "#F5F5F5", border: active ? "none" : "1px solid #E2E2E2" }}>
                    {DIET_EMOJI[d]}
                  </div>
                  <span className="text-[10px] font-medium text-center leading-tight" style={{ color: active ? phase.color : "#545454" }}>
                    {dietLabel(d, lang)}
                  </span>
                </button>
              );
            })}
          </div>
        </>
      )}

      {categoryFilters.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {categoryFilters.map((cf) => (
            <button
              key={cf.key}
              onClick={() => toggleCategoryFilter(cf)}
              className="flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1.5 rounded-full text-white"
              style={{ background: phase.color }}
            >
              {cf.type === "kcal" ? `${cf.min}-${cf.max} kcal` : cf.type === "diet" ? dietLabel(cf.value, lang) : tagLabel(cf.value, lang)} <X size={11} />
            </button>
          ))}
          <button onClick={() => setCategoryFilters([])} className="text-[11px] font-semibold px-3 py-1.5 rounded-full" style={{ background: "#EFEFEF", color: "#545454" }}>
            {t("category_filter_active")}
          </button>
        </div>
      )}

      {/* Pantry mode */}
      {!savedOnly && (
      <div className="rounded-2xl p-5 mb-5" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
        <div className="flex items-center gap-2 mb-3">
          <Refrigerator size={16} style={{ color: phase.color }} />
          <p className="text-sm font-semibold" style={{ color: "#121212" }}>
            {t("pantry_title")}
          </p>
        </div>
        <textarea
          value={pantryText}
          onChange={(e) => setPantryText(sanitizeLiveInput(e.target.value, 300))}
          placeholder={t("pantry_placeholder")}
          rows={2}
          className="w-full rounded-xl px-3 py-2.5 text-sm mb-3 outline-none resize-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
        />

        {pantryMatches.length > 0 && (
          <div className="mb-3 space-y-2">
            <p className="text-[11px] uppercase tracking-widest" style={{ color: phase.color }}>
              {t("library_matches")}
            </p>
            {pantryMatches.map(({ recipe: r, matchCount }) => (
              <button
                key={r.id}
                onClick={() => setOpenRecipeId(r.id)}
                className="w-full flex items-center gap-3 rounded-xl p-2.5 text-left"
                style={{ background: "#FAFAFA", border: "1px solid #E2E2E2" }}
              >
                <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: `linear-gradient(135deg, ${r.color}, ${PHASES[r.phase].tint})` }}>
                  <ChefHat size={16} className="text-white" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold truncate" style={{ color: "#121212" }}>
                    {r.title}
                  </p>
                  <p className="text-[10px]" style={{ color: "#8A8A8A" }}>
                    {matchCount} {t("ingredients_present")} {pantryItems.length} {t("ingredients_available")}
                  </p>
                </div>
                <ChevronRight size={14} style={{ color: "#AFAFAF" }} className="shrink-0" />
              </button>
            ))}
          </div>
        )}

        <button
          onClick={handlePantryGenerate}
          disabled={pantryGenerating || !pantryText.trim()}
          className="w-full py-2.5 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50"
          style={{ background: phase.color, color: "#FFFFFF" }}
        >
          {pantryGenerating ? t("pantry_generating") : <><ChefHat size={14} /> {t("pantry_generate_cta")}</>}
        </button>

        {pantrySuggestions.length > 0 && (
          <div className="mt-3 space-y-2">
            <p className="text-[11px] uppercase tracking-widest" style={{ color: phase.color }}>
              {t("newly_generated")}
            </p>
            {pantrySuggestions.map((r) => (
              <button
                key={r.id}
                onClick={() => setOpenRecipeId(r.id)}
                className="w-full flex items-center gap-3 rounded-xl p-2.5 text-left"
                style={{ background: "#FAFAFA", border: "1px solid #E2E2E2" }}
              >
                <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: `linear-gradient(135deg, ${r.color}, ${PHASES[r.phase].tint})` }}>
                  <Wand2 size={16} className="text-white" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold truncate" style={{ color: "#121212" }}>
                    {r.title}
                  </p>
                  <p className="text-[10px]" style={{ color: "#8A8A8A" }}>
                    {r.time} {t("min")} · {r.kcal} kcal
                  </p>
                </div>
                <ChevronRight size={14} style={{ color: "#AFAFAF" }} className="shrink-0" />
              </button>
            ))}
          </div>
        )}
      </div>
      )}

      <div className="relative mb-3">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "#AFAFAF" }} />
        <input
          value={query}
          onChange={(e) => setQuery(sanitizeLiveInput(e.target.value, 80))}
          placeholder={t("search_recipes")}
          className="w-full pl-9 pr-3 py-2.5 rounded-xl text-sm outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
        />
      </div>

      <div className="flex gap-2 mb-4 overflow-x-auto">
        {availableTags.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className="px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap border"
            style={{ background: filter === f ? phase.color : "#FFFFFF", color: filter === f ? "#FFFFFF" : "#545454", borderColor: filter === f ? phase.color : "#E2E2E2" }}
          >
            {f === "Alle" ? t("filter_all") : tagLabel(f, lang)}
          </button>
        ))}
      </div>

      {!savedOnly && (
      <button
        onClick={handleGenerate}
        disabled={generating}
        className="w-full mb-5 py-3 px-4 rounded-2xl text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-60"
        style={{ background: `linear-gradient(135deg, ${phase.color}, ${phase.soft})`, color: "#FFFFFF" }}
      >
        {generating ? (
          t("generating_ai_recipe")
        ) : (
          <>
            <Wand2 size={16} /> {t("generate_ai_cta")}
          </>
        )}
      </button>
      )}

      {filtered.length === 0 && <p className="text-sm text-center py-10" style={{ color: "#8A8A8A" }}>{t("no_recipes_found")}</p>}

      <div className="space-y-4">
        {filtered.map((r) => {
          const rPhase = localizePhase(PHASES[r.phase], lang);
          return (
            <button key={r.id} onClick={() => setOpenRecipeId(r.id)} className="w-full text-left rounded-2xl overflow-hidden" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
              <div className="min-h-[6rem] relative flex items-end justify-between p-4 pt-10 gap-2" style={{ background: `linear-gradient(135deg, ${r.color}, ${rPhase.tint})` }}>
                <span
                  role="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleFavorite(r.id);
                  }}
                  className="absolute top-3 right-3 w-8 h-8 rounded-full flex items-center justify-center"
                  style={{ background: "rgba(0,0,0,0.28)" }}
                  aria-label={t("save_recipe_aria")}
                >
                  {favoriteIds.includes(r.id) ? <BookmarkCheck size={14} className="text-white" /> : <Bookmark size={14} className="text-white" />}
                </span>
                <p className="font-display text-lg text-white drop-shadow break-words line-clamp-2 flex-1 min-w-0">{r.title || t("recipe_fallback")}</p>
                <span className="text-[10px] font-semibold px-2 py-1 rounded-full text-white/90 shrink-0" style={{ background: "rgba(0,0,0,0.18)" }}>
                  {rPhase.name}
                </span>
              </div>
              <div className="p-4">
                <div className="flex gap-4 text-[11px] mb-3" style={{ color: "#8A8A8A" }}>
                  <span className="flex items-center gap-1"><Clock size={11} />{r.time} {t("min")}</span>
                  <span className="flex items-center gap-1"><Flame size={11} />{r.kcal} kcal</span>
                  <span className="flex items-center gap-1"><Beef size={11} />{r.protein}g</span>
                  <span className="flex items-center gap-1"><Wheat size={11} />{r.carbs}g</span>
                  <span className="flex items-center gap-1"><Nut size={11} />{r.fat}g</span>
                </div>
                <div className="flex gap-1.5 flex-wrap mb-3">
                  {r.cuisine && (
                    <span className="text-[10px] font-semibold px-2 py-1 rounded-full text-white" style={{ background: "#121212" }}>
                      {tagLabel(r.cuisine, lang)}
                    </span>
                  )}
                  {r.tags.map((tag) => (
                    <span key={tag} className="text-[10px] font-medium px-2 py-1 rounded-full" style={{ background: rPhase.tint, color: rPhase.color }}>
                      {tagLabel(tag, lang)}
                    </span>
                  ))}
                  <span className="text-[10px] font-medium px-2 py-1 rounded-full flex items-center gap-1" style={{ background: "#EFEFEF", color: "#545454" }}>
                    <Sparkles size={10} /> {r.micronutrient}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] font-medium pt-3" style={{ color: rPhase.color, borderTop: "1px solid #E2E2E2" }}>
                  <ChefHat size={12} /> {t("view_ingredients")} <ChevronRight size={12} />
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {openRecipe && (
        <RecipeDetailModal
          recipe={openRecipe}
          onClose={() => setOpenRecipeId(null)}
          onAddToShoppingList={addRecipeToShoppingList}
          isFavorite={favoriteIds.includes(openRecipe.id)}
          onToggleFavorite={() => toggleFavorite(openRecipe.id)}
          onSaveAsShortcut={addShortcut}
        />
      )}
    </div>
  );
}

function RecipeDetailModal({ recipe, onClose, onAddToShoppingList, isFavorite, onToggleFavorite, onSaveAsShortcut }) {
  const { t, lang } = useLang();
  const rPhase = localizePhase(PHASES[recipe.phase], lang);
  const compatible = DIET_ORDER.filter((d) => isDietCompatible(recipe, d));
  const [added, setAdded] = useState(false);
  const [shortcutSaved, setShortcutSaved] = useState(false);

  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  function handleAddToList() {
    onAddToShoppingList(recipe);
    setAdded(true);
    setTimeout(() => setAdded(false), 1800);
  }

  function handleSaveShortcut() {
    onSaveAsShortcut({ label: recipe.title, kcal: recipe.kcal, protein: recipe.protein, carbs: recipe.carbs, fat: recipe.fat, ingredients: ingredientsFromRecipe(recipe) });
    setShortcutSaved(true);
    setTimeout(() => setShortcutSaved(false), 1800);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center" style={{ background: "rgba(43,36,28,0.5)" }} onClick={onClose}>
      <div
        className="w-full max-w-md rounded-t-3xl sm:rounded-3xl"
        style={{
          background: "#FFFFFF",
          maxHeight: "min(92vh, 92dvh)",
          overflowY: "auto",
          WebkitOverflowScrolling: "touch",
          overscrollBehavior: "contain",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="min-h-[8rem] relative flex items-end p-5 pr-16 pt-12" style={{ background: `linear-gradient(135deg, ${recipe.color}, ${rPhase.tint})` }}>
          <button
            onClick={onToggleFavorite}
            className="absolute top-4 right-16 w-9 h-9 rounded-full flex items-center justify-center z-10"
            style={{ background: "rgba(0,0,0,0.28)" }}
            aria-label={t("save_recipe_aria")}
          >
            {isFavorite ? <BookmarkCheck size={16} className="text-white" /> : <Bookmark size={16} className="text-white" />}
          </button>
          <button onClick={onClose} className="absolute top-4 right-4 w-9 h-9 rounded-full flex items-center justify-center z-10" style={{ background: "rgba(0,0,0,0.28)" }} aria-label={t("close_recipe_aria") || t("close")}>
            <X size={17} className="text-white" strokeWidth={2.5} />
          </button>
          {recipe.aiGenerated && (
            <span className="absolute top-4 left-4 text-[10px] font-semibold px-2 py-1 rounded-full flex items-center gap-1 text-white" style={{ background: "rgba(0,0,0,0.22)" }}>
              <Sparkles size={10} /> {recipe.pantry ? t("leftover_tag") : t("ai_generated_tag")}
            </span>
          )}
          <p className="font-display text-2xl text-white drop-shadow leading-tight break-words line-clamp-3">{recipe.title || t("recipe_fallback")}</p>
        </div>

        <div className="p-5">
          <div className="flex gap-4 text-xs mb-4" style={{ color: "#545454" }}>
            <span className="flex items-center gap-1"><Clock size={13} />{recipe.time} {t("min")}</span>
            <span className="flex items-center gap-1"><Flame size={13} />{recipe.kcal} kcal</span>
            <span className="flex items-center gap-1"><Beef size={13} />{recipe.protein}g</span>
            <span className="flex items-center gap-1"><Wheat size={13} />{recipe.carbs}g</span>
            <span className="flex items-center gap-1"><Nut size={13} />{recipe.fat}g</span>
          </div>

          <div className="flex gap-1.5 flex-wrap mb-5">
            {recipe.cuisine && (
              <span className="text-[10px] font-semibold px-2 py-1 rounded-full text-white" style={{ background: "#121212" }}>
                {tagLabel(recipe.cuisine, lang)}
              </span>
            )}
            {recipe.tags.map((tag) => (
              <span key={tag} className="text-[10px] font-medium px-2 py-1 rounded-full" style={{ background: rPhase.tint, color: rPhase.color }}>
                {tagLabel(tag, lang)}
              </span>
            ))}
          </div>

          <div className="rounded-2xl p-4 mb-5" style={{ background: rPhase.tint }}>
            <p className="text-[11px] uppercase tracking-widest mb-1.5 flex items-center gap-1.5" style={{ color: rPhase.color }}>
              <Sparkles size={12} /> {t("cycle_benefit")}
            </p>
            <p className="text-xs leading-relaxed" style={{ color: "#262626" }}>
              {recipe.why}
            </p>
          </div>

          <button
            onClick={handleSaveShortcut}
            className="w-full mb-4 py-2.5 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5"
            style={{ background: shortcutSaved ? "#E4EEDF" : rPhase.tint, color: shortcutSaved ? "#5C7A4E" : rPhase.color }}
          >
            {shortcutSaved ? <Check size={13} /> : <Zap size={13} />}
            {shortcutSaved ? t("shortcut_saved") : t("save_as_shortcut")}
          </button>

          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold flex items-center gap-1.5" style={{ color: "#121212" }}>
              <ListChecks size={14} style={{ color: rPhase.color }} /> {t("ingredients_for_one")}
            </p>
            <button
              onClick={handleAddToList}
              className="text-[10px] font-semibold px-2.5 py-1.5 rounded-lg flex items-center gap-1"
              style={{ background: added ? "#E4EEDF" : "#EFEFEF", color: added ? "#5C7A4E" : "#545454" }}
            >
              {added ? <Check size={11} /> : <ShoppingCart size={11} />}
              {added ? t("added_label") : t("add_to_shopping")}
            </button>
          </div>
          <ul className="mb-5">
            {recipe.ingredients.map((ing, i) => (
              <li key={i} className="text-xs py-1.5 flex items-center gap-2" style={{ color: "#262626", borderBottom: i < recipe.ingredients.length - 1 ? "1px solid #EFEFEF" : "none" }}>
                <CircleDot size={7} style={{ color: rPhase.color }} className="shrink-0" />
                {ing}
              </li>
            ))}
          </ul>

          <p className="text-xs font-semibold mb-2 flex items-center gap-1.5" style={{ color: "#121212" }}>
            <ChefHat size={14} style={{ color: rPhase.color }} /> {t("preparation")}
          </p>
          <ol className="mb-5 space-y-2.5">
            {recipe.steps.map((s, i) => (
              <li key={i} className="text-xs leading-relaxed flex gap-2.5" style={{ color: "#262626" }}>
                <span className="shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold" style={{ background: rPhase.tint, color: rPhase.color }}>
                  {i + 1}
                </span>
                {s}
              </li>
            ))}
          </ol>

          <p className="text-[11px]" style={{ color: "#8A8A8A" }}>
            <span className="font-medium" style={{ color: "#545454" }}>
              {t("fits_diet")}:{" "}
            </span>
            {compatible.map((d) => dietLabel(d, lang)).join(", ")}
          </p>

          <button onClick={onClose} className="w-full mt-5 py-3 rounded-xl text-sm font-semibold" style={{ background: "#EFEFEF", color: "#545454" }}>
            {t("close")}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ Shopping list ------------------------------ */
function ShoppingListTab({ phase, items, onToggle, onRemove, onClear, onAdd }) {
  const { t, lang } = useLang();
  const [newItem, setNewItem] = useState("");
  const categories = ["Gemüse & Obst", "Kühlregal", "Trockenwaren & Gewürze", "Sonstiges"];
  const grouped = categories.map((cat) => ({ cat, items: items.filter((i) => i.category === cat) })).filter((g) => g.items.length > 0);
  const checkedCount = items.filter((i) => i.checked).length;

  function submitAdd() {
    if (!newItem.trim()) return;
    onAdd(newItem);
    setNewItem("");
  }

  return (
    <div className="px-5 pt-8">
      <div className="flex items-center justify-between mb-1">
        <h1 className="font-display text-2xl" style={{ color: "#121212" }}>
          {t("shopping_title")}
        </h1>
        {items.length > 0 && (
          <button onClick={onClear} className="text-[11px] font-semibold px-3 py-1.5 rounded-lg" style={{ background: "#F6E1E3", color: "#8C3B47" }}>
            {t("shopping_clear_list")}
          </button>
        )}
      </div>
      <p className="text-xs mb-4" style={{ color: "#8A8A8A" }}>
        {items.length === 0 ? t("shopping_empty") : `${checkedCount} ${t("shopping_done_of")} ${items.length} ${t("shopping_done")}`}
      </p>

      <div className="flex gap-2 mb-5">
        <input
          value={newItem}
          onChange={(e) => setNewItem(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submitAdd()}
          placeholder={t("shopping_add_placeholder")}
          className="flex-1 px-3 py-2.5 rounded-xl text-sm outline-none bg-[#F5F5F5] text-[#121212] border border-[#F5F5F5] focus:bg-white focus:border-[#121212] transition-colors"
        />
        <button onClick={submitAdd} className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0" style={{ background: phase.color }} aria-label={t("add")}>
          <Plus size={18} className="text-white" />
        </button>
      </div>

      {items.length === 0 && (
        <div className="rounded-2xl p-6 flex flex-col items-center text-center" style={{ background: "#FFFFFF", border: "1px dashed #E2E2E2" }}>
          <ShoppingCart size={22} style={{ color: "#AFAFAF" }} className="mb-2" />
          <p className="text-xs leading-relaxed" style={{ color: "#8A8A8A" }}>
            {t("shopping_empty_hint")}
          </p>
        </div>
      )}

      <div className="space-y-5">
        {grouped.map((g) => (
          <div key={g.cat}>
            <p className="text-[11px] uppercase tracking-widest mb-2" style={{ color: phase.color }}>
              {categoryLabel(g.cat, lang)} ({g.items.length})
            </p>
            <div className="space-y-2">
              {g.items.map((item) => (
                <div key={item.id} className="rounded-xl p-3 flex items-center gap-3" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
                  <button
                    onClick={() => onToggle(item.id)}
                    className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 border"
                    style={{ background: item.checked ? phase.color : "#FFFFFF", borderColor: item.checked ? phase.color : "#E2E2E2" }}
                  >
                    {item.checked && <Check size={13} className="text-white" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm" style={{ color: item.checked ? "#AFAFAF" : "#121212", textDecoration: item.checked ? "line-through" : "none" }}>
                      {item.text}
                    </p>
                    {item.recipeTitle && (
                      <p className="text-[10px] truncate" style={{ color: "#AFAFAF" }}>
                        {t("for_recipe")} {item.recipeTitle}
                      </p>
                    )}
                  </div>
                  <button onClick={() => onRemove(item.id)} className="w-7 h-7 rounded-full flex items-center justify-center shrink-0" style={{ background: "#F6E1E3" }} aria-label={t("remove")}>
                    <Trash2 size={12} style={{ color: "#8C3B47" }} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------- Symptoms ------------------------------- */
function generateMoodInsight(moodLogByDate, cycleStartDate, lang) {
  const entries = Object.entries(moodLogByDate).filter(([, v]) => v && v.mood);
  if (entries.length < 3) return lang === "en" ? "Keep logging for a few more days so we can spot patterns in your cycle." : "Logge ein paar Tage weiter, damit wir Muster in deinem Zyklus erkennen können.";

  const byCycleDay = {};
  entries.forEach(([dateKey, v]) => {
    const cd = cycleDayForKey(dateKey, cycleStartDate);
    if (!byCycleDay[cd]) byCycleDay[cd] = [];
    byCycleDay[cd].push(MOOD_VALUE[v.mood]);
  });

  let worstDay = null;
  let worstAvg = 5;
  Object.entries(byCycleDay).forEach(([cd, vals]) => {
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
    if (avg < worstAvg) {
      worstAvg = avg;
      worstDay = cd;
    }
  });
  if (worstDay === null || worstAvg >= 3) return lang === "en" ? "Your mood has been fairly stable across the cycle so far. Keep it up!" : "Deine Stimmung ist über den Zyklus hinweg bisher recht stabil. Weiter so!";

  const phaseKeyAtDay = phaseForDay(Number(worstDay));
  const phaseAtDay = localizePhase(PHASES[phaseKeyAtDay], lang);
  const tipDe =
    phaseKeyAtDay === "luteal" ? "komplexere Kohlenhydrate und Magnesium" : phaseKeyAtDay === "menstruation" ? "eisenreiche Lebensmittel" : phaseKeyAtDay === "follikel" ? "mehr Protein" : "Omega-3-Fettsäuren";
  const tipEn =
    phaseKeyAtDay === "luteal" ? "more complex carbs and magnesium" : phaseKeyAtDay === "menstruation" ? "iron-rich foods" : phaseKeyAtDay === "follikel" ? "more protein" : "omega-3 fatty acids";
  if (lang === "en") return `Pattern detected: on cycle day ${worstDay} (${phaseAtDay.name}) your energy is often lower. Tip: add ${tipEn} on that day.`;
  return `Muster erkannt: An Zyklustag ${worstDay} (${phaseAtDay.name}) ist deine Energie häufig niedriger. Empfehlung: Baue gezielt ${tipDe} ein.`;
}

function MoodTrendChart({ moodLogByDate, cycleStartDate, todayKey, phase }) {
  const { t, lang } = useLang();
  const [selectedDay, setSelectedDay] = useState(null);
  const days = [];
  for (let i = 13; i >= 0; i--) days.push(addDaysToKey(todayKey, -i));

  const selectedEntry = selectedDay ? moodLogByDate[selectedDay] : null;
  const selectedMoodOpt = selectedEntry && selectedEntry.mood ? MOOD_OPTIONS.find((m) => m.id === selectedEntry.mood) : null;

  return (
    <div className="rounded-2xl p-5 mb-4" style={{ background: "#FFFFFF", border: "1px solid #E2E2E2" }}>
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp size={15} style={{ color: phase.color }} />
        <p className="text-xs font-semibold" style={{ color: "#121212" }}>
          {t("mood_trend_title")}
        </p>
      </div>
      <div className="flex items-end gap-1.5 h-24 mb-1">
        {days.map((d) => {
          const entry = moodLogByDate[d];
          const val = entry && entry.mood ? MOOD_VALUE[entry.mood] : 0;
          const heightPct = val ? (val / 4) * 100 : 8;
          const isSelected = selectedDay === d;
          return (
            <button key={d} onClick={() => setSelectedDay(isSelected ? null : d)} className="flex-1 flex flex-col items-center justify-end h-full">
              <div
                className="w-full rounded-t-md transition-all"
                style={{
                  height: `${heightPct}%`,
                  background: val ? phase.color : "#E2E2E2",
                  minHeight: 4,
                  opacity: isSelected || !selectedDay ? 1 : 0.4,
                  boxShadow: isSelected ? `0 0 0 2px ${phase.color}` : "none",
                }}
              />
            </button>
          );
        })}
      </div>
      <div className="flex gap-1.5 mb-1">
        {days.map((d) => (
          <span key={d} className="flex-1 text-center text-[8px]" style={{ color: selectedDay === d ? phase.color : "#AFAFAF", fontWeight: selectedDay === d ? 700 : 400 }}>
            {cycleDayForKey(d, cycleStartDate)}
          </span>
        ))}
      </div>

      {selectedDay && (
        <div className="mt-3 pt-3 rounded-xl px-3 py-2.5" style={{ background: phase.tint }}>
          <p className="text-xs font-semibold" style={{ color: "#121212" }}>
            {formatDateLabel(selectedDay, lang)} · {t("cycle_day")} {cycleDayForKey(selectedDay, cycleStartDate)}
          </p>
          <p className="text-[11px] mt-1" style={{ color: "#545454" }}>
            {selectedMoodOpt ? `${t("mood_today")}: ${moodLabel(selectedMoodOpt, lang)}` : t("no_entry")}
          </p>
          {selectedEntry && selectedEntry.symptoms && selectedEntry.symptoms.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {selectedEntry.symptoms.map((sid) => {
                const s = SYMPTOMS.find((x) => x.id === sid);
                return s ? (
                  <span key={sid} className="text-[10px] px-2 py-0.5 rounded-full" style={{ background: "#FFFFFF", color: "#545454" }}>
                    {localizeSymptom(s, lang).label}
                  </span>
                ) : null;
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SymptomsTab({ phase, goToRecipe, recipes, todayKey, cycleStartDate, moodLogByDate, setTodayMood, toggleTodaySymptom }) {
  const { t, lang } = useLang();
  const todayEntry = moodLogByDate[todayKey] || { mood: null, symptoms: [] };
  const mood = todayEntry.mood;
  const selected = todayEntry.symptoms || [];

  const insight = useMemo(() => generateMoodInsight(moodLogByDate, cycleStartDate, lang), [moodLogByDate, cycleStartDate, lang]);

  return (
    <div className="px-5 pt-8">
      <h1 className="font-display text-2xl mb-1" style={{ color: "#121212" }}>
        {t("symptoms_title")}
      </h1>
      <p className="text-xs mb-5" style={{ color: "#8A8A8A" }}>
        {t("symptoms_subtitle")}
      </p>

      <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "#AFAFAF" }}>
        {t("mood_today")}
      </p>
      <div className="grid grid-cols-2 gap-2 mb-6">
        {MOOD_OPTIONS.map((m) => {
          const MIcon = m.icon;
          const active = mood === m.id;
          return (
            <button
              key={m.id}
              onClick={() => setTodayMood(m.id)}
              className="flex items-center gap-2.5 py-3 px-3 rounded-xl border min-h-[52px]"
              style={{ background: active ? phase.color : "#FFFFFF", color: active ? "#FFFFFF" : "#545454", borderColor: active ? phase.color : "#E2E2E2" }}
            >
              <MIcon size={16} className="shrink-0" />
              <span
                lang={lang}
                className="text-[11px] font-medium flex-1 min-w-0 leading-snug text-left break-words"
                style={{ hyphens: "auto", WebkitHyphens: "auto", overflowWrap: "break-word" }}
              >
                {moodLabel(m, lang)}
              </span>
            </button>
          );
        })}
      </div>

      <p className="text-xs uppercase tracking-widest mb-3" style={{ color: "#AFAFAF" }}>
        {t("select_symptoms")}
      </p>
      <div className="grid grid-cols-2 gap-2 mb-6">
        {SYMPTOMS.map((raw) => {
          const s = localizeSymptom(raw, lang);
          const SIcon = s.icon;
          const active = selected.includes(s.id);
          return (
            <button
              key={s.id}
              onClick={() => toggleTodaySymptom(s.id)}
              className="flex items-center gap-2.5 px-3 py-3 rounded-xl border text-left min-h-[64px]"
              style={{ background: active ? phase.tint : "#FFFFFF", borderColor: active ? phase.color : "#E2E2E2" }}
            >
              <div className="w-7 h-7 rounded-full flex items-center justify-center shrink-0" style={{ background: active ? phase.color : "#EFEFEF" }}>
                <SIcon size={13} style={{ color: active ? "#FFFFFF" : "#8A8A8A" }} />
              </div>
              <span
                lang={lang}
                className="text-xs font-medium flex-1 min-w-0 leading-snug break-words"
                style={{ color: "#262626", hyphens: "auto", WebkitHyphens: "auto", overflowWrap: "break-word" }}
              >
                {s.label}
              </span>
              {active && <Check size={14} className="shrink-0" style={{ color: phase.color }} />}
            </button>
          );
        })}
      </div>

      <MoodTrendChart moodLogByDate={moodLogByDate} cycleStartDate={cycleStartDate} todayKey={todayKey} phase={phase} />

      <div className="rounded-2xl p-4 mb-6 flex items-start gap-3" style={{ background: phase.tint }}>
        <Sparkles size={16} style={{ color: phase.color }} className="shrink-0 mt-0.5" />
        <p className="text-xs leading-relaxed" style={{ color: "#262626" }}>
          <span className="font-semibold">{t("ai_insight_label")} </span>
          {insight}
        </p>
      </div>

      {selected.length > 0 && (
        <div className="space-y-4">
          {selected.map((id) => {
            const symptom = localizeSymptom(SYMPTOMS.find((s) => s.id === id), lang);
            const signatureRecipe = recipes.find((r) => r.id === symptom.recipeId);
            const extraMatches = recipes.filter((r) => r.id !== symptom.recipeId && r.tags.includes(symptom.matchTag)).slice(0, 2);
            const suggestions = [signatureRecipe, ...extraMatches].filter(Boolean).slice(0, 3);
            const SIcon = symptom.icon;
            return (
              <div key={id} className="rounded-2xl overflow-hidden" style={{ background: phase.tint }}>
                <div className="p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-8 h-8 rounded-full flex items-center justify-center" style={{ background: "#FFFFFF" }}>
                      <SIcon size={15} style={{ color: phase.color }} />
                    </div>
                    <p className="text-sm font-semibold" style={{ color: "#121212" }}>
                      {symptom.label}
                    </p>
                  </div>

                  <p className="text-[11px] uppercase tracking-widest mb-1.5" style={{ color: phase.color }}>
                    {t("why_happens")}
                  </p>
                  <p className="text-xs leading-relaxed mb-4" style={{ color: "#262626" }}>
                    {symptom.why}
                  </p>

                  <p className="text-[11px] uppercase tracking-widest mb-1.5" style={{ color: phase.color }}>
                    {t("helpful_ingredients")}
                  </p>
                  <div className="flex gap-1.5 flex-wrap mb-4">
                    {symptom.ingredients.map((ing) => (
                      <span key={ing} className="text-[11px] font-medium px-2.5 py-1 rounded-full" style={{ background: "#FFFFFF", color: "#262626" }}>
                        {ing}
                      </span>
                    ))}
                  </div>

                  {suggestions.length > 0 && (
                    <div className="space-y-2">
                      {suggestions.map((recipe) => (
                        <div key={recipe.id} className="rounded-xl p-3 flex items-center gap-3" style={{ background: "#FFFFFF" }}>
                          <div className="w-11 h-11 rounded-lg flex items-center justify-center shrink-0" style={{ background: `linear-gradient(135deg, ${recipe.color}, ${phase.soft})` }}>
                            <Leaf size={18} className="text-white" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-semibold truncate" style={{ color: "#121212" }}>
                              {recipe.title}
                            </p>
                            <p className="text-[10px]" style={{ color: "#8A8A8A" }}>
                              {recipe.time} {t("min")} · {recipe.kcal} kcal
                            </p>
                          </div>
                          <button onClick={() => goToRecipe(recipe.title)} className="shrink-0 flex items-center gap-1 text-[11px] font-semibold px-3 py-2 rounded-lg" style={{ background: phase.color, color: "#FFFFFF" }}>
                            {t("view")} <ChevronRight size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {selected.length === 0 && (
        <div className="rounded-2xl p-6 flex flex-col items-center text-center" style={{ background: "#FFFFFF", border: "1px dashed #E2E2E2" }}>
          <Sparkles size={20} style={{ color: "#AFAFAF" }} className="mb-2" />
          <p className="text-xs" style={{ color: "#8A8A8A" }}>
            {t("select_symptoms_hint")}
          </p>
        </div>
      )}
    </div>
  );
}
