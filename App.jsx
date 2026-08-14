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
    generate_ai_cta: "Neues KI-Rezept für deine Phase generieren",
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
    generate_ai_cta: "Generate a new AI recipe for your phase",
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
    const food = FOOD_DB.find((f) => f.keys.some((k) => lower.includes(k)));
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
  { keys: ["rind", "rinderhack", "hackfleisch", "hack"], kcal: 230, protein: 20, carbs: 0, fat: 16, defaultG: 150 },
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
    const food = FOOD_DB.find((f) => f.keys.some((k) => lowerName.includes(k)));
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
      if (!lower.includes(k)) return false;
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

const INITIAL_RECIPES = buildConvertedCycleRecipes();

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
      if (!lower.includes(k)) return false;
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
  const found = INGREDIENT_ESTIMATES.find((e) => e.match.some((m) => lower.includes(m)));
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
  const eggFlag = lowerAll.includes("ei") || lowerAll.includes("eier");
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
async function analyzeWithClaude({ text, imageDataUrl, phase, diets, lang }) {
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

  const content = [];
  if (imageDataUrl) {
    const match = imageDataUrl.match(/^data:(image\/\w+);base64,(.+)$/);
    if (match) content.push({ type: "image", source: { type: "base64", media_type: match[1], data: match[2] } });
  }
  content.push({ type: "text", text: instructions });

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 1000, messages: [{ role: "user", content }] }),
  });
  if (!response.ok) throw new Error(`Claude API error ${response.status}`);
  const data = await response.json();
  const textBlock = (data.content || []).find((b) => b.type === "text");
  if (!textBlock) throw new Error("No text block in Claude response");
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
      aiResult = await analyzeWithClaude({ text: rawText, imageDataUrl: imagePreview, phase: selectedPhase, diets: profile.diets, lang });
    } catch (err) {
      console.warn("Claude food analysis failed, using local estimate instead.", err);
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
    <div className="min-h-screen w-full flex justify-center" style={{ background: "#FAFAFA", fontFamily: "'Inter', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600;9..144,700&family=Inter:wght@400;500;600;700&display=swap');
        .font-display { font-family: 'Fraunces', serif; }
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
  const food = FOOD_DB.find((f) => f.keys.some((k) => lower.includes(k)));
  if (food) {
    const hitKey = food.keys.find((k) => lower.includes(k));
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
          <button onClick={handleAddIngredient} className="px-3 py-2 rounded-lg text-xs font-semibold shrink-0" style={{ background: "#5C7A4E", color: "#FFFFFF" }}>
            + {t("add")}
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
        className="w-full mb-5 py-3 rounded-2xl text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-60"
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
