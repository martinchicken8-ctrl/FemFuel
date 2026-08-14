# NicInSync

Zyklusbasierte Ernährungs-App. Fertig eingerichtetes Vite + React + Tailwind-Projekt.

## 1. Lokal testen (optional, aber empfohlen)

Voraussetzung: [Node.js](https://nodejs.org) (Version 18 oder neuer) ist installiert.

```bash
npm install
npm run dev
```

Öffnet die App unter `http://localhost:5173`. Kamera/Mikrofon funktionieren auf `localhost` bereits ohne HTTPS.

## 2. Auf GitHub hochladen

```bash
git init
git add .
git commit -m "Initial commit"
```

Dann ein neues, leeres Repository auf [github.com/new](https://github.com/new) anlegen und:

```bash
git remote add origin https://github.com/DEIN-NUTZERNAME/nicinsync.git
git branch -M main
git push -u origin main
```

(Falls du Git/GitHub nicht nutzen willst: siehe Schritt 3b für Drag & Drop ohne GitHub.)

## 3a. Deployment über Vercel (mit GitHub)

1. Auf [vercel.com](https://vercel.com) mit GitHub anmelden.
2. "Add New Project" → dein `nicinsync`-Repository auswählen.
3. Vercel erkennt Vite automatisch. Einfach auf **Deploy** klicken.
4. Nach ca. 1 Minute bekommst du eine Live-URL wie `nicinsync.vercel.app` – mit automatischem HTTPS, also funktionieren Kamera und Mikrofon direkt.

## 3b. Deployment über Netlify (ohne GitHub, per Drag & Drop)

1. Lokal bauen:
   ```bash
   npm install
   npm run build
   ```
   Das erzeugt einen `dist/`-Ordner.
2. Auf [app.netlify.com/drop](https://app.netlify.com/drop) gehen.
3. Den `dist/`-Ordner per Drag & Drop auf die Seite ziehen.
4. Fertig – du bekommst sofort eine Live-URL mit HTTPS.

## Kamera & Mikrofon

Beide Funktionen brauchen HTTPS (oder `localhost`). Vercel und Netlify liefern automatisch HTTPS aus,
du musst nichts zusätzlich konfigurieren. Der Browser fragt beim ersten Antippen von Foto/Mikrofon
nach Erlaubnis – einfach bestätigen.

## Updates später einspielen

Änderungen an `src/App.jsx` einfach committen und pushen (bei Vercel) bzw. neu bauen und erneut
hochladen (bei Netlify) – beide Dienste sind kostenlos für dieses Projekt.
