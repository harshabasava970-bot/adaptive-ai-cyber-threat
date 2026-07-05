# How to build the CyberShield AI APK

## What this folder contains

```
mobile-app/
├── www/                   ← The mobile web app (HTML + CSS + JS)
│   ├── index.html         ← Single-page app entry point
│   ├── css/mobile.css     ← Phone-only styles (separate from Streamlit)
│   └── js/app.js          ← All logic: navigation, API calls, charts
├── android/               ← Android Studio project skeleton
│   ├── app/
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/cybershield/ai/MainActivity.java
│   │       └── res/values/  ← Dark theme colours
│   └── build.gradle
├── capacitor.config.json  ← Capacitor bridge config
├── package.json           ← npm deps (Capacitor)
└── README.md
```

## Step 1 — Install tools (one time)

Install [Node.js 18+](https://nodejs.org) and [Android Studio](https://developer.android.com/studio).

```bash
cd mobile-app
npm install
```

## Step 2 — Copy web files into Android assets

```bash
# Copy www/ into the Android project
xcopy /E /I www android\app\src\main\assets\public
```

Or use Capacitor to do it automatically:

```bash
npx cap sync android
```

## Step 3 — Build the APK in Android Studio

```bash
npx cap open android
```

Inside Android Studio:
1. Wait for Gradle sync to finish.
2. Menu → **Build → Build Bundle(s)/APK(s) → Build APK(s)**
3. APK is saved to:  
   `android/app/build/outputs/apk/debug/app-debug.apk`

## Step 4 — Install on your phone

**Option A — USB cable:**
1. Connect phone to PC.
2. Copy `app-debug.apk` to your phone's Downloads folder.
3. On the phone: open Files, tap the APK, allow installation.

**Option B — Cloud:**
1. Upload `app-debug.apk` to Google Drive / WhatsApp to yourself.
2. Download on phone and tap to install.

## UI notes

| Feature | Website (Streamlit) | App (mobile) |
|---|---|---|
| Layout | Wide, laptop-optimised sidebar | Bottom nav bar, single column |
| Font sizes | 14px base | 15px base, touch-friendly |
| Charts | Plotly | Chart.js (lighter, works offline) |
| Theme | Identical dark tokens | Identical dark tokens |
| N/A metrics | Before first scan | Before first scan |
| Empty analytics | Placeholder card | Placeholder card |
| Accessibility | #CBD5E1 muted text | #CBD5E1 muted text |
