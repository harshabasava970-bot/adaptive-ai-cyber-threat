# CyberShield AI — Mobile App

A mobile-optimised web app that mirrors the Streamlit dashboard, sized for phones.

## How to build the APK

### Prerequisites
- Android Studio (for packaging) **or** use the pre-built approach below
- Node.js 18+ (for the Capacitor bridge)

### Steps

```bash
# 1. Install dependencies
cd mobile-app
npm install

# 2. Build the web bundle
npm run build

# 3. Sync to Android project
npx cap sync android

# 4. Open in Android Studio and build the APK
npx cap open android
# In Android Studio → Build → Build Bundle(s)/APK(s) → Build APK(s)
# APK appears at: android/app/build/outputs/apk/debug/app-debug.apk
```

### Copy to phone
1. Connect your phone via USB (or use a cloud drive / email).
2. Copy `app-debug.apk` to your phone.
3. On the phone: Settings → Install unknown apps → allow your file manager.
4. Tap the APK to install.

## UI notes
- All sizes use `rem`/`vw`/`vh` so they scale to any phone screen.
- Bottom navigation replaces the sidebar (too narrow on mobile).
- Charts are touch-friendly with Plotly-style tooltips via Chart.js.
- Dark cybersecurity theme is identical to the Streamlit website, colours are token-matched.
