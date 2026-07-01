# Deployment Guide — All Free Platforms
## Adaptive AI for Cyber Threat Detection

This guide walks you through deploying the project using **100% free platforms**.
No credit card required for any step.

---

## Overview

| What           | Where              | Free? | Time Needed |
|----------------|--------------------|-------|-------------|
| Source code    | GitHub             | ✓ Free forever | 5 min |
| FastAPI backend | Render.com        | ✓ 750 hrs/month | 10 min |
| Streamlit dashboard | Streamlit Cloud | ✓ Free forever | 5 min |
| Model storage  | Hugging Face Hub   | ✓ Free forever | 5 min |

---

## Step 1 — Push to GitHub (Required for all deployments)

### 1.1 Create a GitHub account
- Go to https://github.com → Sign up (free)

### 1.2 Create a new repository
- Click the **+** button → New repository
- Name: `adaptive-ai-cyber-threat`
- Set to **Public** (required for free Streamlit Cloud deploy)
- Click **Create repository**

### 1.3 Push your code

Open your terminal in the project folder and run:

```bash
git init
git add .
git commit -m "Initial commit: Module 1 - Project Setup"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/adaptive-ai-cyber-threat.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

---

## Step 2 — Deploy FastAPI on Render.com (Free)

Render gives you a free web service that wakes up on request.

### 2.1 Sign up
- Go to https://render.com → Sign up with GitHub (easiest)

### 2.2 Create a new Web Service
1. Click **New** → **Web Service**
2. Connect your GitHub account if not already connected
3. Select your `adaptive-ai-cyber-threat` repository
4. Click **Connect**

### 2.3 Configure the service
Fill in these fields:

| Field | Value |
|-------|-------|
| Name | `cyber-threat-api` |
| Environment | `Python 3` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn src.api.main:app --host 0.0.0.0 --port $PORT` |
| Instance Type | **Free** |

### 2.4 Add environment variables
Click **Environment** → Add the following:

```
APP_ENV = production
SECRET_KEY = (generate a random 32+ character string)
DATABASE_URL = sqlite:///./data/threat_db.sqlite
LOG_LEVEL = INFO
```

### 2.5 Deploy
Click **Create Web Service** → Wait 3-5 minutes for the first deploy.

Your API will be live at: `https://cyber-threat-api.onrender.com`
API docs: `https://cyber-threat-api.onrender.com/docs`

**Note:** Free Render services sleep after 15 minutes of inactivity and take
~30 seconds to wake up on first request. This is normal for free tier.

---

## Step 3 — Deploy Dashboard on Streamlit Cloud (Free)

Streamlit Cloud is the easiest deployment option — takes under 5 minutes.

### 3.1 Sign up
- Go to https://share.streamlit.io → Sign in with GitHub

### 3.2 Deploy your app
1. Click **New app**
2. Select your repository: `adaptive-ai-cyber-threat`
3. Branch: `main`
4. Main file path: `src/dashboard/app.py`
5. Click **Deploy!**

### 3.3 Add secrets (environment variables)
1. Click **Advanced settings** before deploying
2. Add your environment variables in TOML format:

```toml
APP_ENV = "production"
API_BASE_URL = "https://cyber-threat-api.onrender.com"
```

Your dashboard will be live at: `https://YOUR_USERNAME-adaptive-ai-cyber-threat.streamlit.app`

---

## Step 4 — Store Models on Hugging Face Hub (Free)

After training your models, upload them to Hugging Face Hub for free storage.

### 4.1 Create account
- Go to https://huggingface.co → Sign up (free)

### 4.2 Install huggingface-hub
```bash
pip install huggingface-hub
```

### 4.3 Log in
```bash
huggingface-cli login
# Enter your HuggingFace token (get it from huggingface.co/settings/tokens)
```

### 4.4 Upload a model
```python
from huggingface_hub import HfApi

api = HfApi()
api.upload_folder(
    folder_path="data/models/phishing_distilbert",
    repo_id="YOUR_USERNAME/phishing-distilbert",
    repo_type="model",
)
```

---

## Step 5 — Auto-Deploy on Every Code Push (Free via GitHub Actions)

Once Render and Streamlit Cloud are connected to your GitHub repo, every
`git push` to `main` automatically triggers a redeploy on both platforms.

```bash
# Make changes to code
git add .
git commit -m "feat: add phishing detection model"
git push origin main
# → Render redeploys API automatically
# → Streamlit Cloud redeploys dashboard automatically
```

---

## Sharing Your Project

After deployment, you have:

- **Live API**: `https://cyber-threat-api.onrender.com`
- **API Docs**: `https://cyber-threat-api.onrender.com/docs`
- **Dashboard**: `https://your-username-adaptive-ai-cyber-threat.streamlit.app`
- **Source Code**: `https://github.com/YOUR_USERNAME/adaptive-ai-cyber-threat`

Include all four URLs in your IEEE paper, capstone report, and presentation.

---

## Troubleshooting Common Issues

### "Module not found" on Render
- Check that `requirements.txt` lists all packages
- Verify `src/` is in the Python path (handled by `pyproject.toml`)

### Streamlit app crashes on startup
- Check that `src/dashboard/app.py` exists
- Ensure all imports are in `requirements.txt`

### API takes 30 seconds to respond
- This is normal — free Render services sleep after inactivity
- Use UptimeRobot (free) to ping your API every 14 minutes to keep it awake

### Environment variables not loading
- Double-check spelling in Render's environment panel
- No quotes needed around values in Render

---

*All platforms listed are free. No credit card required.*
