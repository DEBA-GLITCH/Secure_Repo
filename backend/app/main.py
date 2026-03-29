# backend/app/main.py
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.api.routes import health, auth, scan

settings = get_settings()

# ── LangSmith tracing ─────────────────────────────────────────────────────────
# just setting env vars is enough — LangGraph auto-instruments
os.environ["LANGCHAIN_TRACING_V2"] = str(settings.langchain_tracing_v2).lower()
os.environ["LANGCHAIN_API_KEY"]    = settings.langchain_api_key
os.environ["LANGCHAIN_PROJECT"]    = settings.langchain_project

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "SecureRepo API",
    description = "AI-powered security audit agent for GitHub repositories",
    version     = "0.1.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = [settings.frontend_url],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/api")
app.include_router(auth.router,   prefix="/api")
app.include_router(scan.router,   prefix="/api")


@app.get("/")
async def root():
    return {"message": "SecureRepo API", "docs": "/docs"}