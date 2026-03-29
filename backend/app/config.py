# backend/app/config.py
from functools import lru_cache
from typing import Literal
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # ── App ──────────────────────────────────────────────────────
    app_env: Literal["development", "production"] = "development"
    secret_key: str
    frontend_url: str = "http://localhost:3000"

    # ── Supabase / Postgres ───────────────────────────────────────
    database_url: str
    supabase_url: str
    supabase_anon_key: str

    # ── Redis ─────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379"

    # ── GitHub OAuth ──────────────────────────────────────────────
    github_client_id: str
    github_client_secret: str
    github_redirect_uri: str

    # ── Groq ──────────────────────────────────────────────────────
    groq_api_key: str
    groq_model_fast: str = "llama-3.3-70b-versatile"
    groq_model_fallback: str = "mixtral-8x7b-32768"

    # ── OpenRouter ────────────────────────────────────────────────
    openrouter_api_key: str
    openrouter_model_deep: str = "deepseek/deepseek-r1:free"
    openrouter_model_alt: str = "qwen/qwen-2.5-72b-instruct:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # files scoring above this go to deep model instead of fast model
    llm_deep_analysis_threshold: float = 0.6

    # ── Scan limits ───────────────────────────────────────────────
    max_file_size_kb: int = 500
    max_files_per_scan: int = 1000
    scan_job_timeout_seconds: int = 300
    cache_ttl_seconds: int = 3600

    # ── LangSmith (observability) ─────────────────────────────
    langchain_tracing_v2: bool = False
    langchain_endpoint: str = "https://api.smith.langchain.com"
    langchain_api_key: str = ""
    langchain_project: str = "securerepo"

    class Config:
        # tells pydantic where to read env vars from
        env_file = ".env"
        env_file_encoding = "utf-8"
        # so GROQ_API_KEY and groq_api_key both map to the same field
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    # lru_cache means this function runs ONCE ever
    # every import across your entire app gets the same Settings object
    # without this, pydantic reads and validates .env on every single import
    return Settings()