# backend/app/api/routes/health.py
from fastapi import APIRouter
from app.services.cache import get_cache
from app.db.session import engine
from sqlalchemy import text

router = APIRouter()


@router.get("/health")
async def health():
    # checks all dependencies are alive
    # used by Docker, load balancers, and monitoring

    results = {
        "api"      : "ok",
        "redis"    : "unknown",
        "postgres" : "unknown",
    }

    # check Redis
    try:
        cache = get_cache()
        alive = await cache.ping()
        results["redis"] = "ok" if alive else "down"
    except Exception as e:
        results["redis"] = f"down: {e}"

    # check Postgres
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        results["postgres"] = "ok"
    except Exception as e:
        results["postgres"] = f"down: {e}"

    # return 200 only if everything is healthy
    all_ok = all(v == "ok" for v in results.values())
    return {
        "status": "healthy" if all_ok else "degraded",
        "checks": results,
    }