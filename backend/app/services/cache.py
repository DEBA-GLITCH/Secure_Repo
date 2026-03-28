# backend/app/services/cache.py
import json
import hashlib
from typing import Optional, Any
from redis.asyncio import Redis as AsyncRedis
from app.config import get_settings

settings = get_settings()


class CacheService:

    def __init__(self, redis_url: str):
        # create async Redis client
        # decode_responses=True means Redis returns strings not bytes
        # without this you get b"value" instead of "value" everywhere
        self.redis = AsyncRedis.from_url(
            redis_url,
            decode_responses=True,
        )

    def _make_scan_key(self, repo_url: str, commit_sha: str) -> str:
        # this is the cache key design we decided in Q6
        # cache by commit SHA not just URL
        # same repo URL + different commit = different scan result
        # we hash both together so the key is always a fixed length
        raw = f"{repo_url}:{commit_sha}"
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        # prefix makes it easy to find all scan keys in Redis
        # "scan:" namespace separates from other future key types
        return f"scan:{hashed}"

    def _make_job_key(self, job_id: str) -> str:
        # stores job status so frontend can poll it
        return f"job:{job_id}"

    async def get_scan_result(
        self, repo_url: str, commit_sha: str
    ) -> Optional[dict]:
        # returns cached scan result if it exists, None if not
        key = self._make_scan_key(repo_url, commit_sha)
        data = await self.redis.get(key)

        if data is None:
            return None

        # data is stored as JSON string, deserialize it back to dict
        return json.loads(data)

    async def set_scan_result(
        self, repo_url: str, commit_sha: str, result: dict
    ) -> None:
        key = self._make_scan_key(repo_url, commit_sha)
        # serialize dict to JSON string for storage
        # ex=cache_ttl means this key auto-deletes after N seconds
        # so stale results don't live forever
        await self.redis.set(
            key,
            json.dumps(result),
            ex=settings.cache_ttl_seconds,
        )

    async def set_job_status(
        self, job_id: str, status: dict
    ) -> None:
        # stores job progress so frontend can poll
        # status dict looks like:
        # {"status": "running", "scanned_files": 42, "total_files": 120}
        key = self._make_job_key(job_id)
        await self.redis.set(
            key,
            json.dumps(status),
            # jobs expire after scan timeout + buffer
            # no point keeping status around after job is long done
            ex=settings.scan_job_timeout_seconds + 60,
        )

    async def get_job_status(self, job_id: str) -> Optional[dict]:
        key = self._make_job_key(job_id)
        data = await self.redis.get(key)
        if data is None:
            return None
        return json.loads(data)

    async def delete_job_status(self, job_id: str) -> None:
        # clean up after job completes
        # result is in DB at this point, no need for Redis copy
        key = self._make_job_key(job_id)
        await self.redis.delete(key)

    async def ping(self) -> bool:
        # health check — used in /health route
        try:
            return await self.redis.ping()
        except Exception:
            return False

    async def close(self) -> None:
        await self.redis.aclose()


# singleton instance — one cache client for the whole app
# same pattern as get_settings()
_cache: Optional[CacheService] = None


def get_cache() -> CacheService:
    global _cache
    if _cache is None:
        _cache = CacheService(settings.redis_url)
    return _cache