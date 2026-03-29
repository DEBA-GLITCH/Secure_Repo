# backend/app/workers/arq_settings.py
from arq.connections import RedisSettings
from app.config import get_settings
from app.workers.scan_worker import run_scan

settings = get_settings()

# parse redis URL into host/port
# arq needs host and port separately, not a full URL string
def _parse_redis(url: str):
    # url format: redis://localhost:6379
    url   = url.replace("redis://", "")
    parts = url.split(":")
    host  = parts[0]
    port  = int(parts[1]) if len(parts) > 1 else 6379
    return host, port

_host, _port = _parse_redis(settings.redis_url)


class WorkerSettings:
    # list of async functions this worker can execute
    # ARQ matches job names to these functions
    functions = [run_scan]

    # Redis connection for the worker
    redis_settings = RedisSettings(host=_host, port=_port)

    # if a job crashes, retry up to 2 times
    max_tries = 2

    # each job gets max 5 minutes before ARQ force-kills it
    job_timeout = 600  # 10 minutes hard limit

    # poll Redis for new jobs every second
    poll_delay = 1.0

    # called once when worker process starts
    # good place to warm up DB connections, load models etc
    async def on_startup(ctx: dict):
        print("securerepo worker started")

    # called once when worker process shuts down
    async def on_shutdown(ctx: dict):
        print("securerepo worker shutting down")