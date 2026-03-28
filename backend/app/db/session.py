# backend/app/db/session.py
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.config import get_settings

settings = get_settings()

# ── Engine ────────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,

    # how many connections to keep open in the pool at all times
    # think of it like a pool of DB connections ready to be handed out
    # when a request comes in it grabs one, uses it, puts it back
    pool_size=10,

    # if all 10 connections are busy, allow up to 20 extra temporary ones
    # those 20 get destroyed after use, the core 10 stay alive
    max_overflow=20,

    # if a connection sits unused for 30 min, close and replace it
    # prevents "connection gone stale" errors on supabase
    pool_recycle=1800,

    # before handing a connection to your code, test it's still alive
    # costs one tiny round trip but saves you from dead connection errors
    pool_pre_ping=True,

    # echo=True prints every SQL query to terminal — useful while building
    # set to False in production (spammy and leaks query structure in logs)
    echo=settings.app_env == "development",
)

# ── Session factory ───────────────────────────────────────────────────────────
# async_sessionmaker creates AsyncSession objects on demand
# expire_on_commit=False means after you commit, objects stay usable
# without this, accessing an attribute after commit triggers another DB query
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Dependency ────────────────────────────────────────────────────────────────
async def get_db() -> AsyncSession:
    # this is a FastAPI dependency — used like:
    # async def my_route(db: AsyncSession = Depends(get_db)):
    #
    # the "async with" guarantees the session is ALWAYS closed
    # even if an exception is thrown mid-request
    # no leaked connections, ever
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            # something went wrong — roll back ALL changes from this request
            # database stays clean, no half-written data
            await session.rollback()
            raise