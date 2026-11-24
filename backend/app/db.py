"""Step 6 - Database connection.

- Empty DATABASE_URL  -> app runs, nothing is saved.
- Database unreachable -> retries at startup, then runs without saving instead of crashing.
"""
import logging
import time

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from .config import settings
from .models import Base

log = logging.getLogger("uvicorn.error")

_url = settings.database_url
_pg_args = {
    "connect_timeout": 15,      # Neon free tier can take a few seconds to wake up
    "keepalives": 1,            # keep the connection alive on flaky networks
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 5,
}

engine = (
    create_engine(
        _url,
        pool_pre_ping=True,     # test each connection before use (Neon closes idle ones)
        pool_recycle=300,       # replace connections older than 5 minutes
        connect_args=_pg_args if _url.startswith("postgresql") else {},
    )
    if _url else None
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False) if engine else None
ready = False                   # True once tables exist and the DB answered


def init_db(retries: int = 4) -> bool:
    """Create missing tables. Safe to run repeatedly - existing tables are skipped."""
    global ready
    if engine is None:
        log.warning("DATABASE_URL is empty - checks will work but won't be saved")
        return False

    for attempt in range(1, retries + 1):
        try:
            Base.metadata.create_all(engine)
            ready = True
            log.info("Database ready")
            return True
        except OperationalError as e:
            log.warning("Database not reachable (attempt %d/%d): %s", attempt, retries, e.orig)
            engine.dispose()            # drop broken connections before retrying
            time.sleep(3 * attempt)

    log.error("Could not reach the database - checks will work but won't be saved")
    return False
