from collections.abc import Generator

from sqlalchemy import event, text
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.settings import get_settings

settings = get_settings()

if settings.database_url.startswith("sqlite"):
    # NullPool: no connection pooling for SQLite.
    # SQLite connections are cheap to create; pooling only causes contention when
    # many FastAPI threads try to check out a connection simultaneously.
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _record) -> None:
        """Apply performance + concurrency SQLite pragmas on every new connection."""
        cur = dbapi_conn.cursor()
        # WAL allows concurrent readers and a single writer (huge concurrency gain)
        cur.execute("PRAGMA journal_mode=WAL")
        # NORMAL is safe with WAL and much faster than FULL
        cur.execute("PRAGMA synchronous=NORMAL")
        # 64 MB page cache per connection
        cur.execute("PRAGMA cache_size=-65536")
        # Keep temp tables in memory
        cur.execute("PRAGMA temp_store=MEMORY")
        # Increase busy timeout so writers don't fail immediately under contention
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()
else:
    engine = create_engine(settings.database_url)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
