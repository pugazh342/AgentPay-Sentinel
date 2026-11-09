"""SQLite/SQLAlchemy database setup."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.persistence.orm import Base


class Database:
    """Owns the SQLAlchemy engine and request-scoped sessions."""

    def __init__(self, url: str) -> None:
        is_sqlite = url.startswith("sqlite")
        is_memory = is_sqlite and ":memory:" in url
        engine_kwargs: dict = {"future": True}
        if is_sqlite:
            engine_kwargs["connect_args"] = {"check_same_thread": False}
        if is_memory:
            engine_kwargs["poolclass"] = StaticPool

        self.engine: Engine = create_engine(url, **engine_kwargs)
        if is_sqlite:
            event.listen(self.engine, "connect", self._enable_sqlite_foreign_keys)
        self._session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
            autoflush=False,
        )

    @staticmethod
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()
