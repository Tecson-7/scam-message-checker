"""Step 6 - Tables: checks, links, reports, link_cache."""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# JSONB on Postgres, plain JSON elsewhere (lets tests run on SQLite)
JsonType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Check(Base):
    __tablename__ = "checks"
    __table_args__ = (UniqueConstraint("message_hash", "language", name="uq_check_hash_lang"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_hash: Mapped[str] = mapped_column(String(64), index=True)
    masked_text: Mapped[str] = mapped_column(Text)            # never the raw message
    language: Mapped[str] = mapped_column(String(5))
    verdict: Mapped[str] = mapped_column(String(20))
    score: Mapped[int] = mapped_column(Integer)
    category: Mapped[str | None] = mapped_column(String(40))  # filled by the LLM (Step 8)
    tactics: Mapped[list] = mapped_column(JsonType, default=list)
    reasons: Mapped[list] = mapped_column(JsonType, default=list)
    llm_result: Mapped[dict | None] = mapped_column(JsonType)  # cached LLM output (Step 8)
    times_checked: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    links: Mapped[list["Link"]] = relationship(back_populates="check", cascade="all, delete-orphan")


class Link(Base):
    __tablename__ = "links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    original_url: Mapped[str] = mapped_column(Text)
    final_url: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    domain_age_days: Mapped[int | None] = mapped_column(Integer)
    safe_browsing_hit: Mapped[bool | None] = mapped_column(Boolean)
    lookalike_of: Mapped[str | None] = mapped_column(String(50))
    risk: Mapped[int] = mapped_column(Integer, default=0)

    check: Mapped[Check] = relationship(back_populates="links")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"), unique=True)
    upvotes: Mapped[int] = mapped_column(Integer, default=0)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LinkCache(Base):
    """Link results cached for 24h so the same link doesn't hit the APIs again."""
    __tablename__ = "link_cache"

    url: Mapped[str] = mapped_column(Text, primary_key=True)
    result: Mapped[dict] = mapped_column(JsonType)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
