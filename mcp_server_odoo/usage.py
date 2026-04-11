"""Usage tracking and rate limiting for MCP tool calls.

Tracks per-user tool usage in Postgres and enforces daily rate limits.
Uses an in-memory cache to avoid a DB round-trip on every call.
Recording is fire-and-forget so tool calls are never slowed by tracking.

Optional PostHog integration: set POSTHOG_API_KEY env var to enable.
"""

import asyncio
import logging
import os
from datetime import date
from typing import Optional

import asyncpg

from .error_handling import ValidationError

logger = logging.getLogger(__name__)

# Default daily limit when user has no plan assigned
DEFAULT_DAILY_LIMIT = 1000


def _init_posthog():
    """Initialize PostHog client if API key is configured."""
    api_key = os.getenv("POSTHOG_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        from posthog import Posthog

        client = Posthog(api_key, host="https://eu.i.posthog.com")
        logger.info("PostHog analytics enabled")
        return client
    except Exception:
        logger.warning("PostHog import failed — analytics disabled")
        return None


_posthog_client = None


def _get_posthog():
    """Lazy-init PostHog client (called once on first use)."""
    global _posthog_client
    if _posthog_client is None:
        _posthog_client = _init_posthog() or False  # False = tried and failed/disabled
    return _posthog_client if _posthog_client is not False else None


def track_event(event: str, distinct_id: str = "server", properties: Optional[dict] = None):
    """Track a server-side event in PostHog. Fire-and-forget, never raises."""
    try:
        ph = _get_posthog()
        if ph:
            ph.capture(distinct_id=distinct_id, event=event, properties=properties or {})
    except Exception:
        pass


class RateLimitExceeded(ValidationError):
    """Raised when a user exceeds their daily call limit."""

    def __init__(self, limit: int, used: int):
        self.limit = limit
        self.used = used
        super().__init__(
            f"Daily rate limit exceeded: {used}/{limit} calls used today. Resets at midnight UTC."
        )


class UsageTracker:
    """Tracks MCP tool usage and enforces rate limits.

    Uses the existing asyncpg pool from DatabaseManager.
    """

    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool
        # In-memory cache: {zitadel_sub: (day, count, limit)}
        self._cache: dict[str, tuple[date, int, int]] = {}

    async def check_rate_limit(self, zitadel_sub: str) -> None:
        """Check if user is within their daily rate limit.

        Raises RateLimitExceeded if limit is exceeded.
        """
        today = date.today()

        # Check in-memory cache first
        cached = self._cache.get(zitadel_sub)
        if cached and cached[0] == today:
            _, count, limit = cached
            if limit > 0 and count >= limit:
                raise RateLimitExceeded(limit, count)
            return

        # Cache miss or stale day — query Postgres
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COALESCE(ud.call_count, 0) AS call_count,
                    COALESCE(up.daily_limit, $3) AS daily_limit
                FROM user_connections uc
                LEFT JOIN usage_plans up ON uc.plan_id = up.id
                LEFT JOIN usage_daily ud
                    ON ud.zitadel_sub = uc.zitadel_sub AND ud.day = $2
                WHERE uc.zitadel_sub = $1
                """,
                zitadel_sub,
                today,
                DEFAULT_DAILY_LIMIT,
            )

        if row is None:
            # User not found — let it pass, tool handler will fail with "no connection"
            return

        count = row["call_count"]
        limit = row["daily_limit"]
        self._cache[zitadel_sub] = (today, count, limit)

        if limit > 0 and count >= limit:
            raise RateLimitExceeded(limit, count)

    async def record_usage(
        self,
        zitadel_sub: str,
        tool_name: str,
        error: bool = False,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Record a tool call. Safe to call fire-and-forget."""
        today = date.today()
        try:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO usage_log (zitadel_sub, tool_name, error, duration_ms)
                        VALUES ($1, $2, $3, $4)
                        """,
                        zitadel_sub,
                        tool_name,
                        error,
                        duration_ms,
                    )
                    await conn.execute(
                        """
                        INSERT INTO usage_daily (zitadel_sub, day, call_count)
                        VALUES ($1, $2, 1)
                        ON CONFLICT (zitadel_sub, day) DO UPDATE
                        SET call_count = usage_daily.call_count + 1
                        """,
                        zitadel_sub,
                        today,
                    )

            # Update in-memory cache
            cached = self._cache.get(zitadel_sub)
            if cached and cached[0] == today:
                self._cache[zitadel_sub] = (today, cached[1] + 1, cached[2])
            else:
                self._cache.pop(zitadel_sub, None)

        except Exception:
            logger.exception(f"Failed to record usage for {zitadel_sub}")

        # PostHog event (non-blocking, failures silenced)
        try:
            ph = _get_posthog()
            if ph:
                ph.capture(
                    distinct_id=zitadel_sub,
                    event="mcp_tool_called",
                    properties={
                        "tool_name": tool_name,
                        "error": error,
                        "duration_ms": duration_ms,
                    },
                )
        except Exception:
            pass  # never let analytics break tool calls

    def record_usage_fire_and_forget(
        self,
        zitadel_sub: str,
        tool_name: str,
        error: bool = False,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Schedule usage recording without awaiting. Non-blocking."""
        try:
            asyncio.get_event_loop().create_task(
                self.record_usage(zitadel_sub, tool_name, error, duration_ms)
            )
        except RuntimeError:
            logger.debug("No event loop — skipping usage recording")
