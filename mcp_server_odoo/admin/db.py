"""PostgreSQL database manager for admin panel.

Manages user connections, teams, invites, and admin users.
Uses asyncpg for async PostgreSQL access.

Terminology:
- Team: a group of users sharing the same Odoo instance (grouped by odoo_url)
- UserConnection: a user's Odoo API key (self-service, one per user)
- Admin: a Zitadel subject with super-admin privileges (Pantalytics)
- Invite: a token-based invitation for a new team member
"""

import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import urlparse

import asyncpg

from .encryption import decrypt_api_key, encrypt_api_key

logger = logging.getLogger(__name__)

# Schema version for migrations
SCHEMA_VERSION = 8

SCHEMA_SQL = """
-- odoo-mcp-pro schema (c) Pantalytics B.V. -- pnl:a9c2e8
-- Admin users (Zitadel subjects)
CREATE TABLE IF NOT EXISTS admins (
    id          SERIAL PRIMARY KEY,
    zitadel_sub TEXT NOT NULL UNIQUE,
    email       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- User connections: self-service, each user manages their own Odoo connection
-- v3: one connection per user (no tenant dependency)
CREATE TABLE IF NOT EXISTS user_connections (
    id           SERIAL PRIMARY KEY,
    zitadel_sub  TEXT NOT NULL UNIQUE,
    email        TEXT,
    odoo_url     TEXT NOT NULL,
    odoo_api_key TEXT NOT NULL,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

-- v4: Usage tracking and rate limiting
CREATE TABLE IF NOT EXISTS usage_plans (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    daily_limit INTEGER NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO usage_plans (name, daily_limit) VALUES ('free', 1000)
ON CONFLICT (name) DO NOTHING;

ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS plan_id INTEGER REFERENCES usage_plans(id);

-- v5: Optional database name for self-hosted Odoo (14-18)
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS odoo_db TEXT;

-- v6: Connection verification info
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS odoo_version TEXT;
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS odoo_hosting TEXT;
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS last_error TEXT;

CREATE TABLE IF NOT EXISTS usage_log (
    id           BIGSERIAL PRIMARY KEY,
    zitadel_sub  TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    called_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms  INTEGER,
    error        BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_usage_log_sub_called ON usage_log (zitadel_sub, called_at);

CREATE TABLE IF NOT EXISTS usage_daily (
    id           BIGSERIAL PRIMARY KEY,
    zitadel_sub  TEXT NOT NULL,
    day          DATE NOT NULL,
    call_count   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (zitadel_sub, day)
);

-- v7: Teams and invites
CREATE TABLE IF NOT EXISTS teams (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    odoo_url        TEXT NOT NULL UNIQUE,
    created_by_sub  TEXT,
    zitadel_org_id  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS team_id INTEGER REFERENCES teams(id);
ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS team_role TEXT DEFAULT 'member';

CREATE TABLE IF NOT EXISTS invites (
    id           SERIAL PRIMARY KEY,
    team_id      INTEGER NOT NULL REFERENCES teams(id),
    email        TEXT NOT NULL,
    invite_token TEXT NOT NULL UNIQUE,
    invited_by   TEXT NOT NULL,
    accepted_at  TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invites_token ON invites (invite_token);

-- v8: Connection profiles (quick-switch between Odoo instances)
CREATE TABLE IF NOT EXISTS connection_profiles (
    id           SERIAL PRIMARY KEY,
    zitadel_sub  TEXT NOT NULL,
    label        TEXT NOT NULL,
    odoo_url     TEXT NOT NULL,
    odoo_api_key TEXT NOT NULL,
    odoo_db      TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_profiles_sub ON connection_profiles (zitadel_sub);

-- v9: Persistent PKCE state (survives blue-green deploys)
CREATE TABLE IF NOT EXISTS pending_auth (
    state        TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    next_url     TEXT DEFAULT '',
    created_at   TIMESTAMPTZ DEFAULT NOW()
);
"""

INVITE_EXPIRY_DAYS = 7


def _normalize_odoo_url(url: str) -> str:
    """Normalize an Odoo URL for team matching: lowercase, no trailing slash."""
    return url.lower().rstrip("/")


def _team_name_from_url(url: str) -> str:
    """Extract a human-readable team name from an Odoo URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    # Strip common prefixes/suffixes
    name = hostname.replace(".odoo.com", "").replace("www.", "")
    return name


@dataclass
class UserConnection:
    id: int
    zitadel_sub: str
    email: Optional[str]
    odoo_url: str
    odoo_api_key: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    plan_id: Optional[int] = None
    odoo_db: Optional[str] = None
    odoo_version: Optional[str] = None
    odoo_hosting: Optional[str] = None
    last_verified_at: Optional[datetime] = None
    last_error: Optional[str] = None
    team_id: Optional[int] = None
    team_role: Optional[str] = None


@dataclass
class Admin:
    id: int
    zitadel_sub: str
    email: Optional[str]
    created_at: datetime


@dataclass
class Team:
    id: int
    name: str
    odoo_url: str
    created_by_sub: Optional[str]
    zitadel_org_id: Optional[str]
    created_at: datetime


@dataclass
class Invite:
    id: int
    team_id: int
    email: str
    invite_token: str
    invited_by: str
    accepted_at: Optional[datetime]
    expires_at: datetime
    created_at: datetime

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_accepted(self) -> bool:
        return self.accepted_at is not None

    @property
    def is_pending(self) -> bool:
        return not self.is_accepted and not self.is_expired


@dataclass
class ConnectionProfile:
    id: int
    zitadel_sub: str
    label: str
    odoo_url: str
    odoo_api_key: str
    odoo_db: Optional[str]
    created_at: datetime


def get_database_url() -> str:
    """Get PostgreSQL connection URL from environment."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql://mcp:mcp@localhost:5432/mcp_admin",
    )


class DatabaseManager:
    """Async PostgreSQL database manager."""

    def __init__(self, database_url: Optional[str] = None):
        self._database_url = database_url or get_database_url()
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Create connection pool and initialize schema."""
        self._pool = await asyncpg.create_pool(self._database_url, min_size=2, max_size=10)
        await self._init_schema()
        logger.info("Database connected and schema initialized")

    async def close(self):
        """Close connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def _init_schema(self):
        """Initialize database schema and run backfill migrations."""
        async with self._pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
            row = await conn.fetchrow(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            )
            current_version = row["version"] if row else 0
            if current_version < SCHEMA_VERSION:
                await conn.execute(
                    "INSERT INTO schema_version (version) VALUES ($1)", SCHEMA_VERSION
                )

            # v7 backfill: create teams from existing user_connections grouped by odoo_url
            await self._backfill_teams(conn)

            # v8 backfill: create profiles from existing user_connections
            await self._backfill_profiles(conn)

        # Bootstrap admin if configured
        bootstrap_sub = os.getenv("ADMIN_BOOTSTRAP_SUB", "").strip()
        bootstrap_email = os.getenv("ADMIN_BOOTSTRAP_EMAIL", "").strip()
        if bootstrap_sub:
            await self.ensure_admin(bootstrap_sub, bootstrap_email or None)

    async def _backfill_teams(self, conn):
        """Backfill teams from existing user_connections (idempotent)."""
        # Find user_connections without a team_id
        orphans = await conn.fetch(
            "SELECT id, zitadel_sub, email, odoo_url, created_at FROM user_connections WHERE team_id IS NULL ORDER BY created_at ASC"
        )
        if not orphans:
            return

        logger.info(f"Backfilling teams for {len(orphans)} user connections")

        for row in orphans:
            normalized_url = _normalize_odoo_url(row["odoo_url"])
            name = _team_name_from_url(row["odoo_url"])

            # Get or create team
            team = await conn.fetchrow(
                "SELECT id FROM teams WHERE odoo_url = $1", normalized_url
            )
            if not team:
                team = await conn.fetchrow(
                    """INSERT INTO teams (name, odoo_url, created_by_sub)
                       VALUES ($1, $2, $3) RETURNING id""",
                    name, normalized_url, row["zitadel_sub"],
                )
                # First user for this team = admin
                await conn.execute(
                    "UPDATE user_connections SET team_id = $1, team_role = 'admin' WHERE id = $2",
                    team["id"], row["id"],
                )
                logger.info(f"Created team '{name}' ({normalized_url}), admin: {row['email']}")
            else:
                # Subsequent users = member
                await conn.execute(
                    "UPDATE user_connections SET team_id = $1, team_role = 'member' WHERE id = $2",
                    team["id"], row["id"],
                )

    async def _backfill_profiles(self, conn):
        """Create profiles from existing user_connections that don't have one (idempotent)."""
        rows = await conn.fetch("""
            SELECT uc.zitadel_sub, uc.odoo_url, uc.odoo_api_key, uc.odoo_db
            FROM user_connections uc
            WHERE NOT EXISTS (
                SELECT 1 FROM connection_profiles cp WHERE cp.zitadel_sub = uc.zitadel_sub
            )
        """)
        if not rows:
            return

        logger.info(f"Backfilling profiles for {len(rows)} user connections")
        for row in rows:
            label = _team_name_from_url(row["odoo_url"])
            await conn.execute(
                """INSERT INTO connection_profiles (zitadel_sub, label, odoo_url, odoo_api_key, odoo_db)
                   VALUES ($1, $2, $3, $4, $5)""",
                row["zitadel_sub"], label, _normalize_odoo_url(row["odoo_url"]),
                row["odoo_api_key"], row["odoo_db"],
            )

    # --- User Connections (self-service, one per user) ---

    async def get_user_connection_by_sub(self, zitadel_sub: str) -> Optional[UserConnection]:
        """Get a user's Odoo connection by their Zitadel subject ID."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM user_connections WHERE zitadel_sub = $1",
                zitadel_sub,
            )
            if not row:
                return None
            uc = UserConnection(**dict(row))
            uc.odoo_api_key = decrypt_api_key(uc.odoo_api_key)
            return uc

    async def upsert_user_connection(
        self,
        zitadel_sub: str,
        odoo_url: str,
        odoo_api_key: str,
        email: Optional[str] = None,
        odoo_db: Optional[str] = None,
    ) -> UserConnection:
        """Create or update a user's Odoo connection, auto-assigning team."""
        encrypted_key = encrypt_api_key(odoo_api_key)

        # Get or create team for this URL
        team = await self.get_or_create_team(odoo_url, zitadel_sub)

        # Check if this is a new connection (determines team_role)
        async with self._pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id, team_id FROM user_connections WHERE zitadel_sub = $1",
                zitadel_sub,
            )

            # Determine role: admin if first user for this team, else member
            if not existing:
                member_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM user_connections WHERE team_id = $1",
                    team.id,
                )
                role = "admin" if member_count == 0 else "member"
            else:
                # Keep existing role if staying on same team, reset to member if switching
                if existing["team_id"] == team.id:
                    role = None  # don't change
                else:
                    role = "member"

            if role is not None:
                row = await conn.fetchrow(
                    """INSERT INTO user_connections (zitadel_sub, email, odoo_url, odoo_api_key, odoo_db, team_id, team_role)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)
                       ON CONFLICT (zitadel_sub) DO UPDATE SET
                           email = COALESCE($2, user_connections.email),
                           odoo_url = $3,
                           odoo_api_key = $4,
                           odoo_db = $5,
                           team_id = $6,
                           team_role = $7,
                           is_active = TRUE,
                           updated_at = NOW()
                       RETURNING *""",
                    zitadel_sub, email, odoo_url, encrypted_key,
                    odoo_db or None, team.id, role,
                )
            else:
                row = await conn.fetchrow(
                    """INSERT INTO user_connections (zitadel_sub, email, odoo_url, odoo_api_key, odoo_db, team_id)
                       VALUES ($1, $2, $3, $4, $5, $6)
                       ON CONFLICT (zitadel_sub) DO UPDATE SET
                           email = COALESCE($2, user_connections.email),
                           odoo_url = $3,
                           odoo_api_key = $4,
                           odoo_db = $5,
                           team_id = $6,
                           is_active = TRUE,
                           updated_at = NOW()
                       RETURNING *""",
                    zitadel_sub, email, odoo_url, encrypted_key,
                    odoo_db or None, team.id,
                )

            uc = UserConnection(**dict(row))
            uc.odoo_api_key = decrypt_api_key(uc.odoo_api_key)
            logger.info(f"Upserted user connection: {zitadel_sub} -> {odoo_url} (team {team.id})")
            return uc

    async def list_all_connections(self) -> list:
        """List all user connections (for admin dashboard)."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM user_connections ORDER BY created_at DESC")
            connections = [UserConnection(**dict(row)) for row in rows]
            for uc in connections:
                uc.odoo_api_key = decrypt_api_key(uc.odoo_api_key)
            return connections

    async def update_verification(
        self,
        zitadel_sub: str,
        odoo_version: Optional[str] = None,
        odoo_hosting: Optional[str] = None,
        last_error: Optional[str] = None,
    ) -> None:
        """Update verification info for a user's connection."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """UPDATE user_connections SET
                    odoo_version = $2,
                    odoo_hosting = $3,
                    last_verified_at = NOW(),
                    last_error = $4
                WHERE zitadel_sub = $1""",
                zitadel_sub,
                odoo_version,
                odoo_hosting,
                last_error,
            )

    async def delete_user_connection(self, connection_id: int) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute("DELETE FROM user_connections WHERE id = $1", connection_id)
            return result == "DELETE 1"

    async def delete_user_connection_by_sub(self, zitadel_sub: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM user_connections WHERE zitadel_sub = $1", zitadel_sub
            )
            return result == "DELETE 1"

    # --- Admins ---

    async def is_admin(self, zitadel_sub: str) -> bool:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id FROM admins WHERE zitadel_sub = $1", zitadel_sub)
            return row is not None

    async def ensure_admin(self, zitadel_sub: str, email: Optional[str] = None) -> Admin:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO admins (zitadel_sub, email)
                   VALUES ($1, $2)
                   ON CONFLICT (zitadel_sub) DO UPDATE SET email = COALESCE($2, admins.email)
                   RETURNING *""",
                zitadel_sub,
                email,
            )
            admin = Admin(**dict(row))
            logger.info(f"Ensured admin: {zitadel_sub} ({email})")
            return admin

    async def list_admins(self) -> List[Admin]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM admins ORDER BY email, zitadel_sub")
            return [Admin(**dict(r)) for r in rows]

    async def remove_admin(self, admin_id: int) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute("DELETE FROM admins WHERE id = $1", admin_id)
            return result == "DELETE 1"

    # --- Teams ---

    async def get_or_create_team(self, odoo_url: str, created_by_sub: str) -> Team:
        """Get existing team for this Odoo URL or create a new one."""
        normalized = _normalize_odoo_url(odoo_url)
        name = _team_name_from_url(odoo_url)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO teams (name, odoo_url, created_by_sub)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (odoo_url) DO UPDATE SET name = teams.name
                   RETURNING *""",
                name, normalized, created_by_sub,
            )
            return Team(**dict(row))

    async def get_team_by_id(self, team_id: int) -> Optional[Team]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM teams WHERE id = $1", team_id)
            return Team(**dict(row)) if row else None

    async def list_teams(self) -> list:
        """List all teams with member counts (for super admin)."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT t.*,
                    COUNT(uc.id) AS member_count,
                    COALESCE(SUM(u.total_calls), 0) AS total_calls
                FROM teams t
                LEFT JOIN user_connections uc ON uc.team_id = t.id
                LEFT JOIN (
                    SELECT zitadel_sub, COUNT(*) AS total_calls
                    FROM usage_log GROUP BY zitadel_sub
                ) u ON uc.zitadel_sub = u.zitadel_sub
                GROUP BY t.id
                ORDER BY total_calls DESC
            """)
            return [dict(row) for row in rows]

    async def get_team_members(self, team_id: int) -> list:
        """Get all members of a team with usage stats."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    uc.id, uc.zitadel_sub, uc.email, uc.odoo_url, uc.is_active,
                    uc.created_at, uc.last_verified_at, uc.last_error,
                    uc.team_role,
                    COALESCE(u.total_calls, 0) AS total_calls
                FROM user_connections uc
                LEFT JOIN (
                    SELECT zitadel_sub, COUNT(*) AS total_calls
                    FROM usage_log
                    GROUP BY zitadel_sub
                ) u ON uc.zitadel_sub = u.zitadel_sub
                WHERE uc.team_id = $1
                ORDER BY uc.created_at ASC
            """, team_id)
            return [dict(row) for row in rows]

    async def remove_member_from_team(self, connection_id: int, team_id: int) -> bool:
        """Remove a member from a team (deletes their connection)."""
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM user_connections WHERE id = $1 AND team_id = $2",
                connection_id, team_id,
            )
            return result == "DELETE 1"

    # --- Invites ---

    async def create_invite(self, team_id: int, email: str, invited_by: str) -> Invite:
        """Create a new invite for a team member."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=INVITE_EXPIRY_DAYS)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO invites (team_id, email, invite_token, invited_by, expires_at)
                   VALUES ($1, $2, $3, $4, $5)
                   RETURNING *""",
                team_id, email, token, invited_by, expires_at,
            )
            return Invite(**dict(row))

    async def get_invite_by_token(self, token: str) -> Optional[Invite]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM invites WHERE invite_token = $1", token
            )
            return Invite(**dict(row)) if row else None

    async def accept_invite(self, token: str, zitadel_sub: str) -> Optional[Invite]:
        """Accept an invite: mark as accepted and return it."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """UPDATE invites SET accepted_at = NOW()
                   WHERE invite_token = $1 AND accepted_at IS NULL
                   RETURNING *""",
                token,
            )
            return Invite(**dict(row)) if row else None

    async def list_pending_invites(self, team_id: int) -> List[Invite]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT * FROM invites
                   WHERE team_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
                   ORDER BY created_at DESC""",
                team_id,
            )
            return [Invite(**dict(r)) for r in rows]

    async def revoke_invite(self, invite_id: int, team_id: int) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM invites WHERE id = $1 AND team_id = $2 AND accepted_at IS NULL",
                invite_id, team_id,
            )
            return result == "DELETE 1"

    # --- Connection Profiles ---

    async def upsert_profile(
        self, zitadel_sub: str, label: str, odoo_url: str, odoo_api_key: str, odoo_db: Optional[str] = None
    ) -> ConnectionProfile:
        """Save or update a connection profile."""
        encrypted_key = encrypt_api_key(odoo_api_key)
        normalized_url = _normalize_odoo_url(odoo_url)
        async with self._pool.acquire() as conn:
            # Check if profile with same label exists for this user
            existing = await conn.fetchrow(
                "SELECT id FROM connection_profiles WHERE zitadel_sub = $1 AND label = $2",
                zitadel_sub, label,
            )
            if existing:
                row = await conn.fetchrow(
                    """UPDATE connection_profiles SET odoo_url = $3, odoo_api_key = $4, odoo_db = $5
                       WHERE id = $1 AND zitadel_sub = $2 RETURNING *""",
                    existing["id"], zitadel_sub, normalized_url, encrypted_key, odoo_db,
                )
            else:
                row = await conn.fetchrow(
                    """INSERT INTO connection_profiles (zitadel_sub, label, odoo_url, odoo_api_key, odoo_db)
                       VALUES ($1, $2, $3, $4, $5) RETURNING *""",
                    zitadel_sub, label, normalized_url, encrypted_key, odoo_db,
                )
            profile = ConnectionProfile(**dict(row))
            profile.odoo_api_key = decrypt_api_key(profile.odoo_api_key)
            return profile

    async def list_profiles(self, zitadel_sub: str) -> List[ConnectionProfile]:
        """List all saved profiles for a user."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM connection_profiles WHERE zitadel_sub = $1 ORDER BY created_at",
                zitadel_sub,
            )
            profiles = [ConnectionProfile(**dict(r)) for r in rows]
            for p in profiles:
                p.odoo_api_key = decrypt_api_key(p.odoo_api_key)
            return profiles

    async def get_profile(self, profile_id: int, zitadel_sub: str) -> Optional[ConnectionProfile]:
        """Get a specific profile (owned by user)."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM connection_profiles WHERE id = $1 AND zitadel_sub = $2",
                profile_id, zitadel_sub,
            )
            if not row:
                return None
            profile = ConnectionProfile(**dict(row))
            profile.odoo_api_key = decrypt_api_key(profile.odoo_api_key)
            return profile

    async def delete_profile(self, profile_id: int, zitadel_sub: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM connection_profiles WHERE id = $1 AND zitadel_sub = $2",
                profile_id, zitadel_sub,
            )
            return result == "DELETE 1"

    # --- PKCE State (persistent, survives deploys) ---

    async def store_pending_auth(self, state: str, code_verifier: str, redirect_uri: str, next_url: str = ""):
        """Store PKCE state for OAuth callback."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO pending_auth (state, code_verifier, redirect_uri, next_url)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (state) DO UPDATE SET code_verifier=$2, redirect_uri=$3, next_url=$4, created_at=NOW()""",
                state, code_verifier, redirect_uri, next_url,
            )

    async def pop_pending_auth(self, state: str) -> Optional[dict]:
        """Retrieve and delete PKCE state. Returns None if not found or expired (>10 min)."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """DELETE FROM pending_auth
                   WHERE state = $1 AND created_at > NOW() - interval '10 minutes'
                   RETURNING code_verifier, redirect_uri, next_url""",
                state,
            )
            if not row:
                return None
            return {"code_verifier": row["code_verifier"], "redirect_uri": row["redirect_uri"], "next": row["next_url"]}

    async def cleanup_expired_auth(self):
        """Remove expired PKCE states (older than 10 minutes)."""
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM pending_auth WHERE created_at < NOW() - interval '10 minutes'")

    # --- Dashboard (super admin) ---

    async def get_usage_dashboard(self) -> list:
        """Get all users with aggregated usage stats for admin dashboard."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    uc.id, uc.email, uc.odoo_url, uc.odoo_db,
                    uc.odoo_version, uc.odoo_hosting, uc.is_active,
                    uc.created_at, uc.updated_at, uc.last_verified_at, uc.last_error,
                    uc.team_id, uc.team_role,
                    t.name AS team_name,
                    COALESCE(u.total_calls, 0) AS total_calls,
                    u.tools_used,
                    u.first_call,
                    u.last_call
                FROM user_connections uc
                LEFT JOIN teams t ON uc.team_id = t.id
                LEFT JOIN (
                    SELECT
                        zitadel_sub,
                        COUNT(*) AS total_calls,
                        array_agg(DISTINCT tool_name) AS tools_used,
                        MIN(called_at) AS first_call,
                        MAX(called_at) AS last_call
                    FROM usage_log
                    GROUP BY zitadel_sub
                ) u ON uc.zitadel_sub = u.zitadel_sub
                ORDER BY total_calls DESC
            """)
            return [dict(row) for row in rows]
