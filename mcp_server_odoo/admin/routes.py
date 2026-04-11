"""Self-service setup routes for user Odoo connections.

All routes require login authentication via the session cookie.
"""

import logging
import os

from fastapi import Request
from fastapi.responses import RedirectResponse

from .auth import (
    generate_csrf_token,
    require_admin,
    require_login,
    validate_csrf_token,
)

logger = logging.getLogger(__name__)


def register_admin_routes(app, db_manager):
    """Register self-service setup routes.

    Args:
        app: FastAPI app instance
        db_manager: DatabaseManager for user connection operations
    """

    async def _is_admin(user) -> bool:
        """Check if the current user is a super admin."""
        return await db_manager.is_admin(user["sub"])

    # --- Super admin dashboard ---

    @app.get("/dashboard")
    @require_admin
    async def admin_dashboard(request: Request):
        """Super admin dashboard: all users with usage stats."""
        admin = request.state.admin
        users = await db_manager.get_usage_dashboard()
        templates = request.app.state.templates
        return templates.TemplateResponse(
            "usage_dashboard.html",
            {
                "request": request,
                "user": admin,
                "is_admin": True,
                "users": users,
                "active_nav": "dashboard",
            },
        )

    # --- Self-service setup ---

    @app.get("/")
    @require_login
    async def index(request: Request):
        """Redirect root to setup page."""
        return RedirectResponse(url="/admin/setup", status_code=302)

    @app.get("/setup")
    @require_login
    async def setup_page(request: Request):
        """Self-service setup page: user manages their own Odoo connection."""
        user = request.state.user
        connection = await db_manager.get_user_connection_by_sub(user["sub"])

        mcp_server_url = _get_mcp_server_url()
        templates = request.app.state.templates

        # Pass last 3 chars of API key for display (masked)
        api_key_suffix = ""
        if connection and connection.odoo_api_key:
            api_key_suffix = connection.odoo_api_key[-3:]

        # Load saved profiles
        profiles = await db_manager.list_profiles(user["sub"])

        return templates.TemplateResponse(
            "setup.html",
            {
                "request": request,
                "user": user,
                "is_admin": await _is_admin(user),
                "connection": connection,
                "profiles": profiles,
                "api_key_suffix": api_key_suffix,
                "mcp_server_url": mcp_server_url,
                "csrf_token": generate_csrf_token(user),
                "active_nav": "setup",
            },
        )

    def _get_mcp_server_url() -> str:
        """Get the public MCP server URL for connection instructions."""
        url = os.getenv("OAUTH_RESOURCE_SERVER_URL", "").strip().rstrip("/")
        if not url:
            url = os.getenv("ADMIN_BASE_URL", "http://localhost:8000").strip().rstrip("/")
        return url

    @app.post("/setup")
    @require_login
    async def setup_save(request: Request):
        """Save the user's Odoo connection (URL + API key)."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/setup", status_code=302)

        odoo_url = form.get("odoo_url", "").strip().rstrip("/")
        odoo_api_key = form.get("odoo_api_key", "").strip()
        odoo_db = form.get("odoo_db", "").strip()

        # Clean URL: keep only scheme + hostname (strip paths like /web, /odoo, etc.)
        if odoo_url:
            from urllib.parse import urlparse

            parsed = urlparse(odoo_url)
            if parsed.scheme and parsed.hostname:
                port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
                odoo_url = f"{parsed.scheme}://{parsed.hostname}{port_str}"

        # For existing connections: fill in missing fields from current values
        existing = await db_manager.get_user_connection_by_sub(user["sub"])
        if existing:
            odoo_url = odoo_url or existing.odoo_url
            odoo_api_key = odoo_api_key or existing.odoo_api_key
            # odoo_db can be intentionally empty (cleared), so only fall back
            # if the form field was not present at all
            if "odoo_db" not in form:
                odoo_db = existing.odoo_db or ""
        else:
            # New connection: URL and API key are required
            if not odoo_url or not odoo_api_key:
                return RedirectResponse(url="/admin/setup", status_code=302)

        try:
            await db_manager.upsert_user_connection(
                zitadel_sub=user["sub"],
                odoo_url=odoo_url,
                odoo_api_key=odoo_api_key,
                email=user.get("email"),
                odoo_db=odoo_db or None,
            )
            # Auto-save as profile (label = domain name)
            from urllib.parse import urlparse

            label = form.get("profile_label", "").strip()
            if not label:
                parsed_host = urlparse(odoo_url).hostname or odoo_url
                label = parsed_host.replace(".odoo.com", "").replace("www.", "")
            await db_manager.upsert_profile(
                zitadel_sub=user["sub"],
                label=label,
                odoo_url=odoo_url,
                odoo_api_key=odoo_api_key,
                odoo_db=odoo_db or None,
            )
            # Invalidate registry cache so next MCP call uses new connection
            registry = request.app.state.registry
            if registry:
                registry.revoke_user(user["sub"])
            logger.info(f"User {user['email']} saved connection to {odoo_url}")
            return RedirectResponse(url="/admin/setup", status_code=302)
        except Exception as e:
            logger.error(f"Failed to save connection for {user['email']}: {e}")
            return RedirectResponse(url="/admin/setup", status_code=302)

    @app.post("/setup/delete")
    @require_login
    async def setup_delete(request: Request):
        """Delete the user's own connection."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/setup", status_code=302)

        await db_manager.delete_user_connection_by_sub(user["sub"])
        logger.info(f"User {user['email']} removed their connection")
        return RedirectResponse(url="/admin/setup", status_code=302)

    @app.post("/setup/switch")
    @require_login
    async def setup_switch_profile(request: Request):
        """Switch to a saved connection profile."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/setup", status_code=302)

        profile_id = form.get("profile_id", "")
        if not profile_id:
            return RedirectResponse(url="/admin/setup", status_code=302)

        profile = await db_manager.get_profile(int(profile_id), user["sub"])
        if not profile:
            return RedirectResponse(url="/admin/setup", status_code=302)

        # Update active connection from profile
        await db_manager.upsert_user_connection(
            zitadel_sub=user["sub"],
            odoo_url=profile.odoo_url,
            odoo_api_key=profile.odoo_api_key,
            email=user.get("email"),
            odoo_db=profile.odoo_db,
        )

        # Invalidate registry cache for immediate effect
        registry = request.app.state.registry
        if registry:
            registry.revoke_user(user["sub"])

        logger.info(f"User {user['email']} switched to profile '{profile.label}'")
        return RedirectResponse(url="/admin/setup", status_code=302)

    @app.post("/setup/delete-profile")
    @require_login
    async def setup_delete_profile(request: Request):
        """Delete a saved connection profile."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/setup", status_code=302)

        profile_id = form.get("profile_id", "")
        if profile_id:
            await db_manager.delete_profile(int(profile_id), user["sub"])
            logger.info(f"User {user['email']} deleted profile {profile_id}")

        return RedirectResponse(url="/admin/setup", status_code=302)

    @app.post("/setup/verify")
    @require_login
    async def setup_verify(request: Request):
        """Verify the user's Odoo connection and store debug info."""
        from ..config import OdooConfig
        from ..odoo_connection import OdooConnection
        from ..odoo_json2_connection import OdooJSON2Connection
        from ..performance import PerformanceManager
        from ..version_detect import detect_api_version

        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/setup", status_code=302)

        connection = await db_manager.get_user_connection_by_sub(user["sub"])
        if not connection:
            return RedirectResponse(url="/admin/setup", status_code=302)

        odoo_version = None
        odoo_hosting = None
        error_msg = None

        # Step 1: Check URL — can we reach the server?
        try:
            api_version, server_version = detect_api_version(connection.odoo_url)
            odoo_version = server_version
        except Exception as e:
            error_msg = f"Cannot reach Odoo at {connection.odoo_url}. Please check that the URL is correct (just the domain, e.g. https://mycompany.odoo.com) and the server is online."
            logger.warning(f"Verify URL failed for {user['email']}: {e}")
            await db_manager.update_verification(
                zitadel_sub=user["sub"],
                odoo_version=None,
                odoo_hosting=None,
                last_error=error_msg,
            )
            return RedirectResponse(url="/admin/setup", status_code=302)

        # Step 2: Determine hosting type
        url_lower = connection.odoo_url.lower()
        if ".odoo.com" in url_lower:
            odoo_hosting = "odoo.sh"
        else:
            odoo_hosting = "self-hosted"

        # Step 3: Try to connect and authenticate
        try:
            config = OdooConfig(
                url=connection.odoo_url,
                database=connection.odoo_db or "",
                api_key=connection.odoo_api_key,
                username=connection.email if api_version == "xmlrpc" else None,
                api_version=api_version,
            )

            if api_version == "json2":
                conn = OdooJSON2Connection(config)
            else:
                conn = OdooConnection(config, performance_manager=PerformanceManager(config))

            conn.connect()
            conn.authenticate()

            if conn.is_authenticated:
                logger.info(
                    f"Verify OK for {user['email']}: {odoo_version} ({odoo_hosting}), UID={conn.uid}"
                )
            else:
                if api_version == "xmlrpc":
                    error_msg = (
                        f"Authentication failed. Checked: URL OK ({odoo_version}), "
                        f"username '{connection.email}', "
                        f"database '{connection.odoo_db or 'auto-detect'}'. "
                        f"Please verify: (1) your API key is valid, "
                        f"(2) your Odoo login matches '{connection.email}', "
                        f"(3) the database name is correct."
                    )
                else:
                    error_msg = (
                        f"Authentication failed. URL OK ({odoo_version}). "
                        f"Please check that your API key is valid and not expired."
                    )

            conn.disconnect()

        except Exception as e:
            err = str(e)
            if api_version == "xmlrpc" and "database" in err.lower():
                error_msg = (
                    f"Database error. URL OK ({odoo_version}), but the database "
                    f"'{connection.odoo_db or 'auto-detect'}' could not be found. "
                    f"Please set the correct database name in Advanced settings."
                )
            elif "Authentication failed" in err:
                if api_version == "xmlrpc":
                    error_msg = (
                        f"Authentication failed. URL OK ({odoo_version}). "
                        f"Tried username '{connection.email}' with your API key "
                        f"on database '{connection.odoo_db or 'auto-detect'}'. "
                        f"Check all three values."
                    )
                else:
                    error_msg = (
                        f"Authentication failed. URL OK ({odoo_version}). "
                        f"Your API key appears to be invalid or expired."
                    )
            else:
                error_msg = f"Connection failed: {err[:300]}"
            logger.warning(f"Verify failed for {user['email']}: {error_msg}")

        # Store result
        await db_manager.update_verification(
            zitadel_sub=user["sub"],
            odoo_version=odoo_version,
            odoo_hosting=odoo_hosting,
            last_error=error_msg,
        )

        return RedirectResponse(url="/admin/setup", status_code=302)

    # --- Team ---

    @app.get("/team")
    @require_login
    async def team_page(request: Request):
        """Team page: see members sharing the same Odoo instance."""
        user = request.state.user
        connection = await db_manager.get_user_connection_by_sub(user["sub"])
        templates = request.app.state.templates

        team = None
        team_members = []
        pending_invites = []
        is_team_admin = False

        if connection and connection.team_id:
            team = await db_manager.get_team_by_id(connection.team_id)
            team_members = await db_manager.get_team_members(connection.team_id)
            pending_invites = await db_manager.list_pending_invites(connection.team_id)
            is_team_admin = connection.team_role == "admin"

        base_url = os.getenv("ADMIN_BASE_URL", "http://localhost:8000").rstrip("/")

        return templates.TemplateResponse(
            "team.html",
            {
                "request": request,
                "user": user,
                "is_admin": await _is_admin(user),
                "connection": connection,
                "team": team,
                "team_members": team_members,
                "pending_invites": pending_invites,
                "is_team_admin": is_team_admin,
                "base_url": base_url,
                "csrf_token": generate_csrf_token(user),
                "active_nav": "team",
            },
        )

    @app.post("/team/invite")
    @require_login
    async def team_invite(request: Request):
        """Team admin creates an invite."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/team", status_code=302)

        connection = await db_manager.get_user_connection_by_sub(user["sub"])
        if not connection or not connection.team_id or connection.team_role != "admin":
            return RedirectResponse(url="/admin/team", status_code=302)

        email = form.get("email", "").strip().lower()
        if not email or "@" not in email:
            return RedirectResponse(url="/admin/team", status_code=302)

        invite = await db_manager.create_invite(
            team_id=connection.team_id,
            email=email,
            invited_by=user["sub"],
        )
        logger.info(
            f"Team invite created by {user['email']} for {email} (token: {invite.invite_token[:8]}...)"
        )
        return RedirectResponse(url="/admin/team", status_code=302)

    @app.post("/team/revoke-invite")
    @require_login
    async def team_revoke_invite(request: Request):
        """Team admin revokes a pending invite."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/team", status_code=302)

        connection = await db_manager.get_user_connection_by_sub(user["sub"])
        if not connection or not connection.team_id or connection.team_role != "admin":
            return RedirectResponse(url="/admin/team", status_code=302)

        invite_id = form.get("invite_id", "")
        if invite_id:
            await db_manager.revoke_invite(int(invite_id), connection.team_id)
            logger.info(f"Invite {invite_id} revoked by {user['email']}")

        return RedirectResponse(url="/admin/team", status_code=302)

    @app.post("/team/remove")
    @require_login
    async def team_remove_member(request: Request):
        """Team admin removes a member."""
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url="/admin/team", status_code=302)

        connection = await db_manager.get_user_connection_by_sub(user["sub"])
        if not connection or not connection.team_id or connection.team_role != "admin":
            return RedirectResponse(url="/admin/team", status_code=302)

        member_id = form.get("member_id", "")
        if member_id:
            # Prevent removing yourself
            if int(member_id) == connection.id:
                return RedirectResponse(url="/admin/team", status_code=302)
            await db_manager.remove_member_from_team(int(member_id), connection.team_id)
            logger.info(f"Member {member_id} removed by {user['email']}")

        return RedirectResponse(url="/admin/team", status_code=302)

    # --- Invite accept (public route, requires login) ---

    @app.get("/invite/{token}")
    @require_login
    async def invite_accept_page(request: Request):
        """Show invite accept page."""
        token = request.path_params["token"]
        user = request.state.user
        templates = request.app.state.templates

        invite = await db_manager.get_invite_by_token(token)
        if not invite:
            return templates.TemplateResponse(
                "invite_accept.html",
                {
                    "request": request,
                    "user": user,
                    "is_admin": False,
                    "error": "Invite not found.",
                    "invite": None,
                    "team": None,
                    "active_nav": None,
                },
            )

        if invite.is_accepted:
            return templates.TemplateResponse(
                "invite_accept.html",
                {
                    "request": request,
                    "user": user,
                    "is_admin": False,
                    "error": "This invite has already been used.",
                    "invite": None,
                    "team": None,
                    "active_nav": None,
                },
            )

        if invite.is_expired:
            return templates.TemplateResponse(
                "invite_accept.html",
                {
                    "request": request,
                    "user": user,
                    "is_admin": False,
                    "error": "This invite has expired.",
                    "invite": None,
                    "team": None,
                    "active_nav": None,
                },
            )

        team = await db_manager.get_team_by_id(invite.team_id)

        return templates.TemplateResponse(
            "invite_accept.html",
            {
                "request": request,
                "user": user,
                "is_admin": await _is_admin(user),
                "invite": invite,
                "team": team,
                "error": None,
                "csrf_token": generate_csrf_token(user),
                "active_nav": None,
            },
        )

    @app.post("/invite/{token}/accept")
    @require_login
    async def invite_accept(request: Request):
        """Accept an invite: join the team."""
        token = request.path_params["token"]
        user = request.state.user
        form = await request.form()

        csrf_token = form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            return RedirectResponse(url=f"/admin/invite/{token}", status_code=302)

        invite = await db_manager.get_invite_by_token(token)
        if not invite or invite.is_accepted or invite.is_expired:
            return RedirectResponse(url=f"/admin/invite/{token}", status_code=302)

        team = await db_manager.get_team_by_id(invite.team_id)
        if not team:
            return RedirectResponse(url=f"/admin/invite/{token}", status_code=302)

        # Accept the invite
        await db_manager.accept_invite(token, user["sub"])

        # Check if user already has a connection
        existing = await db_manager.get_user_connection_by_sub(user["sub"])
        if existing:
            # Update their team assignment
            async with db_manager._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE user_connections SET team_id = $1, team_role = 'member', odoo_url = $2, updated_at = NOW() WHERE zitadel_sub = $3",
                    team.id,
                    team.odoo_url,
                    user["sub"],
                )
        # If no connection yet, they'll set it up on the setup page (team_id will be assigned via upsert)

        logger.info(f"Invite accepted by {user['email']} for team {team.name}")
        return RedirectResponse(url="/admin/setup", status_code=302)
