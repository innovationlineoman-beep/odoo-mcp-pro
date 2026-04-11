"""OAuth login flow for the admin panel.

Handles Zitadel OIDC Authorization Code + PKCE login for admin users.
"""

import hashlib
import logging
import os
import secrets
from functools import wraps
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

from ..usage import track_event

logger = logging.getLogger(__name__)

# Session cookie name
SESSION_COOKIE = "admin_session"

# Session max age: 8 hours
SESSION_MAX_AGE = 8 * 60 * 60

# PKCE state: stored in Postgres via db_manager (survives blue-green deploys)
_db_manager = None


def _get_serializer() -> URLSafeTimedSerializer:
    """Get the session cookie serializer."""
    secret = os.getenv("ADMIN_SESSION_SECRET", "").strip()
    if not secret:
        raise RuntimeError("ADMIN_SESSION_SECRET environment variable is required")
    return URLSafeTimedSerializer(secret)


def _get_csrf_serializer() -> URLSafeTimedSerializer:
    """Get the CSRF token serializer (uses same secret, different salt)."""
    secret = os.getenv("ADMIN_SESSION_SECRET", "").strip()
    if not secret:
        raise RuntimeError("ADMIN_SESSION_SECRET environment variable is required")
    return URLSafeTimedSerializer(secret, salt="csrf-token")


def generate_csrf_token(session_data: dict) -> str:
    """Generate a CSRF token tied to the current session."""
    s = _get_csrf_serializer()
    return s.dumps(session_data.get("sub", "anonymous"))


def validate_csrf_token(token: str, max_age: int = SESSION_MAX_AGE) -> bool:
    """Validate a CSRF token."""
    try:
        s = _get_csrf_serializer()
        s.loads(token, max_age=max_age)
        return True
    except BadSignature:
        return False


def get_session(request: Request) -> Optional[dict]:
    """Read and validate the session cookie.

    Returns:
        Session data dict with 'sub' and 'email', or None if invalid/missing.
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    try:
        s = _get_serializer()
        data = s.loads(cookie, max_age=SESSION_MAX_AGE)
        return data
    except BadSignature:
        return None


def set_session(response, data: dict):
    """Set a signed session cookie on the response."""
    s = _get_serializer()
    value = s.dumps(data)
    response.set_cookie(
        SESSION_COOKIE,
        value,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=os.getenv("ADMIN_COOKIE_SECURE", "true").lower() == "true",
    )


def clear_session(response):
    """Clear the session cookie."""
    response.delete_cookie(SESSION_COOKIE)


async def get_current_user(request: Request) -> Optional[dict]:
    """Get the current user from the session.

    Returns:
        Dict with 'sub', 'email', and 'is_admin' if authenticated, None otherwise.
    """
    return get_session(request)


async def get_current_admin(request: Request) -> Optional[dict]:
    """Get the current admin from the session.

    Returns:
        Dict with 'sub' and 'email' if authenticated admin, None otherwise.
    """
    session = get_session(request)
    if not session:
        return None
    if not session.get("is_admin"):
        return None
    return session


def require_login(func):
    """Decorator that requires any authenticated user.

    Redirects to login if not authenticated.
    """

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        user = await get_current_user(request)
        if not user:
            # Preserve current path as ?next= so user returns here after login
            next_url = request.url.path
            return RedirectResponse(url=f"/admin/login/start?next={next_url}", status_code=302)
        # Inject user into request state for easy access
        request.state.user = user
        return await func(request, *args, **kwargs)

    return wrapper


def require_admin(func):
    """Decorator that requires admin authentication.

    Redirects to login if not authenticated or not admin.
    """

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        admin = await get_current_admin(request)
        if not admin:
            return RedirectResponse(url="/admin/login/start", status_code=302)
        # Inject admin into request state for easy access
        request.state.admin = admin
        return await func(request, *args, **kwargs)

    return wrapper


def register_auth_routes(app, db_manager, zitadel_issuer_url: str):
    """Register OAuth login/callback/logout routes.

    Args:
        app: FastAPI app instance
        db_manager: DatabaseManager for admin checks
        zitadel_issuer_url: Zitadel issuer URL (e.g. https://my-instance.zitadel.cloud)
    """
    global _db_manager
    _db_manager = db_manager
    issuer = zitadel_issuer_url.rstrip("/")
    client_id = os.getenv("ADMIN_OAUTH_CLIENT_ID", "").strip()
    base_url = os.getenv("ADMIN_BASE_URL", "http://localhost:8000").rstrip("/")

    if not client_id:
        logger.warning("ADMIN_OAUTH_CLIENT_ID not set — admin OAuth login will fail")

    # Dev login: set ADMIN_DEV_LOGIN=true for local testing without Zitadel
    if os.getenv("ADMIN_DEV_LOGIN", "").lower() == "true":

        @app.get("/login/dev")
        async def admin_dev_login(request: Request):
            """Dev-only: instant admin login without Zitadel."""
            bootstrap_sub = os.getenv("ADMIN_BOOTSTRAP_SUB", "dev-admin-001")
            bootstrap_email = os.getenv("ADMIN_BOOTSTRAP_EMAIL", "dev@localhost")
            session_data = {"sub": bootstrap_sub, "email": bootstrap_email, "is_admin": True}
            response = RedirectResponse(url="/admin/dashboard", status_code=302)
            set_session(response, session_data)
            return response

        logger.warning("Dev login enabled at /admin/login/dev — DO NOT use in production")

    @app.get("/login")
    async def admin_login(request: Request):
        """Redirect to Zitadel login, or to setup if already logged in."""
        session = get_session(request)
        if session:
            return RedirectResponse(url="/admin/setup", status_code=302)

        return RedirectResponse(url="/admin/login/start", status_code=302)

    @app.get("/login/start")
    async def admin_login_start(request: Request):
        """Start OAuth flow: redirect to Zitadel authorization endpoint."""
        # Generate PKCE code verifier and challenge
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = hashlib.sha256(code_verifier.encode("ascii")).digest()
        import base64

        code_challenge_b64 = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("ascii")

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        redirect_uri = f"{base_url}/admin/callback"

        # Store PKCE verifier keyed by state (in Postgres, survives deploys)
        next_url = request.query_params.get("next", "")
        await _db_manager.store_pending_auth(state, code_verifier, redirect_uri, next_url)

        # Build authorization URL
        action = request.query_params.get("action", "")
        prompt = "create" if action == "register" else "select_account"
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": f"openid profile email urn:zitadel:iam:org:id:{os.getenv('ZITADEL_ORG_ID')}",
            "state": state,
            "code_challenge": code_challenge_b64,
            "code_challenge_method": "S256",
            "prompt": prompt,
        }

        auth_url = f"{issuer}/oauth/v2/authorize?{urlencode(params)}"
        return RedirectResponse(url=auth_url, status_code=302)

    @app.options("/callback")
    async def admin_callback_options(request: Request):
        """Handle CORS preflight for OAuth callback."""
        from starlette.responses import Response

        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )

    @app.get("/callback")
    async def admin_callback(request: Request):
        """Handle OAuth callback from Zitadel."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            error_desc = request.query_params.get("error_description", "")
            logger.warning(f"OAuth error: {error} - {error_desc}")
            track_event(
                "auth_callback_error", properties={"error": error, "description": error_desc}
            )
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "access_denied.html",
                {"request": request, "message": f"OAuth error: {error}"},
                status_code=403,
            )

        if not code or not state:
            track_event("auth_callback_error", properties={"error": "missing_code_or_state"})
            return RedirectResponse(url="/admin/login", status_code=302)

        # Validate state and get PKCE verifier (from Postgres, survives deploys)
        pending = await _db_manager.pop_pending_auth(state)
        if not pending:
            logger.warning("Invalid or expired OAuth state")
            track_event("auth_state_invalid")
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "auth_error.html",
                {
                    "request": request,
                    "error": "Login session expired. This can happen during a server update. Please try again.",
                    "retry_url": "/admin/login",
                },
                status_code=400,
            )

        # Exchange code for tokens
        token_url = f"{issuer}/oauth/v2/token"
        try:
            async with httpx.AsyncClient(timeout=10) as http_client:
                token_response = await http_client.post(
                    token_url,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": pending["redirect_uri"],
                        "client_id": client_id,
                        "code_verifier": pending["code_verifier"],
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if token_response.status_code != 200:
                logger.error(
                    f"Token exchange failed: {token_response.status_code} {token_response.text}"
                )
                track_event(
                    "auth_token_exchange_failed", properties={"status": token_response.status_code}
                )
                templates = request.app.state.templates
                return templates.TemplateResponse(
                    "access_denied.html",
                    {"request": request, "message": "Token exchange failed"},
                    status_code=403,
                )

            token_data = token_response.json()
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            track_event("auth_token_exchange_failed", properties={"error": str(e)[:200]})
            return RedirectResponse(url="/admin/login", status_code=302)

        # Get user info from Zitadel
        access_token = token_data.get("access_token")
        if not access_token:
            return RedirectResponse(url="/admin/login", status_code=302)

        try:
            async with httpx.AsyncClient(timeout=10) as http_client:
                userinfo_response = await http_client.get(
                    f"{issuer}/oidc/v1/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )

            if userinfo_response.status_code != 200:
                logger.error(f"Userinfo failed: {userinfo_response.status_code}")
                track_event(
                    "auth_userinfo_failed", properties={"status": userinfo_response.status_code}
                )
                templates = request.app.state.templates
                return templates.TemplateResponse(
                    "auth_error.html",
                    {
                        "request": request,
                        "error": "Could not retrieve your account information. Please try again.",
                        "retry_url": "/admin/login",
                    },
                    status_code=502,
                )

            userinfo = userinfo_response.json()
        except Exception as e:
            logger.error(f"Userinfo error: {e}")
            track_event("auth_userinfo_failed", properties={"error": str(e)[:200]})
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "auth_error.html",
                {
                    "request": request,
                    "error": "Login failed due to a temporary error. Please try again.",
                    "retry_url": "/admin/login",
                },
                status_code=502,
            )

        zitadel_sub = userinfo.get("sub", "")
        email = userinfo.get("email", "")

        # Check if user is admin
        is_admin = await db_manager.is_admin(zitadel_sub)

        # Set session for all authenticated users
        session_data = {
            "sub": zitadel_sub,
            "email": email,
            "is_admin": is_admin,
        }

        # Redirect to ?next= URL if set (e.g. invite link), otherwise setup page
        next_url = pending.get("next", "")
        if next_url and next_url.startswith("/admin/"):
            redirect_url = next_url
        else:
            redirect_url = "/admin/setup"
        response = RedirectResponse(url=redirect_url, status_code=302)
        set_session(response, session_data)

        role = "admin" if is_admin else "user"
        logger.info(f"{role.capitalize()} logged in: {email} ({zitadel_sub})")
        track_event("auth_login_success", distinct_id=zitadel_sub, properties={"role": role})
        return response

    @app.get("/logout")
    async def admin_logout(request: Request):
        """Clear session and redirect to Zitadel end session endpoint.

        This ends both the local session (cookie) and the Zitadel session,
        so the user can pick a different account on next login.
        """
        response = RedirectResponse(url="/admin/login", status_code=302)
        clear_session(response)

        # If Zitadel is configured, redirect to end_session endpoint
        if issuer:
            from urllib.parse import urlencode

            post_logout_uri = f"{base_url}/admin/login"
            end_session_url = f"{issuer}/oidc/v1/end_session?" + urlencode(
                {"post_logout_redirect_uri": post_logout_uri}
            )
            response = RedirectResponse(url=end_session_url, status_code=302)
            clear_session(response)

        return response
