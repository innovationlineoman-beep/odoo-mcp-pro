"""OAuth 2.1 token verification via Zitadel introspection.

This module provides a TokenVerifier implementation that validates
Bearer tokens by calling Zitadel's RFC 7662 token introspection endpoint.

Security model:
- Claude.ai acts as a public client (PKCE, no client_secret) -- this is
  correct per OAuth 2.1 for browser/CLI clients that cannot keep secrets.
- The MCP server acts as a Resource Server and validates tokens via
  introspection using its own client_id:client_secret (confidential).
- Audience validation ensures tokens are intended for this resource server.

Used when the MCP server runs in HTTP transport mode with OAuth enabled.
Not used for stdio transport (local Claude Desktop).
"""

import base64
import logging
import time
from typing import Dict, List, Optional, Tuple

import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier

logger = logging.getLogger(__name__)

# Cache introspection results to reduce Zitadel round-trips
# Key: token hash, Value: (AccessToken, timestamp)
CACHE_TTL = 60  # seconds


class ZitadelTokenVerifier(TokenVerifier):
    """Validates Bearer tokens via Zitadel's introspection endpoint (RFC 7662).

    The MCP server acts as a Resource Server (RS). Zitadel is the
    Authorization Server (AS). Token validation uses the introspection
    endpoint with Basic Auth (client_id:client_secret).

    Security checks performed:
    1. Token is active (not revoked/expired) per Zitadel
    2. Audience matches this resource server (if configured)
    3. Required scopes are present (if configured)
    4. Token expiry is validated by the MCP middleware

    Introspection results are cached for 60 seconds to reduce latency
    and avoid hitting Zitadel rate limits.
    """

    def __init__(
        self,
        introspection_url: str,
        client_id: str,
        client_secret: str,
        expected_audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        timeout: int = 10,
    ):
        self.introspection_url = introspection_url
        self._auth_header = (
            "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        )
        self._expected_audience = expected_audience
        self._required_scopes = set(required_scopes) if required_scopes else set()
        self.timeout = timeout
        self._cache: Dict[str, Tuple[AccessToken, float]] = {}

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verify a Bearer token via Zitadel introspection.

        Results are cached for 60 seconds to reduce Zitadel round-trips.

        Args:
            token: The Bearer token from the Authorization header.

        Returns:
            AccessToken if valid, None if invalid/expired/wrong audience.
        """
        # Check cache first
        cache_key = token[-16:]  # last 16 chars as key (avoid storing full token)
        cached = self._cache.get(cache_key)
        if cached:
            access_token, cached_at = cached
            if time.time() - cached_at < CACHE_TTL:
                return access_token
            del self._cache[cache_key]

        # Introspect with retry
        result = await self._introspect(token)

        # Cache valid results
        if result:
            self._cache[cache_key] = (result, time.time())
            # Evict old entries periodically
            if len(self._cache) > 200:
                self._evict_expired()

        return result

    async def _introspect(self, token: str) -> Optional[AccessToken]:
        """Call Zitadel introspection endpoint with retry."""
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.introspection_url,
                        headers={
                            "Authorization": self._auth_header,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        data={"token": token},
                    )

                if response.status_code != 200:
                    logger.warning(f"Introspection endpoint returned {response.status_code}")
                    return None

                data = response.json()

                if not data.get("active"):
                    logger.debug("Token is not active")
                    return None

                # Audience validation (RFC 7662 S2.2)
                if self._expected_audience:
                    token_aud = data.get("aud", [])
                    if isinstance(token_aud, str):
                        token_aud = [token_aud]
                    if self._expected_audience not in token_aud:
                        logger.warning(
                            f"Token audience {token_aud} does not include "
                            f"expected audience {self._expected_audience}"
                        )
                        return None

                # Extract scopes
                scopes = data.get("scope", "").split() if data.get("scope") else []

                # Scope validation
                if self._required_scopes and not self._required_scopes.issubset(set(scopes)):
                    missing = self._required_scopes - set(scopes)
                    logger.warning(f"Token missing required scopes: {missing}")
                    return None

                # Extract user identity
                zitadel_sub = data.get("sub", data.get("client_id", "unknown"))
                client_id = zitadel_sub
                expires_at = data.get("exp")

                return AccessToken(
                    token=token,
                    client_id=client_id,
                    scopes=scopes,
                    expires_at=expires_at,
                )

            except httpx.TimeoutException:
                if attempt == 0:
                    logger.warning("Introspection timeout, retrying...")
                    continue
                logger.error(f"Token introspection timeout after {self.timeout}s (2 attempts)")
                return None
            except Exception as e:
                if attempt == 0:
                    logger.warning(f"Introspection error, retrying: {e}")
                    continue
                logger.error(f"Token introspection failed: {e}")
                return None

        return None

    def _evict_expired(self):
        """Remove expired entries from cache."""
        now = time.time()
        expired = [k for k, (_, ts) in self._cache.items() if now - ts >= CACHE_TTL]
        for k in expired:
            del self._cache[k]
