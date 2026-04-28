"""
MCPGuard — Authentication Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JWT verification for Clerk authentication and optional auth.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient


CLERK_JWKS_URL = os.getenv("CLERK_JWKS_URL", "")


def _get_token_from_header(request: Request) -> Optional[str]:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def _get_api_key_from_header(request: Request) -> Optional[str]:
    """Extract API key from X-API-Key header."""
    return request.headers.get("X-API-Key")


async def get_current_user(request: Request) -> dict:
    """
    Dependency that validates the Bearer token using Clerk's JWKS.

    Returns a dict with user info (sub, email, etc.) from the JWT claims.
    Raises 401 if token is missing or invalid.
    """
    token = _get_token_from_header(request)
    api_key = _get_api_key_from_header(request)

    if not token and not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "unauthorized", "message": "Authentication required. Provide a Bearer token or API key."}},
        )

    if token and CLERK_JWKS_URL:
        try:
            jwks_client = PyJWKClient(CLERK_JWKS_URL)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            return {
                "id": payload.get("sub"),
                "email": payload.get("email", ""),
                "metadata": payload.get("metadata", {}),
            }
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "token_expired", "message": "Authentication token has expired."}},
            )
        except (jwt.InvalidTokenError, Exception) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"code": "invalid_token", "message": "Invalid authentication token."}},
            )

    if api_key:
        # TODO: Validate API key against database
        return {"id": None, "email": "", "api_key": api_key}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "unauthorized", "message": "Could not validate credentials."}},
    )


async def optional_user(request: Request) -> Optional[dict]:
    """
    Dependency that returns user info if authenticated, None otherwise.
    Used for endpoints that work for both authenticated and anonymous users.
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None
