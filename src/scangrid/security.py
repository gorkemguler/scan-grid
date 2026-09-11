"""Auth helpers shared by the API, worker routes and dashboard."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)

from .config import Settings, get_settings

_bearer = HTTPBearer(auto_error=False)
_basic = HTTPBasic(auto_error=False)


def require_api_token(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> None:
    if creds is None or not secrets.compare_digest(creds.credentials, settings.api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_dashboard_user(
    creds: HTTPBasicCredentials | None = Depends(_basic),
    settings: Settings = Depends(get_settings),
) -> None:
    if not settings.dashboard_user:
        return
    ok = (
        creds is not None
        and secrets.compare_digest(creds.username, settings.dashboard_user)
        and secrets.compare_digest(creds.password, settings.dashboard_password)
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dashboard authentication required.",
            headers={"WWW-Authenticate": "Basic"},
        )
