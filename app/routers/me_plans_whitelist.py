# app/routers/me_plans_whitelist.py
from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, Body, Security
from pydantic import BaseModel, Field

from .utils.identity_utils import (
    _save_whitelist_to_disk,
    _WHITELIST_FILE,
    _COGNITO_WHITELIST,
    _WHITELIST_LOCK,
)
from ..security import require_admin_api_key

router = APIRouter(
    prefix="/me/plans",
    tags=["me-plans-whitelist"],
    responses={
        401: {"description": "Unauthorized (admin api key mancante/invalid)"},
        403: {"description": "Forbidden"},
    },
)

class WhitelistPatch(BaseModel):
    replace: Optional[List[str]] = None
    add: List[str] = Field(default_factory=list)
    remove: List[str] = Field(default_factory=list)

@router.get(
    "/whitelist",
    summary="Legge la whitelist (Cognito 'sub') abilitata agli acquisti",
    dependencies=[Security(require_admin_api_key)],
)
def get_purchases_whitelist():
    with _WHITELIST_LOCK:
        return {"whitelist": sorted(_COGNITO_WHITELIST), "file": str(_WHITELIST_FILE)}

@router.post(
    "/whitelist",
    summary="Aggiorna la whitelist (Cognito 'sub') per gli acquisti",
    dependencies=[Security(require_admin_api_key)],
)
def patch_purchases_whitelist(patch: WhitelistPatch = Body(...)):
    normalized_add = [s.strip() for s in (patch.add or []) if s and s.strip()]
    normalized_remove = [s.strip() for s in (patch.remove or []) if s and s.strip()]
    normalized_replace = None
    if patch.replace is not None:
        normalized_replace = [s.strip() for s in patch.replace if s and s.strip()]

    with _WHITELIST_LOCK:
        if normalized_replace is not None:
            _COGNITO_WHITELIST.clear()
            _COGNITO_WHITELIST.update(normalized_replace)
        else:
            _COGNITO_WHITELIST.update(normalized_add)
            _COGNITO_WHITELIST.difference_update(normalized_remove)

        _save_whitelist_to_disk(_COGNITO_WHITELIST)

        return {
            "whitelist": sorted(_COGNITO_WHITELIST),
            "file": str(_WHITELIST_FILE),
            "replaced": normalized_replace is not None,
            "added": normalized_add,
            "removed": normalized_remove,
        }
