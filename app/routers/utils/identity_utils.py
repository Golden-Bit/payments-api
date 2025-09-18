# --- PATCH: import
import json
import os
from typing import Optional, Literal, Dict, Any, List, Set
from threading import RLock
from pathlib import Path  # ← NEW

from fastapi import HTTPException

# --- REPLACE: stato whitelist e helper (persistenza JSON su disco)
_WHITELIST_LOCK = RLock()
_WHITELIST_FILE = Path(os.getenv("WHITELIST_FILE", "C:\\Users\\info\\Desktop\\work_space\\repositories\\payments-api\\app\\data\\whitelist_cognito_subs.json"))  # path configurabile

def _load_whitelist_from_disk() -> Set[str]:
    """
    Carica la whitelist da JSON.
    Formati accettati:
      - lista semplice: ["sub1", "sub2", ...]
      - oggetto: {"provider": "cognito", "ids": ["sub1", ...]}  (o chiave "whitelist")
    """
    try:
        if not _WHITELIST_FILE.exists():
            return set()
        with _WHITELIST_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            ids = data.get("ids") or data.get("whitelist") or []
        else:
            ids = data
        return {str(s).strip() for s in ids if str(s).strip()}
    except Exception:
        # In caso di file corrotto o json invalido, fallback a set vuoto
        return set()

def _save_whitelist_to_disk(ids: Set[str]) -> None:
    """
    Salva la whitelist in modo atomico su disco come:
      {"provider": "cognito", "ids": ["...", "..."]}
    """
    _WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _WHITELIST_FILE.with_suffix(".tmp")
    payload = {"provider": "cognito", "ids": sorted(ids)}
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, _WHITELIST_FILE)

# Cache in-memory inizializzata da disco
_COGNITO_WHITELIST: Set[str] = _load_whitelist_from_disk()

def _provider_user_id(user: Dict[str, Any]) -> str:
    # Cognito: 'sub' (fallback 'cognito:username')
    return str(user.get("sub") or user.get("cognito:username") or "").strip()

def _is_user_whitelisted(uid: str) -> bool:
    with _WHITELIST_LOCK:
        print(uid)
        print(_WHITELIST_LOCK)
        return uid in _COGNITO_WHITELIST

def _require_user_whitelisted(user: Dict[str, Any]) -> None:
    uid = _provider_user_id(user)
    if not uid or not _is_user_whitelisted(uid):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "purchases_whitelist_enforced",
                "message": "Acquisti consentiti solo a utenti autorizzati (whitelist Cognito).",
                "provider_user_id": uid or None,
            },
        )
