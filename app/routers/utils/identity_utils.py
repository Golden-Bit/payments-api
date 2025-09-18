# --- PATCH: import
import json
import os
from typing import Optional, Literal, Dict, Any, List, Set
from threading import RLock
from pathlib import Path  # ← NEW

from fastapi import HTTPException

# --- REPLACE: stato whitelist e helper (persistenza JSON su disco)
_WHITELIST_LOCK = RLock()
# --- REPLACE: usa la discovery (funziona su Linux/Windows)

# --- ADD: discovery del file whitelist in CWD quando il path configurato non esiste
def _discover_whitelist_file(configured: str) -> Path:
    """
    Ritorna il Path effettivo da usare:
      1) se il path configurato esiste → usalo;
      2) altrimenti cerca in tutta la working directory (ricorsivo) un file con lo stesso nome;
         - prima ricerca case-sensitive (match esatto del nome)
         - poi fallback case-insensitive (utile su Linux se il nome ha case diverso)
      3) se non trovato, ritorna comunque il path configurato (verrà creato in _save_whitelist_to_disk).
    """
    candidate = Path(configured).expanduser()
    if candidate.exists():
        return candidate

    root = Path.cwd()
    fname = candidate.name

    # 2a) match esatto del nome
    for p in root.rglob(fname):
        if p.is_file():
            return p

    # 2b) fallback case-insensitive (potrebbe essere costoso, ma è usato solo se non trovata corrispondenza esatta)
    fname_lower = fname.lower()
    for p in root.rglob("*"):
        try:
            if p.is_file() and p.name.lower() == fname_lower:
                return p
        except Exception:
            continue

    # 3) non trovato: useremo il path configurato (che verrà creato alla prima scrittura)
    return candidate

_WHITELIST_FILE = _discover_whitelist_file(
    os.getenv(
        "WHITELIST_FILE",
        "app\\data\\whitelist_cognito_subs.json"
    )
)

print(_WHITELIST_FILE.absolute())
_WHITELIST_FILE = _WHITELIST_FILE.absolute()
print(_WHITELIST_FILE)

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
    """
    Restituisce l'ID del provider (Cognito 'sub').
    Struttura attuale dell'oggetto user:
      {
        'user_ref': '...',
        'username': '...',
        'email': ...,
        'name': ...,
        'claims': {'sub': '...', 'username': '...', ...}
      }
    """
    if not user:
        return ""

    # 1) forma corretta: Cognito 'sub' dentro i claims
    claims = user.get("claims") or {}
    uid = claims.get("sub")

    # 2) fallback difensivi (solo se proprio manca nei claims)
    if not uid:
        uid = user.get("sub")  # in alcuni setup il middleware lo espone top-level
    if not uid:
        # spesso user_ref == sub nel tuo setup; usalo come ultima spiaggia
        uid = user.get("user_ref")

    return str(uid or "").strip()


def _is_user_whitelisted(uid: str) -> bool:
    with _WHITELIST_LOCK:
        print(uid)
        print(_COGNITO_WHITELIST)
        return uid in _COGNITO_WHITELIST

def _require_user_whitelisted(user: Dict[str, Any]) -> None:
    uid = _provider_user_id(user)
    print(uid)
    if not uid or not _is_user_whitelisted(uid):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "purchases_whitelist_enforced",
                "message": "Acquisti consentiti solo a utenti autorizzati (whitelist Cognito).",
                "provider_user_id": uid or None,
            },
        )
