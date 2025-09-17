from __future__ import annotations
import json
import os
from typing import Dict, Tuple, Optional, List, Callable, Any
import uuid
from typing import Optional, Literal, Dict, Any, List
from datetime import datetime, timezone
import stripe
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, EmailStr
import threading
import time as _time


# --- NEW: Modelli per "piano dinamico controllato" ---
from pydantic import field_validator

from app.auth_sdk.sdk import AccessTokenRequest, CognitoSDK
from app.routers.utils.chache_utils import _FileLock, FILE_CACHE_LOCK_PATH, _load_cache_file, _save_cache_file

# =============================================================================
#                         CONFIG / DEPENDENCIES
# =============================================================================

AUTH_API_BASE = os.getenv("AUTH_API_BASE", "https://teatek-llm.theia-innovation.com/auth").rstrip("/")  # base URL del tuo servizio Auth
_auth_sdk = CognitoSDK(base_url=AUTH_API_BASE)


# --- ADD CONFIG: Admin API Key per endpoint privilegiati ---
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "adminkey123:admin")

# Se necessario, puoi fissare anche la Stripe API version via env
STRIPE_API_VERSION = os.getenv("STRIPE_API_VERSION")
if STRIPE_API_VERSION:
    stripe.api_version = STRIPE_API_VERSION

class ResourceItem(BaseModel):
    key: str
    quantity: float = Field(..., ge=0)
    unit: Optional[str] = None


class ConsumeResourcesRequest(BaseModel):
    items: List[ResourceItem] = Field(..., min_items=1, description="Delta di consumo (quantità positive)")
    reason: Optional[str] = Field(None, description="Motivo del consumo (solo log/metadata)")
    # NEW: opzionali — guard di concorrenza in caso di upgrade/downgrade avvenuto tra le chiamate
    expected_plan_type: Optional[str] = Field(None, description="Se fornito, deve combaciare con il piano attuale.")
    expected_variant: Optional[str] = Field(None, description="Se fornito, deve combaciare con la variante attuale.")


class SetResourcesRequest(BaseModel):
    resources_provided: List[ResourceItem] = Field(..., min_items=1, description="Nuovo set completo di risorse fornite")
    reset_used: bool = Field(False, description="Se true, azzera le risorse usate")
    reason: Optional[str] = Field(None, description="Motivo impostazione (solo log/metadata)")
    # NEW: opzionali — guard di concorrenza in caso di upgrade/downgrade avvenuto tra le chiamate
    expected_plan_type: Optional[str] = Field(None)
    expected_variant: Optional[str] = Field(None)


class DynamicResource(BaseModel):
    key: str
    quantity: float = Field(..., ge=0)
    unit: Optional[str] = None  # opzionale (es. "GB", "TB", "hours", "units")


class DynamicRecurring(BaseModel):
    interval: Literal["day", "week", "month", "year"]
    interval_count: int = Field(1, ge=1, le=52)
    usage_type: Literal["licensed", "metered"] = "licensed"


# --- UPDATED: DynamicCheckoutRequest con supporto alle varianti catalogate ---
class DynamicCheckoutRequest(BaseModel):
    """
    Richiesta controllata:
      - Usare **EITHER** 'variant' (catalogo: free/base/pro + mensile/annuale)
        **OPPURE** 'pricing_method' + 'resources' (dinamico calcolato lato server).
      - plan_type è sempre richiesto.
      - success_url / cancel_url (validati server) e locale (facoltativo).
      - I parametri sensibili (currency, recurring, trial, tax, ecc.) sono definiti da policy lato server.
    """
    success_url: str
    cancel_url: str

    plan_type: str = Field(..., description="Tipo di piano lato server (chiave della mappa).")

    # Modalità 1: VARIANTE DI CATALOGO
    variant: Optional[str] = Field(
        None,
        description="Variante del piano (es. free_monthly, base_monthly, pro_monthly, free_annual, base_annual, pro_annual)."
    )

    # Modalità 2: DINAMICA (alternative a 'variant')
    pricing_method: Optional[str] = Field(
        None,
        description="Metodo di pricing lato server (registry). Richiesto se non usi 'variant'."
    )
    resources: Optional[List[DynamicResource]] = Field(
        None,
        description="Risorse/quantità richieste (richiesto se usi 'pricing_method')."
    )

    locale: Optional[str] = None  # solo UX


    # ✨ NUOVO: opzionale — se il piano applica "portal_update",
    # usa questo selettore per costruire/riusare la Portal Configuration
    # (puoi passare direttamente configuration_id OPPURE plan_type + variants_override)
    portal: Optional[PortalConfigSelector] = None

    @field_validator("variant")
    @classmethod
    def _variant_vs_dynamic(cls, v, info):
        """
        Vincoli:
          - XOR: o usi 'variant' OPPURE 'pricing_method' (+ 'resources').
          - Se usi 'pricing_method', 'resources' deve essere non vuoto.
        """
        data = info.data
        has_variant = v is not None
        has_pm = bool(data.get("pricing_method"))
        has_res = data.get("resources") is not None and len(data.get("resources") or []) > 0

        if has_variant and (has_pm or has_res):
            raise ValueError("Usa EITHER 'variant' OR 'pricing_method/resources', non entrambi.")

        if (not has_variant) and (not has_pm):
            raise ValueError("Devi passare 'variant' oppure 'pricing_method' + 'resources'.")

        if has_pm and not has_res:
            raise ValueError("Quando usi 'pricing_method' devi fornire anche 'resources' non vuoto.")

        return v



# =============================================================================
#                        SCHEMI INPUT (Pydantic) — ME
# =============================================================================

class PlanRecurring(BaseModel):
    interval: Literal["day", "week", "month", "year"] = Field(..., description="Cadenza (giorno/settimana/mese/anno).")
    interval_count: int = Field(1, ge=1, le=52, description="Moltiplicatore intervallo (1=mensile, 12=annuale, ...).")
    usage_type: Literal["licensed", "metered"] = Field("licensed", description="Modello: licensed/mettered.")


class PlanConfig(BaseModel):
    product_id: Optional[str] = Field(None, description="Usa Product esistente (facoltativo).")
    product_name: Optional[str] = Field(None, description="Nome Product da creare se non passi product_id.")
    currency: str = Field(..., min_length=3, max_length=3, description="Valuta ISO-4217 (es. 'eur').")
    unit_amount: int = Field(..., ge=1, description="Importo in minimi (es. 2900 => 29.00 EUR).")
    recurring: PlanRecurring
    tax_behavior: Optional[Literal["inclusive", "exclusive", "unspecified"]] = None
    trial_period_days: Optional[int] = Field(None, ge=1, le=365)
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict)


class PortalSessionRequest(BaseModel):
     """
     ✅ Nuovo schema: rimuove la logica dei preset.
     Passa direttamente un selettore 'portal' (PortalConfigSelector) con eventuali override.
     """
     return_url: str = Field(..., description="URL a cui tornare al termine del Portal.")
     portal: PortalConfigSelector = Field(..., description="Selettore/override della Portal Configuration.")
     flow_data: Optional[Dict[str, Any]] = Field(
         None, description="(Opz.) Flow iniziale del Portal, es: {'type':'payment_method_update'}."
     )

class RawDiscountSpec(BaseModel):
    """
    Specifica 'grezza' di sconto da trasformare in Coupon Stripe:
      - kind = 'percent'  → percent_off (es. 10 = 10%)
      - kind = 'amount'   → amount_off (cent) + currency ('eur', 'usd', ...)
    """
    kind: Literal["percent", "amount"] = Field(..., description="Tipo di sconto")
    percent_off: Optional[float] = Field(None, ge=0, le=100, description="Sconto percentuale, es. 10 = 10%")
    amount_off: Optional[int]    = Field(None, ge=1, description="Importo sconto in minimi (cent)")
    currency: Optional[str]      = Field(None, min_length=3, max_length=3, description="Valuta ISO per amount_off")
    duration: Literal["once", "repeating", "forever"] = Field("once", description="Durata del coupon")
    duration_in_months: Optional[int] = Field(None, ge=1, le=36, description="Obbligatorio se duration='repeating'")
    name: Optional[str] = Field(None, description="Nome/etichetta coupon (facoltativo)")

    @field_validator("percent_off")
    @classmethod
    def _validate_percent_off(cls, v, info):
        if (info.data.get("kind") == "percent") and (v is None):
            raise ValueError("percent_off richiesto quando kind='percent'")
        return v

    @field_validator("amount_off")
    @classmethod
    def _validate_amount_off(cls, v, info):
        if info.data.get("kind") == "amount":
            if v is None:
                raise ValueError("amount_off richiesto quando kind='amount'")
        return v

    @field_validator("currency")
    @classmethod
    def _validate_currency_for_amount(cls, v, info):
        if info.data.get("kind") == "amount":
            # currency può anche mancare in input: la inferiamo dal price target più avanti
            # Qui non forziamo l'errore.
            return v
        return v

class PortalUpgradeDeepLinkRequest(BaseModel):
    return_url: str
    subscription_id: str
    portal: PortalConfigSelector

    # Target
    target_price_id: Optional[str] = None
    target_plan_type: Optional[str] = None
    target_variant: Optional[str] = None

    quantity: Optional[int] = 1

    # Sconti (tutte le strade sono compatibili e si sommano):
    coupon_id: Optional[str] = None
    promotion_code: Optional[str] = None
    discounts: Optional[List[Dict[str, Any]]] = None         # pass-through raw Stripe
    raw_discounts: Optional[List[RawDiscountSpec]] = None     # <<< NUOVO



class CancelRequest(BaseModel):
    cancel_now: bool = False
    invoice_now: Optional[bool] = None
    prorate: Optional[bool] = None


class PauseRequest(BaseModel):
    behavior: Literal["keep_as_draft", "mark_uncollectible", "void"]
    resumes_at: Optional[int] = None


class ResumeRequest(BaseModel):
    billing_cycle_anchor: Optional[Literal["now", "unmodified"]] = None
    proration_behavior: Optional[Literal["create_prorations", "always_invoice", "none"]] = None


class AttachMeRequest(BaseModel):
    payment_method_id: str = Field(..., description="ID PaymentMethod (pm_...) ottenuto via Stripe.js/Elements/SetupIntent")
    set_as_default_for_subscription_id: Optional[str] = Field(
        None, description="Se presente, imposta questo PM come default per la Subscription indicata."
    )

class PortalUpdateDeepLinkRequest(BaseModel):
    return_url: str
    subscription_id: str
    # Selettore/config del Portal (riuso o creazione con override)
    portal: PortalConfigSelector

class PortalCancelDeepLinkRequest(BaseModel):
    return_url: str
    subscription_id: str
    portal: PortalConfigSelector
    # (opzionale) pre-compila il cancel "immediato" al posto di fine periodo
    immediate: Optional[bool] = False

# =============================================================================
#                       UTILS — TOKEN & UTENTE CORRENTE
# =============================================================================



def _require_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing/invalid Authorization header")
    return authorization.split(" ", 1)[1].strip()



def _now_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def _verify_and_get_user(access_token: str) -> Dict[str, Any]:
    """
    Verifica il token via SDK Cognito e ritorna un payload normalizzato:
    {
      "user_ref": "<sub|username>",
      "username": "<username se presente>",
      "email": "<email se presente>",
      "name": "<name/preferred_username se presente>",
      "claims": { ... }   # tutte le claim originali
    }

    - Accetta sia risposte 'pure' con le claim (il tuo esempio) sia {"valid": true, "claims": {...}}.
    - Verifica: exp / iat (con leeway), token_use == 'access'.
    - user_ref: preferisce 'sub' (globally unique), fallback 'username'.
    """
    try:
        # 1) Chiamata al tuo servizio Auth tramite SDK ESISTENTE
        resp = _auth_sdk.verify_token(AccessTokenRequest(access_token=access_token))

    except Exception as e:
        # Es. rete giù o 4xx/5xx dell’Auth API
        raise HTTPException(status_code=401, detail=f"Token verification failed: {e}")

    # 2) Normalizza la struttura risposta: può essere già claims “pure”
    #    come nel tuo esempio, oppure avere wrapper {"valid": true, "claims": {...}}
    if isinstance(resp, dict) and "claims" in resp:
        claims = resp.get("claims") or {}
        valid_flag = resp.get("valid")
        # Se è presente "valid" e False → rifiuta
        if valid_flag is False:
            raise HTTPException(status_code=401, detail="Token non valido (flag 'valid' = false)")
    elif isinstance(resp, dict):
        # Molti servizi (o la tua implementazione) possono restituire direttamente le claim
        # come nel tuo esempio:
        # {'sub': '...', 'iss': '...', 'token_use': 'access', 'username': 'user-...','exp': ...}
        claims = resp
    else:
        raise HTTPException(status_code=401, detail="Formato risposta verify-token non riconosciuto")

    # 3) Verifiche minime di sicurezza lato gateway (oltre a quelle fatte dal tuo servizio Auth)
    now = _now_ts()
    leeway = 60  # 60s di tolleranza su clock skew

    # exp
    exp = claims.get("exp")
    if isinstance(exp, int) and now > exp + leeway:
        raise HTTPException(status_code=401, detail="Token scaduto")

    # iat (opzionale: rifiuta token con iat troppo nel futuro)
    iat = claims.get("iat")
    if isinstance(iat, int) and iat - leeway > now:
        raise HTTPException(status_code=401, detail="Token non ancora valido (iat nel futuro)")

    # token_use (per gli access token Cognito dovrebbe essere 'access')
    token_use = claims.get("token_use") or claims.get("tokenUse")
    if token_use and str(token_use).lower() != "access":
        # Se vuoi permettere anche id_token, rimuovi questo check o gestiscilo a parte
        raise HTTPException(status_code=401, detail="Token non di tipo access")

    # 4) Determina l'identificatore univoco da usare in Stripe (e nel tuo dominio)
    #    - sub è stabile e unico (raccomandato)
    #    - username è comodo per UI/logs ma può cambiare in alcuni setup
    sub: Optional[str] = claims.get("sub")
    username: Optional[str] = claims.get("username") or claims.get("cognito:username")

    user_ref = sub or username
    if not user_ref:
        raise HTTPException(status_code=401, detail="Token privo di identificatore (mancano 'sub' e 'username')")

    # 5) Info aggiuntive utili per creare/aggiornare Customer Stripe
    email: Optional[str] = claims.get("email")
    name: Optional[str] = (
        claims.get("name") or
        claims.get("preferred_username") or
        username
    )

    # 6) Ritorna payload normalizzato
    return {
        "user_ref": user_ref,  # da usare come internal_customer_ref in Stripe metadata
        "username": username,
        "email": email,
        "name": name,
        "claims": claims,
    }

# =============================================================================
#                       UTILS — STRIPE HELPERS (ME)
# =============================================================================

def _base_idem_from_request(req: Request) -> str:
    return req.headers.get("Idempotency-Key") or req.headers.get("X-Idempotency-Key") or str(uuid.uuid4())


def _idem(base: str, suffix: str) -> str:
    return f"{base}:{suffix}"


def _opts_from_request(req: Request) -> Dict[str, Any]:
    opts: Dict[str, Any] = {}
    acct = req.headers.get("x-stripe-account")
    if acct:
        opts["stripe_account"] = acct
    return opts




_CUSTOMER_CACHE_LOCK = threading.Lock()
_CUSTOMER_CACHE_TTL = int(os.getenv("CUSTOMER_CACHE_TTL", "86400"))  # 24h di default
# struttura: { user_ref: {"cid": "cus_xxx", "ts": epoch_seconds} }
_CUSTOMER_CACHE: Dict[str, Dict[str, Any]] = {}


def _cache_get_customer_id(user_ref: str) -> Optional[str]:
    now = int(_time.time())
    # manteniamo anche il lock di processo per compatibilità con chiamate in-thread
    with _CUSTOMER_CACHE_LOCK:
        with _FileLock(FILE_CACHE_LOCK_PATH):
            data = _load_cache_file()
            rec = (data.get("customers") or {}).get(user_ref)
            if not rec:
                return None
            ts = int(rec.get("ts") or 0)
            if (now - ts) > _CUSTOMER_CACHE_TTL:
                # scaduto → elimina e salva
                try:
                    del data["customers"][user_ref]
                    _save_cache_file(data)
                except Exception:
                    pass
                return None
            return rec.get("cid")

def _cache_set_customer_id(user_ref: str, cid: str) -> None:
    now = int(_time.time())
    with _CUSTOMER_CACHE_LOCK:
        with _FileLock(FILE_CACHE_LOCK_PATH):
            data = _load_cache_file()
            cust = data.get("customers") or {}
            cust[user_ref] = {"cid": cid, "ts": now}
            data["customers"] = cust
            _save_cache_file(data)



def _get_or_ensure_customer_id_cached(
    *,
    user_ref: str,
    email: Optional[str],
    name: Optional[str],
    opts: Dict[str, Any],
) -> str:
    """
    1) prova cache (user_ref -> customer_id)
    2) se in cache, valida con retrieve (economico). Se 404 → fallback ensure + aggiorna cache
    3) se non in cache → ensure + cache
    """
    # 1) cache
    cid = _cache_get_customer_id(user_ref)

    if cid:
        try:
            # retrieve è rapido; evita la search costosa
            #stripe.Customer.retrieve(cid, **opts)
            return cid
        except stripe.error.InvalidRequestError as e:
            # risorsa mancante o ID non valido → fallback a ensure
            if getattr(e, "code", None) == "resource_missing" or "No such customer" in str(e):
                pass
            else:
                # altri errori (rete, 5xx) li rilanciamo
                raise

    # 2) ensure (potrebbe fare una sola search con OR se hai applicato l'ottimizzazione suggerita)
    cid = _ensure_customer_for_user(user_ref=user_ref, email=email, name=name, opts=opts)
    # 3) aggiorna cache
    _cache_set_customer_id(user_ref, cid)
    return cid

def _ensure_customer_for_user(user_ref: str, email: Optional[str], name: Optional[str], opts: Dict[str, Any]) -> str:
    """
    Trova o crea UNICO Customer Stripe per l'utente corrente.
    - Cerca con metadata.internal_customer_ref == user_ref
    - In fallback cerca per email (se disponibile)
    - Se non trovato, crea Customer con metadata.internal_customer_ref = user_ref
    """
    try:
        # 1) ricerca per metadata.internal_customer_ref
        query = f'metadata["internal_customer_ref"]:"{user_ref}"'
        res = stripe.Customer.search(query=query, **opts)
        if res and res.get("data"):
            return res["data"][0]["id"]

        # 2) fallback: ricerca per email (se presente)
        if email:
            res2 = stripe.Customer.search(query=f'email:"{email}"', **opts)
            if res2 and res2.get("data"):
                # assicurati di scrivere il ref
                cid = res2["data"][0]["id"]
                stripe.Customer.modify(cid, metadata={"internal_customer_ref": user_ref}, **opts)
                return cid

        # 3) crea nuovo
        created = stripe.Customer.create(
            email=email,
            name=name,
            metadata={"internal_customer_ref": user_ref},
            **opts,
        )
        return created["id"]
    except Exception as e:
        _raise_from_stripe_error(e)

def _raise_from_stripe_error(e: Exception) -> None:
    # Adapter semplice: mappa errori Stripe a HTTPException con messaggio chiaro
    msg = getattr(e, "user_message", None) or str(e)
    raise HTTPException(status_code=400, detail={"error": {"message": msg}})

def _require_api_key(x_api_key: Optional[str]) -> None:
    if not ADMIN_API_KEY or not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden (missing/invalid API key)")

def _parse_resources_json(s: Optional[str]) -> List[Dict[str, Any]]:
    if not s:
        return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return v
    except Exception:
        pass
    return []

def _to_map(items: List[Dict[str, Any]]) -> Dict[Tuple[str, Optional[str]], float]:
    acc: Dict[Tuple[str, Optional[str]], float] = {}
    for it in items:
        k = (it.get("key"), it.get("unit"))
        q = float(it.get("quantity", 0) or 0)
        acc[k] = acc.get(k, 0.0) + q
    return acc

def _to_list(m: Dict[Tuple[str, Optional[str]], float]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for (k, u), q in m.items():
        out.append({"key": k, "unit": u, "quantity": q})
    return out

def _compute_remaining(provided: List[Dict[str, Any]], used: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    mp = _to_map(provided)
    mu = _to_map(used)
    rem: Dict[Tuple[str, Optional[str]], float] = {}
    all_keys = set(mp.keys()) | set(mu.keys())
    for key in all_keys:
        rem[key] = max(0.0, mp.get(key, 0.0) - mu.get(key, 0.0))
    return _to_list(rem)

def _assert_not_exceed(provided: List[Dict[str, Any]], used: List[Dict[str, Any]]) -> None:
    mp = _to_map(provided)
    mu = _to_map(used)

    #print(mp, mu)

    for key, uq in mu.items():
        if uq - 1e-9 > mp.get(key, 0.0):  # tolleranza float minima
            k, u = key
            raise HTTPException(
                status_code=400,
                detail=f"Consumo eccede disponibilità per resource='{k}' unit='{u}' (used={uq}, provided={mp.get(key,0.0)})"
            )

def _ensure_subscription_ownership(subscription: Dict[str, Any], expected_customer_id: str) -> None:
    sub_customer = subscription.get("customer")
    if not sub_customer or sub_customer != expected_customer_id:
        raise HTTPException(status_code=403, detail="La Subscription non appartiene all'utente corrente")



########################################################################################################################

# --- NEW: utilities per min/max/step sui "resource items" ---

def _decorate_with_rules(plan_type: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggiunge ai dict delle risorse (key, unit, quantity) i campi opzionali:
      - min, max, step
    I valori provengono da RESOURCE_RULES[plan_type][key].
    Se una regola non esiste, lascia i campi assenti.
    """
    rules = RESOURCE_RULES.get(plan_type) or {}
    out: List[Dict[str, Any]] = []
    for it in items:
        key = it.get("key")
        rec = dict(it)
        r = rules.get(key) or {}
        if r.get("min") is not None:
            rec["min"] = float(r["min"])
        if r.get("max") is not None:
            rec["max"] = float(r["max"])
        if r.get("step") is not None:
            rec["step"] = float(r["step"])
        out.append(rec)
    return out

def _idx_by_key_unit(items: List[Dict[str, Any]]) -> Dict[Tuple[str, Optional[str]], Dict[str, Any]]:
    """Indicizza una lista di risorse in un dict: (key, unit) -> item dict completo."""
    idx: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
    for it in items or []:
        idx[(it.get("key"), it.get("unit"))] = it
    return idx

def _fits_min_max_step(value: float, rule: Dict[str, Any]) -> bool:
    """
    Verifica che 'value' rispetti i vincoli min/max/step.
    Se step esiste, si verifica (value - base) % step == 0, dove base = min se esiste, altrimenti 0.
    """
    mv = rule.get("min")
    Mv = rule.get("max")
    st = rule.get("step")

    if (mv is not None) and (value < float(mv) - 1e-9):
        return False
    if (Mv is not None) and (value > float(Mv) + 1e-9):
        return False

    if st is not None:
        base = float(mv) if (mv is not None) else 0.0
        step = float(st)
        # distanza dal "pavimento"
        k = (value - base) / step
        # tolleranza per float
        if abs(round(k) - k) > 1e-9:
            return False
    return True

def _assert_set_constraints(plan_type: str, new_provided: List[Dict[str, Any]]) -> None:
    """Verifica che TUTTE le qty in 'new_provided' rispettino min/max/step del plan_type."""
    rules = RESOURCE_RULES.get(plan_type) or {}
    for it in new_provided:
        key = it.get("key")
        unit = it.get("unit")
        qty = float(it.get("quantity", 0) or 0)
        r = rules.get(key) or {}
        # Se non ci sono regole, nessun vincolo
        if not r:
            continue
        if not _fits_min_max_step(qty, r):
            raise HTTPException(
                status_code=400,
                detail=f"Quantity non ammessa per resource='{key}' unit='{unit}' (vincoli: {r})"
            )

def _assert_consume_constraints(plan_type: str, deltas: List[Dict[str, Any]]) -> None:
    """
    Per i CONSUMI, applichiamo vincoli sul DELTA:
      - delta >= 0
      - se 'step' definito: delta deve essere multiplo di step (base=0)
      - non controlliamo min/max qui (sarà _assert_not_exceed a garantire che used<=provided)
    """
    rules = RESOURCE_RULES.get(plan_type) or {}

    for it in deltas:
        key = it.get("key")
        unit = it.get("unit")
        dq = float(it.get("quantity", 0) or 0)
        if dq < 0:

            raise HTTPException(status_code=400, detail="Quantità negativa non consentita nel consumo.")
        r = rules.get(key) or {}
        st = r.get("step")
        if st is not None and st > 0:
            k = dq / float(st)
            if abs(round(k) - k) > 1e-9:

                raise HTTPException(
                    status_code=400,
                    detail=f"Delta consumo non allineato allo step per resource='{key}' unit='{unit}' (step={st})"
                )

########################################################################################################################

# --- NEW: helper calendario (aware dei mesi reali) ---

def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        if (year % 400 == 0) or (year % 4 == 0 and year % 100 != 0):
            return 29
        return 28
    if month in (1,3,5,7,8,10,12):
        return 31
    return 30

def _add_months_utc(ts: int, months: int) -> int:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    y, m, d = dt.year, dt.month, dt.day
    m_total = (m - 1) + months
    y_new = y + (m_total // 12)
    m_new = (m_total % 12) + 1
    d_new = min(d, _days_in_month(y_new, m_new))
    return int(datetime(y_new, m_new, d_new, dt.hour, dt.minute, dt.second, tzinfo=timezone.utc).timestamp())

def _advance_ts_calendar(ts: int, interval: str, count: int) -> int:
    if count < 1:
        count = 1
    if interval == "month":
        return _add_months_utc(ts, count)
    elif interval == "year":
        return _add_months_utc(ts, 12 * count)
    elif interval == "week":
        return ts + count * 7 * 24 * 3600
    elif interval == "day":
        return ts + count * 24 * 3600
    return ts + count * 30 * 24 * 3600  # fallback prudente

def _sum_resource_lists(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ma = _to_map(a); mb = _to_map(b)
    for k, q in mb.items(): ma[k] = ma.get(k, 0.0) + float(q)
    # NB: qui torniamo SOLO key/unit/quantity; i vincoli tornano dal "base"
    return _to_list(ma)

def _apply_resource_grant(provided: List[Dict[str, Any]],
                          used: List[Dict[str, Any]],
                          base: List[Dict[str, Any]],
                          mode: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    mode = (mode or "").lower().strip()
    if mode == "reset":
        return (list(base), [])
    return (_sum_resource_lists(provided, base), used)

def _extract_grant_config_from_metadata(md: Dict[str, Any]) -> Tuple[str, int]:
    interval = str(md.get("res_grant_interval") or "month").lower().strip()
    try:
        interval_count = int(md.get("res_grant_interval_count") or 1)
    except Exception:
        interval_count = 1
    if interval_count < 1:
        interval_count = 1
    return interval, interval_count

def _maybe_rollover_resources_stripe_aligned(
    subscription_id: str,
    opts: Dict[str, Any],
    catchup_cap: int = 36,
) -> Optional[Dict[str, Any]]:
    """
    Allinea i metadata risorse al “periodo” corrente secondo Stripe (senza webhook).
    - Inizializza last_grant_period_end al primo current_period_end noto (Stripe).
    - Se uno o più confini sono passati, applica i grant (reset/add) per ciascun confine.
    - Scrive i metadata aggiornati e ritorna il dict patchato, o None se nulla da fare.
    """
    sub = stripe.Subscription.retrieve(subscription_id, **opts)
    md = sub.get("metadata") or {}

    res_mode = md.get("res_mode") or "reset"
    base = _parse_resources_json(md.get("base_resources_provided_json"))
    provided = _parse_resources_json(md.get("resources_provided_json"))
    used = _parse_resources_json(md.get("resources_used_json"))
    if not base:
        return None

    interval, interval_count = _extract_grant_config_from_metadata(md)

    try:
        last_grant_period_end = int(md.get("last_grant_period_end") or 0)
    except Exception:
        last_grant_period_end = 0

    now_ts = _now_ts()

    if last_grant_period_end <= 0:
        curr_end = int(sub.get("current_period_end") or 0)
        if curr_end <= 0:
            return None
        patch = {
            **md,
            "last_grant_period_end": str(curr_end),
            "last_grant_at": str(now_ts),
            # assicura che i campi base/starting ci siano
            "resources_provided_json": json.dumps(provided or base, separators=(",", ":")),
            "resources_used_json": json.dumps(used or [], separators=(",", ":")),
        }
        stripe.Subscription.modify(subscription_id, metadata=patch, **opts)
        return patch

    grants = 0
    cursor = last_grant_period_end
    while now_ts >= cursor:
        provided, used = _apply_resource_grant(provided, used, base, res_mode)
        grants += 1
        if grants >= catchup_cap:
            break
        cursor = _advance_ts_calendar(cursor, interval, interval_count)

    if grants == 0:
        return None

    patch_md = {
        **md,
        "resources_provided_json": json.dumps(provided, separators=(",", ":")),
        "resources_used_json": json.dumps(used, separators=(",", ":")),
        "last_grant_period_end": str(cursor),
        "last_grant_at": str(now_ts),
        "last_grant_count": str(grants),
    }
    stripe.Subscription.modify(subscription_id, metadata=patch_md, **opts)
    return patch_md

# ─────────────────────────────────────────────────────────────────────────────
# NEW: Helper Variant-first (riuso ultimo equivalente / creazione)
# ─────────────────────────────────────────────────────────────────────────────
def _price_equivalent(pr: Dict[str, Any],
                      *,
                      currency: str,
                      unit_amount: int,
                      interval: str,
                      interval_count: int,
                      usage_type: str,
                      tax_behavior: Optional[str] = None) -> bool:
    if pr.get("currency") != currency:
        return False
    if int(pr.get("unit_amount") or 0) != int(unit_amount):
        return False
    rec = pr.get("recurring") or {}
    if rec.get("interval") != interval:
        return False
    if int(rec.get("interval_count") or 1) != int(interval_count):
        return False
    if rec.get("usage_type") != usage_type:
        return False
    if tax_behavior is not None:
        if (pr.get("tax_behavior") or "exclusive") != tax_behavior:
            return False
    return True


def _list_prices_for_product(product_id: str, opts: Dict[str, Any]) -> List[Dict[str, Any]]:
    res = stripe.Price.list(product=product_id, active=None, limit=100, **opts)
    prices = res.get("data", [])
    prices.sort(key=lambda p: int(p.get("created") or 0))
    return prices


def _pick_latest_equivalent_by_variant(prices: List[Dict[str, Any]],
                                       *,
                                       variant: str,
                                       currency: str,
                                       unit_amount: int,
                                       interval: str,
                                       interval_count: int,
                                       usage_type: str,
                                       tax_behavior: Optional[str]) -> Optional[Dict[str, Any]]:
    candidates = [p for p in prices if (p.get("metadata") or {}).get("variant") == variant]
    for pr in reversed(candidates):
        if _price_equivalent(
            pr, currency=currency, unit_amount=unit_amount,
            interval=interval, interval_count=interval_count,
            usage_type=usage_type, tax_behavior=tax_behavior
        ):
            return pr
    return None


def _search_equivalent_any(prices: List[Dict[str, Any]],
                           *,
                           currency: str,
                           unit_amount: int,
                           interval: str,
                           interval_count: int,
                           usage_type: str,
                           tax_behavior: Optional[str]) -> Optional[Dict[str, Any]]:
    matches = []
    for pr in prices:
        if _price_equivalent(
            pr, currency=currency, unit_amount=unit_amount,
            interval=interval, interval_count=interval_count,
            usage_type=usage_type, tax_behavior=tax_behavior
        ):
            matches.append(pr)
    if not matches:
        return None
    matches.sort(key=lambda p: int(p.get("created") or 0))
    return matches[-1]


def _search_product_by_key(product_key: str, opts: Dict[str, Any]) -> Optional[str]:
    try:
        res = stripe.Product.search(query=f'metadata["product_key"]:"{product_key}"', **opts)
        if res and res.get("data"):
            return res["data"][0]["id"]
    except Exception:
        pass
    return None


def _ensure_product(product_key: str, product_name: str, base_idem: str, opts: Dict[str, Any]) -> str:
    pid = _search_product_by_key(product_key, opts)
    if pid:
        return pid
    p = stripe.Product.create(
        name=product_name,
        metadata={"product_key": product_key},
        idempotency_key=_idem(base_idem, f"product.ensure.{product_key}"),
        **opts,
    )
    return p["id"]

def _ensure_price_for_variant(
    plan_type: str,
    variant: str,
    base_idem: str,
    opts: Dict[str, Any],
    allow_fallback_equivalent_any: bool = True,
    reactivate_if_inactive: bool = True
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Garantisce esistenza (o riuso) del Price per (plan_type, variant).
    Restituisce: (price_id, product_id, price_obj) per evitare future Price.retrieve.
    """
    variants = PLAN_VARIANTS.get(plan_type) or {}
    vconf = variants.get(variant)
    if not vconf:
        raise HTTPException(status_code=400, detail=f"Variante '{variant}' non definita per plan_type '{plan_type}'")
    bp = vconf.get("blueprint")
    if not bp:
        raise HTTPException(status_code=400, detail=f"Variante '{variant}' priva di blueprint")

    policy = PLAN_POLICIES.get(plan_type) or {}
    currency       = policy.get("currency") or "eur"
    product_key    = bp["product_key"]
    product_name   = bp["product_name"]
    unit_amount    = int(bp["unit_amount"])
    interval       = bp.get("interval") or policy.get("recurring", {}).get("interval") or "month"
    interval_count = int(bp.get("interval_count") or policy.get("recurring", {}).get("interval_count") or 1)
    usage_type     = bp.get("usage_type") or policy.get("recurring", {}).get("usage_type") or "licensed"
    tax_behavior   = policy.get("tax_behavior") or "exclusive"

    # 1) Product (riuso/creazione)
    product_id = _ensure_product(product_key, product_name, base_idem, opts)

    # 2) Lista price del product (unica chiamata; useremo questi payload fino alla fine)
    prices = _list_prices_for_product(product_id, opts)

    # 3) Cerca equivalente col TAG di variant
    pr = _pick_latest_equivalent_by_variant(
        prices,
        variant=variant,
        currency=currency,
        unit_amount=unit_amount,
        interval=interval,
        interval_count=interval_count,
        usage_type=usage_type,
        tax_behavior=tax_behavior,
    )
    if pr:
        if reactivate_if_inactive and (pr.get("active") is False):
            stripe.Price.modify(pr["id"], active=True, **opts)
            pr = {**pr, "active": True}
        return pr["id"], product_id, pr

    # 4) Fallback: qualunque equivalente, poi patch metadata 'variant'
    if allow_fallback_equivalent_any:
        pr2 = _search_equivalent_any(
            prices,
            currency=currency,
            unit_amount=unit_amount,
            interval=interval,
            interval_count=interval_count,
            usage_type=usage_type,
            tax_behavior=tax_behavior,
        )
        if pr2:
            md = dict(pr2.get("metadata") or {})
            changed = False
            if md.get("variant") != variant:
                md["variant"] = variant
                md.setdefault("plan_type", plan_type)
                md.setdefault("product_key", product_key)
                stripe.Price.modify(pr2["id"], metadata=md, **opts)
                pr2 = {**pr2, "metadata": md}
                changed = True
            if reactivate_if_inactive and (pr2.get("active") is False):
                stripe.Price.modify(pr2["id"], active=True, **opts)
                pr2 = {**pr2, "active": True}
                changed = True
            # Nota: se non è cambiato nulla, riusiamo pr2 “as is”
            return pr2["id"], product_id, pr2

    # 5) Nessun equivalente → creiamo il Price
    pr_new = stripe.Price.create(
        product=product_id,
        currency=currency,
        unit_amount=unit_amount,
        recurring={
            "interval": interval,
            "interval_count": interval_count,
            "usage_type": usage_type,
        },
        tax_behavior=tax_behavior,
        metadata={"plan_type": plan_type, "variant": variant, "product_key": product_key},
        idempotency_key=_idem(
            base_idem,
            f"price.ensure.variant.{plan_type}.{variant}.{unit_amount}.{currency}.{interval}.{interval_count}.{usage_type}"
        ),
        **opts,
    )
    return pr_new["id"], product_id, pr_new



# NEW: se current_period_* non sono disponibili, inferisci i bound del periodo corrente
def _infer_period_bounds(sub: Dict[str, Any]) -> Tuple[int, int]:
    cps = sub.get("current_period_start")
    cpe = sub.get("current_period_end")
    if isinstance(cps, int) and isinstance(cpe, int) and cps > 0 and cpe > 0:
        return cps, cpe
    # fallback: usa anchor + interval dell'item attivo
    now_ts = _now_ts()
    anchor = (sub.get("billing_cycle_anchor")
              or sub.get("trial_start")
              or sub.get("start_date")
              or sub.get("created")
              or now_ts)
    # prendi il primo item non 'deleted'
    items = (sub.get("items") or {}).get("data") or []
    interval, count = "month", 1
    for it in items:
        if it.get("deleted"):
            continue
        rec = (it.get("price") or {}).get("recurring") or {}
        interval = rec.get("interval") or interval
        count = int(rec.get("interval_count") or count)
        break
    # scorri finché 'now' cade dentro [start,end)
    start = int(anchor)
    end = _advance_ts_calendar(start, interval, count)
    safety = 0
    while now_ts >= end and safety < 240:
        start = end
        end = _advance_ts_calendar(start, interval, count)
        safety += 1
    return start, end


def _sync_subscription_variant_state(subscription_id: str, opts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    md = sub.get("metadata") or {}
    items = (sub.get("items") or {}).get("data") or []
    if not items:
        return None

    # Item attivo
    item = next((it for it in items if not it.get("deleted")), items[0])
    price = item.get("price") or {}
    price_id = price.get("id")
    product = price.get("product")
    product_id = product.get("id") if isinstance(product, dict) else product
    price_md = price.get("metadata") or {}
    new_variant = price_md.get("variant")
    new_plan_type = price_md.get("plan_type") or md.get("plan_type")

    changed = (
        (md.get("active_price_id") != price_id) or
        (md.get("active_product_id") != product_id) or
        (new_variant is not None and md.get("variant") != new_variant) or
        (new_plan_type is not None and md.get("plan_type") != new_plan_type)
    )
    if not changed:
        return None

    # Stato corrente
    provided = _parse_resources_json(md.get("resources_provided_json"))
    used = _parse_resources_json(md.get("resources_used_json"))

    patch_md = dict(md)
    patch_md.update({
        "active_price_id": price_id,
        "active_product_id": product_id,
    })

    # Calcolo delta tra vecchia e nuova dote (solo se riconosciamo entrambe le varianti del nostro catalogo)
    old_variant = md.get("variant")
    old_plan_type = md.get("plan_type")
    base_old: List[Dict[str, Any]] = []
    base_new: List[Dict[str, Any]] = []

    if old_plan_type and old_variant and old_plan_type in PLAN_VARIANTS and old_variant in PLAN_VARIANTS[old_plan_type]:
        base_old = PLAN_VARIANTS[old_plan_type][old_variant].get("base_resources") or []

    if new_plan_type and new_variant and new_plan_type in PLAN_VARIANTS and new_variant in PLAN_VARIANTS[new_plan_type]:
        base_new = PLAN_VARIANTS[new_plan_type][new_variant].get("base_resources") or []

        # Applichiamo SOLO IL DELTA POSITIVO (upgrade). Usati invariati.
        new_provided = _apply_upgrade_delta_for_credits(provided, used, base_old, base_new)

        # Aggiorniamo i metadata per i grant futuri
        patch_md.update({
            "plan_type": new_plan_type,
            "variant": new_variant,
            "base_resources_provided_json": json.dumps(base_new, separators=(",", ":")),
            "resources_provided_json": json.dumps(new_provided, separators=(",", ":")),
            # NON tocchiamo resources_used_json → manteniamo i consumi
        })
        # res_mode/grant config: mantieni policy/variante nuovi se vuoi riallinearli qui; altrimenti lascia come sono
        vconf = PLAN_VARIANTS[new_plan_type][new_variant]
        res_mode = str(vconf.get("res_mode") or PLAN_POLICIES.get(new_plan_type, {}).get("res_mode") or "add")
        patch_md["res_mode"] = res_mode
        patch_md["res_grant_interval"] = str(PLAN_POLICIES.get(new_plan_type, {}).get("res_grant_interval") or "month")
        patch_md["res_grant_interval_count"] = str(int(PLAN_POLICIES.get(new_plan_type, {}).get("res_grant_interval_count") or 1))
    else:
        # Variante sconosciuta o dinamica → aggiorna solo riferimenti price/product/plan_type (senza manomettere i crediti)
        if new_plan_type:
            patch_md["plan_type"] = new_plan_type
        if new_variant:
            patch_md["variant"] = new_variant

    stripe.Subscription.modify(subscription_id, metadata=patch_md, **opts)
    return patch_md


def _list_portal_configurations(opts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Utility: elenca (pagine principali) le Billing Portal Configurations."""
    res = stripe.billing_portal.Configuration.list(limit=100, **opts)
    return res.get("data", []) or []


from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# 2) _assert_unique_intervals_per_product — usa dati già in memoria, zero HTTP
# ─────────────────────────────────────────────────────────────────────────────
def _assert_unique_intervals_per_product(
    product_price_pairs: List[Dict[str, Any]],
    opts: Dict[str, Any]  # tenuto per compatibilità firma, NON usato
) -> None:
    """
    Controlla che per ogni product non ci siano due price con lo stesso
    (interval, interval_count). Usa i campi già presenti nei pair:
      {"product_id", "price_id", "interval", "interval_count"}
    """
    by_product: Dict[str, Dict[str, str]] = {}
    for pair in product_price_pairs:
        pid = pair["product_id"]
        ivk = f'{pair.get("interval")}:{int(pair.get("interval_count") or 1)}'
        seen = by_product.setdefault(pid, {})
        if ivk in seen:
            raise HTTPException(
                status_code=400,
                detail=(
                    "For each product, its price must have unique billing intervals. "
                    f"Product '{pid}' has duplicate interval '{ivk}' for prices: "
                    f"{seen[ivk]} and {pair['price_id']}."
                ),
            )
        seen[ivk] = pair["price_id"]

def _build_portal_features(product_price_pairs: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Costruisce il blocco 'features' per la Portal Configuration.

    - Una riga per ciascuna coppia {product_id, price_id}, così per ogni product
      c'è al più un price per intervallo → evita errori 400 da Stripe.
    - Abilita payment_method_update perché subscription_update lo richiede.
    - Consente upgrade/downgrade immediati con calcolo pro-rata.
    - Opzionalmente abilita cancellazione e aggiornamenti profilo.
    """
    products_block = []
    for pair in product_price_pairs:
        products_block.append({
            "product": pair["product_id"],
            "prices": [pair["price_id"]],  # 1 price per product → no duplicati di intervallo
        })

    return {
        # 🔐 Necessario quando abiliti subscription_update
        "payment_method_update": {
            "enabled": True
        },
        # 🔄 Upgrade/Downgrade tra i prezzi indicati
        "subscription_update": {
            "enabled": True,
            "default_allowed_updates": ["price"],
            "proration_behavior": "none",  # pro-rata automatico
            "products": products_block,
        },
        # (Opzionale) Consenti la cancellazione direttamente dal Portal
        "subscription_cancel": {"enabled": True, "mode": "at_period_end"},
        #
        # (Opzionale) Aggiornamenti profilo cliente nel Portal
        # "customer_update": {
        #     "enabled": True,
        #     "allowed_updates": ["address", "name", "shipping"]
        # },
    }




def ensure_portal_configuration(
    *,
    plan_type: str,
    portal_preset: str,           # "monthly" | "annual"
    base_idem: str,
    opts: Dict[str, Any],
) -> str:
    """
    Garantisce l'esistenza (o aggiorna) di una Billing Portal Configuration coerente con:
      - plan_type (es. 'AI Standard')
      - portal_preset ('monthly' o 'annual'), che determina le varianti da mostrare.
    Se i Product/Price per le varianti non esistono, li crea tramite _ensure_price_for_variant(...).
    Ritorna l'ID della configuration.

    DIFFERENZE vs versione precedente:
    - Non si aggregano più molti price dello stesso product in un'unica riga,
      ma si crea una riga per ciascuna (product, price), così Stripe non alza
      più il 400 "duplicate intervals".
    - Aggiunto guard-rail _assert_unique_intervals_per_product(...).
    - Facoltativo: esclusi i price con unit_amount=0 (free) dal Portal.
    """
    # 1) Recupera le varianti desiderate dal preset
    variants = PORTAL_PRESETS.get(portal_preset)
    if not variants:
        raise HTTPException(status_code=400, detail=f"Preset Portal non valido: '{portal_preset}'")

    # 2) Assicurati che 'plan_type' sia noto alle tue mappe di varianti
    all_variants = PLAN_VARIANTS.get(plan_type)
    if not all_variants:
        raise HTTPException(status_code=400, detail=f"plan_type sconosciuto per il Portal: '{plan_type}'")

    # 3) Per ciascuna variante, assicurati Price (e Product)
    #    Costruiamo la lista di coppie (product_id, price_id), una per variante.
    product_price_pairs: List[Dict[str, str]] = []
    for v in variants:
        if v not in all_variants:
            raise HTTPException(
                status_code=400,
                detail=f"Variante '{v}' non definita per plan_type '{plan_type}'"
            )

        price_id, product_id, _ = _ensure_price_for_variant(plan_type, v, base_idem, opts)

        # (consigliato) Escludi piani a 0 €/periodo dal Portal (free → crea confusione nell'upgrade)
        pr = stripe.Price.retrieve(price_id, **opts)
        if int(pr.get("unit_amount") or 0) <= 0:
            continue

        product_price_pairs.append({"product_id": product_id, "price_id": price_id})

    if not product_price_pairs:
        raise HTTPException(status_code=400, detail="Nessun price valido (>0) per costruire il Portal preset.")

    # 4) Guard-rail: intercetta eventuali “duplicate intervals” PRIMA della chiamata a Stripe
    _assert_unique_intervals_per_product(product_price_pairs, opts)

    # 5) Verifica se esiste già una configuration per (plan_type, portal_preset); in caso affermativo aggiorna
    existing = _list_portal_configurations(opts)
    for conf in existing:
        md = conf.get("metadata") or {}
        if md.get("plan_type") == plan_type and md.get("portal_preset") == portal_preset:
            features = _build_portal_features(product_price_pairs)
            upd = stripe.billing_portal.Configuration.modify(
                conf["id"],
                features=features,
                business_profile={"headline": f"{plan_type} — {portal_preset.capitalize()} plans"},
                idempotency_key=_idem(base_idem, f"portal.config.update.{plan_type}.{portal_preset}"),
                **opts,
            )
            return upd["id"]

    # 6) Altrimenti, crea una nuova configuration
    features = _build_portal_features(product_price_pairs)
    created = stripe.billing_portal.Configuration.create(
        business_profile={"headline": f"{plan_type} — {portal_preset.capitalize()} plans"},
        features=features,
        metadata={"plan_type": plan_type, "portal_preset": portal_preset},
        idempotency_key=_idem(base_idem, f"portal.config.create.{plan_type}.{portal_preset}"),
        **opts,
    )
    return created["id"]


# >>> ADD: enforcement "una subscription viva per utente"
ALIVE_SUB_STATUSES = {"trialing", "active", "past_due", "unpaid", "incomplete", "paused", "incomplete_expired"}

def _find_alive_subscription_id_for_customer(customer_id: str, opts: Dict[str, Any]) -> Optional[str]:
    """
    Ritorna l'ID della subscription 'in vita' più recente per il customer, se esiste.
    Consideriamo 'alive' anche incomplete/past_due/unpaid/paused per prevenire duplicati.
    """
    subs = stripe.Subscription.list(customer=customer_id, status="all", limit=100, **opts)
    candidates: List[Dict[str, Any]] = []
    for s in subs.get("data", []) or []:
        st = (s.get("status") or "").lower()
        if st in ALIVE_SUB_STATUSES and not s.get("canceled_at"):
            candidates.append(s)
    if not candidates:
        return None
    candidates.sort(key=lambda s: int(s.get("created") or 0), reverse=True)
    return candidates[0]["id"]


# >>> ADD: modelli per override/riuso di Billing Portal Configuration
class PortalFeaturesOverride(BaseModel):
    # Mappa 1:1 con l'oggetto "features" del Portal.
    payment_method_update: Optional[Dict[str, Any]] = None
    subscription_update: Optional[Dict[str, Any]] = None
    subscription_cancel: Optional[Dict[str, Any]] = None
    customer_update: Optional[Dict[str, Any]] = None
    invoice_history: Optional[Dict[str, Any]] = None  # ⬅️ AGGIUNGI QUESTO

class BusinessProfileOverride(BaseModel):
    headline: Optional[str] = None
    privacy_policy_url: Optional[str] = None
    terms_of_service_url: Optional[str] = None

class BrandingOverride(BaseModel):
    # NB: lo "branding" del Portal è globale, non per-config; metto qui per completezza (no-op su Configuration.create)
    logo: Optional[str] = None  # file id Stripe, non URL
    icon: Optional[str] = None

class PortalConfigSelector(BaseModel):
    """
    Se passi configuration_id lo useremo direttamente.
    Altrimenti, se plan_type+portal_preset/variants_override sono forniti, creeremo/aggiorneremo via ensure_*.
    """
    configuration_id: Optional[str] = None
    plan_type: Optional[str] = None
    portal_preset: Optional[Literal["monthly", "annual"]] = None
    # Facoltativo: bypassa i preset e dichiara tu le varianti
    variants_override: Optional[List[str]] = None
    # Override opzionali per UI/feature
    features_override: Optional[PortalFeaturesOverride] = None
    business_profile_override: Optional[BusinessProfileOverride] = None
    branding_override: Optional[BrandingOverride] = None


# >>> ADD: costruttore features di default per upgrade/downgrade istantaneo, payment method update e cancel opzionale
def _default_features_for_products(product_price_pairs: List[Dict[str, str]]) -> Dict[str, Any]:
    products_block = [{"product": p["product_id"], "prices": [p["price_id"]]} for p in product_price_pairs]
    return {
        "payment_method_update": {"enabled": True},
        "subscription_update": {
            "enabled": True,
            "default_allowed_updates": ["price"],
            "proration_behavior": "create_prorations",
            "products": products_block,
        },
        "subscription_cancel": {"enabled": True, "mode": "at_period_end"},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helper: fingerprint stabile della configuration
# ─────────────────────────────────────────────────────────────────────────────
import hashlib
import json

def _config_fingerprint(
    *,
    plan_type: str,
    tag: str,
    features: Dict[str, Any],
    business_profile: Dict[str, Any],
) -> str:
    """
    Calcola un hash deterministico della configurazione desiderata del Billing Portal.
    Usiamo:
      - plan_type (es. "AI Standard")
      - tag (portal_preset o "custom")
      - features (così come verranno inviati a Stripe)
      - business_profile (headline, ecc.)

    Nota: NON sanitizziamo nulla; il fingerprint riflette esattamente ciò che stai per inviare.
    """
    payload = {
        "plan_type": plan_type,
        "tag": tag,
        "features": features,
        "business_profile": business_profile,
    }
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# CACHE process-local (fingerprint → configuration_id) per ridurre Configuration.list
# ─────────────────────────────────────────────────────────────────────────────

_PORTAL_CONF_CACHE: Dict[str, str] = {}

def _portal_cache_key(plan_type: str, tag_val: str, fp: str) -> str:
    return f"portal:{plan_type}:{tag_val}:{fp}"


# ─────────────────────────────────────────────────────────────────────────────
# 3) ensure_portal_configuration_with_overrides — nessun retrieve superfluo + cache
# ─────────────────────────────────────────────────────────────────────────────
def ensure_portal_configuration_with_overrides(
    *,
    plan_type: str,
    portal_preset: Optional[str],
    variants_override: Optional[List[str]],
    base_idem: str,
    opts: Dict[str, Any],
    business_profile_override: Optional[BusinessProfileOverride] = None,
    features_override: Optional[PortalFeaturesOverride] = None,
) -> str:
    """
    - Risolve varianti da preset/override
    - Provisioning Price/Product senza retrieve ridondanti
    - Esclude price free (unit_amount <= 0) senza chiamate extra
    - Controlla duplicati intervallo in-memory
    - Cache fingerprint→configuration_id per evitare Configuration.list
    """
    # 1) Varianti
    if variants_override and len(variants_override) > 0:
        variants = variants_override
    else:
        if not portal_preset:
            raise HTTPException(status_code=400, detail="portal_preset o variants_override richiesti")
        variants = PORTAL_PRESETS.get(portal_preset)
        if not variants:
            raise HTTPException(status_code=400, detail=f"Preset Portal non valido: '{portal_preset}'")

    # 2) Plan/varianti note
    all_variants = PLAN_VARIANTS.get(plan_type)
    if not all_variants:
        raise HTTPException(status_code=400, detail=f"plan_type sconosciuto per il Portal: '{plan_type}'")

    # 3) Provisioning price/product (riuso/crea) — nessun Price.retrieve fuori da qui
    product_price_pairs: List[Dict[str, Any]] = []
    for v in variants:
        if v not in all_variants:
            raise HTTPException(status_code=400, detail=f"Variante '{v}' non definita per plan_type '{plan_type}'")

        price_id, product_id, price_obj = _ensure_price_for_variant(plan_type, v, base_idem, opts)

        # Filtra “free” senza recuperare di nuovo: unit_amount è già qui
        unit_amount = int(price_obj.get("unit_amount") or 0)
        if unit_amount <= 0:
            continue

        rec = price_obj.get("recurring") or {}
        product_price_pairs.append({
            "product_id":     product_id,
            "price_id":       price_id,
            "interval":       rec.get("interval"),
            "interval_count": int(rec.get("interval_count") or 1),
            "unit_amount":    unit_amount,
        })

    if not product_price_pairs:
        raise HTTPException(status_code=400, detail="Nessun price valido (>0) per costruire il Portal.")

    # 4) Guard-rail duplicati (nessuna chiamata HTTP)
    _assert_unique_intervals_per_product(product_price_pairs, opts)

    # 5) Features base (+ eventuale override)
    products_block = [{"product": p["product_id"], "prices": [p["price_id"]]} for p in product_price_pairs]
    features = {
        "payment_method_update": {"enabled": True},
        "subscription_update": {
            "enabled": True,
            "default_allowed_updates": ["price"],
            "proration_behavior": "create_prorations",
            "products": products_block,
        },
        "subscription_cancel": {"enabled": True, "mode": "at_period_end"},
    }
    if features_override:
        ov = features_override.model_dump(exclude_none=True)
        # merge shallow tranne subscription_update
        for k, v in ov.items():
            if k != "subscription_update":
                features[k] = v
        # deep-merge per subscription_update (preserva products se assente nell'override)
        su_base = features.get("subscription_update", {}) or {}
        su_ov   = ov.get("subscription_update") or {}
        if su_ov:
            merged = dict(su_base)
            for kk, vv in su_ov.items():
                if kk == "products":
                    continue
                merged[kk] = vv
            if "products" in su_ov:
                merged["products"] = su_ov["products"]
            features["subscription_update"] = merged

    # 6) Business profile
    business_profile = {"headline": f"{plan_type} plans"}
    if business_profile_override:
        business_profile.update(business_profile_override.model_dump(exclude_none=True))

    # 7) Fingerprint & cache
    tag_val   = portal_preset or "custom"
    desired_fp = _config_fingerprint(plan_type=plan_type, tag=tag_val, features=features, business_profile=business_profile)

    cache_key = _portal_cache_key(plan_type, tag_val, desired_fp)
    cached_id = _PORTAL_CONF_CACHE.get(cache_key)
    if cached_id:
        return cached_id

    # 8) Prova riuso solo se necessario (cache miss)
    existing = _list_portal_configurations(opts)
    for conf in existing:
        md = conf.get("metadata") or {}
        if md.get("plan_type") == plan_type and md.get("portal_preset") == tag_val and md.get("features_fp") == desired_fp:
            _PORTAL_CONF_CACHE[cache_key] = conf["id"]
            return conf["id"]

    # 9) Crea nuova configuration
    created = stripe.billing_portal.Configuration.create(
        business_profile=business_profile,
        features=features,
        metadata={
            "plan_type": plan_type,
            "portal_preset": tag_val,
            "features_fp": desired_fp,
            "features_version": "v2_fp_only",
        },
        idempotency_key=_idem(base_idem, f"portal.config.create.{plan_type}.{tag_val}.{desired_fp[:10]}"),
        **opts,
    )
    _PORTAL_CONF_CACHE[cache_key] = created["id"]
    return created["id"]


# >>> ADD: risolutore "selettore" per ottenere una Configuration pronta (reuse o create)
def _resolve_portal_configuration_id(
    *,
    selector: PortalConfigSelector,
    base_idem: str,
    opts: Dict[str, Any],
) -> str:
    if selector.configuration_id:
        # trust esplicito
        return selector.configuration_id

    if not selector.plan_type:
        raise HTTPException(status_code=400, detail="plan_type richiesto se non passi configuration_id")

    return ensure_portal_configuration_with_overrides(
        plan_type=selector.plan_type,
        portal_preset=selector.portal_preset,
        variants_override=selector.variants_override,
        base_idem=base_idem,
        opts=opts,
        business_profile_override=selector.business_profile_override,
        features_override=selector.features_override,
    )

def _map_subtract(ma: Dict[Tuple[str, Optional[str]], float],
                  mb: Dict[Tuple[str, Optional[str]], float]) -> Dict[Tuple[str, Optional[str]], float]:
    out: Dict[Tuple[str, Optional[str]], float] = {}
    all_keys = set(ma.keys()) | set(mb.keys())
    for k in all_keys:
        out[k] = float(ma.get(k, 0.0)) - float(mb.get(k, 0.0))
    return out

def _positive_part(m: Dict[Tuple[str, Optional[str]], float]) -> Dict[Tuple[str, Optional[str]], float]:
    return {k: max(0.0, v) for k, v in m.items() if v > 0.0}

def _apply_upgrade_delta_for_credits(
    provided: List[Dict[str, Any]],
    used: List[Dict[str, Any]],
    old_base: List[Dict[str, Any]],
    new_base: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Aggiunge al 'provided' soltanto il delta positivo (nuova_dote - vecchia_dote), lasciando invariato 'used'.
    Non sottrae crediti in caso di downgrade (delta negativo ignorato).
    Garantisce provided >= used per ogni chiave/unit.
    """
    mp = _to_map(provided)
    mu = _to_map(used)
    m_old = _to_map(old_base)
    m_new = _to_map(new_base)

    delta = _map_subtract(m_new, m_old)       # nuovo - vecchio
    delta_pos = _positive_part(delta)         # solo parte positiva (upgrade)

    # Somma delta positivo
    for k, dq in delta_pos.items():
        mp[k] = mp.get(k, 0.0) + dq

    # Guard-rail: provided >= used
    for k, uq in mu.items():
        if uq - 1e-9 > mp.get(k, 0.0):
            mp[k] = uq

    return _to_list(mp)

# --- FAST HELPERS per usare la subscription pre-caricata senza re-retrieve ---

def _active_item_ids_from_sub(sub: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """
    Estrae dal payload della Subscription (già caricato) l'item attivo:
    - price_id
    - product_id (stringa, anche se price.product è dict o string)
    - price_obj (quello presente in sub, se c'è)
    """
    items = (sub.get("items") or {}).get("data") or []
    for it in items:
        if it.get("deleted"):
            continue
        price = it.get("price") or {}
        price_id = price.get("id")
        prod = price.get("product")
        product_id = (prod.get("id") if isinstance(prod, dict) else prod) if prod else None
        return price_id, product_id, price
    return None, None, None


def _fast_sync_and_rollover_in_memory(
    sub: Dict[str, Any],
    opts: Dict[str, Any],
) -> Tuple[Dict[str, str], List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    """
    Esegue in-memory:
      1) SYNC variante/prezzo/prodotto (senza re-retrieve): 1x Price.retrieve SOLO se servono i metadata price.
      2) ROLLOVER crediti allineato allo “Stripe period” usando la sub già in mano.
    Ritorna:
      - patch_md  (solo i campi modificati)
      - provided  (lista risorse after-sync/rollover)
      - used      (lista risorse after-sync/rollover)
      - changed   (True se qualcosa da patchare su Stripe)
    """
    md = sub.get("metadata") or {}
    provided = _parse_resources_json(md.get("resources_provided_json"))
    used = _parse_resources_json(md.get("resources_used_json"))
    base = _parse_resources_json(md.get("base_resources_provided_json"))
    res_mode = (md.get("res_mode") or "reset").strip().lower()

    patch_md: Dict[str, str] = {}
    changed = False

    # ── 1) SYNC variante / price / product (senza re-retrieve)
    price_id_cur, product_id_cur, price_obj_in_sub = _active_item_ids_from_sub(sub)
    need_price_metadata = False
    if price_id_cur and (
        md.get("active_price_id") != price_id_cur or
        md.get("active_product_id") != product_id_cur or
        (not md.get("variant")) or
        (not md.get("plan_type"))
    ):
        # Prova a leggere i metadata del price dall’oggetto già presente
        price_md = (price_obj_in_sub or {}).get("metadata") or {}
        if not price_md or not price_md.get("variant"):
            need_price_metadata = True

        if need_price_metadata:
            # 1 sola chiamata Price.retrieve (no expand): basta id product e metadata
            pr = stripe.Price.retrieve(price_id_cur, **opts)
            price_md = pr.get("metadata") or {}
            prod = pr.get("product")
            product_id_cur = (prod.get("id") if isinstance(prod, dict) else prod) or product_id_cur

        new_variant = price_md.get("variant")
        new_plan_type = price_md.get("plan_type") or md.get("plan_type")

        # aggiorna sempre gli id attivi
        if price_id_cur:
            patch_md["active_price_id"] = price_id_cur
        if product_id_cur:
            patch_md["active_product_id"] = product_id_cur

        # se riconosciamo plan_type/variant → aggiorna base/resources + grant config
        if new_plan_type and new_variant and new_plan_type in PLAN_VARIANTS and new_variant in PLAN_VARIANTS[new_plan_type]:
            old_base = base
            base_new = PLAN_VARIANTS[new_plan_type][new_variant].get("base_resources") or []
            provided = _apply_upgrade_delta_for_credits(provided, used, old_base, base_new)
            base = base_new  # per eventuale rollover più sotto

            # res_mode & grant config dalla variante/policy
            vconf = PLAN_VARIANTS[new_plan_type][new_variant]
            res_mode = str(vconf.get("res_mode") or PLAN_POLICIES.get(new_plan_type, {}).get("res_mode") or "add")

            patch_md.update({
                "plan_type": new_plan_type,
                "variant": new_variant,
                "base_resources_provided_json": json.dumps(base_new, separators=(",", ":")),
                "res_mode": res_mode,
                "res_grant_interval": str(PLAN_POLICIES.get(new_plan_type, {}).get("res_grant_interval") or "month"),
                "res_grant_interval_count": str(int(PLAN_POLICIES.get(new_plan_type, {}).get("res_grant_interval_count") or 1)),
            })
        changed = True

    # ── 2) ROLLOVER allineato a Stripe period (senza re-retrieve)
    interval, interval_count = _extract_grant_config_from_metadata({**md, **patch_md})
    now_ts = _now_ts()
    try:
        last_grant_period_end = int(md.get("last_grant_period_end") or 0)
    except Exception:
        last_grant_period_end = 0

    # init "last_grant_period_end" se manca, usando current_period_end della sub già in mano
    if last_grant_period_end <= 0:
        curr_end = int(sub.get("current_period_end") or 0)
        if curr_end > 0 and base:
            patch_md.update({
                "last_grant_period_end": str(curr_end),
                "last_grant_at": str(now_ts),
            })
            # assicurati che i campi esistano (ma non risovrascrivere se già popolati)
            if not provided:
                provided = list(base)
                patch_md["resources_provided_json"] = json.dumps(provided, separators=(",", ":"))
            if not used:
                used = []
                patch_md["resources_used_json"] = "[]"
            changed = True
        # se non abbiamo current_period_end o base → nessun rollover
        return patch_md, provided, used, changed

    # se abbiamo una base nuova dal sync, usala
    base = _parse_resources_json(patch_md.get("base_resources_provided_json")) or base

    # applica grant multipli se sono passati più boundaries
    grants = 0
    cursor = last_grant_period_end
    while cursor and now_ts >= cursor:
        provided, used = _apply_resource_grant(provided, used, base, res_mode)
        grants += 1
        if grants >= 36:  # cap di sicurezza
            break
        cursor = _advance_ts_calendar(cursor, interval, interval_count)

    if grants > 0:
        patch_md.update({
            "resources_provided_json": json.dumps(provided, separators=(",", ":")),
            "resources_used_json": json.dumps(used, separators=(",", ":")),
            "last_grant_period_end": str(cursor),
            "last_grant_at": str(now_ts),
            "last_grant_count": str(grants),
        })
        changed = True

    return patch_md, provided, used, changed

########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
# --- NEW: Registry pricing & plan builders ---

# ─────────────────────────────────────────────────────────────────────────────
# PRESETS del Billing Portal (quali varianti mostrare)
# ─────────────────────────────────────────────────────────────────────────────

# Predefiniamo due preset:
# - "monthly": mostra le varianti mensili
# - "annual":  mostra le varianti annuali
PORTAL_PRESETS: Dict[str, List[str]] = {
    "monthly": [ "base_monthly", "pro_monthly"],
    "annual":  [ "base_annual",  "pro_annual"],
}

PORTAL_PRESETS: Dict[str, List[str]] = {
    # mostriamo le 3 varianti mensili nel portal "monthly"
    "monthly": [
        "starter_monthly",
        "premium_monthly",
        "enterprise_monthly",
    ],
    # e le 3 varianti annuali nel portal "annual"
    "annual": [
        "starter_annual",
        "premium_annual",
        "enterprise_annual",
    ],
}



# --- NEW: Regole per risorsa per plan_type (vincoli min/max/step) ---
# Le chiavi delle risorse DEVONO combaciare con quelle usate dai pricing methods.
'''RESOURCE_RULES: Dict[str, Dict[str, Dict[str, Optional[float]]]] = {
    # Esempio: per AI Standard
    "Cloud Standard": {
        "n_servers":     {"min": 1.0,   "max": 50.0,   "step": 1.0},
        "ssd_gb":        {"min": 0.0,   "max": 5000.0, "step": 10.0},
        "bandwidth_tb":  {"min": 0.0,   "max": 100.0,  "step": 1.0},
        "gpu_hours":     {"min": None,  "max": None,   "step": None},  # opzionale
        "storage_gb":    {"min": 0.0,   "max": 10000.0,"step": 10.0},
    },
    # Esempio: per AI Pro
    "Cloud Pro": {
        "n_servers":     {"min": 1.0,   "max": 200.0,  "step": 1.0},
        "ssd_gb":        {"min": 0.0,   "max": 20000.0,"step": 10.0},
        "bandwidth_tb":  {"min": 0.0,   "max": 300.0,  "step": 1.0},
        "gpu_hours":     {"min": 0.0,   "max": 5000.0, "step": 1.0},
        "storage_gb":    {"min": 0.0,   "max": 50000.0,"step": 10.0},
    },
}'''

# --- Regole risorsa: ora gestiamo solo "credits" (accumulabili) ---
RESOURCE_RULES: Dict[str, Dict[str, Dict[str, Optional[float]]]] = {
    "ai_standard": {
        "credits": {"min": 0.0, "max": None, "step": 1.0},  # step 1 credito
    },
    "AI Pro": {
        "credits": {"min": 0.0, "max": None, "step": 1.0},
    },
}
# --- NEW: Policy lato server per ogni plan_type ---
# Tutto ciò che prima stava nell'input utente, ora è fissato qui.
# --- MOD: Policy lato server per ogni plan_type (aggiunte chiavi res_*) ---

PLAN_POLICIES: Dict[str, Dict[str, Any]] = {
    "ai_standard": {
        "currency": "eur",
        "recurring": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
        #"trial_period_days": 7,
        "tax_behavior": "exclusive",
        "allow_promotion_codes": False,
        "automatic_tax": {"enabled": True},
        "tax_id_collection": {"enabled": True},
        "billing_address_collection": "required",
        "payment_settings": None,
        "payment_behavior": None,
        "customer_update": {"address": "auto", "name": "auto"},

        # ▼▼▼ ACCUMULO crediti
        "res_mode": "add",
        "res_grant_interval": "month",           # accredito mensile (anche per annuali, vedi varianti sotto)
        "res_grant_interval_count": 1,

        "enforce_single_subscription": "portal_update",
    },
    "AI Pro": {
        "currency": "eur",
        "recurring": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
        #"trial_period_days": 14,
        "tax_behavior": "exclusive",
        "allow_promotion_codes": True,
        "automatic_tax": {"enabled": True},
        "tax_id_collection": {"enabled": True},
        "billing_address_collection": "required",
        "payment_settings": None,
        "payment_behavior": None,
        "customer_update": {"address": "auto", "name": "auto"},

        # ▼▼▼ ACCUMULO crediti
        "res_mode": "add",
        "res_grant_interval": "month",
        "res_grant_interval_count": 1,

        "enforce_single_subscription": "portal_update",
    },
}


'''PLAN_VARIANTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "AI Standard": {
        # Mensili
        "base_monthly": {
            "blueprint": {
                "product_key": "ai_plan_base_monthly",
                "product_name": "AI Plan – Base (Monthly)",
                "unit_amount": 2900,  # €29,00
                "interval": "month", "interval_count": 1, "usage_type": "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 1000, "unit": "credits"},
            ],
            "res_mode": "add",
        },
        "pro_monthly": {
            "blueprint": {
                "product_key": "ai_plan_pro_monthly",
                "product_name": "AI Plan – Pro (Monthly)",
                "unit_amount": 9900,  # €99,00
                "interval": "month", "interval_count": 1, "usage_type": "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 5000, "unit": "credits"},
            ],
            "res_mode": "add",
        },

        # Annuali (puoi scegliere se mettere 12x o la stessa dote mensile: i grant seguiranno policy)
        "base_annual": {
            "blueprint": {
                "product_key": "ai_plan_base_annual",
                "product_name": "AI Plan – Base (Annual)",
                "unit_amount": 29000,  # €290,00
                "interval": "year", "interval_count": 1, "usage_type": "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 12000, "unit": "credits"},  # 12×1000
            ],
            "res_mode": "add",
        },
        "pro_annual": {
            "blueprint": {
                "product_key": "ai_plan_pro_annual",
                "product_name": "AI Plan – Pro (Annual)",
                "unit_amount": 99000,  # €990,00
                "interval": "year", "interval_count": 1, "usage_type": "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 60000, "unit": "credits"},  # 12×5000
            ],
            "res_mode": "add",
        },
    },
}'''

PLAN_VARIANTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "ai_standard": {
        # ───────────── Mensili ─────────────
        "starter_monthly": {
            "blueprint": {
                "product_key":  "ai_std_starter_monthly",
                "product_name": "BoxedAI – Starter (Monthly)",
                "unit_amount":  199,   # €1.99
                "interval":     "month",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 1000, "unit": "credits"},
            ],
            "res_mode": "add",
        },
        "premium_monthly": {
            "blueprint": {
                "product_key":  "ai_std_premium_monthly",
                "product_name": "BoxedAI – Premium (Monthly)",
                "unit_amount":  499,   # €4.99
                "interval":     "month",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 5000, "unit": "credits"},
            ],
            "res_mode": "add",
        },
        "enterprise_monthly": {
            "blueprint": {
                "product_key":  "ai_std_enterprise_monthly",
                "product_name": "BoxedAI – Enterprise (Monthly)",
                "unit_amount":  999,   # €9.99
                "interval":     "month",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 15000, "unit": "credits"},
            ],
            "res_mode": "add",
        },

        # ───────────── Annuali ─────────────
        "starter_annual": {
            "blueprint": {
                "product_key":  "ai_std_starter_annual",
                "product_name": "BoxedAI – Starter (Annual)",
                "unit_amount":  1990,  # €19.90
                "interval":     "year",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 12000, "unit": "credits"},  # 12×1000
            ],
            "res_mode": "add",
        },
        "premium_annual": {
            "blueprint": {
                "product_key":  "ai_std_premium_annual",
                "product_name": "BoxedAI – Premium (Annual)",
                "unit_amount":  4990,  # €49.90
                "interval":     "year",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 60000, "unit": "credits"},  # 12×5000
            ],
            "res_mode": "add",
        },
        "enterprise_annual": {
            "blueprint": {
                "product_key":  "ai_std_enterprise_annual",
                "product_name": "BoxedAI – Enterprise (Annual)",
                "unit_amount":  9990,  # €99.90
                "interval":     "year",
                "interval_count": 1,
                "usage_type":   "licensed",
            },
            "base_resources": [
                {"key": "credits", "quantity": 180000, "unit": "credits"},  # 12×15000
            ],
            "res_mode": "add",
        },
    },
}



# (opzionale) limita quali pricing_method sono ammessi per ciascun piano
ALLOWED_METHODS_BY_PLAN: Dict[str, List[str]] = {
    "AI Standard": ["linear_sum"],
    "AI Pro": ["linear_sum", "tiered_ai"],
}

# (opzionale) allowlist domini di redirect per evitare open-redirect
REDIRECT_ALLOWLIST = os.getenv("REDIRECT_ALLOWLIST", "https://tuo-sito.com,https://console.tuo-sito.com,http://localhost:3000")
_ALLOWED_RETURN_HOSTS = {u.strip() for u in REDIRECT_ALLOWLIST.split(",") if u.strip()}

from urllib.parse import urlparse
def _validate_return_url(url: str) -> str:
    try:
        u = urlparse(url)
        origin = f"{u.scheme}://{u.netloc}"

        if origin not in _ALLOWED_RETURN_HOSTS:
            raise ValueError(f"origin non in allowlist: {origin}")
        return url
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid success_url/cancel_url")


# --- Registry pricing & plan builders (UPDATED) ---

from typing import Tuple, Dict, Optional, List, Callable, Any

# Risultato del pricing:
# (product_name, unit_amount, price_metadata, product_metadata, description, resources_provided)
PricingResult = Tuple[str, int, Dict[str, str], Dict[str, str], Optional[str], List[DynamicResource]]

PricingFn = Callable[[DynamicCheckoutRequest], PricingResult]

# Il builder crea realmente Product+Price su Stripe
# -> ritorna (price_id, created_product_id)
#    NOTA: ora riceve anche la 'policy' lato server (currency/recurring/tax, ecc.)
PlanBuilderFn = Callable[
    [DynamicCheckoutRequest, PricingResult, str, Dict[str, Any]],
    Tuple[str, Optional[str]]
]

def _q(resources: List[DynamicResource], key: str, default: float = 0.0) -> float:
    for r in resources:
        if r.key == key:
            return float(r.quantity)
    return float(default)

# ---------------------------
# PRICING METHODS (esempi)
# ---------------------------

def pricing_linear_sum(req: DynamicCheckoutRequest) -> PricingResult:
    """
    Prezzo lineare:
      - server: 20,00€ cad (2000 cent)
      - ssd_gb: 0,05€ / GB (5 cent)
      - bandwidth_tb: 7,00€ / TB (700 cent)
    Le "risorse fornite" iniziali sono quelle richieste, ma vengono
    decorate con i vincoli (min/max/step) definiti per il plan_type.
    """
    per_server = 2000   # cent
    per_gb_ssd = 5      # cent
    per_tb_bw = 700     # cent

    n   = _q(req.resources, "n_servers")
    ssd = _q(req.resources, "ssd_gb")
    bw  = _q(req.resources, "bandwidth_tb")

    unit_amount = max(100, int(n * per_server + ssd * per_gb_ssd + bw * per_tb_bw))  # minimo 1,00€

    product_name = f"{req.plan_type} (Linear)"
    price_md = {
        "pricing_method": "linear_sum",
        "n_servers": str(int(n)),
        "ssd_gb": str(int(ssd)),
        "bandwidth_tb": str(int(bw)),
    }
    product_md = {"plan_type": req.plan_type, "plan_key": f"{req.plan_type}_linear_v1"}
    desc = f"{int(n)} server, {int(ssd)}GB SSD, {int(bw)}TB BW"

    # default: fornite = richieste → poi decoro con i vincoli di policy
    provided_dicts = [r.model_dump() for r in req.resources]
    provided_dicts = _decorate_with_rules(req.plan_type, provided_dicts)

    # Ritorno come DynamicResource (preserva key/unit/quantity + aggiunge min/max/step come extra fields)
    provided = [DynamicResource(**{k: v for k, v in d.items() if k in ("key", "unit", "quantity")}) for d in provided_dicts]

    return product_name, unit_amount, price_md, product_md, desc, provided


def pricing_tiered_ai(req: DynamicCheckoutRequest) -> PricingResult:
    """
    Prezzo a scaglioni:
      - prime 100 GPUh: 25,00€ / h (2500 cent)
      - oltre 100 GPUh: 18,00€ / h (1800 cent)
      - storage: 2,00€ / GB (200 cent)
    Le "risorse fornite" iniziali sono quelle richieste, decorate con i vincoli (min/max/step) da policy.
    """
    gpu = _q(req.resources, "gpu_hours")
    st  = _q(req.resources, "storage_gb")

    unit_amount = max(
        100,
        int(min(gpu, 100) * 2500 + max(gpu - 100, 0) * 1800 + st * 200)  # minimo 1,00€
    )

    product_name = f"{req.plan_type} (AI Tiered)"
    price_md = {
        "pricing_method": "tiered_ai",
        "gpu_hours": str(int(gpu)),
        "storage_gb": str(int(st)),
    }
    product_md = {"plan_type": req.plan_type, "plan_key": f"{req.plan_type}_ai_tiered_v1"}
    desc = f"{int(gpu)} GPUh, {int(st)}GB storage"

    # default: fornite = richieste → poi decoro con i vincoli di policy
    provided_dicts = [r.model_dump() for r in req.resources]
    provided_dicts = _decorate_with_rules(req.plan_type, provided_dicts)

    # Ritorno come DynamicResource (preserva key/unit/quantity + aggiunge min/max/step come extra fields)
    provided = [DynamicResource(**{k: v for k, v in d.items() if k in ("key", "unit", "quantity")}) for d in provided_dicts]

    return product_name, unit_amount, price_md, product_md, desc, provided

PRICING_METHODS: Dict[str, PricingFn] = {
    "linear_sum": pricing_linear_sum,
    "tiered_ai": pricing_tiered_ai,
}

def pricing_credits_pack(req: DynamicCheckoutRequest) -> PricingResult:
    """
    Prezzo per pacchetto crediti: es. 1€ ogni 100 crediti (0.01€/credito).
    Expect: resources = [{"key":"credits","quantity":N,"unit":"credits"}]
    """
    credits = _q(req.resources, "credits")
    cents_per_credit = 1  # 0.01 € a credito → 100 crediti = 1 €
    unit_amount = max(100, int(credits * cents_per_credit))  # minimo 1,00€

    product_name = f"{req.plan_type} (Credits pack)"
    price_md = {"pricing_method": "credits_pack", "credits": str(int(credits))}
    product_md = {"plan_type": req.plan_type, "plan_key": f"{req.plan_type}_credits_pack_v1"}
    desc = f"{int(credits)} credits"

    provided_dicts = [{"key": "credits", "quantity": int(credits), "unit": "credits"}]
    provided_dicts = _decorate_with_rules(req.plan_type, provided_dicts)
    provided = [DynamicResource(**{k: v for k, v in d.items() if k in ("key", "unit", "quantity")}) for d in provided_dicts]

    return product_name, unit_amount, price_md, product_md, desc, provided

PRICING_METHODS["credits_pack"] = pricing_credits_pack

# Consenti il metodo ai piani
ALLOWED_METHODS_BY_PLAN.update({
    "AI Standard": ["credits_pack"],
    "AI Pro": ["credits_pack"],
})

# ---------------------------
# PLAN BUILDERS
# ---------------------------
def _build_product_and_price_default(
    req: DynamicCheckoutRequest,
    calc: PricingResult,
    base_idem: str,
    opts: Dict[str, Any],
) -> Tuple[str, Optional[str]]:
    # 👇 PRIMA COSA: prendi la policy lato server dal plan_type
    policy = PLAN_POLICIES.get(req.plan_type)
    if not policy:
        raise HTTPException(status_code=400, detail=f"Policy non definita per plan_type='{req.plan_type}'")

    product_name, unit_amount, price_md, product_md, description, _provided = calc

    product = stripe.Product.create(
        name=product_name,
        description=description,
        metadata=product_md,
        idempotency_key=_idem(base_idem, f"product.create.{req.plan_type}.{req.pricing_method}"),
        **opts,
    )
    price = stripe.Price.create(
        product=product["id"],
        currency=policy["currency"],
        unit_amount=int(unit_amount),
        recurring={
            "interval": policy["recurring"]["interval"],
            "interval_count": policy["recurring"]["interval_count"],
            "usage_type": policy["recurring"]["usage_type"],
        },
        tax_behavior=policy.get("tax_behavior") or "exclusive",
        metadata=price_md,
        idempotency_key=_idem(base_idem, f"price.create.{req.plan_type}.{req.pricing_method}"),
        **opts,
    )
    return price["id"], product["id"]

PLAN_BUILDERS: Dict[str, PlanBuilderFn] = {
    # Specializza per tipo di piano se serve; altrimenti usa il default
    "AI Standard": _build_product_and_price_default,
    "AI Pro":      _build_product_and_price_default,
    "_default":    _build_product_and_price_default,
}

# (opzionale) mapping per vincolare i metodi ammessi per ciascun piano
ALLOWED_METHODS_BY_PLAN: Dict[str, List[str]] = {
    "AI Standard": ["linear_sum"],
    "AI Pro": ["linear_sum", "tiered_ai"],
}

def _create_price_from_dynamic_request(
    req: DynamicCheckoutRequest,
    base_idem: str,
    opts: Dict[str, Any],
) -> Tuple[str, Optional[str], PricingResult]:
    # (opzionale) vincola pricing_method per plan_type
    allowed = ALLOWED_METHODS_BY_PLAN.get(req.plan_type)
    if allowed and req.pricing_method not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"pricing_method '{req.pricing_method}' non consentito per plan_type '{req.plan_type}'"
        )

    pricing = PRICING_METHODS.get(req.pricing_method)
    if not pricing:
        raise HTTPException(status_code=400, detail=f"pricing_method non ammesso: {req.pricing_method}")

    builder = PLAN_BUILDERS.get(req.plan_type) or PLAN_BUILDERS["_default"]

    calc = pricing(req)  # -> PricingResult
    # 👇 CHIAMATA AL BUILDER SENZA policy (la recupera internamente)
    price_id, product_id = builder(req, calc, base_idem, opts)

    return price_id, product_id, calc
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################