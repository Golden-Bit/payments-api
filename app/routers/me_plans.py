# app/routers/me_plans.py
from __future__ import annotations

import os
import uuid
from typing import Optional, Literal, Dict, Any
from datetime import datetime, timezone
import stripe
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, EmailStr

# ✅ IMPORTA ED USA LO SDK ESISTENTE (come da richiesta)
from ..auth_sdk.sdk import CognitoSDK, AccessTokenRequest  # <-- aggiorna il path di import

# Se riusi helper/costrutti dal router /plans, puoi importarli direttamente
# oppure incollarne una copia qui. Qui li reimplementiamo in modo minimale e sicuro per “ME”.

router = APIRouter(
    prefix="/me/plans",
    tags=["me-plans-subscriptions"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized (token mancante/invalid)"},
        403: {"description": "Forbidden"},
        429: {"description": "Rate limited by Stripe"},
        500: {"description": "Errore interno"},
    },
)

# =============================================================================
#                         CONFIG / DEPENDENCIES
# =============================================================================

AUTH_API_BASE = os.getenv("AUTH_API_BASE", "https://teatek-llm.theia-innovation.com/auth").rstrip("/")  # base URL del tuo servizio Auth
_auth_sdk = CognitoSDK(base_url=AUTH_API_BASE)

# Se necessario, puoi fissare anche la Stripe API version via env
STRIPE_API_VERSION = os.getenv("STRIPE_API_VERSION")
if STRIPE_API_VERSION:
    stripe.api_version = STRIPE_API_VERSION

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


class CheckoutMeRequest(BaseModel):
    """
    Richiesta per creare la Checkout Session dell'UTENTE CORRENTE.
    ⚠️ Nessun 'customer.internal_customer_ref' accettato: lo ricaviamo dal token (sub/username).
    """
    success_url: str = Field(..., description="URL post-pagamento (puoi usare {CHECKOUT_SESSION_ID}).")
    cancel_url: str = Field(..., description="URL annullamento.")
    price_id: Optional[str] = Field(None, description="Price ricorrente esistente (price_...).")
    plan: Optional[PlanConfig] = Field(None, description="Se non passi price_id, creo Product+Price da qui.")
    quantity: int = Field(1, ge=1, description="Quantità (es. posti/licenze).")

    # UI & tassazione
    allow_promotion_codes: bool = True
    automatic_tax: Optional[Dict[str, Any]] = Field(default_factory=lambda: {"enabled": True})
    tax_id_collection: Optional[Dict[str, Any]] = Field(default_factory=lambda: {"enabled": True})
    locale: Optional[str] = None
    billing_address_collection: Optional[Literal["auto", "required"]] = "auto"

    # Metadati da scrivere sulla Subscription
    subscription_metadata: Optional[Dict[str, str]] = Field(default_factory=dict)

    # Opzioni avanzate pass-through (usare con cautela)
    payment_settings: Optional[Dict[str, Any]] = None
    payment_behavior: Optional[str] = None

    # 🌟 customer_update gestito lato server (per VAT/address) — opzionale override
    customer_update: Optional[Dict[str, Any]] = None


class PortalMeRequest(BaseModel):
    return_url: str = Field(..., description="URL a cui tornare al termine del Portal.")
    configuration: Optional[str] = Field(None, description="ID configurazione Portal; se non passata uso default.")
    flow_data: Optional[Dict[str, Any]] = Field(None, description="Deep link Portal (es. {'type':'payment_method_update'}).")


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


def _ensure_price_and_product(req_body: CheckoutMeRequest, opts: Dict[str, Any], base_idem: str) -> str:
    if req_body.price_id:
        return req_body.price_id
    if not req_body.plan:
        raise HTTPException(status_code=400, detail="Devi fornire 'price_id' oppure 'plan'.")

    try:
        product_id = req_body.plan.product_id
        if not product_id:
            p = stripe.Product.create(
                name=req_body.plan.product_name or "Subscription",
                idempotency_key=_idem(base_idem, "product.create"),
                **opts
            )
            product_id = p["id"]

        price = stripe.Price.create(
            product=product_id,
            currency=req_body.plan.currency,
            unit_amount=req_body.plan.unit_amount,
            recurring={
                "interval": req_body.plan.recurring.interval,
                "interval_count": req_body.plan.recurring.interval_count,
                "usage_type": req_body.plan.recurring.usage_type,
            },
            tax_behavior=req_body.plan.tax_behavior,
            metadata=req_body.plan.metadata or {},
            idempotency_key=_idem(base_idem, "price.create"),
            **opts,
        )
        return price["id"]
    except Exception as e:
        _raise_from_stripe_error(e)


def _raise_from_stripe_error(e: Exception) -> None:
    # Adapter semplice: mappa errori Stripe a HTTPException con messaggio chiaro
    msg = getattr(e, "user_message", None) or str(e)
    raise HTTPException(status_code=400, detail={"error": {"message": msg}})


# =============================================================================
#                                  ENDPOINTS “ME”
# =============================================================================

@router.post(
    "/checkout",
    summary="Crea la Checkout Session per l'UTENTE CORRENTE e restituisce l'URL",
)
def me_create_checkout(
    request: Request,
    payload: CheckoutMeRequest = Body(...),
    authorization: Optional[str] = Header(None),
):
    """
    - Verifica token via CognitoSDK (senza X-API-Key)
    - Risolve/crea il Customer per l’utente (metadata.internal_customer_ref = user_ref)
    - Crea (se serve) Product+Price con idempotency separata
    - Forza best practice AutomaticTax/VAT con customer_update (se richiesto)
    - Crea Checkout Session (mode=subscription) con idempotency dedicata
    """
    access_token = _require_bearer_token(authorization)

    user = _verify_and_get_user(access_token)  # {"user_ref", "email", "name", "claims"}

    base_idem = _base_idem_from_request(request)
    opts = _opts_from_request(request)

    try:
        # 1) Customer per l'utente corrente (no override dal client!)
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)

        # 2) Price (ed eventuale Product)
        created_product_id = None
        created_price_id = None
        if payload.price_id:
            price_id = payload.price_id
        else:
            price_id = _ensure_price_and_product(payload, opts, base_idem)
            created_price_id = price_id
            if payload.plan and not payload.plan.product_id:
                pr = stripe.Price.retrieve(price_id, expand=["product"], **opts)
                if isinstance(pr.get("product"), dict):
                    created_product_id = pr["product"]["id"]

        # 3) Subscription metadata — imposta SEMPRE il ref utente
        subscription_metadata = {**(payload.subscription_metadata or {})}
        subscription_metadata.setdefault("internal_customer_ref", user["user_ref"])

        # 4) customer_update (VAT/address) — fallback automatico
        cu = dict(payload.customer_update or {})
        if payload.automatic_tax and payload.automatic_tax.get("enabled"):
            if payload.billing_address_collection != "required":
                payload.billing_address_collection = "required"
            cu.setdefault("address", "auto")
        if payload.tax_id_collection and payload.tax_id_collection.get("enabled"):
            cu.setdefault("name", "auto")

        # 5) Crea Checkout Session
        create_kwargs: Dict[str, Any] = dict(
            mode="subscription",
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
            line_items=[{"price": price_id, "quantity": payload.quantity}],
            customer=customer_id,
            client_reference_id=user["user_ref"],  # tracciabilità
            allow_promotion_codes=payload.allow_promotion_codes,
            automatic_tax=payload.automatic_tax,
            tax_id_collection=payload.tax_id_collection,
            locale=payload.locale,
            billing_address_collection=payload.billing_address_collection,
            subscription_data={
                **({"trial_period_days": payload.plan.trial_period_days} if payload.plan and payload.plan.trial_period_days else {}),
                "metadata": subscription_metadata,
            },
            idempotency_key=_idem(base_idem, "checkout.session.create"),
            **opts,
        )
        if cu:
            create_kwargs["customer_update"] = cu
        if payload.payment_settings:
            create_kwargs["payment_settings"] = payload.payment_settings
        if payload.payment_behavior:
            create_kwargs["payment_behavior"] = payload.payment_behavior

        session = stripe.checkout.Session.create(**create_kwargs)

        return {
            "id": session["id"],
            "url": session["url"],
            "customer_id": session.get("customer"),
            "created_product_id": created_product_id,
            "created_price_id": created_price_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        _raise_from_stripe_error(e)


@router.post(
    "/portal/session",
    summary="Crea un link al Billing Portal per l'UTENTE CORRENTE",
)
def me_billing_portal(
    request: Request,
    payload: PortalMeRequest = Body(...),
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        # Customer dell'utente
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        sess = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=payload.return_url,
            configuration=payload.configuration,
            flow_data=payload.flow_data,
            **opts,
        )
        return {"id": sess["id"], "url": sess["url"]}
    except HTTPException:
        raise
    except Exception as e:
        _raise_from_stripe_error(e)


# ---------------------- CONSULTAZIONE (ME) ----------------------

@router.get(
    "/subscriptions",
    summary="Lista abbonamenti dell'UTENTE CORRENTE",
)
def me_list_subscriptions(
    request: Request,
    authorization: Optional[str] = Header(None),
    status_filter: Optional[str] = None,
    limit: int = 10,
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status_filter:
            params["status"] = status_filter
        return stripe.Subscription.list(**params, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/subscriptions/{subscription_id}",
    summary="Dettaglio Subscription dell'UTENTE CORRENTE",
)
def me_get_subscription(
    subscription_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    _ = _verify_and_get_user(access_token)  # non serve altro per ora (ownership check su Connect se necessario)
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.retrieve(subscription_id, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/payment-methods",
    summary="PaymentMethods dell'UTENTE CORRENTE",
)
def me_list_payment_methods(
    request: Request,
    authorization: Optional[str] = Header(None),
    type: str = "card",
    limit: int = 10,
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        return stripe.PaymentMethod.list(customer=customer_id, type=type, limit=limit, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/invoices",
    summary="Storico fatture (Invoices) dell'UTENTE CORRENTE",
)
def me_list_invoices(
    request: Request,
    authorization: Optional[str] = Header(None),
    limit: int = 10,
    status: Optional[str] = None,
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status:
            params["status"] = status
        return stripe.Invoice.list(**params, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/charges",
    summary="Storico addebiti (Charges) dell'UTENTE CORRENTE",
)
def me_list_charges(
    request: Request,
    authorization: Optional[str] = Header(None),
    limit: int = 10,
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        customer_id = _ensure_customer_for_user(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        return stripe.Charge.list(customer=customer_id, limit=limit, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


# ---------------------- AZIONI (ME) ----------------------

@router.post(
    "/subscriptions/{subscription_id}/cancel",
    summary="Cancella una Subscription dell'UTENTE CORRENTE",
)
def me_cancel_subscription(
    subscription_id: str,
    payload: CancelRequest = Body(...),
    request: Request = None,
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    _ = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        if payload.cancel_now:
            return stripe.Subscription.delete(
                subscription_id,
                invoice_now=payload.invoice_now,
                prorate=payload.prorate,
                **opts
            )
        else:
            return stripe.Subscription.modify(subscription_id, cancel_at_period_end=True, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/pause",
    summary="Pausa la riscossione di una Subscription (ME)",
)
def me_pause_subscription(
    subscription_id: str,
    payload: PauseRequest = Body(...),
    request: Request = None,
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    _ = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.modify(
            subscription_id,
            pause_collection={
                "behavior": payload.behavior,
                **({"resumes_at": payload.resumes_at} if payload.resumes_at else {}),
            },
            **opts
        )
    except Exception as e:
        _raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/resume",
    summary="Riprende una Subscription in pausa (ME)",
)
def me_resume_subscription(
    subscription_id: str,
    payload: ResumeRequest = Body(default=ResumeRequest()),
    request: Request = None,
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    _ = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.resume(
            subscription_id,
            billing_cycle_anchor=payload.billing_cycle_anchor,
            proration_behavior=payload.proration_behavior,
            **opts
        )
    except Exception as e:
        _raise_from_stripe_error(e)



@router.post(
    "/payment-methods/attach",
    summary="Collega un PaymentMethod all'UTENTE CORRENTE (+ opz. set default su Subscription)",
    description="""
Collega un PaymentMethod (pm_...) al Customer dell'utente autenticato.  
- Il PM deve essere creato sul frontend (Stripe.js/SetupIntent).  
- Se `set_as_default_for_subscription_id` è passato, il PM diventa default per quella Subscription.  
""",
)
def me_attach_payment_method(
    payload: AttachMeRequest = Body(...),
    request: Request = None,
    authorization: Optional[str] = Header(None),
):
    access_token = _require_bearer_token(authorization)
    user = _verify_and_get_user(access_token)
    opts = _opts_from_request(request)

    try:
        # Trova/crea Customer per l’utente
        customer_id = _ensure_customer_for_user(
            user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
        )

        # 1) attach PaymentMethod
        pm = stripe.PaymentMethod.attach(payload.payment_method_id, customer=customer_id, **opts)

        # 2) opzionale: set default per Subscription
        if payload.set_as_default_for_subscription_id:
            stripe.Subscription.modify(
                payload.set_as_default_for_subscription_id,
                default_payment_method=payload.payment_method_id,
                **opts,
            )

        return pm
    except Exception as e:
        _raise_from_stripe_error(e)
