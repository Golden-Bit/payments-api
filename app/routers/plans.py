# app/routers/plans.py
from __future__ import annotations

from typing import Optional, Literal, Dict, Any, List
from fastapi import APIRouter, Depends, Body, Request, HTTPException
from pydantic import BaseModel, Field, EmailStr
import stripe, uuid

from ..security import require_user_or_admin, Principal
from ..utils.errors import raise_from_stripe_error

router = APIRouter(
    prefix="/plans",
    tags=["plans-subscriptions"],
    responses={
        400: {"description": "Bad Request (parametri non validi o prerequisiti mancanti)"},
        401: {"description": "Unauthorized (X-API-Key mancante o non valida)"},
        403: {"description": "Forbidden (ruolo non sufficiente)"},
        429: {"description": "Rate limited by Stripe"},
        500: {"description": "Errore interno o configurazione mancante"},
    },
)

# =============================================================================
#                           SCHEMI INPUT (Pydantic)
# =============================================================================

class PlanRecurring(BaseModel):
    """
    Definisce la cadenza di fatturazione di un prezzo ricorrente (Price).
    - interval: periodo (day/week/month/year)
    - interval_count: moltiplicatore dell'intervallo (es. 1 = mensile, 12 = annuale)
    - usage_type: 'licensed' (per posti/licenze) o 'metered' (a consumo)
    """
    interval: Literal["day", "week", "month", "year"] = Field(..., description="Frequenza del ciclo di fatturazione.")
    interval_count: int = Field(1, ge=1, le=52, description="Numero di intervalli tra le fatturazioni (1=mensile, 12=annuale, etc.).")
    usage_type: Literal["licensed", "metered"] = Field("licensed", description="Modello di utilizzo: licenza o consumo (metered).")


class PlanConfig(BaseModel):
    """
    Dettagli per creare al volo Product+Price se non passi un price_id esistente.
    - product_id: se già esiste un Product
    - product_name: se vuoi creare un Product con questo nome
    - currency/unit_amount/recurring: definiscono il Price
    - trial_period_days: prova gratuita da applicare alla Subscription
    - metadata: metadati da scrivere sul Price
    """
    product_id: Optional[str] = Field(None, description="Se presente, il Price verrà associato a questo Product.")
    product_name: Optional[str] = Field(None, description="Nome Product da creare se product_id non è fornito.")
    currency: str = Field(..., min_length=3, max_length=3, description="Valuta ISO a 3 lettere (es. 'eur').")
    unit_amount: int = Field(..., ge=1, description="Importo per periodo in minimi della valuta (es. 2900 = 29.00 EUR).")
    recurring: PlanRecurring
    tax_behavior: Optional[Literal["inclusive", "exclusive", "unspecified"]] = Field(
        None, description="Comportamento fiscale del Price (se supportato)."
    )
    trial_period_days: Optional[int] = Field(None, ge=1, le=365, description="Giorni di trial da applicare alla Subscription.")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati (k/v stringa) sul Price.")


class CustomerRef(BaseModel):
    """
    Riferimento/creazione Customer:
    - customer_id: riusa un Customer esistente (cus_...)
    - email (+name): cerca/crea Customer; salva 'internal_customer_ref' in metadata
    - search_existing_by_email: usa Customer Search su email prima di creare
    - create_if_missing: crea il Customer se non trovato
    - metadata: metadati aggiuntivi
    """
    customer_id: Optional[str] = Field(None, description="ID Stripe del cliente (cus_...). Se presente, si userà questo.")
    email: Optional[EmailStr] = Field(None, description="Email cliente, usata per cercare/creare Customer.")
    name: Optional[str] = Field(None, description="Nome visuale del cliente.")
    search_existing_by_email: bool = Field(True, description="Se true, tenta Customer.search per email prima di creare.")
    create_if_missing: bool = Field(True, description="Se true, crea il Customer se non trovato.")
    internal_customer_ref: Optional[str] = Field(None, description="Tuo riferimento interno; viene scritto in metadata.")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati aggiuntivi sul Customer.")


class CheckoutSubscriptionRequest(BaseModel):
    """
    Richiesta per creare una Checkout Session (mode=subscription) e ottenere la URL Stripe.
    Opzioni principali:
    - price_id oppure plan (per creare Product+Price al volo)
    - customer: CustomerRef (riuso o creazione)
    - automatic_tax: {"enabled": true} → richiede indirizzo cliente
    - tax_id_collection: {"enabled": true} → può richiedere update del 'name'
    - customer_update: consenti a Checkout di aggiornare 'name' e/o 'address' sul Customer
    - billing_address_collection: 'auto' o 'required' (consigliato 'required' con automatic_tax)
    """
    success_url: str = Field(..., description="URL di ritorno post-pagamento. Usa {CHECKOUT_SESSION_ID} se vuoi leggere l'id.")
    cancel_url: str = Field(..., description="URL di annullamento.")
    price_id: Optional[str] = Field(None, description="ID Price ricorrente esistente (price_...). Se assente, usa 'plan'.")
    plan: Optional[PlanConfig] = Field(None, description="Dettagli del piano per creare Product+Price se non passi price_id.")
    quantity: int = Field(1, ge=1, description="Quantità (es. numero licenze).")
    customer: Optional[CustomerRef] = Field(None, description="Cliente Stripe da collegare o creare.")
    client_reference_id: Optional[str] = Field(None, description="Tuo id interno per riconciliazione (compare sulla Session).")
    allow_promotion_codes: bool = Field(True, description="Consente l’inserimento di codici promo in Checkout.")
    automatic_tax: Optional[Dict[str, Any]] = Field(None, description="Es.: {'enabled': True} per tassazione automatica.")
    tax_id_collection: Optional[Dict[str, Any]] = Field(None, description="Es.: {'enabled': True} per raccogliere VAT/Tax ID.")
    locale: Optional[str] = Field(None, description="Locale UI Checkout (es. 'it').")
    subscription_metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati scritti sulla Subscription.")
    billing_address_collection: Optional[Literal["auto", "required"]] = Field(
        "auto", description="Raccolta indirizzo di fatturazione (consigliato 'required' con automatic_tax)."
    )
    # Opzioni avanzate pass-through (usare con cautela)
    payment_settings: Optional[Dict[str, Any]] = Field(None, description="Impostazioni pagamento per la Subscription.")
    payment_behavior: Optional[str] = Field(None, description="Comportamento pagamento (vedi API Subscriptions).")

    # ✅ Supporto a customer_update per risolvere errori di tassazione & VAT
    customer_update: Optional[Dict[str, Any]] = Field(
        None,
        description="Es.: {'address':'auto','name':'auto'} per salvare dati inseriti in Checkout sul Customer.",
    )


class PortalSessionRequest(BaseModel):
    """
    Crea una Session del Billing Portal per far gestire all'utente:
    - abbonamenti (cambio piano, cancellazione),
    - metodi di pagamento,
    - storico fatture,
    - eventuali deep link (flow_data).
    """
    customer_id: str = Field(..., description="ID cliente Stripe (cus_...).")
    return_url: str = Field(..., description="URL a cui tornare al termine del Portal.")
    configuration: Optional[str] = Field(None, description="ID configurazione Portal da usare (altrimenti default).")
    flow_data: Optional[Dict[str, Any]] = Field(None, description="Deep link del Portal (es. {'type':'payment_method_update'}).")


class CancelRequest(BaseModel):
    """Cancella una Subscription subito (invoice_now/prorate opzionali) o a fine periodo."""
    cancel_now: bool = Field(False, description="true= cancella subito; false= fine periodo (cancel_at_period_end).")
    invoice_now: Optional[bool] = Field(None, description="Se cancella subito, fattura subito eventuali prorate.")
    prorate: Optional[bool] = Field(None, description="Se cancella subito, applica proratazione.")


class PauseRequest(BaseModel):
    """Pausa la riscossione dei pagamenti impostando pause_collection."""
    behavior: Literal["keep_as_draft", "mark_uncollectible", "void"] = Field(..., description="Gestione delle fatture durante la pausa.")
    resumes_at: Optional[int] = Field(None, description="Timestamp Unix per ripresa automatica (opzionale).")


class ResumeRequest(BaseModel):
    """Riprende una Subscription in pausa (endpoint resume)."""
    billing_cycle_anchor: Optional[Literal["now", "unmodified"]] = Field(None, description="Cambia/lascia l'anchor del ciclo.")
    proration_behavior: Optional[Literal["create_prorations", "always_invoice", "none"]] = Field(None, description="Gestione proration in ripresa.")


class PaymentMethodAttachRequest(BaseModel):
    """Collega un PaymentMethod al Customer e opzionalmente setta default per una Subscription."""
    customer_id: str = Field(..., description="ID Customer (cus_...).")
    payment_method_id: str = Field(..., description="ID PaymentMethod (pm_...). Ottenuto via Stripe.js/Elements/SetupIntent.")
    set_as_default_for_subscription_id: Optional[str] = Field(
        None, description="Se presente, imposta questo PM come default per la Subscription indicata."
    )

# =============================================================================
#                               HELPERS INTERNI
# =============================================================================

def _base_idem_from_request(req: Request) -> str:
    """
    Ricava una chiave base d’idempotenza per la richiesta corrente:
    - usa eventuale 'Idempotency-Key' del client,
    - altrimenti ne genera una nuova.
    ATTENZIONE: non va riutilizzata tal quale su endpoint diversi!
    Viene sempre derivata per operazione con _idem(...).
    """
    return req.headers.get("Idempotency-Key") or req.headers.get("X-Idempotency-Key") or str(uuid.uuid4())


def _idem(base: str, suffix: str) -> str:
    """Deriva una chiave d’idempotenza specifica per un’operazione (evita riuso cross-endpoint)."""
    return f"{base}:{suffix}"


def _opts_from_request(req: Request) -> Dict[str, Any]:
    """
    Costruisce le opzioni SDK Stripe a partire dalla request FastAPI.
    - Propaga Stripe Connect: 'x-stripe-account' → stripe_account.
    - NON inserire qui idempotency_key: viene passata per-singola chiamata.
    """
    opts: Dict[str, Any] = {}
    acct = req.headers.get("x-stripe-account")
    if acct:
        opts["stripe_account"] = acct
    return opts


def _ensure_customer(ref: Optional[CustomerRef], opts: Dict[str, Any]) -> Optional[str]:
    """
    Risolve/crea il Customer:
    - Se customer_id: lo riusa e scrive eventuali metadata (internal_customer_ref).
    - Altrimenti, se email & search_existing_by_email: Customer.search.
    - Se non trovato e create_if_missing: Customer.create.
    """
    if not ref:
        return None
    try:
        if ref.customer_id:
            if ref.internal_customer_ref or ref.metadata:
                stripe.Customer.modify(
                    ref.customer_id,
                    metadata={**(ref.metadata or {}), **({"internal_customer_ref": ref.internal_customer_ref} if ref.internal_customer_ref else {})},
                    **opts,
                )
            return ref.customer_id

        cust_id = None
        if ref.email and ref.search_existing_by_email:
            res = stripe.Customer.search(query=f'email:"{ref.email}"', **opts)
            if res and res.get("data"):
                cust_id = res["data"][0]["id"]

        if not cust_id and ref.create_if_missing:
            created = stripe.Customer.create(
                email=ref.email,
                name=ref.name,
                metadata={**(ref.metadata or {}), **({"internal_customer_ref": ref.internal_customer_ref} if ref.internal_customer_ref else {})},
                **opts,
            )
            cust_id = created["id"]
        return cust_id
    except Exception as e:
        raise_from_stripe_error(e)


def _ensure_price_and_product(req_body: CheckoutSubscriptionRequest, opts: Dict[str, Any], base_idem: str) -> str:
    """
    Ritorna un price_id:
    - Se payload.price_id presente → lo riusa.
    - Altrimenti crea Product (se manca) e poi Price, applicando idempotency *distinte*.
    """
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
        raise_from_stripe_error(e)

# =============================================================================
#                                 ENDPOINTS
# =============================================================================

@router.post(
    "/checkout",
    summary="Crea Checkout Session (abbonamento) e restituisce l'URL",
    description="""
Crea una **Checkout Session** con `mode=subscription` e restituisce:
- `url`: link alla pagina di pagamento Stripe,
- `id`: id della Session,
- `customer_id`: l'eventuale Customer collegato/creato,
- `created_product_id` / `created_price_id` se creati al volo.

**Tassazione & VAT**
- Se `automatic_tax.enabled = true`, Stripe necessita di una **tax location** valida:
  - passa un Customer con address valido **oppure**
  - imposta `billing_address_collection = "required"` e `customer_update.address = "auto"` per salvare l'indirizzo inserito in Checkout.
- Se `tax_id_collection.enabled = true` su Customer esistente, abilita `customer_update.name = "auto"` per permettere l’aggiornamento del nome fiscale.

**Idempotenza**
- Ogni operazione ha una chiave derivata dedicata: `product.create`, `price.create`, `checkout.session.create`.
    """,
)
def create_subscription_checkout(
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: CheckoutSubscriptionRequest = Body(...),
):
    base_idem = _base_idem_from_request(request)
    opts = _opts_from_request(request)

    try:
        # 1) Customer (riuso/ricerca/creazione)
        customer_id = _ensure_customer(payload.customer, opts)

        # 2) Price (ed eventuale Product)
        created_product_id = None
        created_price_id = None

        if payload.price_id:
            price_id = payload.price_id
        else:
            price_id = _ensure_price_and_product(payload, opts, base_idem)
            created_price_id = price_id
            # se abbiamo creato un Product al volo, recuperalo via expand
            if payload.plan and not payload.plan.product_id:
                pr = stripe.Price.retrieve(price_id, expand=["product"], **opts)
                if isinstance(pr.get("product"), dict):
                    created_product_id = pr["product"]["id"]

        # 3) Subscription metadata (aggiungi internal_customer_ref se fornito)
        subscription_metadata = {**(payload.subscription_metadata or {})}
        if payload.customer and payload.customer.internal_customer_ref:
            subscription_metadata.setdefault("internal_customer_ref", payload.customer.internal_customer_ref)

        # 4) Fallback automatici per tassazione / VAT
        #    (non sovrascrive valori già presenti in payload.customer_update)
        cu = dict(payload.customer_update or {})
        if payload.automatic_tax and payload.automatic_tax.get("enabled"):
            # Richiedi indirizzo in Checkout e salvalo sul Customer
            if payload.billing_address_collection != "required":
                payload.billing_address_collection = "required"
            cu.setdefault("address", "auto")

        if payload.tax_id_collection and payload.tax_id_collection.get("enabled"):
            # Consenti aggiornamento del 'name' per VAT (business name)
            cu.setdefault("name", "auto")

        # 5) Crea la Checkout Session (idempotency dedicata)
        create_kwargs: Dict[str, Any] = dict(
            mode="subscription",
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
            line_items=[{"price": price_id, "quantity": payload.quantity}],
            customer=customer_id,
            client_reference_id=payload.client_reference_id,
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
        # passa customer_update solo se non vuoto
        if cu:
            create_kwargs["customer_update"] = cu
        # passa eventuali opzioni avanzate
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
    except Exception as e:
        raise_from_stripe_error(e)


@router.post(
    "/portal/session",
    summary="Crea link al Billing Portal (gestione abbonamenti/metodi/storico)",
    description="""
Restituisce una **Billing Portal Session** (URL temporaneo Stripe-hosted) per:
- gestione abbonamenti (cambio piano/cancellazione),
- gestione metodi di pagamento,
- download storico fatture.
    """,
)
def create_billing_portal_session(
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: PortalSessionRequest = Body(...),
):
    opts = _opts_from_request(request)
    try:
        sess = stripe.billing_portal.Session.create(
            customer=payload.customer_id,
            return_url=payload.return_url,
            configuration=payload.configuration,
            flow_data=payload.flow_data,
            **opts,
        )
        return {"id": sess["id"], "url": sess["url"]}
    except Exception as e:
        raise_from_stripe_error(e)

# ------------------------ Gestione/consultazione abbonamenti ------------------------

@router.get(
    "/customers/{customer_id}/subscriptions",
    summary="Lista abbonamenti di un Customer",
    description="Restituisce le Subscription del Customer. Usa 'status_filter' (active/past_due/canceled/trialing/all) e 'limit'.",
)
def list_customer_subscriptions(
    customer_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    status_filter: Optional[str] = None,
    limit: int = 10,
):
    opts = _opts_from_request(request)
    try:
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status_filter:
            params["status"] = status_filter
        return stripe.Subscription.list(**params, **opts)
    except Exception as e:
        raise_from_stripe_error(e)


@router.get(
    "/subscriptions/{subscription_id}",
    summary="Dettaglio Subscription",
    description="Recupera una Subscription per id.",
)
def get_subscription(
    subscription_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
):
    opts = _opts_from_request(request)
    try:
        return stripe.Subscription.retrieve(subscription_id, **opts)
    except Exception as e:
        raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/cancel",
    summary="Cancella una Subscription (immediato o a fine periodo)",
    description="""
- Se `cancel_now=true` → DELETE immediato (opz. invoice_now/prorate).
- Altrimenti → update `cancel_at_period_end=true` (cancellazione al termine del periodo).
""",
)
def cancel_subscription(
    subscription_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: CancelRequest = Body(...),
):
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
        raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/pause",
    summary="Pausa la riscossione di una Subscription",
    description="Imposta `pause_collection` con behavior e opzionale resumes_at.",
)
def pause_subscription(
    subscription_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: PauseRequest = Body(...),
):
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
        raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/resume",
    summary="Riprende una Subscription in pausa",
    description="Chiama l'endpoint 'resume' con anchor/proration opzionali.",
)
def resume_subscription(
    subscription_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: ResumeRequest = Body(default=ResumeRequest()),
):
    opts = _opts_from_request(request)
    try:
        return stripe.Subscription.resume(
            subscription_id,
            billing_cycle_anchor=payload.billing_cycle_anchor,
            proration_behavior=payload.proration_behavior,
            **opts
        )
    except Exception as e:
        raise_from_stripe_error(e)

# ------------------------ Payment Methods & storico ------------------------

@router.get(
    "/customers/{customer_id}/payment-methods",
    summary="Lista PaymentMethods del Customer",
    description="Filtra per tipo (es. 'card', 'sepa_debit') e limita il numero di risultati.",
)
def list_payment_methods(
    customer_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    type: str = "card",
    limit: int = 10,
):
    opts = _opts_from_request(request)
    try:
        return stripe.PaymentMethod.list(customer=customer_id, type=type, limit=limit, **opts)
    except Exception as e:
        raise_from_stripe_error(e)


@router.post(
    "/customers/payment-methods/attach",
    summary="Attach PM al Customer (+ set default per Subscription opzionale)",
    description="""
Collega un PaymentMethod (pm_...) al Customer (idealmente ottenuto via SetupIntent su frontend).
Se fornisci `set_as_default_for_subscription_id`, imposta quel PM come default della Subscription.
""",
)
def attach_payment_method(
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: PaymentMethodAttachRequest = Body(...),
):
    opts = _opts_from_request(request)
    try:
        pm = stripe.PaymentMethod.attach(payload.payment_method_id, customer=payload.customer_id, **opts)
        if payload.set_as_default_for_subscription_id:
            stripe.Subscription.modify(
                payload.set_as_default_for_subscription_id,
                default_payment_method=payload.payment_method_id,
                **opts
            )
        return pm
    except Exception as e:
        raise_from_stripe_error(e)


@router.get(
    "/customers/{customer_id}/invoices",
    summary="Storico fatture (Invoices) del Customer",
    description="Restituisce le fatture del Customer, con filtro 'status' opzionale e 'limit'.",
)
def list_invoices(
    customer_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    limit: int = 10,
    status: Optional[str] = None,
):
    opts = _opts_from_request(request)
    try:
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status:
            params["status"] = status
        return stripe.Invoice.list(**params, **opts)
    except Exception as e:
        raise_from_stripe_error(e)


@router.get(
    "/customers/{customer_id}/charges",
    summary="Storico addebiti (Charges) del Customer",
    description="Lista di Charges associati al Customer (limit configurabile).",
)
def list_charges(
    customer_id: str,
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    limit: int = 10,
):
    opts = _opts_from_request(request)
    try:
        return stripe.Charge.list(customer=customer_id, limit=limit, **opts)
    except Exception as e:
        raise_from_stripe_error(e)
