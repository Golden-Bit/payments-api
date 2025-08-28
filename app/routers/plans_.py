# app/routers/plans.py
from __future__ import annotations

from typing import Optional, Literal, Dict, Any, List
from fastapi import APIRouter, Depends, Body, Request, HTTPException, status
from pydantic import BaseModel, Field, EmailStr
import stripe

from ..security import require_user_or_admin, Principal
from ..utils.errors import raise_from_stripe_error

router = APIRouter(prefix="/plans", tags=["plans-subscriptions"])

# ---------
# Schemi input
# ---------

class PlanRecurring(BaseModel):
    """Definisce la cadenza di fatturazione del prezzo ricorrente."""
    interval: Literal["day", "week", "month", "year"] = Field(..., description="Frequenza del ciclo di fatturazione.")
    interval_count: int = Field(1, ge=1, le=52, description="Numero di intervalli tra le fatturazioni (es. 1=mensile, 12=annuale).")
    usage_type: Literal["licensed", "metered"] = Field("licensed", description="Modello di utilizzo: prezzo a licenza o a consumo.")

class PlanConfig(BaseModel):
    """
    Configurazione del 'piano' da proporre in Checkout.
    Se non passi price_id, la API creerà Product+Price con questi parametri.
    """
    product_id: Optional[str] = Field(None, description="Se presente, il Price verrà associato a questo Product.")
    product_name: Optional[str] = Field(None, description="Nome Product da creare se product_id non è fornito.")
    currency: str = Field(..., min_length=3, max_length=3, description="Valuta ISO a 3 lettere (es. 'eur').")
    unit_amount: int = Field(..., ge=1, description="Importo per periodo in minimi della valuta (es. 2900 = 29.00 EUR).")
    recurring: PlanRecurring
    tax_behavior: Optional[Literal["inclusive", "exclusive", "unspecified"]] = Field(None, description="Comportamento fiscale del Price.")
    trial_period_days: Optional[int] = Field(None, ge=1, le=365, description="Giorni di trial da applicare alla Subscription.")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati (chiave-valore stringa) sul Price.")

class CustomerRef(BaseModel):
    """
    Riferimento al cliente. Usa uno di:
    - customer_id (cus_...) per collegare cliente esistente;
    - email (+nome) per crearne uno; puoi salvare internal_customer_ref in metadata.
    """
    customer_id: Optional[str] = Field(None, description="ID Stripe del cliente (cus_...). Se presente, si userà questo.")
    email: Optional[EmailStr] = Field(None, description="Email cliente, usata per creare/ricercare un Customer.")
    name: Optional[str] = Field(None, description="Nome visuale del cliente.")
    search_existing_by_email: bool = Field(True, description="Se true, tenta Customer.search per email prima di crearne uno.")
    create_if_missing: bool = Field(True, description="Se true, crea il Customer se non trovato/esistente.")
    internal_customer_ref: Optional[str] = Field(None, description="Tuo riferimento interno (verrà scritto in metadata).")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati aggiuntivi da salvare sul Customer.")

class CheckoutSubscriptionRequest(BaseModel):
    """
    Crea una Checkout Session (mode=subscription) e restituisce l'URL della pagina Stripe.
    Passa un price_id esistente o i dettagli del piano (PlanConfig) per creare Product+Price.
    """
    success_url: str = Field(..., description="URL da aprire dopo il pagamento riuscito. Includi {CHECKOUT_SESSION_ID} se vuoi recuperare l'id della sessione.")
    cancel_url: str = Field(..., description="URL di annullamento.")
    price_id: Optional[str] = Field(None, description="ID di un Price ricorrente esistente (price_...). Se assente, usa 'plan'.")
    plan: Optional[PlanConfig] = Field(None, description="Dettagli del piano per creare Product+Price se non passi price_id.")
    quantity: int = Field(1, ge=1, description="Quantità (es. posti/licenze).")
    customer: Optional[CustomerRef] = Field(None, description="Riferimento al cliente; se assente, Checkout potrà crearne uno.")
    client_reference_id: Optional[str] = Field(None, description="Tuo id interno per riconciliazione (comparirà sulla Session).")
    allow_promotion_codes: bool = Field(True, description="Consente l'inserimento di codici promo in Checkout.")
    automatic_tax: Optional[Dict[str, Any]] = Field(None, description="Esempio: {'enabled': true} per abilitare tassazione automatica.")
    tax_id_collection: Optional[Dict[str, Any]] = Field(None, description="Esempio: {'enabled': true} per raccogliere VAT ID.")
    locale: Optional[str] = Field(None, description="Localizzazione UI Checkout (es. 'it').")
    subscription_metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadati da scrivere sulla Subscription creata.")
    billing_address_collection: Optional[Literal["auto", "required"]] = Field("auto", description="Raccolta indirizzo di fatturazione in Checkout.")
    # Opzioni avanzate pass-through (usale con cautela)
    payment_settings: Optional[Dict[str, Any]] = Field(None, description="Impostazioni pagamento per la Subscription.")
    payment_behavior: Optional[str] = Field(None, description="Comportamento pagamento (vedi API Subscriptions).")

class PortalSessionRequest(BaseModel):
    """Crea una Billing Portal Session per un Customer e restituisce l'URL."""
    customer_id: str = Field(..., description="ID cliente Stripe (cus_...).")
    return_url: str = Field(..., description="URL a cui tornare al termine della gestione nel Portal.")
    configuration: Optional[str] = Field(None, description="ID di una configurazione del Portal; se assente, usa quella di default.")
    flow_data: Optional[Dict[str, Any]] = Field(None, description="Deep link flows del Portal (es. type='payment_method_update', 'subscription_update', ecc.).")

class CancelRequest(BaseModel):
    """Cancellazione abbonamento: immediata o a fine periodo."""
    cancel_now: bool = Field(False, description="Se true, cancella subito. Se false, imposta cancel_at_period_end=true.")
    invoice_now: Optional[bool] = Field(None, description="Se cancella subito, fattura subito eventuali prorate (opzionale).")
    prorate: Optional[bool] = Field(None, description="Se cancella subito, applica proratazione (opzionale).")

class PauseRequest(BaseModel):
    """Pausa della riscossione dei pagamenti."""
    behavior: Literal["keep_as_draft", "mark_uncollectible", "void"] = Field(..., description="Come gestire le fatture durante la pausa.")
    resumes_at: Optional[int] = Field(None, description="Timestamp Unix opzionale per definire quando riprendere automaticamente.")

class ResumeRequest(BaseModel):
    """Ripresa di un abbonamento in pausa."""
    billing_cycle_anchor: Optional[Literal["now", "unmodified"]] = Field(None, description="Ripristina l'anchor del ciclo di fatturazione o mantienilo inalterato.")
    proration_behavior: Optional[Literal["create_prorations", "always_invoice", "none"]] = Field(None, description="Come gestire le proration in ripresa.")

class PaymentMethodAttachRequest(BaseModel):
    """Collega un PaymentMethod (pm_...) al Customer e/o setta come default della Subscription."""
    customer_id: str = Field(..., description="ID cliente (cus_...).")
    payment_method_id: str = Field(..., description="ID PaymentMethod (pm_...). Ottenuto via Stripe.js/Elements/SetupIntent.")
    set_as_default_for_subscription_id: Optional[str] = Field(None, description="Se presente, imposta questo PM come default per la Subscription indicata.")

# ---------
# Helpers interni
# ---------

def _opts_from_request(req: Request) -> Dict[str, Any]:
    """
    Estrae header opzionali da propagare allo SDK Stripe:
    - Idempotency-Key (idempotenza)
    - x-stripe-account (Connect)
    """
    opts: Dict[str, Any] = {}
    idem = req.headers.get("Idempotency-Key") or req.headers.get("X-Idempotency-Key")
    if idem:
        opts["idempotency_key"] = idem
    acct = req.headers.get("x-stripe-account")
    if acct:
        opts["stripe_account"] = acct
    return opts

def _ensure_customer(ref: Optional[CustomerRef], opts: Dict[str, Any]) -> Optional[str]:
    """Risolvi o crea il Customer e assicura che internal_customer_ref venga salvato in metadata."""
    if not ref:
        return None
    try:
        if ref.customer_id:
            # aggiorna eventuale metadata
            if ref.internal_customer_ref or ref.metadata:
                stripe.Customer.modify(
                    ref.customer_id,
                    metadata={**(ref.metadata or {}), **({"internal_customer_ref": ref.internal_customer_ref} if ref.internal_customer_ref else {})},
                    **opts,
                )
            return ref.customer_id
        # Cerca per email se richiesto
        cust_id = None
        if ref.email and ref.search_existing_by_email:
            res = stripe.Customer.search(query=f'email:"{ref.email}"', **opts)
            if res and res.get("data"):
                cust_id = res["data"][0]["id"]
        # Crea se mancante
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

def _ensure_price_and_product(req: CheckoutSubscriptionRequest, opts: Dict[str, Any]) -> str:
    """Ritorna un price_id: usa price_id se fornito, altrimenti crea Product+Price secondo PlanConfig."""
    if req.price_id:
        return req.price_id
    if not req.plan:
        raise HTTPException(status_code=400, detail="Devi fornire 'price_id' oppure 'plan'.")
    try:
        product_id = req.plan.product_id
        if not product_id:
            # Crea Product minimale
            p = stripe.Product.create(name=req.plan.product_name or "Subscription", **opts)
            product_id = p["id"]
        price = stripe.Price.create(
            product=product_id,
            currency=req.plan.currency,
            unit_amount=req.plan.unit_amount,
            recurring={
                "interval": req.plan.recurring.interval,
                "interval_count": req.plan.recurring.interval_count,
                "usage_type": req.plan.recurring.usage_type,
            },
            tax_behavior=req.plan.tax_behavior,
            metadata=req.plan.metadata or {},
            **opts,
        )
        return price["id"]
    except Exception as e:
        raise_from_stripe_error(e)

# ---------
# Endpoint principali
# ---------

@router.post("/checkout", summary="Crea pagina di pagamento (Checkout) per abbonamento e restituisce l'URL")
def create_subscription_checkout(
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: CheckoutSubscriptionRequest = Body(..., examples={
        "piano_standard": {
            "summary": "Piano Standard mensile EUR 29 con trial 7 giorni",
            "description": "Crea Product+Price al volo e Checkout Session. Collega a Customer esistente e salva riferimenti interni.",
            "value": {
                "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
                "cancel_url": "https://tuo-sito.com/cancel",
                "plan": {
                    "product_name": "AI Standard",
                    "currency": "eur",
                    "unit_amount": 2900,
                    "recurring": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
                    "trial_period_days": 7,
                    "metadata": {"plan_key": "ai_std_v1"}
                },
                "quantity": 1,
                "customer": {
                    "customer_id": "cus_1234567890",  # oppure ometti per creare da email
                    "internal_customer_ref": "user-42"
                },
                "client_reference_id": "user-42",
                "allow_promotion_codes": True,
                "automatic_tax": {"enabled": True},
                "tax_id_collection": {"enabled": True},
                "subscription_metadata": {"tenant_id": "acme-1"},
                "billing_address_collection": "auto"
            }
        },
        "con_price_esistente": {
            "summary": "Usa un Price ricorrente già esistente",
            "value": {
                "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
                "cancel_url": "https://tuo-sito.com/cancel",
                "price_id": "price_abc123",
                "customer": {"email": "mario.rossi@example.com", "name": "Mario Rossi", "internal_customer_ref": "crm-987"},
                "client_reference_id": "crm-987"
            }
        }
    })
):
    """
    Crea una **Checkout Session** con `mode=subscription` e restituisce:
    - `url`: link alla pagina Stripe
    - `id`: id della sessione (per retrieve o debug)
    - `customer_id`: cliente collegato/creato
    - eventuali id creati (product/price)
    """
    opts = _opts_from_request(request)
    try:
        # 1) Customer
        customer_id = _ensure_customer(payload.customer, opts)

        # 2) Price
        created_product_id = None
        created_price_id = None
        if payload.price_id:
            price_id = payload.price_id
        else:
            pre_existing_products = set()
            if payload.plan and payload.plan.product_id:
                pre_existing_products.add(payload.plan.product_id)
            price_id = _ensure_price_and_product(payload, opts)
            created_price_id = price_id
            # piccola euristica: se non avevi product_id, abbiamo creato un Product
            if payload.plan and not payload.plan.product_id:
                # purtroppo non abbiamo direttamente product_id qui: lo recuperiamo dal Price
                pr_obj = stripe.Price.retrieve(price_id, expand=["product"], **opts)
                if isinstance(pr_obj.get("product"), dict):
                    created_product_id = pr_obj["product"]["id"]

        # 3) Subscription metadata: includi internal_customer_ref se fornito
        subscription_metadata = {**(payload.subscription_metadata or {})}
        if payload.customer and payload.customer.internal_customer_ref:
            subscription_metadata.setdefault("internal_customer_ref", payload.customer.internal_customer_ref)

        # 4) Crea Checkout Session
        session = stripe.checkout.Session.create(
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
                **({
                       "trial_period_days": payload.plan.trial_period_days} if payload.plan and payload.plan.trial_period_days else {}),
                "metadata": subscription_metadata
            },
            **opts,
        )

        return {
            "id": session["id"],
            "url": session["url"],
            "customer_id": session.get("customer"),
            "created_product_id": created_product_id,
            "created_price_id": created_price_id,
        }
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/portal/session", summary="Crea un link al Billing Portal per gestione abbonamenti/metodi/storico")
def create_billing_portal_session(
    request: Request,
    p: Principal = Depends(require_user_or_admin),
    payload: PortalSessionRequest = Body(..., examples={
        "semplice": {
            "summary": "Portal standard",
            "value": {"customer_id": "cus_123", "return_url": "https://tuo-sito.com/account"}
        },
        "deeplink": {
            "summary": "Portal con deep link (aggiorna metodo pagamento)",
            "value": {
                "customer_id": "cus_123",
                "return_url": "https://tuo-sito.com/account",
                "flow_data": {"type": "payment_method_update"}
            }
        }
    })
):
    """
    Restituisce un URL temporaneo del **Billing Customer Portal** per il cliente.
    Usa `flow_data` per deep link verso azioni specifiche (es. update metodo pagamento, update/cancel subscription).
    """
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

# ---- Gestione/consultazione abbonamenti ----

@router.get("/customers/{customer_id}/subscriptions", summary="Lista abbonamenti di un Customer")
def list_customer_subscriptions(customer_id: str, request: Request, p: Principal = Depends(require_user_or_admin), status_filter: Optional[str] = None, limit: int = 10):
    """
    Elenca le Subscription (active, past_due, canceled, trialing, all ...).
    Usa `status_filter` per filtrare, altrimenti default (active).
    """
    opts = _opts_from_request(request)
    try:
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status_filter:
            params["status"] = status_filter
        return stripe.Subscription.list(**params, **opts)
    except Exception as e:
        raise_from_stripe_error(e)

@router.get("/subscriptions/{subscription_id}", summary="Dettaglio Subscription")
def get_subscription(subscription_id: str, request: Request, p: Principal = Depends(require_user_or_admin)):
    opts = _opts_from_request(request)
    try:
        return stripe.Subscription.retrieve(subscription_id, **opts)
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/subscriptions/{subscription_id}/cancel", summary="Cancella abbonamento (subito o a fine periodo)")
def cancel_subscription(subscription_id: str, request: Request, p: Principal = Depends(require_user_or_admin), payload: CancelRequest = Body(...)):
    """
    - Se `cancel_now=true` -> DELETE /v1/subscriptions/{id} (con invoice_now/prorate se richiesto).
    - Altrimenti -> update cancel_at_period_end=true (si disattiva al termine del periodo corrente).
    """
    opts = _opts_from_request(request)
    try:
        if payload.cancel_now:
            return stripe.Subscription.delete(subscription_id, invoice_now=payload.invoice_now, prorate=payload.prorate, **opts)
        else:
            return stripe.Subscription.modify(subscription_id, cancel_at_period_end=True, **opts)
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/subscriptions/{subscription_id}/pause", summary="Pausa riscossione pagamenti dell'abbonamento")
def pause_subscription(subscription_id: str, request: Request, p: Principal = Depends(require_user_or_admin), payload: PauseRequest = Body(...)):
    """
    Pausa la riscossione dei pagamenti impostando `pause_collection`.
    """
    opts = _opts_from_request(request)
    try:
        return stripe.Subscription.modify(
            subscription_id,
            pause_collection={
                "behavior": payload.behavior,
                **({"resumes_at": payload.resumes_at} if payload.resumes_at else {})
            },
            **opts
        )
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/subscriptions/{subscription_id}/resume", summary="Riprende un abbonamento in pausa")
def resume_subscription(subscription_id: str, request: Request, p: Principal = Depends(require_user_or_admin), payload: ResumeRequest = Body(default=ResumeRequest())):
    """
    Usa l'endpoint dedicato **resume** per togliere la pausa e (opzionalmente) reimpostare l'anchor o creare proration.
    """
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

# ---- Metodi di pagamento & storico ----

@router.get("/customers/{customer_id}/payment-methods", summary="Lista PaymentMethods del Customer")
def list_payment_methods(customer_id: str, request: Request, p: Principal = Depends(require_user_or_admin), type: str = "card", limit: int = 10):
    """
    Restituisce i PaymentMethods salvati per il Customer (filtrabili per tipo, es. 'card', 'sepa_debit', ...).
    """
    opts = _opts_from_request(request)
    try:
        return stripe.PaymentMethod.list(customer=customer_id, type=type, limit=limit, **opts)
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/customers/payment-methods/attach", summary="Collega un PaymentMethod a un Customer (e opzionalmente set default per una Subscription)")
def attach_payment_method(request: Request, p: Principal = Depends(require_user_or_admin), payload: PaymentMethodAttachRequest = Body(...)):
    """
    Collega `pm_...` al Customer (idealmente ottenuto via SetupIntent).
    Puoi opzionalmente impostarlo come default per una Subscription.
    """
    opts = _opts_from_request(request)
    try:
        pm = stripe.PaymentMethod.attach(payload.payment_method_id, customer=payload.customer_id, **opts)
        if payload.set_as_default_for_subscription_id:
            stripe.Subscription.modify(payload.set_as_default_for_subscription_id, default_payment_method=payload.payment_method_id, **opts)
        return pm
    except Exception as e:
        raise_from_stripe_error(e)

@router.get("/customers/{customer_id}/invoices", summary="Storico fatture (Invoices) del Customer")
def list_invoices(customer_id: str, request: Request, p: Principal = Depends(require_user_or_admin), limit: int = 10, status: Optional[str] = None):
    opts = _opts_from_request(request)
    try:
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status:
            params["status"] = status
        return stripe.Invoice.list(**params, **opts)
    except Exception as e:
        raise_from_stripe_error(e)

@router.get("/customers/{customer_id}/charges", summary="Storico addebiti (Charges) del Customer")
def list_charges(customer_id: str, request: Request, p: Principal = Depends(require_user_or_admin), limit: int = 10):
    opts = _opts_from_request(request)
    try:
        return stripe.Charge.list(customer=customer_id, limit=limit, **opts)
    except Exception as e:
        raise_from_stripe_error(e)
