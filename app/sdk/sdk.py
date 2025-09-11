# teatek_me_plans_sdk.py
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Literal

import requests
from pydantic import BaseModel, Field, field_validator

# ─────────────────────────────────────────────────────────────────────────────
# Errori / util
# ─────────────────────────────────────────────────────────────────────────────

class ApiError(RuntimeError):
    """Errore HTTP dall'API: contiene status_code e payload di dettaglio."""
    def __init__(self, status_code: int, payload: Any):
        super().__init__(f"HTTP {status_code}: {payload}")
        self.status_code = status_code
        self.payload = payload

def _idem(suffix: str) -> str:
    """Genera una Idempotency-Key “random + suffix” per sicurezza client-side."""
    return f"{uuid.uuid4()}:{suffix}"

# ─────────────────────────────────────────────────────────────────────────────
# Schemi INPUT (rispecchiano il server) — Pydantic v2 per validazione
# ─────────────────────────────────────────────────────────────────────────────

class ResourceItem(BaseModel):
    key: str
    quantity: float = Field(..., ge=0)
    unit: Optional[str] = None

class ConsumeResourcesRequest(BaseModel):
    """
    Body per /me/plans/subscriptions/{subscription_id}/resources/consume
    NOTA: il server si aspetta SEMPRE `items=[...]`.
    """
    items: List[ResourceItem] = Field(..., min_items=1, description="Delta di consumo (quantità positive)")
    reason: Optional[str] = Field(None, description="Motivo del consumo (solo log/metadata)")
    expected_plan_type: Optional[str] = Field(None, description="Guard di concorrenza")
    expected_variant: Optional[str] = Field(None, description="Guard di concorrenza")

class SetResourcesRequest(BaseModel):
    """
    Body per /me/plans/subscriptions/{subscription_id}/resources/set
    """
    resources_provided: List[ResourceItem] = Field(..., min_items=1, description="Set completo delle risorse fornite")
    reset_used: bool = Field(False, description="Se true azzera 'used'")
    reason: Optional[str] = Field(None, description="Motivo set (log/metadata)")
    expected_plan_type: Optional[str] = None
    expected_variant: Optional[str] = None

# --------------- Checkout dinamico/varianti -----------------

class DynamicResource(BaseModel):
    key: str
    quantity: float = Field(..., ge=0)
    unit: Optional[str] = None  # es. "credits"

class PortalFeaturesOverride(BaseModel):
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
    logo: Optional[str] = None
    icon: Optional[str] = None

class PortalConfigSelector(BaseModel):
    """
    Se passi configuration_id lo useremo direttamente.
    Altrimenti plan_type + portal_preset o variants_override.
    """
    configuration_id: Optional[str] = None
    plan_type: Optional[str] = None
    portal_preset: Optional[Literal["monthly","annual"]] = None
    variants_override: Optional[List[str]] = None
    features_override: Optional[PortalFeaturesOverride] = None
    business_profile_override: Optional[BusinessProfileOverride] = None
    branding_override: Optional[BrandingOverride] = None

class DynamicCheckoutRequest(BaseModel):
    """
    Richiesta per /me/plans/checkout.
    Usa EITHER 'variant' OR 'pricing_method' + 'resources'.
    """
    success_url: str
    cancel_url: str

    plan_type: str

    # Modalità A (catalogo)
    variant: Optional[str] = Field(
        None,
        description="es. base_monthly | pro_monthly | base_annual | pro_annual"
    )

    # Modalità B (dinamico)
    pricing_method: Optional[str] = Field(
        None, description="Metodo di pricing lato server (registry)"
    )
    resources: Optional[List[DynamicResource]] = Field(
        None, description="Risorse richieste (obbligatorie se usi pricing_method)"
    )

    locale: Optional[str] = None
    # opzionale, usato dal server in enforcement “portal_update”
    portal: Optional[PortalConfigSelector] = None

    @field_validator("variant")
    @classmethod
    def _xor_variant_or_dynamic(cls, v, info):
        has_variant = v is not None
        has_pm = bool(info.data.get("pricing_method"))
        has_res = info.data.get("resources") and len(info.data.get("resources") or []) > 0

        if has_variant and (has_pm or has_res):
            raise ValueError("Usa EITHER 'variant' OR 'pricing_method/resources', non entrambi.")
        if (not has_variant) and (not has_pm):
            raise ValueError("Devi passare 'variant' oppure 'pricing_method' + 'resources'.")
        if has_pm and not has_res:
            raise ValueError("Quando usi 'pricing_method' devi fornire 'resources' non vuoto.")
        return v

class PortalSessionRequest(BaseModel):
    """
    Body per POST /me/plans/portal/session (nuovo schema).
    Passa un selettore 'portal' (PortalConfigSelector) con eventuali override UI.
    """
    return_url: str
    portal: PortalConfigSelector
    flow_data: Optional[Dict[str, Any]] = None

# NEW ─────────────────────────────────────────────────────────────────────────
class RawDiscountSpec(BaseModel):
    """
    Specifica 'grezza' di sconto da trasformare lato server in Coupon Stripe:
      - kind = 'percent'  → percent_off (es. 10 = 10%)
      - kind = 'amount'   → amount_off (in cent) + currency ('eur', 'usd', ...)
      - duration          → once | repeating | forever
      - duration_in_months→ richiesto se duration='repeating'
    """
    kind: Literal["percent", "amount"] = Field(..., description="Tipo di sconto")
    percent_off: Optional[float] = Field(None, ge=0, le=100, description="Sconto percentuale, es. 10 = 10%")
    amount_off: Optional[int]    = Field(None, ge=1, description="Importo in minimi (cent)")
    currency: Optional[str]      = Field(None, min_length=3, max_length=3, description="ISO currency per amount_off")
    duration: Literal["once", "repeating", "forever"] = Field("once", description="Durata del coupon")
    duration_in_months: Optional[int] = Field(None, ge=1, le=36, description="Obbligatorio se duration='repeating'")
    name: Optional[str] = Field(None, description="Etichetta coupon (facoltativa)")

    # ── Validazioni base (Pydantic v2)
    @field_validator("percent_off")
    @classmethod
    def _validate_percent_off(cls, v, info):
        if (info.data.get("kind") == "percent") and (v is None):
            raise ValueError("percent_off richiesto quando kind='percent'")
        return v

    @field_validator("amount_off")
    @classmethod
    def _validate_amount_off(cls, v, info):
        if info.data.get("kind") == "amount" and v is None:
            raise ValueError("amount_off richiesto quando kind='amount'")
        return v

    @field_validator("currency")
    @classmethod
    def _validate_currency_for_amount(cls, v, info):
        # currency può essere omessa: il server la inferirà dal price target.
        return v

    # ── Helper di comodo
    @classmethod
    def percent(cls, percent_off: float, *, duration: Literal["once","repeating","forever"]="once",
                duration_in_months: Optional[int]=None, name: Optional[str]=None) -> "RawDiscountSpec":
        return cls(kind="percent", percent_off=percent_off, duration=duration,
                   duration_in_months=duration_in_months, name=name)

    @classmethod
    def amount(cls, amount_off: int, currency: Optional[str]=None, *,
               duration: Literal["once","repeating","forever"]="once",
               duration_in_months: Optional[int]=None, name: Optional[str]=None) -> "RawDiscountSpec":
        return cls(kind="amount", amount_off=amount_off, currency=currency, duration=duration,
                   duration_in_months=duration_in_months, name=name)

class PortalUpgradeDeepLinkRequest(BaseModel):
    """
    Body per POST /me/plans/portal/deeplinks/upgrade.
    Genera un link al Portal che apre direttamente la conferma di upgrade/downgrade.
    """
    return_url: str
    subscription_id: str
    portal: PortalConfigSelector

    # Target: EITHER 'target_price_id' OR ('target_plan_type' + 'target_variant')
    target_price_id: Optional[str] = None
    target_plan_type: Optional[str] = None
    target_variant: Optional[str] = None

    quantity: Optional[int] = 1
    #proration_behavior: Optional[Literal["create_prorations", "always_invoice", "none"]] = "create_prorations"

    # Sconti opzionali (tutte supportate; lato server verranno fuse in 'discounts'):
    coupon_id: Optional[str] = None
    promotion_code: Optional[str] = None
    discounts: Optional[List[Dict[str, Any]]] = None
    raw_discounts: Optional[List[RawDiscountSpec]] = None   # NEW ← sconti grezzi



class PortalUpdateDeepLinkRequest(BaseModel):
    return_url: str
    subscription_id: str
    portal: PortalConfigSelector

class PortalCancelDeepLinkRequest(BaseModel):
    return_url: str
    subscription_id: str
    portal: PortalConfigSelector
    immediate: Optional[bool] = False

# --------------- Azioni subscription -----------------

class CancelRequest(BaseModel):
    cancel_now: bool = False
    invoice_now: Optional[bool] = None
    prorate: Optional[bool] = None

class PauseRequest(BaseModel):
    behavior: Literal["keep_as_draft","mark_uncollectible","void"]
    resumes_at: Optional[int] = None  # epoch seconds

class ResumeRequest(BaseModel):
    billing_cycle_anchor: Optional[Literal["now","unmodified"]] = None
    proration_behavior: Optional[Literal["create_prorations","always_invoice","none"]] = None

class AttachMeRequest(BaseModel):
    payment_method_id: str
    set_as_default_for_subscription_id: Optional[str] = None

# ─────────────────────────────────────────────────────────────────────────────
# Schemi OUTPUT / wrappers comodi
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckoutSessionOut:
    id: str
    url: str
    customer_id: Optional[str]
    created_product_id: Optional[str]
    created_price_id: Optional[str]

@dataclass
class PortalSessionOut:
    id: str
    url: str
    configuration_id: str

@dataclass
class PortalDeepLinkOut:
    id: str
    url: str
    configuration_id: str

@dataclass
class ListOut:
    data: List[Dict[str, Any]]
    raw: Dict[str, Any]

@dataclass
class ResourcesState:
    subscription_id: str
    plan_type: Optional[str]
    variant: Optional[str]
    pricing_method: Optional[str]
    active_price_id: Optional[str]
    resources: Dict[str, List[Dict[str, Any]]]   # requested/provided/used/remaining
    period_start: Optional[int]
    period_end: Optional[int]
    customer_id: Optional[str]
    raw: Dict[str, Any]

# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────

class MePlansClient:
    """
    Client Python per gli endpoint:
      - POST   /me/plans/checkout
      - POST   /me/plans/portal/session
      - POST   /me/plans/portal/deeplinks/update
      - POST   /me/plans/portal/deeplinks/cancel
      - POST   /me/plans/portal/deeplinks/pause
      - GET    /me/plans/subscriptions
      - GET    /me/plans/subscriptions/{subscription_id}
      - GET    /me/plans/payment-methods
      - GET    /me/plans/invoices
      - GET    /me/plans/charges
      - POST   /me/plans/subscriptions/{subscription_id}/cancel
      - POST   /me/plans/subscriptions/{subscription_id}/pause
      - POST   /me/plans/subscriptions/{subscription_id}/resume
      - GET    /me/plans/subscriptions/{subscription_id}/resources
      - POST   /me/plans/subscriptions/{subscription_id}/resources/consume
      - POST   /me/plans/subscriptions/{subscription_id}/resources/set
      - POST   /me/plans/payment-methods/attach
    """

    def __init__(
        self,
        api_base: str,
        access_token: str,
        *,
        admin_api_key: Optional[str] = None,
        default_timeout: float = 40.0,
        stripe_account: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        """
        :param api_base: es. "http://localhost:8000"
        :param access_token: Bearer token ottenuto dal tuo Auth Service (Cognito)
        :param admin_api_key: richiesto per endpoint privilegiati (Portal, consume/set risorse, deeplink)
        :param default_timeout: timeout HTTP (secondi)
        :param stripe_account: opzionale, header 'x-stripe-account' per Connect
        :param session: opzionale, riuso di requests.Session
        """
        self.api_base = api_base.rstrip("/")
        self.access_token = access_token
        self.admin_api_key = admin_api_key
        self.default_timeout = default_timeout
        self.stripe_account = stripe_account
        self._http = session or requests.Session()

    # ------------- HTTP helpers -------------

    def _headers(self, *, admin: bool = False, idempotency_suffix: Optional[str] = None) -> Dict[str, str]:
        h = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        if self.stripe_account:
            h["x-stripe-account"] = self.stripe_account
        if admin:
            if not self.admin_api_key:
                raise ApiError(403, "Missing admin_api_key for privileged endpoint")
            h["X-API-Key"] = self.admin_api_key
        if idempotency_suffix:
            h["Idempotency-Key"] = _idem(idempotency_suffix)
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        admin: bool = False,
        idempotency_suffix: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        url = f"{self.api_base}{path}"
        h = self._headers(admin=admin, idempotency_suffix=idempotency_suffix)

        resp = self._http.request(
            method,
            url,
            headers=h,
            params=params,
            json=(json_body if json_body is not None else None),
            timeout=timeout or self.default_timeout,
        )
        if resp.status_code >= 300:
            try:
                payload = resp.json()
            except Exception:
                payload = resp.text
            raise ApiError(resp.status_code, payload)
        if not resp.content:
            return None
        try:
            return resp.json()
        except Exception:
            return resp.text

    # ------------- Endpoint mapping -------------

    # 1) Checkout
    def create_checkout(self, body: DynamicCheckoutRequest) -> CheckoutSessionOut:
        """
        POST /me/plans/checkout
        - Autenticazione: JWT Bearer (utente)
        - Idempotency: impostata dallo SDK
        - Richiede `variant` (catalogo) OPPURE `pricing_method` + `resources` (dinamico)
        """
        data = self._request(
            "POST",
            "/me/plans/checkout",
            json_body=body.model_dump(exclude_none=True),
            idempotency_suffix="me.plans.checkout",
        )
        return CheckoutSessionOut(
            id=data.get("id"),
            url=data.get("url"),
            customer_id=data.get("customer_id"),
            created_product_id=data.get("created_product_id"),
            created_price_id=data.get("created_price_id"),
        )

    # 2) Billing Portal (sessione)
    def create_portal_session(self, body: PortalSessionRequest) -> PortalSessionOut:
        """
        POST /me/plans/portal/session
        - Richiede X-API-Key (admin)
        """
        data = self._request(
            "POST",
            "/me/plans/portal/session",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix="me.plans.portal.session",
        )
        return PortalSessionOut(id=data["id"], url=data["url"], configuration_id=data["configuration_id"])

    def create_deeplink_upgrade(self, body: PortalUpgradeDeepLinkRequest) -> PortalDeepLinkOut:
        """
        POST /me/plans/portal/deeplinks/upgrade
        - Richiede X-API-Key (admin) e ownership della subscription
        - Apre direttamente la schermata di conferma upgrade/downgrade nel Portal
        """
        data = self._request(
            "POST",
            "/me/plans/portal/deeplinks/upgrade",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix="portal.deeplink.upgrade",
        )
        return PortalDeepLinkOut(
            id=data["id"],
            url=data["url"],
            configuration_id=data["configuration_id"],
        )

    # 3) Deeplink — update
    def create_deeplink_update(self, body: PortalUpdateDeepLinkRequest) -> PortalDeepLinkOut:
        """
        POST /me/plans/portal/deeplinks/update
        - Richiede X-API-Key (admin) e ownership della subscription
        """
        data = self._request(
            "POST",
            "/me/plans/portal/deeplinks/update",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix="portal.deeplink.update",
        )
        return PortalDeepLinkOut(id=data["id"], url=data["url"], configuration_id=data["configuration_id"])

    # 4) Deeplink — cancel
    def create_deeplink_cancel(self, body: PortalCancelDeepLinkRequest) -> PortalDeepLinkOut:
        """
        POST /me/plans/portal/deeplinks/cancel
        - Richiede X-API-Key (admin) e ownership della subscription
        - Se immediate=True il deeplink apre il flow “cancel now”
        """
        data = self._request(
            "POST",
            "/me/plans/portal/deeplinks/cancel",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix="portal.deeplink.cancel",
        )
        return PortalDeepLinkOut(id=data["id"], url=data["url"], configuration_id=data["configuration_id"])

    # 6) List subscriptions (ME)
    def list_subscriptions(self, *, status_filter: Optional[str] = None, limit: int = 10) -> ListOut:
        """
        GET /me/plans/subscriptions?status_filter=&limit=
        """
        params: Dict[str, Any] = {"limit": limit}
        if status_filter:
            params["status_filter"] = status_filter
        data = self._request("GET", "/me/plans/subscriptions", params=params)
        return ListOut(data=data.get("data") or [], raw=data)

    # 7) Get subscription
    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """
        GET /me/plans/subscriptions/{subscription_id}
        """
        return self._request("GET", f"/me/plans/subscriptions/{subscription_id}")

    # 8) List payment methods
    def list_payment_methods(self, *, type: str = "card", limit: int = 10) -> ListOut:
        """
        GET /me/plans/payment-methods?type=card&limit=10
        """
        data = self._request("GET", "/me/plans/payment-methods", params={"type": type, "limit": limit})
        return ListOut(data=data.get("data") or [], raw=data)

    # 9) List invoices
    def list_invoices(self, *, limit: int = 10, status: Optional[str] = None) -> ListOut:
        """
        GET /me/plans/invoices?status=&limit=
        """
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        data = self._request("GET", "/me/plans/invoices", params=params)
        return ListOut(data=data.get("data") or [], raw=data)

    # 10) List charges
    def list_charges(self, *, limit: int = 10) -> ListOut:
        """
        GET /me/plans/charges?limit=
        """
        data = self._request("GET", "/me/plans/charges", params={"limit": limit})
        return ListOut(data=data.get("data") or [], raw=data)

    # 11) Cancel subscription
    def cancel_subscription(self, subscription_id: str, body: CancelRequest) -> Dict[str, Any]:
        """
        POST /me/plans/subscriptions/{subscription_id}/cancel
        - Se cancel_now=True → Subscription.delete (opzionali invoice_now/prorate)
        - Altrimenti → cancel_at_period_end=True
        """
        return self._request(
            "POST",
            f"/me/plans/subscriptions/{subscription_id}/cancel",
            json_body=body.model_dump(exclude_none=True),
            idempotency_suffix=f"cancel.{subscription_id}",
        )

    # 12) Pause subscription
    def pause_subscription(self, subscription_id: str, body: PauseRequest) -> Dict[str, Any]:
        """
        POST /me/plans/subscriptions/{subscription_id}/pause
        """
        return self._request(
            "POST",
            f"/me/plans/subscriptions/{subscription_id}/pause",
            json_body=body.model_dump(exclude_none=True),
            idempotency_suffix=f"pause.{subscription_id}",
        )

    # 13) Resume subscription
    def resume_subscription(self, subscription_id: str, body: Optional[ResumeRequest] = None) -> Dict[str, Any]:
        """
        POST /me/plans/subscriptions/{subscription_id}/resume
        """
        payload = (body.model_dump(exclude_none=True) if body else {})
        return self._request(
            "POST",
            f"/me/plans/subscriptions/{subscription_id}/resume",
            json_body=payload,
            idempotency_suffix=f"resume.{subscription_id}",
        )

    # 14) Get resources state (provided/used/remaining)
    def get_subscription_resources(self, subscription_id: str) -> ResourcesState:
        """
        GET /me/plans/subscriptions/{subscription_id}/resources
        - Esegue sync lazy (variant upgrade/downgrade) + rollover lato server
        - Restituisce stato risorse e “period bounds” robusti
        """
        data = self._request("GET", f"/me/plans/subscriptions/{subscription_id}/resources")
        return ResourcesState(
            subscription_id=data.get("subscription_id"),
            plan_type=data.get("plan_type"),
            variant=data.get("variant"),
            pricing_method=data.get("pricing_method"),
            active_price_id=data.get("active_price_id"),
            resources=data.get("resources") or {},
            period_start=data.get("period_start"),
            period_end=data.get("period_end"),
            customer_id=data.get("customer_id"),
            raw=data,
        )

    # 15) Consume resources (server: JWT + API Key)
    def consume_resources(self, subscription_id: str, body: ConsumeResourcesRequest) -> Dict[str, Any]:
        """
        POST /me/plans/subscriptions/{subscription_id}/resources/consume
        - Richiede X-API-Key (admin) nella tua implementazione
        - ATTENZIONE: il body DEVE contenere `items=[...]`
        """
        return self._request(
            "POST",
            f"/me/plans/subscriptions/{subscription_id}/resources/consume",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix=f"resources.consume.{subscription_id}",
        )

    # 16) Set resources (server: JWT + API Key)
    def set_resources(self, subscription_id: str, body: SetResourcesRequest) -> Dict[str, Any]:
        """
        POST /me/plans/subscriptions/{subscription_id}/resources/set
        - Richiede X-API-Key (admin)
        """
        return self._request(
            "POST",
            f"/me/plans/subscriptions/{subscription_id}/resources/set",
            json_body=body.model_dump(exclude_none=True),
            admin=True,
            idempotency_suffix=f"resources.set.{subscription_id}",
        )

    # 17) Attach payment method
    def attach_payment_method(self, body: AttachMeRequest) -> Dict[str, Any]:
        """
        POST /me/plans/payment-methods/attach
        - Collega un PM al Customer; opzionale: set come default su una subscription
        """
        return self._request(
            "POST",
            "/me/plans/payment-methods/attach",
            json_body=body.model_dump(exclude_none=True),
            idempotency_suffix="pm.attach",
        )
