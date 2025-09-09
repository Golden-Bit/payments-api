from __future__ import annotations

"""
Demo end-to-end (ME, Credits)
Login ➜ (IN PARALLELO) Checkout + Portal ➜ Deeplink URLs (UPDATE/CANCEL/PAUSE + 2 UPGRADE + 2 DOWNGRADE con sconti grezzi)
     ➜ Stato Crediti ➜ Consumo ➜ Rilettura

Aggiornato per:
  - nuovo input Portal Session: PortalSessionRequest(portal=PortalConfigSelector(...))
  - nuovo endpoint deeplink: POST /me/plans/portal/deeplinks/upgrade (upgrade/downgrade confermati)
  - supporto "sconti grezzi" (percentuali/amount) via raw_discounts=[RawDiscountSpec(...), ...]

Requisiti:
  pip install fastapi uvicorn requests stripe python-dotenv pydantic watchdog

Env (.env opzionale):
  API_BASE=http://localhost:8000
  AUTH_API_BASE=https://teatek-llm.theia-innovation.com/auth
  STRIPE_WEBHOOK_SECRET=whsec_xxx
  STRIPE_SECRET_KEY=sk_test_xxx
  RETURN_URL=https://tuo-sito.com/account
  DEMO_USERNAME=test.user@example.com
  DEMO_PASSWORD=Password!234
  ADMIN_API_KEY=supersecret_admin_key
  STRIPE_ACCOUNT=acct_xxx             # opzionale per Connect
  PROMOTION_CODE_ID_UPGRADE=promo_xxx # opzionale: promotion_code da combinare con upgrade
  COUPON_ID_DOWNGRADE=co_xxx          # opzionale: coupon da combinare con downgrade
"""

import os
import json
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Literal, Dict, Any, List, Tuple

import requests
import stripe
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

# 👉 Import SDK aggiornato (include RawDiscountSpec e PortalUpgradeDeepLinkRequest.raw_discounts)
from app.sdk.sdk import (
    MePlansClient,
    DynamicCheckoutRequest,
    PortalSessionRequest,
    PortalUpdateDeepLinkRequest,
    PortalCancelDeepLinkRequest,
    PortalUpgradeDeepLinkRequest,
    ConsumeResourcesRequest,
    SetResourcesRequest,
    ResourceItem,
    PortalConfigSelector,
    PortalFeaturesOverride,
    BusinessProfileOverride,
    RawDiscountSpec,  # <— NEW
)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

API_BASE: str = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
AUTH_BASE: str = os.getenv("AUTH_API_BASE", "https://teatek-llm.theia-innovation.com/auth").rstrip("/")

STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxx")
STRIPE_SECRET_KEY:     str = os.getenv("STRIPE_SECRET_KEY",     "sk_test_xxx")
RETURN_URL:            str = os.getenv("RETURN_URL", "https://tuo-sito.com/account")
ADMIN_API_KEY:         str = os.getenv("ADMIN_API_KEY", "adminkey123:admin")
STRIPE_ACCOUNT:        Optional[str] = os.getenv("STRIPE_ACCOUNT")

# Sconti "catalogo" opzionali (non grezzi) — li combiniamo a scopo demo
PROMOTION_CODE_ID_UPGRADE: Optional[str] = os.getenv("PROMOTION_CODE_ID_UPGRADE")  # es. 'promo_...'
COUPON_ID_DOWNGRADE: Optional[str]      = os.getenv("COUPON_ID_DOWNGRADE")         # es. 'co_...'

USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

# Flag demo
RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT_AND_PORTAL: bool = True
TAIL_WEBHOOK_LOG: bool = True

WEBHOOK_PORT = 9100
WEBHOOK_LOG_FILE = Path("webhook_events_demo.jsonl")

# Variabili globali
ACCESS_TOKEN_GLOBAL: Optional[str] = None
GLOBAL_PLAN_TYPE: Optional[str] = None
GLOBAL_VARIANT: Optional[str] = None
CLIENT: Optional[MePlansClient] = None

# Varianti esposte per "AI Standard" (coerenti col server)
VARIANTS_BUCKET = ["base_monthly", "pro_monthly", "base_annual", "pro_annual"]

# Stati "alive"
ALIVE_SUB_STATUSES = {"trialing", "active", "past_due", "unpaid", "incomplete", "paused", "incomplete_expired"}

# Parametri consumo demo
DEFAULT_CONSUME_FALLBACK = 5
CONSUME_REASON = "demo_consume"

# ─────────────────────────────────────────────────────────────────────────────
# SDK AUTH MINIMAL (solo per ottenere l'access token)
# ─────────────────────────────────────────────────────────────────────────────
class SignInRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)

class CognitoSDK:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.headers = {"Content-Type": "application/json"}

    def signin(self, data: SignInRequest) -> dict:
        url = f"{self.base_url}/v1/user/signin"
        r = requests.post(url, json=data.model_dump(), headers=self.headers, timeout=40)
        r.raise_for_status()
        return r.json()

# ─────────────────────────────────────────────────────────────────────────────
# Login + client factory
# ─────────────────────────────────────────────────────────────────────────────
def signin_and_get_access_token() -> str:
    sdk = CognitoSDK(AUTH_BASE)
    resp = sdk.signin(SignInRequest(username=USERNAME, password=PASSWORD))
    token = resp.get("AuthenticationResult", {}).get("AccessToken")
    if not token:
        raise RuntimeError(f"Signin ok ma AccessToken non trovato: {resp}")
    return token

def build_client(access_token: str) -> MePlansClient:
    return MePlansClient(
        api_base=API_BASE,
        access_token=access_token,
        admin_api_key=ADMIN_API_KEY,
        default_timeout=40.0,
        stripe_account=STRIPE_ACCOUNT,
    )

def get_client() -> MePlansClient:
    global CLIENT
    if CLIENT is None:
        raise RuntimeError("SDK client non inizializzato. Chiama build_client() dopo il login.")
    return CLIENT

# ─────────────────────────────────────────────────────────────────────────────
# Helpers REST via SDK
# ─────────────────────────────────────────────────────────────────────────────
def list_subscriptions(limit: int = 10, status_filter: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    out = client.list_subscriptions(status_filter=status_filter, limit=limit)
    return out.raw

def get_existing_active_subscription_id() -> Optional[str]:
    try:
        subs = list_subscriptions(limit=10)
        data = subs.get("data") or []
        if not data:
            return None
        data_sorted = sorted(data, key=lambda s: int(s.get("created") or 0), reverse=True)
        for s in data_sorted:
            st = (s.get("status") or "").lower()
            if st in ALIVE_SUB_STATUSES and not s.get("canceled_at"):
                return s.get("id")
    except Exception:
        pass
    return None

def wait_for_new_subscription(timeout_sec: int = 180, poll_every: float = 3.0) -> Optional[str]:
    print(f"[Wait] In attesa che la subscription sia creata/attiva (max {timeout_sec}s)…")
    started = time.time()
    seen: Optional[str] = None
    while time.time() - started < timeout_sec:
        sid = get_existing_active_subscription_id()
        if sid and sid != seen:
            return sid
        time.sleep(poll_every)
    return None

def get_subscription_resources(subscription_id: str) -> Dict[str, Any]:
    client = get_client()
    state = client.get_subscription_resources(subscription_id)
    return state.raw

# ─────────────────────────────────────────────────────────────────────────────
# Pretty printer / calcoli crediti
# ─────────────────────────────────────────────────────────────────────────────
def _parse_credits_triplet(state: Dict[str, Any]) -> Tuple[float, float, float]:
    res = state.get("resources", {})
    provided = sum(float(it.get("quantity", 0) or 0) for it in res.get("provided", []) if it.get("key") == "credits")
    used     = sum(float(it.get("quantity", 0) or 0) for it in res.get("used", [])     if it.get("key") == "credits")
    remaining= sum(float(it.get("quantity", 0) or 0) for it in res.get("remaining", [])if it.get("key") == "credits")
    return provided, used, remaining

def pretty_print_credits_state(state: Dict[str, Any]) -> None:
    provided, used, remaining = _parse_credits_triplet(state)
    print("\n[Crediti]")
    print(f"  Provided:  {int(provided)}")
    print(f"  Used:      {int(used)}")
    print(f"  Remaining: {int(remaining)}")
    ps = state.get("period_start"); pe = state.get("period_end")
    if ps and pe:
        ps_dt = datetime.fromtimestamp(int(ps), tz=timezone.utc)
        pe_dt = datetime.fromtimestamp(int(pe), tz=timezone.utc)
        print(f"  Period:    {ps_dt.isoformat()} → {pe_dt.isoformat()}")
    print(f"  Plan Type: {state.get('plan_type')}  Variant: {state.get('variant')}  Price: {state.get('active_price_id')}")

def pretty_print_credits_diff(before: Dict[str, Any], after: Dict[str, Any]) -> None:
    bp, bu, br = _parse_credits_triplet(before)
    ap, au, ar = _parse_credits_triplet(after)
    print("\n[Delta Crediti dopo consumo]")
    print(f"  Provided:  {int(bp)} → {int(ap)}  (Δ {int(ap - bp)})")
    print(f"  Used:      {int(bu)} → {int(au)}  (Δ {int(au - bu)})")
    print(f"  Remaining: {int(br)} → {int(ar)}  (Δ {int(ar - br)})")

# ─────────────────────────────────────────────────────────────────────────────
# Consumo crediti — via SDK
# ─────────────────────────────────────────────────────────────────────────────
def consume_credits(subscription_id: str, quantity: float, reason: str = CONSUME_REASON) -> Dict[str, Any]:
    client = get_client()
    body = ConsumeResourcesRequest(
        items=[ResourceItem(key="credits", quantity=float(quantity), unit="credits")],
        reason=reason,
    )
    res = client.consume_resources(subscription_id, body)
    print(f"[Consume] OK via SDK. Quantità: {quantity}")
    return res

def choose_safe_consume_amount(state: Dict[str, Any]) -> int:
    try:
        _, _, remaining = _parse_credits_triplet(state)
        remaining = int(remaining)
        if remaining >= 10:
            return 10
        elif remaining > 0:
            return 1
        else:
            return 0
    except Exception:
        return DEFAULT_CONSUME_FALLBACK

# ─────────────────────────────────────────────────────────────────────────────
# /me/plans — CHECKOUT + PORTAL (via SDK, aggiornati)
# ─────────────────────────────────────────────────────────────────────────────
def me_create_checkout_session_variant(*, plan_type: str, variant: str, locale: Optional[str] = "it"):
    """
    Crea una Checkout Session per una variante di catalogo.
    Include nel payload 'portal' un selettore configurato per gestire upgrade/downgrade.
    """
    client = get_client()

    selector = PortalConfigSelector(
        plan_type=plan_type,
        variants_override=VARIANTS_BUCKET,
        features_override=PortalFeaturesOverride(
            payment_method_update={"enabled": True},
            subscription_update={
                "enabled": True,
                "default_allowed_updates": ["price"],
                "proration_behavior": "none"  # nessuna proratazione monetaria
            },
            subscription_cancel={"enabled": True, "mode": "immediately"},
        ),
        business_profile_override=BusinessProfileOverride(headline=f"{plan_type} – Manage plan"),
    )

    req = DynamicCheckoutRequest(
        success_url="https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://tuo-sito.com/cancel",
        plan_type=plan_type,
        variant=variant,
        locale=locale,
        portal=selector,
    )

    out = client.create_checkout(req)
    print("\n[Checkout] Session ID:", out.id)
    print("[Checkout] URL:", out.url)
    return out

def me_create_billing_portal_session(*, plan_type: str, variants: List[str], return_url: Optional[str] = None):
    """
    NUOVO: usa PortalSessionRequest con 'portal: PortalConfigSelector'
    """
    client = get_client()
    selector = PortalConfigSelector(
        plan_type=plan_type,
        variants_override=variants,
        features_override=PortalFeaturesOverride(
            payment_method_update={"enabled": True},
            subscription_update={"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "none"},
            subscription_cancel={"enabled": True, "mode": "at_period_end"},
        ),
        business_profile_override=BusinessProfileOverride(headline=f"{plan_type} – Billing Portal"),
    )

    req = PortalSessionRequest(
        return_url=return_url or RETURN_URL,
        portal=selector,
        flow_data=None,  # opzionale
    )
    out = client.create_portal_session(req)
    print("\n[Portal] Session ID:", out.id)
    print("[Portal] URL:", out.url)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# /me/plans — DEEPLINKS (update/cancel/pause)
# ─────────────────────────────────────────────────────────────────────────────
def portal_deeplink_update(*, subscription_id: str, plan_type: str, variants: List[str], return_url: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    selector = PortalConfigSelector(
        plan_type=plan_type,
        variants_override=variants,
        features_override=PortalFeaturesOverride(
            payment_method_update={"enabled": True},
            subscription_update={"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "none"},
            subscription_cancel={"enabled": True, "mode": "immediately"},
        ),
        business_profile_override=BusinessProfileOverride(headline=f"{plan_type} – Update plan"),
    )
    req = PortalUpdateDeepLinkRequest(
        return_url=return_url or RETURN_URL,
        subscription_id=subscription_id,
        portal=selector,
    )
    out = client.create_deeplink_update(req)
    return {"id": out.id, "url": out.url, "configuration_id": out.configuration_id}

def portal_deeplink_cancel_immediate(*, subscription_id: str, plan_type: str, variants_for_context: Optional[List[str]] = None, return_url: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    selector = PortalConfigSelector(
        plan_type=plan_type,
        variants_override=(variants_for_context or VARIANTS_BUCKET),
        features_override=PortalFeaturesOverride(
            subscription_cancel={"enabled": True, "mode": "immediately"},
            payment_method_update={"enabled": True},
        ),
        business_profile_override=BusinessProfileOverride(headline=f"{plan_type} – Cancel subscription (immediate)"),
    )
    req = PortalCancelDeepLinkRequest(
        return_url=return_url or RETURN_URL,
        subscription_id=subscription_id,
        portal=selector,
        immediate=True,
    )
    out = client.create_deeplink_cancel(req)
    return {"id": out.id, "url": out.url, "configuration_id": out.configuration_id}
# ─────────────────────────────────────────────────────────────────────────────
# /me/plans — DEEPLINKS UPGRADE (4 link: 2 upgrade + 2 downgrade con sconti grezzi)
# ─────────────────────────────────────────────────────────────────────────────
def _adjacent_variants(current: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Restituisce (down_variant, up_variant) rispetto all'ordine VARIANTS_BUCKET.
    Se current non è nel bucket, usa fallback 'base_monthly' come riferimento.
    """
    if current in VARIANTS_BUCKET:
        i = VARIANTS_BUCKET.index(current)
    else:
        i = 0
    down_v = VARIANTS_BUCKET[i - 1] if i - 1 >= 0 else None
    up_v   = VARIANTS_BUCKET[i + 1] if i + 1 < len(VARIANTS_BUCKET) else None
    return down_v, up_v

def portal_deeplink_upgrade_quad(
    *,
    subscription_id: str,
    plan_type: str,
    current_variant: Optional[str],
    return_url: Optional[str] = None,
    quantity: int = 1,
) -> Dict[str, Optional[str]]:
    """
    Crea QUATTRO deeplink di conferma:
      - UPGRADE (percentuale grezza)    → upgrade_pct_url
      - UPGRADE (importo grezzo)        → upgrade_amount_url
      - DOWNGRADE (percentuale grezza)  → downgrade_pct_url
      - DOWNGRADE (importo grezzo)      → downgrade_amount_url

    Ognuno può opzionalmente combinarsi con PROMOTION_CODE (upgrade) o COUPON_ID (downgrade).
    """
    client = get_client()
    down_v, up_v = _adjacent_variants(current_variant)

    selector = PortalConfigSelector(
        plan_type=plan_type,
        variants_override=VARIANTS_BUCKET,
        features_override=PortalFeaturesOverride(
            payment_method_update={"enabled": True},
            subscription_update={"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "create_prorations"},
            subscription_cancel={"enabled": True, "mode": "at_period_end"},
        ),
        business_profile_override=BusinessProfileOverride(headline=f"{plan_type} – Confirm change (raw discounts)"),
    )

    urls: Dict[str, Optional[str]] = {
        "upgrade_pct_url": None,
        "upgrade_amount_url": None,
        "downgrade_pct_url": None,
        "downgrade_amount_url": None,
    }

    # ---------------------
    # UPGRADE: percentuale
    # ---------------------
    if up_v:
        up_req_pct = PortalUpgradeDeepLinkRequest(
            return_url=return_url or RETURN_URL,
            subscription_id=subscription_id,
            portal=selector,
            target_plan_type=plan_type,
            target_variant=up_v,
            quantity=quantity,
            promotion_code=(PROMOTION_CODE_ID_UPGRADE or None),   # facoltativo: combiniamo promo + raw
            raw_discounts=[
                RawDiscountSpec.percent(10, name="Upgrade +10% OFF"),  # 10% OFF una tantum
            ],
        )
        up_out_pct = client.create_deeplink_upgrade(up_req_pct)
        urls["upgrade_pct_url"] = up_out_pct.url
        print("\n[Upgrade %] Deeplink (confirmed):", up_out_pct.url)

    # ---------------------
    # UPGRADE: importo
    # ---------------------
    if up_v:
        up_req_amt = PortalUpgradeDeepLinkRequest(
            return_url=return_url or RETURN_URL,
            subscription_id=subscription_id,
            portal=selector,
            target_plan_type=plan_type,
            target_variant=up_v,
            quantity=quantity,
            # niente promo stavolta: solo raw amount
            raw_discounts=[
                RawDiscountSpec.amount(1500, currency="eur", name="Upgrade 15 EUR OFF"),  # 15€ OFF
            ],
        )
        up_out_amt = client.create_deeplink_upgrade(up_req_amt)
        urls["upgrade_amount_url"] = up_out_amt.url
        print("[Upgrade €] Deeplink (confirmed):", up_out_amt.url)

    # -----------------------
    # DOWNGRADE: percentuale
    # -----------------------
    if down_v:
        down_req_pct = PortalUpgradeDeepLinkRequest(
            return_url=return_url or RETURN_URL,
            subscription_id=subscription_id,
            portal=selector,
            target_plan_type=plan_type,
            target_variant=down_v,
            quantity=quantity,
            coupon_id=(COUPON_ID_DOWNGRADE or None),  # facoltativo: combiniamo coupon + raw
            raw_discounts=[
                # esempio: sconto ricorrente per 2 mesi
                RawDiscountSpec.percent(5, duration="repeating", duration_in_months=2, name="Downgrade 5% x2m"),
            ],
        )
        down_out_pct = client.create_deeplink_upgrade(down_req_pct)
        urls["downgrade_pct_url"] = down_out_pct.url
        print("[Downgrade %] Deeplink (confirmed):", down_out_pct.url)

    # -----------------------
    # DOWNGRADE: importo
    # -----------------------
    if down_v:
        down_req_amt = PortalUpgradeDeepLinkRequest(
            return_url=return_url or RETURN_URL,
            subscription_id=subscription_id,
            portal=selector,
            target_plan_type=plan_type,
            target_variant=down_v,
            quantity=quantity,
            # solo raw amount
            raw_discounts=[
                RawDiscountSpec.amount(700, currency="eur", name="Downgrade 7 EUR OFF"),  # 7€ OFF una tantum
            ],
        )
        down_out_amt = client.create_deeplink_upgrade(down_req_amt)
        urls["downgrade_amount_url"] = down_out_amt.url
        print("[Downgrade €] Deeplink (confirmed):", down_out_amt.url)

    if not up_v and not down_v:
        print("[Upgrade/Downgrade] Nessuna variante adiacente disponibile nel bucket.")
    return urls

def generate_all_deeplinks(*, subscription_id: str, plan_type: str, current_variant: Optional[str]) -> Dict[str, Optional[str]]:
    print("\n[Deeplink] Creo UPDATE/CANCEL/PAUSE + 2xUPGRADE + 2xDOWNGRADE (sconti grezzi)…")
    upd = portal_deeplink_update(subscription_id=subscription_id, plan_type=plan_type, variants=VARIANTS_BUCKET)
    can = portal_deeplink_cancel_immediate(subscription_id=subscription_id, plan_type=plan_type, variants_for_context=VARIANTS_BUCKET)
    # opzionale: mostra PAUSE
    quad = portal_deeplink_upgrade_quad(
        subscription_id=subscription_id,
        plan_type=plan_type,
        current_variant=current_variant,
    )

    urls = {
        "update_url": upd.get("url"),
        "cancel_url": can.get("url"),
        "upgrade_pct_url": quad.get("upgrade_pct_url"),
        "upgrade_amount_url": quad.get("upgrade_amount_url"),
        "downgrade_pct_url": quad.get("downgrade_pct_url"),
        "downgrade_amount_url": quad.get("downgrade_amount_url"),
    }

    print("[Deeplink] UPDATE:", urls["update_url"])
    print("[Deeplink] CANCEL (immediate):", urls["cancel_url"])
    print("[Deeplink] UPGRADE (10%):", urls["upgrade_pct_url"])
    print("[Deeplink] UPGRADE (€):", urls["upgrade_amount_url"])
    print("[Deeplink] DOWNGRADE (5% x2m):", urls["downgrade_pct_url"])
    print("[Deeplink] DOWNGRADE (€):", urls["downgrade_amount_url"])
    return urls

# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK FastAPI — post-checkout: genera anche 2+2 UPGRADE/DOWNGRADE (sconti grezzi)
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — checkout + portal + deeplinks + consume, via SDK)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET == "whsec_xxx":
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET mancante o placeholder")

    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature") or request.headers.get("stripe-signature") or ""

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook signature verification failed: {e}")

    etype = event.get("type")
    obj = event.get("data", {}).get("object", {}) or {}

    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "event_type": etype,
        "object_id": obj.get("id"),
    }

    if etype == "checkout.session.completed":
        cs_id = obj.get("id")
        customer_id = obj.get("customer")
        subscription_id = obj.get("subscription")

        record.update({"checkout_session_id": cs_id, "customer_id": customer_id, "subscription_id": subscription_id})

        # Fallback retrieve
        if not subscription_id and cs_id:
            try:
                sess = stripe.checkout.Session.retrieve(cs_id)
                subscription_id = sess.get("subscription")
                customer_id = sess.get("customer")
                record["subscription_id"] = subscription_id
                record["customer_id"] = customer_id
            except Exception as e:
                record["retrieve_error"] = str(e)

        # Genera deeplink post-acquisto (UPDATE/CANCEL/PAUSE + 2xUP + 2xDOWN)
        global ACCESS_TOKEN_GLOBAL, GLOBAL_PLAN_TYPE
        if ACCESS_TOKEN_GLOBAL and subscription_id:
            try:
                plan = GLOBAL_PLAN_TYPE or "AI Standard"

                # Leggi lo stato per ricavare la variant corrente
                state = get_subscription_resources(subscription_id)
                variant_now = state.get("variant")

                upd = portal_deeplink_update(subscription_id=subscription_id, plan_type=plan, variants=VARIANTS_BUCKET)
                can = portal_deeplink_cancel_immediate(subscription_id=subscription_id, plan_type=plan, variants_for_context=VARIANTS_BUCKET)
                quad = portal_deeplink_upgrade_quad(subscription_id=subscription_id, plan_type=plan, current_variant=variant_now)

                record["deeplink_update_url"] = upd.get("url")
                record["deeplink_cancel_url"] = can.get("url")
                record["deeplink_upgrade_pct_url"] = quad.get("upgrade_pct_url")
                record["deeplink_upgrade_amount_url"] = quad.get("upgrade_amount_url")
                record["deeplink_downgrade_pct_url"] = quad.get("downgrade_pct_url")
                record["deeplink_downgrade_amount_url"] = quad.get("downgrade_amount_url")

                print("\n[Webhook] Deeplinks creati:")
                print("  UPDATE:", record["deeplink_update_url"])
                print("  CANCEL (immediate):", record["deeplink_cancel_url"])
                print("  UPGRADE (10%):", record["deeplink_upgrade_pct_url"])
                print("  UPGRADE (€):", record["deeplink_upgrade_amount_url"])
                print("  DOWNGRADE (5% x2m):", record["deeplink_downgrade_pct_url"])
                print("  DOWNGRADE (€):", record["deeplink_downgrade_amount_url"])
            except Exception as e:
                record["postflow_error"] = str(e)
        else:
            record["postflow_error"] = "Access token o subscription_id mancanti; impossibile generare i deeplinks."

    # Log JSONL
    WEBHOOK_LOG_FILE.touch(exist_ok=True)
    with WEBHOOK_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}

def run_webhook_server_blocking():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=WEBHOOK_PORT)

# ─────────────────────────────────────────────────────────────────────────────
# Tail del JSONL per stampare i deeplinks
# ─────────────────────────────────────────────────────────────────────────────
def tail_webhook_log():
    print(f"[Tail] Seguendo {WEBHOOK_LOG_FILE} per deeplinks post-checkout…")
    last_size = WEBHOOK_LOG_FILE.stat().st_size if WEBHOOK_LOG_FILE.exists() else 0
    while True:
        try:
            time.sleep(1.0)
            if not WEBHOOK_LOG_FILE.exists():
                continue
            size = WEBHOOK_LOG_FILE.stat().st_size
            if size > last_size:
                with WEBHOOK_LOG_FILE.open("rb") as fh:
                    fh.seek(last_size)
                    chunk = fh.read(size - last_size).decode("utf-8", errors="ignore")
                last_size = size
                for line in chunk.splitlines():
                    try:
                        obj = json.loads(line)
                        keys = [
                            "deeplink_update_url",
                            "deeplink_cancel_url",
                            "deeplink_pause_url",
                            "deeplink_upgrade_pct_url",
                            "deeplink_upgrade_amount_url",
                            "deeplink_downgrade_pct_url",
                            "deeplink_downgrade_amount_url",
                        ]
                        if any(obj.get(k) for k in keys):
                            print("\n[Tail] Deeplinks dal webhook:")
                            for k in keys:
                                if obj.get(k):
                                    label = k.replace("deeplink_", "").replace("_url", "").upper()
                                    print(f"  {label}: {obj[k]}")
                    except Exception:
                        pass
        except KeyboardInterrupt:
            break
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    stripe.api_key = STRIPE_SECRET_KEY

    # 0) Login + SDK
    global ACCESS_TOKEN_GLOBAL, CLIENT
    ACCESS_TOKEN_GLOBAL = signin_and_get_access_token()
    print("[Auth] Login eseguito. Access token ottenuto.")
    CLIENT = build_client(ACCESS_TOKEN_GLOBAL)
    print("[SDK] Client inizializzato (API_BASE=", API_BASE, ")")

    # 1) Webhook server (facoltativo)
    if RUN_WEBHOOK_SERVER:
        threading.Thread(target=run_webhook_server_blocking, daemon=True).start()
        print(f"[Webhook] Server su http://localhost:{WEBHOOK_PORT}/webhooks/stripe")
        print(f"         Esegui:\n         stripe listen --forward-to localhost:{WEBHOOK_PORT}/webhooks/stripe")
        time.sleep(1.0)

    # 1bis) Tail del file log per deeplinks post-checkout
    if TAIL_WEBHOOK_LOG:
        threading.Thread(target=tail_webhook_log, daemon=True).start()

    # 2) Se esiste già una subscription viva → Portal + Deeplinks + crediti + Consumo
    existing_sub_id = get_existing_active_subscription_id()
    if existing_sub_id:
        print(f"\n[Found] Subscription viva: {existing_sub_id} → creo Portal + Deeplinks e mostro crediti.")
        plan_type = "AI Standard"

        # Portal "gestione" (NUOVO schema)
        me_create_billing_portal_session(plan_type=plan_type, variants=VARIANTS_BUCKET, return_url=RETURN_URL)

        # Stato crediti (prima) + variant corrente
        state_before = get_subscription_resources(existing_sub_id)
        pretty_print_credits_state(state_before)
        current_variant = state_before.get("variant")

        # Deeplinks (include 2xUP + 2xDOWN con sconti grezzi)
        generate_all_deeplinks(subscription_id=existing_sub_id, plan_type=plan_type, current_variant=current_variant)

        # Consumo crediti
        amt = choose_safe_consume_amount(state_before)
        if amt > 0:
            print(f"\n[Consume] Provo a consumare {amt} credit(i)…")
            try:
                consume_credits(existing_sub_id, amt, reason=CONSUME_REASON)
                state_after = get_subscription_resources(existing_sub_id)
                pretty_print_credits_state(state_after)
                pretty_print_credits_diff(state_before, state_after)
            except Exception as e:
                print("[Consume][WARN] Non è stato possibile consumare crediti:", e)
        else:
            print("\n[Consume] Nessun credito disponibile da consumare (remaining = 0).")

    # 3) CHECKOUT + PORTAL + UPGRADE/DOWNGRADE + Consumo
    global GLOBAL_PLAN_TYPE, GLOBAL_VARIANT
    if MAKE_CHECKOUT_AND_PORTAL:
        try:
            plan_type = "AI Standard"
            variant   = "base_monthly"  # cambia se vuoi: pro_monthly/base_annual/pro_annual

            GLOBAL_PLAN_TYPE = plan_type
            GLOBAL_VARIANT   = variant

            # A) Checkout
            co = me_create_checkout_session_variant(plan_type=plan_type, variant=variant, locale="it")

            # B) Portal session in parallelo (NUOVO schema)
            portal = me_create_billing_portal_session(plan_type=plan_type, variants=VARIANTS_BUCKET, return_url=RETURN_URL)

            print("\n>>> Apri nel browser e completa il pagamento (test):")
            print(co.url, "\n")
            print("Nota: il Billing Portal è già disponibile:")
            print(portal.url, "\n")

            # Polling (se non usi il webhook per leggere la sub)
            input("Dopo aver completato il pagamento, premi INVIO per continuare...")
            new_sid = wait_for_new_subscription(timeout_sec=180, poll_every=3.0)
            if new_sid:
                print(f"[OK] Subscription rilevata: {new_sid}")

                # Stato crediti (prima) + variant corrente
                state_before = get_subscription_resources(new_sid)
                pretty_print_credits_state(state_before)
                current_variant = state_before.get("variant")

                # Deeplinks (UPDATE/CANCEL/PAUSE + 2xUP/2xDOWN con sconti grezzi)
                generate_all_deeplinks(subscription_id=new_sid, plan_type=plan_type, current_variant=current_variant)

                # Consumo crediti
                amt = choose_safe_consume_amount(state_before)
                if amt > 0:
                    print(f"\n[Consume] Provo a consumare {amt} credit(i)…")
                    try:
                        consume_credits(new_sid, amt, reason=CONSUME_REASON)
                        state_after = get_subscription_resources(new_sid)
                        pretty_print_credits_state(state_after)
                        pretty_print_credits_diff(state_before, state_after)
                    except Exception as e:
                        print("[Consume][WARN] Non è stato possibile consumare crediti:", e)
                else:
                    print("\n[Consume] Nessun credito disponibile da consumare (remaining = 0).")
            else:
                print("[WARN] Subscription non trovata entro il timeout. Se usi il webhook, i link appariranno nel tail.")
        except Exception as e:
            print("[ERROR] Checkout/Portal:", e)

    # 4) Loop demo (Ctrl+C per uscire) — solo se webhook attivo
    if RUN_WEBHOOK_SERVER:
        print("[Demo] In attesa eventi… Ctrl+C per uscire.")
        try:
            while True:
                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nArresto richiesto. Bye.")
    else:
        print("Operazioni completate.")

if __name__ == "__main__":
    main()
