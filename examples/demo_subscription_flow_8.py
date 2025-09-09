from __future__ import annotations

"""
Demo end-to-end (ME, Credits) — Login ➜ (IN PARALLELO) Checkout + Portal ➜ Deeplink URLs + Stato Crediti ➜ Consumo ➜ Rilettura

Questa versione usa **ESCLUSIVAMENTE** lo SDK `teatek_me_plans_sdk` per chiamare gli endpoint /me/plans
(invece di invocare le API via `requests`). L'unica eccezione è il login (Cognito) e la parte Stripe (webhook),
che restano com'erano nella demo originale.

Requisiti (come in precedenza):
  pip install fastapi uvicorn requests stripe python-dotenv pydantic watchdog

Env (.env opzionale) — default preservati:
  API_BASE=http://localhost:8000
  AUTH_API_BASE=https://teatek-llm.theia-innovation.com/auth
  STRIPE_WEBHOOK_SECRET=whsec_xxx
  STRIPE_SECRET_KEY=sk_test_xxx
  RETURN_URL=https://tuo-sito.com/account
  DEMO_USERNAME=test.user@example.com
  DEMO_PASSWORD=Password!234
  ADMIN_API_KEY=supersecret_admin_key
  STRIPE_ACCOUNT=acct_xxx    # opzionale per Connect; se non presente, header x-stripe-account non viene inviato
"""

import os
import json
import uuid
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Literal, Dict, Any, List, Tuple
from dataclasses import asdict

import requests
import stripe
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

# 👉 Importa lo SDK (NON viene ridefinito qui)
from app.sdk.sdk import (
    MePlansClient,
    DynamicCheckoutRequest,
    PortalMeRequest,
    PortalUpdateDeepLinkRequest,
    PortalCancelDeepLinkRequest,
    PortalPauseDeepLinkRequest,
    ConsumeResourcesRequest,
    SetResourcesRequest,
    ResourceItem,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG (valori di default preservati)
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

API_BASE: str = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
AUTH_BASE: str = os.getenv("AUTH_API_BASE", "https://teatek-llm.theia-innovation.com/auth").rstrip("/")

STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxx")
STRIPE_SECRET_KEY:     str = os.getenv("STRIPE_SECRET_KEY",     "sk_test_xxx")
RETURN_URL:            str = os.getenv("RETURN_URL", "https://tuo-sito.com/account")
ADMIN_API_KEY:         str = os.getenv("ADMIN_API_KEY", "adminkey123:admin")
STRIPE_ACCOUNT:        Optional[str] = os.getenv("STRIPE_ACCOUNT")

USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

# Flag demo (default preservati)
RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT_AND_PORTAL: bool = True
TAIL_WEBHOOK_LOG: bool = True   # stampa i deeplink appena il webhook li scrive

WEBHOOK_PORT = 9100
WEBHOOK_LOG_FILE = Path("webhook_events_demo.jsonl")

# Variabili globali
ACCESS_TOKEN_GLOBAL: Optional[str] = None
GLOBAL_PLAN_TYPE: Optional[str] = None
GLOBAL_VARIANT: Optional[str] = None
GLOBAL_PORTAL_PRESET: Optional[Literal["monthly","annual"]] = None
CLIENT: Optional[MePlansClient] = None  # SDK client globale, creato dopo il login

# Varianti che il server espone per "AI Standard" (allineate con PLAN_VARIANTS lato server)
VARIANTS_BUCKET = ["base_monthly", "pro_monthly", "base_annual", "pro_annual"]

# Stati "alive" utili per la ricerca subscription create dal checkout
ALIVE_SUB_STATUSES = {"trialing", "active", "past_due", "unpaid", "incomplete", "paused", "incomplete_expired"}

# Parametri consumo demo
DEFAULT_CONSUME_FALLBACK = 5   # se non riusciamo a dedurre un importo "sicuro", proveremo a consumare 5 crediti
CONSUME_REASON = "demo_consume"

# ─────────────────────────────────────────────────────────────────────────────
# SDK AUTH MINIMAL (uguale a prima; serve solo per ottenere l'access token)
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
    """Istanzia il client SDK allineato con le policy del server."""
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
    """Cerca una subscription 'alive' già esistente per l'utente."""
    try:
        subs = list_subscriptions(limit=10)
        data = subs.get("data") or []
        if not data:
            return None
        data_sorted = sorted(data, key=lambda s: int(s.get("created") or 0), reverse=True)
        for s in data_sorted:
            st = (s.get("status") or "").lower()
            if st in ALIVE_SUB_STATUSES:
                return s.get("id")
    except Exception:
        pass
    return None


def wait_for_new_subscription(timeout_sec: int = 120, poll_every: float = 2.0) -> Optional[str]:
    """Polling semplice: attende la comparsa di una subscription 'alive' appena dopo il checkout."""
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
    # Convertiamo nello stesso shape dict che usava la demo precedente
    return state.raw


# ─────────────────────────────────────────────────────────────────────────────
# Pretty printer / calcoli crediti
# ─────────────────────────────────────────────────────────────────────────────

def _parse_credits_triplet(state: Dict[str, Any]) -> Tuple[float, float, float]:
    """Ritorna (provided, used, remaining) per 'credits' aggregando eventuali righe multiple."""
    res = state.get("resources", {})
    provided = sum([float(it.get("quantity", 0) or 0) for it in res.get("provided", []) if it.get("key") == "credits"])
    used     = sum([float(it.get("quantity", 0) or 0) for it in res.get("used", [])     if it.get("key") == "credits"])
    remaining= sum([float(it.get("quantity", 0) or 0) for it in res.get("remaining", [])if it.get("key") == "credits"])
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
        # expected_plan_type="AI Standard",  # opzionali
        # expected_variant="base_monthly",
    )
    res = client.consume_resources(subscription_id, body)
    print(f"[Consume] OK via SDK. Quantità: {quantity}")
    return res


def choose_safe_consume_amount(state: Dict[str, Any]) -> int:
    """
    Sceglie un importo 'sicuro' da consumare in base ai remaining.
    - Se remaining >= 10 → consuma 10
    - Se 0 < remaining < 10 → consuma 1
    - Se remaining == 0 → ritorna 0 (skip)
    In caso non riuscissimo a leggere, usa DEFAULT_CONSUME_FALLBACK.
    """
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
# CHIAMATE /me/plans — CHECKOUT + PORTAL (via SDK)
# ─────────────────────────────────────────────────────────────────────────────

def me_create_checkout_session_variant(*, plan_type: str, variant: str, locale: Optional[str] = "it"):
    """
    Crea una Checkout Session per una variante di catalogo usando lo SDK.
    Configuriamo un selettore Portal già pronto con proration_behavior='none' per upgrade/downgrade monetari senza proratazione.
    (La logica crediti resta indipendente e basata su delta una tantum lato server.)
    """
    client = get_client()

    req = DynamicCheckoutRequest(
        success_url="https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        cancel_url="https://tuo-sito.com/cancel",
        plan_type=plan_type,
        variant=variant,
        locale=locale,
        portal={
            "plan_type": plan_type,
            "variants_override": VARIANTS_BUCKET,
            "features_override": {
                "payment_method_update": {"enabled": True},
                "subscription_update": {
                    "enabled": True,
                    "default_allowed_updates": ["price"],
                    "proration_behavior": "none"  # ← niente proratazione monetaria
                },
                "subscription_cancel": {"enabled": True, "mode": "immediately"}
            },
            "business_profile_override": {"headline": f"{plan_type} – Manage plan"}
        }
    )

    out = client.create_checkout(req)
    print("\n[Checkout] Session ID:", out.id)
    print("[Checkout] URL:", out.url)
    return out


def me_create_billing_portal_session(*, plan_type: str, portal_preset: Literal["monthly","annual"], return_url: Optional[str] = None):
    client = get_client()
    req = PortalMeRequest(
        return_url=return_url or RETURN_URL,
        portal_preset=portal_preset,
        plan_type=plan_type,
        flow_data=None,
    )
    out = client.create_portal_session(req)
    print("\n[Portal] Session ID:", out.id)
    print("[Portal] URL:", out.url)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CHIAMATE /me/plans — DEEPLINKS (via SDK)
# ─────────────────────────────────────────────────────────────────────────────

def portal_deeplink_update(*, subscription_id: str, plan_type: str, variants: List[str], return_url: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    req = PortalUpdateDeepLinkRequest(
        return_url=return_url or RETURN_URL,
        subscription_id=subscription_id,
        portal={
            "plan_type": plan_type,
            "variants_override": variants,
            "features_override": {
                "payment_method_update": {"enabled": True},
                "subscription_update": {"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "none"},
                "subscription_cancel": {"enabled": True, "mode": "immediately"}
            },
            "business_profile_override": {"headline": f"{plan_type} – Update plan"}
        }
    )
    out = client.create_deeplink_update(req)
    return {"id": out.id, "url": out.url, "configuration_id": out.configuration_id}


def portal_deeplink_cancel_immediate(*, subscription_id: str, plan_type: str, variants_for_context: Optional[List[str]] = None, return_url: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    portal_block: Dict[str, Any] = {"plan_type": plan_type}
    if variants_for_context:
        portal_block["variants_override"] = variants_for_context
    portal_block.update({
        "features_override": {
            "subscription_cancel": {"enabled": True, "mode": "immediately"},
            "payment_method_update": {"enabled": True}
        },
        "business_profile_override": {"headline": f"{plan_type} – Cancel subscription (immediate)"}
    })

    req = PortalCancelDeepLinkRequest(
        return_url=return_url or RETURN_URL,
        subscription_id=subscription_id,
        portal=portal_block,  # type: ignore
        immediate=True,
    )
    out = client.create_deeplink_cancel(req)
    return {"id": out.id, "url": out.url, "configuration_id": out.configuration_id}


def portal_deeplink_pause(*, subscription_id: str, plan_type: str, variants_for_context: Optional[List[str]] = None, return_url: Optional[str] = None) -> Dict[str, Any]:
    client = get_client()
    portal_block: Dict[str, Any] = {"plan_type": plan_type}
    if variants_for_context:
        portal_block["variants_override"] = variants_for_context
    portal_block.update({
        "features_override": {
            "payment_method_update": {"enabled": True},
            "subscription_update": {"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "none"},
            "subscription_cancel": {"enabled": True, "mode": "immediately"}
        },
        "business_profile_override": {"headline": f"{plan_type} – Pause collection"}
    })

    req = PortalPauseDeepLinkRequest(
        return_url=return_url or RETURN_URL,
        subscription_id=subscription_id,
        portal=portal_block,  # type: ignore
        suggested_behavior=None,
    )
    out = client.create_deeplink_pause(req)
    return {"id": out.id, "url": out.url, "configuration_id": out.configuration_id}


def generate_all_deeplinks(*, subscription_id: str, plan_type: str) -> Dict[str, Optional[str]]:
    print("\n[Deeplink] Creo UPDATE/CANCEL/PAUSE…")
    upd = portal_deeplink_update(subscription_id=subscription_id, plan_type=plan_type, variants=VARIANTS_BUCKET)
    can = portal_deeplink_cancel_immediate(subscription_id=subscription_id, plan_type=plan_type, variants_for_context=VARIANTS_BUCKET)
    # opzionale: se non vuoi mostrare PAUSE, tieni commentato
    # pau = portal_deeplink_pause(subscription_id=subscription_id, plan_type=plan_type, variants_for_context=VARIANTS_BUCKET)
    pau: Dict[str, str] = {}
    urls = {"update_url": upd.get("url"), "cancel_url": can.get("url"), "pause_url": pau.get("url") if pau else None}
    print("[Deeplink] UPDATE:", urls["update_url"])
    print("[Deeplink] CANCEL (immediate):", urls["cancel_url"])
    print("[Deeplink] PAUSE:", urls["pause_url"])
    return urls


# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK FastAPI — post-checkout: genera i DEEPLINKS (facoltativo per la demo)
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — checkout + portal + deeplinks + consume, via SDK)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    A 'checkout.session.completed':
      - genera i 3 deeplink (update/cancel-immediate/pause) via SDK
      - logga su JSONL e stampa a console
    NOTA: non serve per i crediti; la logica crediti è lato server via lazy-sync.
    """
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

        # Genera deeplink post-acquisto (solo per comodità demo)
        global ACCESS_TOKEN_GLOBAL, GLOBAL_PLAN_TYPE
        if ACCESS_TOKEN_GLOBAL and subscription_id:
            try:
                plan = GLOBAL_PLAN_TYPE or "AI Standard"
                upd = portal_deeplink_update(subscription_id=subscription_id, plan_type=plan, variants=VARIANTS_BUCKET)
                can = portal_deeplink_cancel_immediate(subscription_id=subscription_id, plan_type=plan, variants_for_context=VARIANTS_BUCKET)
                pau = portal_deeplink_pause(subscription_id=subscription_id, plan_type=plan, variants_for_context=VARIANTS_BUCKET)
                record["deeplink_update_url"] = upd.get("url")
                record["deeplink_cancel_url"] = can.get("url")
                record["deeplink_pause_url"]  = pau.get("url")

                print("\n[Webhook] Deeplinks creati:")
                print("  UPDATE:", record["deeplink_update_url"])
                print("  CANCEL (immediate):", record["deeplink_cancel_url"])
                print("  PAUSE:", record["deeplink_pause_url"])
            except Exception as e:
                record["postflow_error"] = str(e)
        else:
            record["postflow_error"] = "Access token o subscription_id mancanti; impossibile generare i deeplink."

    # Log JSONL
    WEBHOOK_LOG_FILE.touch(exist_ok=True)
    with WEBHOOK_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}


def run_webhook_server_blocking():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=WEBHOOK_PORT)


# ─────────────────────────────────────────────────────────────────────────────
# Tail del file JSONL per stampare appena compaiono i deeplink dal webhook
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
                        if obj.get("deeplink_update_url") or obj.get("deeplink_cancel_url") or obj.get("deeplink_pause_url"):
                            print("\n[Tail] Deeplinks dal webhook:")
                            if obj.get("deeplink_update_url"):  print("  UPDATE:", obj["deeplink_update_url"])
                            if obj.get("deeplink_cancel_url"):  print("  CANCEL (immediate):", obj["deeplink_cancel_url"])
                            if obj.get("deeplink_pause_url"):   print("  PAUSE:", obj["deeplink_pause_url"])
                    except Exception:
                        pass
        except KeyboardInterrupt:
            break
        except Exception:
            # non bloccare la demo
            pass


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Stripe SDK per verify/retrieve nel webhook (solo per il sink demo)
    stripe.api_key = STRIPE_SECRET_KEY

    # 0) Login
    global ACCESS_TOKEN_GLOBAL, CLIENT
    ACCESS_TOKEN_GLOBAL = signin_and_get_access_token()
    print("[Auth] Login eseguito. Access token ottenuto.")

    # 0bis) Inizializza il client SDK
    CLIENT = build_client(ACCESS_TOKEN_GLOBAL)
    print("[SDK] Client inizializzato (API_BASE=", API_BASE, ")")

    # 1) Webhook server (facoltativo)
    if RUN_WEBHOOK_SERVER:
        threading.Thread(target=run_webhook_server_blocking, daemon=True).start()
        print(f"[Webhook] Server avviato su http://localhost:{WEBHOOK_PORT}/webhooks/stripe")
        print(f"         Esegui:\n         stripe listen --forward-to localhost:{WEBHOOK_PORT}/webhooks/stripe")
        time.sleep(1.0)

    # 1bis) Tail del file log per stampare i deeplinks generati dal webhook
    if TAIL_WEBHOOK_LOG:
        threading.Thread(target=tail_webhook_log, daemon=True).start()

    # 2) Se esiste già una subscription viva → crea SUBITO Portal + Deeplinks + mostra crediti + CONSUMO + rilettura
    existing_sub_id = get_existing_active_subscription_id()
    if existing_sub_id:
        print(f"\n[Found] Subscription viva: {existing_sub_id} → creo Portal + Deeplinks e mostro crediti.")
        plan_type = "AI Standard"
        # Portal "gestione"
        me_create_billing_portal_session(plan_type=plan_type, portal_preset="monthly", return_url=RETURN_URL)
        # Deeplinks SUBITO
        generate_all_deeplinks(subscription_id=existing_sub_id, plan_type=plan_type)
        # Stato crediti (prima)
        state_before = get_subscription_resources(existing_sub_id)
        pretty_print_credits_state(state_before)

        # Consumo crediti
        amt = choose_safe_consume_amount(state_before)
        if amt > 0:
            print(f"\n[Consume] Provo a consumare {amt} credit(i)…")
            try:
                consume_credits(existing_sub_id, amt, reason=CONSUME_REASON)
                # Stato crediti (dopo)
                state_after = get_subscription_resources(existing_sub_id)
                pretty_print_credits_state(state_after)
                pretty_print_credits_diff(state_before, state_after)
            except Exception as e:
                print("[Consume][WARN] Non è stato possibile consumare crediti:", e)
        else:
            print("\n[Consume] Nessun credito disponibile da consumare (remaining = 0).")

    # 3) CHECKOUT + PORTAL (se vuoi forzare un nuovo acquisto) + CONSUMO + rilettura
    global GLOBAL_PLAN_TYPE, GLOBAL_VARIANT, GLOBAL_PORTAL_PRESET
    if MAKE_CHECKOUT_AND_PORTAL:
        try:
            plan_type = "AI Standard"
            variant   = "base_monthly"  # puoi cambiare in pro_monthly/base_annual/pro_annual

            GLOBAL_PLAN_TYPE = plan_type
            GLOBAL_VARIANT   = variant
            GLOBAL_PORTAL_PRESET = "annual" if variant.endswith("_annual") else "monthly"

            # A) Checkout (ottieni URL da aprire)
            co = me_create_checkout_session_variant(plan_type=plan_type, variant=variant, locale="it")

            # B) Portal session in parallelo (PM/profile)
            portal = me_create_billing_portal_session(plan_type=plan_type, portal_preset=GLOBAL_PORTAL_PRESET, return_url=RETURN_URL)

            print("\n>>> Apri nel browser e completa il pagamento (test):")
            print(co.url, "\n")
            print("Nota: il Billing Portal è già disponibile:")
            print(portal.url, "\n")

            # Se NON usi il webhook, puoi proseguire manualmente con polling per ottenere la subscription
            input("Dopo aver completato il pagamento, premi INVIO per continuare...")
            new_sid = wait_for_new_subscription(timeout_sec=180, poll_every=3.0)
            if new_sid:
                print(f"[OK] Subscription rilevata: {new_sid}")
                # Crea deeplinks ora (senza webhook)
                generate_all_deeplinks(subscription_id=new_sid, plan_type=plan_type)
                # Stato crediti (prima)
                state_before = get_subscription_resources(new_sid)
                pretty_print_credits_state(state_before)

                # Consumo crediti
                amt = choose_safe_consume_amount(state_before)
                if amt > 0:
                    print(f"\n[Consume] Provo a consumare {amt} credit(i)…")
                    try:
                        consume_credits(new_sid, amt, reason=CONSUME_REASON)
                        # Stato crediti (dopo)
                        state_after = get_subscription_resources(new_sid)
                        pretty_print_credits_state(state_after)
                        pretty_print_credits_diff(state_before, state_after)
                    except Exception as e:
                        print("[Consume][WARN] Non è stato possibile consumare crediti:", e)
                else:
                    print("\n[Consume] Nessun credito disponibile da consumare (remaining = 0).")
            else:
                print("[WARN] Non sono riuscito a trovare una subscription viva entro il timeout. Se stai usando il webhook, i link appariranno nel tail.")

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
