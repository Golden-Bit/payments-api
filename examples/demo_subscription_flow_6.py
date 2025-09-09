"""
Demo end-to-end (ME) — Login ➜ (IN PARALLELO) Checkout + Portal ➜ Deeplink URLs
- Se ESISTE una subscription attiva: genera SUBITO i deeplink (update/cancel/pause) accanto al Portal.
- Se NON esiste: i deeplink vengono creati dal webhook a pagamento completato e stampati a console.

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
"""

from __future__ import annotations
import os, json, uuid, threading, time, io
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Literal, Dict, Any, List

import requests
import stripe
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
import uvicorn
from pydantic import BaseModel, Field

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

USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT_AND_PORTAL: bool = True
TAIL_WEBHOOK_LOG: bool = True   # stampa i deeplink appena il webhook li scrive

WEBHOOK_PORT = 9100
WEBHOOK_LOG_FILE = Path("webhook_events_demo.jsonl")

ACCESS_TOKEN_GLOBAL: Optional[str] = None
GLOBAL_PLAN_TYPE: Optional[str] = None
GLOBAL_VARIANT: Optional[str] = None
GLOBAL_PORTAL_PRESET: Optional[Literal["monthly","annual"]] = None  # calcolato da variant

# Varianti che il server espone per "AI Standard" (allinea con PLAN_VARIANTS)
VARIANTS_BUCKET = ["base_monthly", "pro_monthly", "base_annual", "pro_annual"]


# ─────────────────────────────────────────────────────────────────────────────
# SDK AUTH MINIMAL
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
# Login
# ─────────────────────────────────────────────────────────────────────────────
def signin_and_get_access_token() -> str:
    sdk = CognitoSDK(AUTH_BASE)
    resp = sdk.signin(SignInRequest(username=USERNAME, password=PASSWORD))
    token = resp.get("AuthenticationResult", {}).get("AccessToken")
    if not token:
        raise RuntimeError(f"Signin ok ma AccessToken non trovato: {resp}")
    return token


# ─────────────────────────────────────────────────────────────────────────────
# Helper REST verso la tua API
# ─────────────────────────────────────────────────────────────────────────────
def list_subscriptions(access_token: str, status_filter: Optional[str] = None, limit: int = 10) -> dict:
    url = f"{API_BASE}/me/plans/subscriptions"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"limit": limit}
    if status_filter:
        params["status_filter"] = status_filter
    r = requests.get(url, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    return r.json()

def get_existing_active_subscription_id(access_token: str) -> Optional[str]:
    try:
        subs = list_subscriptions(access_token, status_filter="active", limit=1)
        data = subs.get("data") or []
        if data:
            return data[0].get("id")
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CHIAMATE /me/plans — CHECKOUT + PORTAL
# ─────────────────────────────────────────────────────────────────────────────
def me_create_checkout_session_variant(
    access_token: str,
    *,
    plan_type: str,
    variant: str,
    locale: Optional[str] = "it",
) -> dict:
    url = f"{API_BASE}/me/plans/checkout"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.checkout.variant",
    }
    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",
        "plan_type": plan_type,
        "variant": variant,
        "locale": locale,
        # Se policy → 'portal_update', anticipiamo la config del Portal
        "portal": {
            "plan_type": plan_type,
            "variants_override": VARIANTS_BUCKET,
            "features_override": {
                "payment_method_update": {"enabled": True},
                "subscription_update": {
                    "enabled": True,
                    "default_allowed_updates": ["price"],
                    "proration_behavior": "create_prorations"
                },
                "subscription_cancel": {"enabled": True, "mode": "immediately"}
            },
            "business_profile_override": {"headline": f"{plan_type} – Manage plan"}
        }
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    return res

def me_create_billing_portal_session(
    access_token: str,
    *,
    plan_type: str,
    portal_preset: Literal["monthly","annual"],
    return_url: Optional[str] = None
) -> dict:
    url = f"{API_BASE}/me/plans/portal/session"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": ADMIN_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.portal.session",
    }
    payload = {
        "return_url": return_url or RETURN_URL,
        "portal_preset": portal_preset,
        "plan_type": plan_type,
        # "flow_data": {"type": "payment_method_update"}
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Portal] Session ID:", res.get("id"))
    print("[Portal] URL:", res.get("url"))
    return res


# ─────────────────────────────────────────────────────────────────────────────
# CHIAMATE /me/plans — DEEPLINKS (post-acquisto o sub esistente)
# ─────────────────────────────────────────────────────────────────────────────
def portal_deeplink_update(access_token: str, *, subscription_id: str, plan_type: str, variants: List[str], return_url: Optional[str] = None) -> dict:
    url = f"{API_BASE}/me/plans/portal/deeplinks/update"
    headers = {"Authorization": f"Bearer {access_token}", "X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json",
               "Idempotency-Key": f"{uuid.uuid4()}:portal.deeplink.update"}
    payload = {
        "return_url": return_url or RETURN_URL,
        "subscription_id": subscription_id,
        "portal": {
            "plan_type": plan_type,
            "variants_override": variants,
            "features_override": {
                "payment_method_update": {"enabled": True},
                "subscription_update": {"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "create_prorations"},
                "subscription_cancel": {"enabled": True, "mode": "immediately"}
            },
            "business_profile_override": {"headline": f"{plan_type} – Update plan"}
        }
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal Deeplink UPDATE] failed: {r.status_code} {r.text}")
    return r.json()

def portal_deeplink_cancel_immediate(access_token: str, *, subscription_id: str, plan_type: str, variants_for_context: Optional[List[str]] = None, return_url: Optional[str] = None) -> dict:
    url = f"{API_BASE}/me/plans/portal/deeplinks/cancel"
    headers = {"Authorization": f"Bearer {access_token}", "X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json",
               "Idempotency-Key": f"{uuid.uuid4()}:portal.deeplink.cancel"}
    payload = {
        "return_url": return_url or RETURN_URL,
        "subscription_id": subscription_id,
        "immediate": True,
        "portal": {
            "plan_type": plan_type,
            **({"variants_override": variants_for_context} if variants_for_context else {}),
            "features_override": {"subscription_cancel": {"enabled": True, "mode": "immediately"}, "payment_method_update": {"enabled": True}},
            "business_profile_override": {"headline": f"{plan_type} – Cancel subscription (immediate)"}
        }
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal Deeplink CANCEL] failed: {r.status_code} {r.text}")
    return r.json()

def portal_deeplink_pause(access_token: str, *, subscription_id: str, plan_type: str, variants_for_context: Optional[List[str]] = None, return_url: Optional[str] = None) -> dict:
    url = f"{API_BASE}/me/plans/portal/deeplinks/pause"
    headers = {"Authorization": f"Bearer {access_token}", "X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json",
               "Idempotency-Key": f"{uuid.uuid4()}:portal.deeplink.pause"}
    payload = {
        "return_url": return_url or RETURN_URL,
        "subscription_id": subscription_id,
        "portal": {
            "plan_type": plan_type,
            **({"variants_override": variants_for_context} if variants_for_context else {}),
            "features_override": {
                "payment_method_update": {"enabled": True},
                "subscription_update": {"enabled": True, "default_allowed_updates": ["price"], "proration_behavior": "create_prorations"},
                "subscription_cancel": {"enabled": True, "mode": "immediately"}
            },
            "business_profile_override": {"headline": f"{plan_type} – Pause collection"}
        }
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal Deeplink PAUSE] failed: {r.status_code} {r.text}")
    return r.json()

def generate_all_deeplinks(access_token: str, *, subscription_id: str, plan_type: str) -> Dict[str, str]:
    print("\n[Deeplink] Creo UPDATE/CANCEL/PAUSE…")
    upd = portal_deeplink_update(access_token, subscription_id=subscription_id, plan_type=plan_type, variants=VARIANTS_BUCKET)
    can = portal_deeplink_cancel_immediate(access_token, subscription_id=subscription_id, plan_type=plan_type, variants_for_context=VARIANTS_BUCKET)
    pau = {} #portal_deeplink_pause(access_token, subscription_id=subscription_id, plan_type=plan_type, variants_for_context=VARIANTS_BUCKET)
    urls = {"update_url": upd.get("url"), "cancel_url": can.get("url"), "pause_url": pau.get("url")}
    print("[Deeplink] UPDATE:", urls["update_url"])
    print("[Deeplink] CANCEL (immediate):", urls["cancel_url"])
    print("[Deeplink] PAUSE:", urls["pause_url"])
    return urls


# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK FastAPI — post-checkout: genera i DEEPLINKS
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — checkout + portal + deeplinks)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    A 'checkout.session.completed':
      - genera i 3 deeplink (update/cancel-immediate/pause)
      - logga su JSONL e stampa a console
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

        # Genera deeplink post-acquisto
        global ACCESS_TOKEN_GLOBAL, GLOBAL_PLAN_TYPE
        if ACCESS_TOKEN_GLOBAL and subscription_id:
            try:
                plan = GLOBAL_PLAN_TYPE or "AI Standard"
                upd = portal_deeplink_update(ACCESS_TOKEN_GLOBAL, subscription_id=subscription_id, plan_type=plan, variants=VARIANTS_BUCKET)
                can = portal_deeplink_cancel_immediate(ACCESS_TOKEN_GLOBAL, subscription_id=subscription_id, plan_type=plan, variants_for_context=VARIANTS_BUCKET)
                pau = portal_deeplink_pause(ACCESS_TOKEN_GLOBAL, subscription_id=subscription_id, plan_type=plan, variants_for_context=VARIANTS_BUCKET)
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
    # Stripe SDK per verify/retrieve nel webhook
    stripe.api_key = STRIPE_SECRET_KEY

    # 0) Login
    global ACCESS_TOKEN_GLOBAL
    ACCESS_TOKEN_GLOBAL = signin_and_get_access_token()
    print("[Auth] Login eseguito. Access token ottenuto.")

    # 1) Webhook server
    if RUN_WEBHOOK_SERVER:
        threading.Thread(target=run_webhook_server_blocking, daemon=True).start()
        print(f"[Webhook] Server avviato su http://localhost:{WEBHOOK_PORT}/webhooks/stripe")
        print(f"         Esegui:\n         stripe listen --forward-to localhost:{WEBHOOK_PORT}/webhooks/stripe")
        time.sleep(1.0)

    # 1bis) Tail del file log per stampare i deeplink generati dal webhook
    if TAIL_WEBHOOK_LOG:
        threading.Thread(target=tail_webhook_log, daemon=True).start()

    # 2) Se esiste già una subscription attiva → crea SUBITO Portal + Deeplinks
    existing_sub_id = get_existing_active_subscription_id(ACCESS_TOKEN_GLOBAL)
    if existing_sub_id:
        print(f"\n[Found] Subscription attiva: {existing_sub_id} → creo Portal + Deeplinks in parallelo.")
        plan_type = "AI Standard"
        # Portal "gestione"
        me_create_billing_portal_session(ACCESS_TOKEN_GLOBAL, plan_type=plan_type, portal_preset="monthly", return_url=RETURN_URL)
        # Deeplinks SUBITO
        generate_all_deeplinks(ACCESS_TOKEN_GLOBAL, subscription_id=existing_sub_id, plan_type=plan_type)

    # 3) CHECKOUT + PORTAL (se vuoi forzare un nuovo acquisto)
    global GLOBAL_PLAN_TYPE, GLOBAL_VARIANT, GLOBAL_PORTAL_PRESET
    if MAKE_CHECKOUT_AND_PORTAL:
        try:
            plan_type = "AI Standard"
            variant   = "base_monthly"

            GLOBAL_PLAN_TYPE = plan_type
            GLOBAL_VARIANT   = variant
            GLOBAL_PORTAL_PRESET = "annual" if variant.endswith("_annual") else "monthly"

            # A) Checkout (ottieni URL da aprire)
            co = me_create_checkout_session_variant(ACCESS_TOKEN_GLOBAL, plan_type=plan_type, variant=variant, locale="it")

            # B) Portal session in parallelo (PM/profile)
            portal = me_create_billing_portal_session(ACCESS_TOKEN_GLOBAL, plan_type=plan_type, portal_preset=GLOBAL_PORTAL_PRESET, return_url=RETURN_URL)

            print("\n>>> Apri nel browser e completa il pagamento (test):")
            print(co.get("url"), "\n")
            print("Nota: il Billing Portal è già disponibile:")
            print(portal.get("url"), "\n")
            print("Al termine del pagamento, i deeplink verranno stampati dal webhook/tailer.")
        except Exception as e:
            print("[ERROR] Checkout/Portal:", e)

    # 4) Loop demo (Ctrl+C per uscire)
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
