"""
Demo end-to-end (ME) — Login ➜ Checkout dinamico ➜ Webhook ➜ Portal ➜ Risorse (get/consume/set)

Requisiti:
  pip install fastapi uvicorn requests stripe python-dotenv pydantic

Env (.env opzionale):
  API_BASE=http://localhost:8000
  AUTH_API_BASE=https://teatek-llm.theia-innovation.com/auth
  STRIPE_WEBHOOK_SECRET=whsec_xxx
  STRIPE_SECRET_KEY=sk_test_xxx
  RETURN_URL=https://tuo-sito.com/account
  DEMO_USERNAME=test.user@example.com
  DEMO_PASSWORD=Password!234
  ADMIN_API_KEY=supersecret_admin_key  # richiesto per /resources/consume e /resources/set

Uso:
  1) Avvia la tua API (uvicorn app.main:app --reload).
  2) In un terminale: stripe listen --forward-to localhost:9000/webhooks/stripe
  3) Esegui questo script: python demo_subscription_flow_me_dynamic.py
  4) Apri la URL di Checkout e completa il pagamento (test).
"""

from __future__ import annotations
import os, json, uuid, threading, time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

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

# 👇 Username/Password fissati nello script (override via .env se vuoi)
USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")# "user-slm02i0nl")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT: bool = True

WEBHOOK_LOG_FILE = Path("webhook_events.jsonl")

# sarà valorizzato al login e riusato dal webhook
ACCESS_TOKEN_GLOBAL: Optional[str] = None

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
# LOGIN
# ─────────────────────────────────────────────────────────────────────────────
def signin_and_get_access_token() -> str:
    sdk = CognitoSDK(AUTH_BASE)
    resp = sdk.signin(SignInRequest(username=USERNAME, password=PASSWORD))
    token = resp.get("AuthenticationResult", {}).get("AccessToken")
    if not token:
        raise RuntimeError(f"Signin ok ma AccessToken non trovato: {resp}")
    return token

# ─────────────────────────────────────────────────────────────────────────────
# CHIAMATE /me/plans
# ─────────────────────────────────────────────────────────────────────────────
def me_create_checkout_session(access_token: str) -> dict:
    """
    Checkout dinamico controllato: l'utente passa SOLO plan_type, pricing_method, resources.
    Il backend applica la policy lato server (currency/recurring/tax).
    """
    url = f"{API_BASE}/me/plans/checkout"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.checkout.dynamic",
    }
    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",

        # 👇 SOLO questi campi di business, coerenti con l'endpoint "strict"
        "plan_type": "AI Standard",
        "pricing_method": "linear_sum",
        "resources": [
            {"key": "n_servers",    "quantity": 2,   "unit": "units"},
            {"key": "ssd_gb",       "quantity": 200, "unit": "GB"},
            {"key": "bandwidth_tb", "quantity": 3,   "unit": "TB"},
        ],

        # (facoltativi e innocui per UI/UX — non influiscono sul prezzo)
        "allow_promotion_codes": True,
        "locale": "it",
        # puoi inviare anche tax_id_collection/automatic_tax/customer_update se il backend lo consente;
        # in questa demo restiamo minimal e demandiamo tutto alla policy lato server.
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id:", res.get("customer_id"))
    return res

def me_create_billing_portal(access_token: str) -> dict:
    url = f"{API_BASE}/me/plans/portal/session"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.portal.session",
    }
    payload = {"return_url": RETURN_URL}
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal] Create failed: {r.status_code} {r.text}")
    return r.json()

def me_get_resources(access_token: str, subscription_id: str) -> dict:
    url = f"{API_BASE}/me/plans/subscriptions/{subscription_id}/resources"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Resources] Get failed: {r.status_code} {r.text}")
    return r.json()

def admin_consume_resources(access_token: str, subscription_id: str, items: list, reason: str) -> dict:
    """
    Richiede JWT **e** X-API-Key (ADMIN_API_KEY).
    """
    if not ADMIN_API_KEY:
        raise RuntimeError("ADMIN_API_KEY mancante: impossibile chiamare /resources/consume")
    url = f"{API_BASE}/me/plans/subscriptions/{subscription_id}/resources/consume"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": ADMIN_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:resources.consume",
    }
    payload = {
        "items": items,  # [{key, quantity, unit}]
        "reason": reason
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Resources] Consume failed: {r.status_code} {r.text}")
    return r.json()

def admin_set_resources(access_token: str, subscription_id: str, resources_provided: list, reset_used: bool, reason: str) -> dict:
    """
    Richiede JWT **e** X-API-Key (ADMIN_API_KEY).
    """
    if not ADMIN_API_KEY:
        raise RuntimeError("ADMIN_API_KEY mancante: impossibile chiamare /resources/set")
    url = f"{API_BASE}/me/plans/subscriptions/{subscription_id}/resources/set"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": ADMIN_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:resources.set",
    }
    payload = {
        "resources_provided": resources_provided,  # [{key, quantity, unit}]
        "reset_used": reset_used,
        "reason": reason
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Resources] Set failed: {r.status_code} {r.text}")
    return r.json()

# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK FastAPI — orchestration post-checkout
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — ME dynamic)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    Verifica firma, logga evento e, a 'checkout.session.completed':
      - crea Portal URL
      - legge risorse
      - consuma alcune risorse
      - setta nuovo pacchetto risorse
      - ristampa stato dopo ogni azione
    """
    if not STRIPE_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET == "whsec_xxx":
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET mancante o placeholder")

    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature") or request.headers.get("stripe-signature") or ""

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET
        )
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

        record.update({
            "checkout_session_id": cs_id,
            "customer_id": customer_id,
            "subscription_id": subscription_id,
        })

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

        # Orchestrazione: Portal + Risorse
        global ACCESS_TOKEN_GLOBAL
        if ACCESS_TOKEN_GLOBAL and subscription_id:
            try:
                # 1) Billing Portal
                portal = me_create_billing_portal(ACCESS_TOKEN_GLOBAL)
                record["portal_url"] = portal.get("url")
                print("\n[Portal] URL:", record["portal_url"])

                # 2) GET Risorse
                state1 = me_get_resources(ACCESS_TOKEN_GLOBAL, subscription_id)
                print("\n[Resources] Stato iniziale:")
                print(json.dumps(state1, indent=2, ensure_ascii=False))

                # 3) CONSUME qualche risorsa
                consume_res = [
                    {"key": "n_servers", "quantity": 1, "unit": "units"},
                    {"key": "ssd_gb",    "quantity": 50, "unit": "GB"},
                ]
                state2 = admin_consume_resources(
                    ACCESS_TOKEN_GLOBAL, subscription_id, consume_res, reason="demo-consume"
                )
                print("\n[Resources] Dopo consume:")
                print(json.dumps(state2, indent=2, ensure_ascii=False))

                # 4) SET nuovo pacchetto di risorse (es. aumento n_servers e storage) mantenendo used
                new_provided = [
                    {"key": "n_servers",    "quantity": 5,   "unit": "units"},
                    {"key": "ssd_gb",       "quantity": 400, "unit": "GB"},
                    {"key": "bandwidth_tb", "quantity": 6,   "unit": "TB"},
                ]
                state3 = admin_set_resources(
                    ACCESS_TOKEN_GLOBAL, subscription_id, new_provided, reset_used=False, reason="demo-set"
                )
                print("\n[Resources] Dopo set (reset_used=False):")
                print(json.dumps(state3, indent=2, ensure_ascii=False))

                # 5) GET finale per conferma
                state4 = me_get_resources(ACCESS_TOKEN_GLOBAL, subscription_id)
                print("\n[Resources] Stato finale (get):")
                print(json.dumps(state4, indent=2, ensure_ascii=False))

            except Exception as e:
                record["postflow_error"] = str(e)
        else:
            record["postflow_error"] = "Access token o subscription_id mancanti; impossibile completare la demo."

    # Log JSONL
    WEBHOOK_LOG_FILE.touch(exist_ok=True)
    with WEBHOOK_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}

def run_webhook_server_blocking():
    uvicorn.run(app, host="0.0.0.0", port=9000)

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
    server_thread = None
    if RUN_WEBHOOK_SERVER:
        server_thread = threading.Thread(target=run_webhook_server_blocking, daemon=True)
        server_thread.start()
        print("[Webhook] Server avviato su http://localhost:9000/webhooks/stripe")
        print("         Esegui:")
        print("         stripe listen --forward-to localhost:9000/webhooks/stripe")
        time.sleep(1.0)

    # 2) Checkout dinamico
    if MAKE_CHECKOUT:
        try:
            res = me_create_checkout_session(ACCESS_TOKEN_GLOBAL)
            print("\n>>> Apri nel browser e completa il pagamento (test):")
            print(res.get("url"), "\n")
        except Exception as e:
            print("[ERROR] Checkout:", e)

    # 3) Attesa eventi
    if RUN_WEBHOOK_SERVER:
        print("[Webhook] In attesa eventi... Ctrl+C per uscire.")
        try:
            while True:
                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nArresto richiesto. Bye.")
    else:
        print("Operazioni completate.")

if __name__ == "__main__":
    main()
