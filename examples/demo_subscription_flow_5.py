"""
Demo end-to-end (ME) — Login ➜ Checkout (plan_type + variant) ➜ Webhook (log) ➜ Portal (preset) ➜ Risorse (get/consume/set)

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
  ADMIN_API_KEY=supersecret_admin_key  # richiesto per /portal/session, /resources/consume e /resources/set

Uso:
  1) Avvia la tua API (uvicorn app.main:app --reload).
  2) In un terminale: stripe listen --forward-to localhost:9000/webhooks/stripe
  3) Esegui questo script: python demo_subscription_flow_me_dynamic_variant.py
  4) Apri la URL di Checkout e completa il pagamento (test).
"""

from __future__ import annotations
import os, json, uuid, threading, time
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

# 👇 Username/Password fissati nello script (override via .env se vuoi)
USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT: bool = True

WEBHOOK_LOG_FILE = Path("webhook_events.jsonl")

# sarà valorizzato al login e riusato dal webhook
ACCESS_TOKEN_GLOBAL: Optional[str] = None

# memorizziamo plan_type/variant scelti, per inferire il preset del Portal
GLOBAL_PLAN_TYPE: Optional[str] = None
GLOBAL_VARIANT: Optional[str] = None
GLOBAL_PORTAL_PRESET: Optional[Literal["monthly","annual"]] = None  # calcolato da variant

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
def me_create_checkout_session_variant(
    access_token: str,
    *,
    plan_type: str,
    variant: str,
    locale: Optional[str] = "it",
    allow_promotion_codes: bool = True,
) -> dict:
    """
    Checkout dinamico controllato: l'utente passa plan_type + variant.
    Il backend risolve Product/Price coerenti (policy lato server).
    """
    url = f"{API_BASE}/me/plans/checkout"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.checkout.variant",
    }

    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",
        # --- business ---
        "plan_type": plan_type,
        "variant": variant,  # <-- usa varianti definite lato server (es. base_monthly, pro_annual, ...)
        # opzionale UX
        "allow_promotion_codes": allow_promotion_codes,
        "locale": locale,
    }

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id:", res.get("customer_id"))
    return res


def me_create_checkout_session_resources(
    access_token: str,
    *,
    plan_type: str,
    pricing_method: str,
    resources: List[Dict[str, Any]],
    locale: Optional[str] = "it",
    allow_promotion_codes: bool = True,
) -> dict:
    """
    Checkout con approccio alternativo: pricing_method + resources.
    Utile se vuoi bypassare le varianti e calcolare il prezzo in modo dinamico.
    """
    url = f"{API_BASE}/me/plans/checkout"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.checkout.resources",
    }

    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",
        # --- business ---
        "plan_type": plan_type,
        "pricing_method": pricing_method,
        "resources": resources,
        # opzionale UX
        "allow_promotion_codes": allow_promotion_codes,
        "locale": locale,
    }

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id:", res.get("customer_id"))
    return res


def me_create_billing_portal(access_token: str, *, plan_type: str, portal_preset: Literal["monthly","annual"]) -> dict:
    """
    Nuovo endpoint /me/plans/portal/session:
    - Richiede JWT + X-API-Key
    - Accetta plan_type e portal_preset (monthly/annual)
    - La configurazione del Portal viene risolta lato server da preset
    """
    url = f"{API_BASE}/me/plans/portal/session"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": ADMIN_API_KEY,  # ora obbligatorio per questo endpoint
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.portal.session",
    }
    payload = {
        "return_url": RETURN_URL,
        "portal_preset": portal_preset,  # "monthly" | "annual"
        "plan_type": plan_type,
        # opzionale: deep link/flow
        # "flow_data": {"type": "payment_method_update"},
    }

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
# WEBHOOK FastAPI — orchestration post-checkout (solo log/azioni demo)
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — ME dynamic, plan_type + variant)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    Verifica firma, logga evento e, a 'checkout.session.completed':
      - genera Portal URL (usando il nuovo endpoint con preset monthly/annual)
      - legge risorse
      - consuma risorse
      - setta nuovo pacchetto risorse
      - ristampa stato dopo ogni azione

    NB: la logica di sync/rollover è lato backend, non nel webhook.
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

        # Fallback retrieve se serve
        if not subscription_id and cs_id:
            try:
                sess = stripe.checkout.Session.retrieve(cs_id)
                subscription_id = sess.get("subscription")
                customer_id = sess.get("customer")
                record["subscription_id"] = subscription_id
                record["customer_id"] = customer_id
            except Exception as e:
                record["retrieve_error"] = str(e)

        # Orchestrazione demo
        global ACCESS_TOKEN_GLOBAL, GLOBAL_PLAN_TYPE, GLOBAL_PORTAL_PRESET
        if ACCESS_TOKEN_GLOBAL and subscription_id:
            try:
                # 1) Billing Portal via nuovo endpoint (usa preset mensile o annuale)
                preset = GLOBAL_PORTAL_PRESET or "monthly"
                ptype  = GLOBAL_PLAN_TYPE or "AI Standard"
                portal = me_create_billing_portal(ACCESS_TOKEN_GLOBAL, plan_type=ptype, portal_preset=preset)
                record["portal_url"] = portal.get("url")
                print("\n[Portal] URL:", record["portal_url"])

                # 2) GET Risorse (il backend fa lazy sync/rollover se necessario)
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

                # 4) SET nuovo pacchetto di risorse mantenendo used
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

    # 2) Checkout (scegli una delle due modalità)
    global GLOBAL_PLAN_TYPE, GLOBAL_VARIANT, GLOBAL_PORTAL_PRESET
    if MAKE_CHECKOUT:
        try:
            # A) Variante: plan_type + variant (consigliato)
            # Varianti disponibili per "AI Standard": free_monthly | base_monthly | pro_monthly | free_annual | base_annual | pro_annual
            plan_type = "AI Standard"      # famiglia/piano lato server
            variant   = "base_monthly"     # cambia per testare diversi casi

            # memorizza per il webhook (per scegliere il preset del Portal)
            GLOBAL_PLAN_TYPE = plan_type
            GLOBAL_VARIANT = variant
            GLOBAL_PORTAL_PRESET = "annual" if variant.endswith("_annual") else "monthly"

            res = me_create_checkout_session_variant(
                ACCESS_TOKEN_GLOBAL,
                plan_type=plan_type,
                variant=variant,
                locale="it",
                allow_promotion_codes=True,
            )

            # B) Alternativa: pricing dinamico con risorse (se vuoi testare anche questo)
            # res = me_create_checkout_session_resources(
            #     ACCESS_TOKEN_GLOBAL,
            #     plan_type="AI Standard",
            #     pricing_method="linear_sum",
            #     resources=[
            #         {"key": "n_servers",    "quantity": 2,   "unit": "units"},
            #         {"key": "ssd_gb",       "quantity": 200, "unit": "GB"},
            #         {"key": "bandwidth_tb", "quantity": 3,   "unit": "TB"},
            #     ],
            #     locale="it",
            #     allow_promotion_codes=True,
            # )
            # GLOBAL_PLAN_TYPE = "AI Standard"
            # GLOBAL_PORTAL_PRESET = "monthly"  # in questo caso scegli tu il preset desiderato

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
