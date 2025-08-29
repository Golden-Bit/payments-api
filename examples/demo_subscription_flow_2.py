"""
Demo end-to-end (ME) — Login Cognito ➜ Checkout (/me) ➜ Webhook ➜ Portal (/me)

Cosa fa:
1) Effettua il login utente (Cognito) con username/password fissati nello script.
2) Avvia un server FastAPI (porta 9000) per ricevere il webhook Stripe
   e verificare la firma con STRIPE_WEBHOOK_SECRET; appende gli eventi in JSONL.
3) Crea una Checkout Session (abbonamento) via /me/plans/checkout (Bearer <access_token>),
   SENZA passare customer_id: lo risolve la tua API dal token utente.
4) Quando Stripe invia 'checkout.session.completed' al webhook:
   - salva customer_id/subscription_id su file
   - chiama /me/plans/portal/session (Bearer) per ottenere il link al Billing Portal
   - aggiunge 'portal_url' nello stesso record

Prerequisiti:
  pip install fastapi uvicorn requests stripe python-dotenv pydantic

Ambiente (.env opzionale: tutti i valori qui sotto sono sovrascrivibili):
  API_BASE=http://localhost:8000          # URL della tua API (stesso host del backend)
  AUTH_BASE=http://localhost:8000         # URL del servizio auth con le rotte /v1/user/*
  STRIPE_WEBHOOK_SECRET=whsec_xxx         # ottenuto da `stripe listen`
  STRIPE_SECRET_KEY=sk_test_xxx           # per verify/retrieve nel webhook
  RETURN_URL=https://tuo-sito.com/account # Redirect del Portal
  DEMO_USERNAME=test.user                 # (opzionale) username di demo
  DEMO_PASSWORD=Password!234              # (opzionale) password di demo

Uso:
  1) Avvia la TUA API (uvicorn app.main:app --reload) con le rotte /me/plans attive.
  2) In un altro terminale: stripe listen --forward-to localhost:9000/webhooks/stripe
  3) Esegui questo script: python demo_subscription_flow_me.py
  4) Apri l'URL di Checkout stampato e completa il pagamento (in modalità test).
  5) Vedi gli eventi in webhook_events.jsonl, incluso il link del Billing Portal.

Note:
  - Lo script NON chiama /admin/customers: l’utente viene mappato a uno Stripe Customer lato backend.
  - Per evitare errori di fiscalità/VAT, questo script imposta:
      customer_update = {"address":"auto","name":"auto"}
      billing_address_collection = "required"
    Così i dati inseriti in Checkout vengono salvati sul Customer.
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

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

API_BASE: str = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
AUTH_BASE: str = os.getenv("AUTH_API_BASE", "https://teatek-llm.theia-innovation.com/auth ").rstrip("/")

STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxx")
STRIPE_SECRET_KEY:     str = os.getenv("STRIPE_SECRET_KEY",     "sk_test_xxx")  # usato SOLO nel webhook per verify/retrieve
RETURN_URL: str        = os.getenv("RETURN_URL", "https://tuo-sito.com/account")

# 👇 Username/Password fissati nello script (override via .env se vuoi)
USERNAME: str = os.getenv("DEMO_USERNAME", "sansalonesimone0@gmail.com")# "user-slm02i0nl")
PASSWORD: str = os.getenv("DEMO_PASSWORD", "h326JH%gesL")

# Flag
RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT: bool = True

# Config del piano per la Checkout (Product+Price creati al volo dal backend)
CHECKOUT_PLAN = {
    "product_name": "AI Standard",
    "currency": "eur",
    "unit_amount": 2900,  # 29.00 EUR
    "recurring": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
    "trial_period_days": 7,
    "metadata": {"plan_key": "ai_std_v1"}
}

WEBHOOK_LOG_FILE = Path("webhook_events.jsonl")

# Sarà popolato dopo il login e usato *anche* dal webhook per creare il Portal
ACCESS_TOKEN_GLOBAL: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# SDK AUTH (riuso del vostro SDK Cognito)
# ─────────────────────────────────────────────────────────────────────────────
# Nota: importiamo le classi principali dal vostro SDK così come sono state definite.
# Se il modulo si chiama diversamente, aggiorna l'import di conseguenza.
from pydantic import BaseModel, Field

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
# HELPER: LOGIN & TOKEN
# ─────────────────────────────────────────────────────────────────────────────
def signin_and_get_access_token() -> str:
    """
    Esegue il login Cognito via SDK e ritorna l'Access Token.
    La risposta può variare (AccessToken vs access_token); gestiamo entrambi.
    """
    sdk = CognitoSDK(AUTH_BASE)
    resp = sdk.signin(SignInRequest(username=USERNAME, password=PASSWORD))
    #print(resp)
    #print(resp["AuthenticationResult"])
    #print(resp["AuthenticationResult"]["AccessToken"])
    # fallback robusto sulle chiavi comuni
    token = resp.get("AuthenticationResult", {}).get("AccessToken")
    print(token)
    if not token:
        raise RuntimeError(f"Signin ok ma non trovo AccessToken nella risposta: {resp}")
    return token


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: CHIAMATE /me/plans (autenticate Bearer)
# ─────────────────────────────────────────────────────────────────────────────
def me_create_checkout_session(access_token: str) -> dict:
    """
    Crea la Checkout Session via /me/plans/checkout usando Bearer <access_token>.
    Non passiamo customer_id: il backend risolve/crea il Customer dallo user del token.
    """
    url = f"{API_BASE}/me/plans/checkout"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        # Idempotency dedicata a QUESTA singola POST:
        "Idempotency-Key": f"{uuid.uuid4()}:me.plans.checkout.create",
    }
    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",

        # piano creato al volo
        "plan": CHECKOUT_PLAN,
        "quantity": 1,

        # tassazione & VAT: chiedi indirizzo e salva su Customer
        "automatic_tax": {"enabled": True},
        "tax_id_collection": {"enabled": True},
        "billing_address_collection": "required",
        "customer_update": {"address": "auto", "name": "auto"},

        # opzionale per analytics/reconciliazione lato tuo:
        "client_reference_id": USERNAME,
        "allow_promotion_codes": True,

        # metadati lato Subscription (il backend può aggiungere anche internal_customer_ref=user_ref)
        "subscription_metadata": {"tenant_id": "acme-1", "initiator": "demo-me"},
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id (se disponibile):", res.get("customer_id"))
    print("Apri questa URL nel browser e completa il pagamento (test).\n")
    return res


def me_create_billing_portal(access_token: str) -> dict:
    """
    Crea un link al Billing Portal via /me/plans/portal/session (Bearer).
    Non passiamo customer_id: lo risolve il backend dal token utente.
    """
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


# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK FastAPI — scrive JSONL e genera Portal URL via /me
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Stripe Webhook Sink (demo — ME)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    Verifica la firma e salva l'evento su file JSONL.
    Per 'checkout.session.completed':
      - salva customer_id e subscription_id
      - genera URL Billing Portal via /me/plans/portal/session (Bearer lo stesso Access Token)
      - appende 'portal_url' nello stesso record
    """
    if not STRIPE_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET == "whsec_xxx":
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET mancante o placeholder")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

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
        client_ref = obj.get("client_reference_id")

        record.update({
            "checkout_session_id": cs_id,
            "customer_id": customer_id,
            "subscription_id": subscription_id,
            "client_reference_id": client_ref,
        })

        # Recupero di sicurezza se 'customer' fosse assente
        if not customer_id and cs_id:
            try:
                sess = stripe.checkout.Session.retrieve(cs_id)
                record["customer_id"] = sess.get("customer")
                record["subscription_id"] = sess.get("subscription")
                customer_id = record["customer_id"]
            except Exception as e:
                record["retrieve_error"] = str(e)

        # Genera Billing Portal link via /me (se abbiamo un access token valido)
        global ACCESS_TOKEN_GLOBAL
        if ACCESS_TOKEN_GLOBAL:
            try:
                portal = me_create_billing_portal(ACCESS_TOKEN_GLOBAL)
                record["portal_url"] = portal.get("url")
            except Exception as e:
                record["portal_error"] = str(e)
        else:
            record["portal_error"] = "Access token mancante nel webhook; impossibile chiamare /me/plans/portal/session"

    elif etype in ("invoice.paid", "customer.subscription.created"):
        # Nota: per 'customer.subscription.created' l'oggetto è la Subscription → id = subscription_id
        if etype == "invoice.paid":
            record.update({
                "customer_id": obj.get("customer"),
                "subscription_id": obj.get("subscription"),
                "invoice_id": obj.get("id"),
            })
        else:
            record.update({
                "customer_id": obj.get("customer"),
                "subscription_id": obj.get("id"),
            })

    # Append su file JSONL
    WEBHOOK_LOG_FILE.touch(exist_ok=True)
    with WEBHOOK_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}


def run_webhook_server_blocking():
    """Avvia il server webhook su :9000 (bloccante)."""
    uvicorn.run(app, host="0.0.0.0", port=9000)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    # Config Stripe SDK per verify/retrieve dei webhook
    stripe.api_key = STRIPE_SECRET_KEY

    # 0) Login Cognito (ottieni Access Token)
    global ACCESS_TOKEN_GLOBAL
    ACCESS_TOKEN_GLOBAL = signin_and_get_access_token()
    print("[Auth] Login eseguito. Access token ottenuto.")

    # 1) Avvia il server webhook in background (thread)
    server_thread = None
    if RUN_WEBHOOK_SERVER:
        server_thread = threading.Thread(target=run_webhook_server_blocking, daemon=True)
        server_thread.start()
        print("[Webhook] Server avviato su http://localhost:9000/webhooks/stripe")
        print("         In un altro terminale, lancia:")
        print("         stripe listen --forward-to localhost:9000/webhooks/stripe")
        time.sleep(1.0)  # breve attesa per far salire il server

    # 2) Crea la Checkout Session (abbonamento) via /me/plans/checkout
    if MAKE_CHECKOUT:
        try:
            me_create_checkout_session(ACCESS_TOKEN_GLOBAL)
        except Exception as e:
            print("[ERROR] Checkout:", e)

    # 3) Mantieni vivo il processo per ricevere i webhook
    if RUN_WEBHOOK_SERVER:
        print("[Webhook] In attesa eventi... premi Ctrl+C per uscire.")
        try:
            while True:
                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nArresto richiesto. Bye.")
    else:
        print("Operazioni completate.")


if __name__ == "__main__":
    main()
