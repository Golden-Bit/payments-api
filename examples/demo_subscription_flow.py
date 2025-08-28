"""
Demo end-to-end (parametri fissi, senza argparse) — Customer ➜ Checkout ➜ Webhook ➜ Portal

Cosa fa:
1) Avvia un server FastAPI (porta 9000) per ricevere il webhook Stripe
   e verificare la firma con STRIPE_WEBHOOK_SECRET; appende gli eventi in JSONL.
2) Crea o aggiorna un Customer tramite la TUA API /admin/customers (chiave ADMIN_API_KEY),
   assicurando un indirizzo valido per evitare errori con automatic_tax e VAT.
3) Crea una Checkout Session (abbonamento) via /plans/checkout (chiave USER_API_KEY),
   usando il customer_id appena ottenuto; stampa l’URL da aprire nel browser.
4) Quando Stripe invia 'checkout.session.completed' al webhook:
   - salva customer_id/subscription_id su file
   - chiama la TUA API /plans/portal/session per ottenere il link al Billing Portal
   - aggiunge 'portal_url' nello stesso record

Prerequisiti:
  pip install fastapi uvicorn requests stripe python-dotenv

Ambiente (.env opzionale: tutti i valori qui sotto sono sovrascrivibili):
  API_BASE=http://localhost:8000          # URL della tua API FastAPI
  ADMIN_API_KEY=adminkey123               # X-API-Key per /admin/*
  USER_API_KEY=userkey456                 # X-API-Key per /plans/*
  STRIPE_WEBHOOK_SECRET=whsec_xxx         # ottenuto da `stripe listen`
  STRIPE_SECRET_KEY=sk_test_xxx           # per verify/retrieve nel webhook
  RETURN_URL=https://tuo-sito.com/account # Redirect del Portal
  CUSTOMER_ID=cus_xxx                     # (opzionale) se vuoi riusare un Customer esistente

Uso:
  1) Avvia la TUA API (uvicorn app.main:app --reload).
  2) In un altro terminale: stripe listen --forward-to localhost:9000/webhooks/stripe
  3) Esegui questo script: python demo_subscription_flow_full.py
  4) Apri l'URL di Checkout stampato e completa il pagamento (in modalità test).
  5) Vedi gli eventi in webhook_events.jsonl, incluso il link del Billing Portal.
"""

from __future__ import annotations
import os, json, uuid, threading, time
from pathlib import Path
from datetime import datetime, timezone

import requests
import stripe
from dotenv import load_dotenv

from fastapi import FastAPI, Request, HTTPException
import uvicorn

# =============================================================================
#                              CONFIGURAZIONE
# =============================================================================
load_dotenv()

API_BASE: str = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "adminkey123")  # per /admin/*
USER_API_KEY:  str = os.getenv("USER_API_KEY",  "userkey456")   # per /plans/*

STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxx")
STRIPE_SECRET_KEY:     str = os.getenv("STRIPE_SECRET_KEY",     "sk_test_xxx")  # usato SOLO nel webhook per verify/retrieve

RETURN_URL: str = os.getenv("RETURN_URL", "https://tuo-sito.com/account")

# Se già possiedi un Customer Stripe da usare, impostalo qui o via .env CUSTOMER_ID
EXISTING_CUSTOMER_ID: str | None = os.getenv("CUSTOMER_ID") or None

# Flag: se metti False a uno dei due, salta lo step relativo
RUN_WEBHOOK_SERVER: bool = True
MAKE_CHECKOUT: bool = True

# Dati anagrafici/indirizzo per il Customer di test (usati in creazione o aggiornamento)
CUSTOMER_PROFILE = {
    "email": "mario.rossi@example.com",
    "name":  "Mario Rossi",
    "address": {
        "line1":       "Via Roma 1",
        "city":        "Milano",
        "postal_code": "20100",
        "country":     "IT"
    },
    # questo metadato torna utile per riconciliare con il tuo DB utente
    "metadata": {"internal_customer_ref": "user-42"}
}

# Config del piano per la Checkout (verrà creato Product+Price al volo)
CHECKOUT_PLAN = {
    "product_name": "AI Standard",
    "currency": "eur",
    "unit_amount": 2900,  # 29.00 EUR
    "recurring": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
    "trial_period_days": 7,
    "metadata": {"plan_key": "ai_std_v1"}
}

WEBHOOK_LOG_FILE = Path("webhook_events.jsonl")


# =============================================================================
#                    HELPER: CHIAMATE ALLA TUA API (CLIENT)
# =============================================================================

def create_customer_via_api(profile: dict) -> str:
    """
    Crea un Customer tramite /admin/customers (richiede ADMIN_API_KEY).
    Ritorna l'ID Stripe (cus_...).
    """
    url = f"{API_BASE}/admin/customers"
    headers = {
        "X-API-Key": ADMIN_API_KEY,
        "Content-Type": "application/json",
        # Idempotency dedicata a QUESTA singola POST:
        "Idempotency-Key": f"{uuid.uuid4()}:admin.customers.create",
    }
    r = requests.post(url, headers=headers, data=json.dumps(profile), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Customer] Create failed: {r.status_code} {r.text}")
    data = r.json()
    cus_id = data.get("id")
    if not cus_id:
        raise RuntimeError("[Customer] Create: risposta senza 'id'")
    print(f"[Customer] Creato: {cus_id}")
    return cus_id


def update_customer_via_api(customer_id: str, fields: dict) -> str:
    """
    Aggiorna un Customer esistente tramite /admin/customers/{cus_id} (POST).
    Utile per assicurare un indirizzo valido (automatic_tax) e metadati.
    """
    url = f"{API_BASE}/admin/customers/{customer_id}"
    headers = {
        "X-API-Key": ADMIN_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:admin.customers.update",
    }
    r = requests.post(url, headers=headers, data=json.dumps(fields), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Customer] Update failed: {r.status_code} {r.text}")
    print(f"[Customer] Aggiornato: {customer_id}")
    return customer_id


def create_checkout_session_via_api(customer_id: str) -> dict:
    """
    Crea la Checkout Session di abbonamento via /plans/checkout usando il customer_id fornito.
    - automatic_tax.enabled = true
    - tax_id_collection.enabled = true
    - billing_address_collection = 'auto' (la rotta /plans applicherà fallback adeguati)
    """
    url = f"{API_BASE}/plans/checkout"
    headers = {
        "X-API-Key": USER_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:plans.checkout.create",
    }
    payload = {
        "success_url": "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}",
        "cancel_url":  "https://tuo-sito.com/cancel",
        "plan": CHECKOUT_PLAN,               # crea Product+Price al volo
        "quantity": 1,
        "customer": {"customer_id": customer_id, "internal_customer_ref": "user-42"},
        "client_reference_id": "user-42",
        "allow_promotion_codes": True,
        "automatic_tax": {"enabled": True},
        "tax_id_collection": {"enabled": True},
        "billing_address_collection": "auto",
        "subscription_metadata": {"tenant_id": "acme-1"},

        # Consigliato: lascia che Checkout aggiorni 'address' e 'name' sul Customer
        # qualora mancassero o cambiassero in pagina (utile per VAT e fiscalità):
        "customer_update": {"address": "auto", "name": "auto"},
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"[Checkout] Create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id:", res.get("customer_id"))
    print("Apri questa URL nel browser e completa il pagamento (test).\n")
    return res


def create_billing_portal_via_api(customer_id: str) -> dict:
    """
    Crea un link al Billing Portal via /plans/portal/session (USER_API_KEY).
    Richiamato dal webhook al completamento della sessione di Checkout.
    """
    url = f"{API_BASE}/plans/portal/session"
    headers = {
        "X-API-Key": USER_API_KEY,
        "Content-Type": "application/json",
        "Idempotency-Key": f"{uuid.uuid4()}:plans.portal.session",
    }
    payload = {"customer_id": customer_id, "return_url": RETURN_URL}
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"[Portal] Create failed: {r.status_code} {r.text}")
    return r.json()


# =============================================================================
#                             WEBHOOK (FastAPI)
# =============================================================================
app = FastAPI(title="Stripe Webhook Sink (demo — customer ➜ checkout)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    Verifica la firma e salva l'evento su file JSONL.
    Per 'checkout.session.completed':
      - salva customer_id e subscription_id
      - genera URL Billing Portal via /plans/portal/session
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

    # Caso principale: completamento della sessione di Checkout
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

        # Genera Billing Portal link (se abbiamo un customer_id valido)
        if customer_id:
            try:
                portal = create_billing_portal_via_api(customer_id)
                record["portal_url"] = portal.get("url")
            except Exception as e:
                record["portal_error"] = str(e)

    # Altri eventi utili (salviamo info minime)
    elif etype in ("invoice.paid", "customer.subscription.created"):
        record.update({
            "customer_id": obj.get("customer"),
            "subscription_id": obj.get("subscription"),
            "invoice_id": obj.get("id") if etype == "invoice.paid" else None
        })

    # Append su file JSONL (semplice audit locale)
    WEBHOOK_LOG_FILE.touch(exist_ok=True)
    with WEBHOOK_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}


def run_webhook_server_blocking():
    """Avvia il server webhook su :9000 (bloccante)."""
    uvicorn.run(app, host="0.0.0.0", port=9000)


# =============================================================================
#                                   MAIN
# =============================================================================
def main():
    # Config Stripe SDK per verify/retrieve dei webhook
    stripe.api_key = STRIPE_SECRET_KEY

    # 1) Avvia il server webhook in background (thread)
    server_thread = None
    if RUN_WEBHOOK_SERVER:
        server_thread = threading.Thread(target=run_webhook_server_blocking, daemon=True)
        server_thread.start()
        print("[Webhook] Server avviato su http://localhost:9000/webhooks/stripe")
        print("         In un altro terminale, lancia:")
        print("         stripe listen --forward-to localhost:9000/webhooks/stripe")
        time.sleep(1.0)  # breve attesa per far salire il server

    # 2) Crea/aggiorna Customer e avvia Checkout
    if MAKE_CHECKOUT:
        try:
            if EXISTING_CUSTOMER_ID:
                # Aggiorna un Customer esistente con indirizzo valido
                customer_id = update_customer_via_api(EXISTING_CUSTOMER_ID, {
                    "email": CUSTOMER_PROFILE["email"],
                    "name":  CUSTOMER_PROFILE["name"],
                    "address": CUSTOMER_PROFILE["address"],
                    "metadata": CUSTOMER_PROFILE.get("metadata", {})
                })
            else:
                # Crea un nuovo Customer con indirizzo valido
                customer_id = create_customer_via_api(CUSTOMER_PROFILE)

            # Crea la Checkout Session (abbonamento) usando quel customer_id
            create_checkout_session_via_api(customer_id)

        except Exception as e:
            print("[ERROR]", e)

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
