"""
Demo end-to-end (parametri fissi, senza argparse):
- Avvia un webhook FastAPI (thread) per ricevere 'checkout.session.completed' da Stripe,
  verificando la firma e appendendo su file JSONL.
- Crea una Checkout Session (abbonamento) chiamando la TUA API /plans/checkout.
- Quando arriva il webhook, genera anche un link Billing Portal tramite /plans/portal/session
  e lo salva nello stesso file.

Prerequisiti:
  pip install fastapi uvicorn requests stripe python-dotenv

Note:
  - Per testare i webhook in locale: stripe listen --forward-to localhost:9000/webhooks/stripe
  - La tua API (FastAPI) deve essere in esecuzione su API_BASE (default: http://localhost:8000)
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

# -----------------------
# CONFIGURAZIONE FISSA (modifica qui)
# -----------------------
# Puoi comunque usare .env per sovrascrivere: API_BASE, API_KEY, STRIPE_WEBHOOK_SECRET, RETURN_URL, STRIPE_SECRET_KEY
load_dotenv()

API_BASE: str = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
API_KEY: str = os.getenv("API_KEY", "userkey456")  # X-API-Key della TUA API
RETURN_URL: str = os.getenv("RETURN_URL", "https://tuo-sito.com/account")
STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_xxx")  # da 'stripe listen'
STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "sk_test_xxx")        # solo per verify/retrieve nel webhook

# Cosa vuoi fare?
RUN_WEBHOOK_SERVER: bool = True    # avvia server webhook su :9000
MAKE_CHECKOUT: bool = True         # crea una Checkout Session dopo l'avvio del webhook

# Dati demo per la Checkout (la tua API /plans/checkout gestisce questi campi)
CHECKOUT_PAYLOAD = {
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
    # Opzione A (riuso cliente esistente): decommenta e commenta l'opzione B
    # "customer": {"customer_id": "cus_1234567890", "internal_customer_ref": "user-42"},
    # Opzione B (creazione al volo con email+nome):
    "customer": {"email": "mario.rossi@example.com", "name": "Mario Rossi", "internal_customer_ref": "user-42"},
    "client_reference_id": "user-42",
    "allow_promotion_codes": True,
    "automatic_tax": {"enabled": True},
    "tax_id_collection": {"enabled": True},
    "subscription_metadata": {"tenant_id": "acme-1"},
    "billing_address_collection": "auto"
}

# Header comuni verso la TUA API
COMMON_HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "Idempotency-Key": str(uuid.uuid4()),  # idempotenza consigliata
}

# File di log JSONL per gli eventi
LOG_FILE = Path("webhook_events.jsonl")

# -----------------------
# CLIENT: crea Checkout Session via TUA API
# -----------------------
def create_subscription_checkout() -> dict:
    url = f"{API_BASE}/plans/checkout"
    r = requests.post(url, headers=COMMON_HEADERS, data=json.dumps(CHECKOUT_PAYLOAD), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"Checkout create failed: {r.status_code} {r.text}")
    res = r.json()
    print("\n[Checkout] Session ID:", res.get("id"))
    print("[Checkout] URL:", res.get("url"))
    print("[Checkout] customer_id (se già noto):", res.get("customer_id"))
    print("Apri questa URL nel browser e completa il pagamento (test).\n")
    return res

# -----------------------
# WEBHOOK FastAPI
# -----------------------
app = FastAPI(title="Stripe Webhook Sink (demo, fixed params)")

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """
    Verifica la firma e salva l'evento su file JSONL.
    Per 'checkout.session.completed':
      - salva customer_id e subscription_id
      - chiama la TUA API /plans/portal/session per ottenere un URL di Billing Portal
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

    # Caso principale: checkout completato
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
            except Exception as e:
                record["retrieve_error"] = str(e)

        # Genera Billing Portal link tramite la TUA API
        try:
            portal_resp = requests.post(
                f"{API_BASE}/plans/portal/session",
                headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
                data=json.dumps({"customer_id": record.get("customer_id"), "return_url": RETURN_URL}),
                timeout=30
            )
            if portal_resp.status_code < 300:
                portal = portal_resp.json()
                record["portal_url"] = portal.get("url")
            else:
                record["portal_error"] = f"{portal_resp.status_code} {portal_resp.text}"
        except Exception as e:
            record["portal_error"] = str(e)

    elif etype in ("invoice.paid", "customer.subscription.created"):
        record.update({
            "customer_id": obj.get("customer"),
            "subscription_id": obj.get("subscription"),
            "invoice_id": obj.get("id") if etype == "invoice.paid" else None
        })

    # Append su file JSONL
    LOG_FILE.touch(exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {"received": True}

def run_webhook_server_blocking():
    """
    Avvia il server webhook su :9000 (bloccante).
    """
    uvicorn.run(app, host="0.0.0.0", port=9000)

# -----------------------
# BOOTSTRAP
# -----------------------
def main():
    # chiave Stripe per verify/retrieve in webhook
    stripe.api_key = STRIPE_SECRET_KEY

    # 1) Avvia webhook (thread) se richiesto
    server_thread = None
    if RUN_WEBHOOK_SERVER:
        server_thread = threading.Thread(target=run_webhook_server_blocking, daemon=True)
        server_thread.start()
        print("[Webhook] Server avviato su http://localhost:9000/webhooks/stripe")
        print("         Avvia in un altro terminale: stripe listen --forward-to localhost:9000/webhooks/stripe")
        time.sleep(1.0)  # piccola attesa per far salire il server

    # 2) Crea Checkout Session se richiesto
    if MAKE_CHECKOUT:
        try:
            create_subscription_checkout()
        except Exception as e:
            print("[Checkout] ERRORE:", e)

    # 3) Mantieni vivo il processo se il webhook è attivo
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
