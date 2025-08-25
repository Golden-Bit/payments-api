from fastapi import APIRouter, Request, HTTPException
import stripe
from ..config import settings

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

@router.post("/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()  # RAW body necessario per la verifica firma :contentReference[oaicite:39]{index=39}
    sig_header = request.headers.get("stripe-signature")
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload, sig_header=sig_header, secret=settings.STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

    # Gestione eventi principali (esempi)
    if event["type"] == "payment_intent.succeeded":
        pi = event["data"]["object"]
        # TODO: aggiorna ordini, invia email, ecc.
    elif event["type"] == "checkout.session.completed":
        sess = event["data"]["object"]
        # TODO: fulfilment
    # Nota: gli oggetti nei webhook non sono auto-expanded; recupera con retrieve se serve :contentReference[oaicite:40]{index=40}

    return {"received": True}
