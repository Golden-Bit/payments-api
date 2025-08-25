from fastapi import HTTPException
import stripe

def raise_from_stripe_error(e: Exception):
    if isinstance(e, stripe.error.StripeError):
        # Mappa minima, rimanda il messaggio strutturato di Stripe
        status = getattr(e, "http_status", 400) or 400
        payload = getattr(e, "json_body", {}) or {}
        raise HTTPException(status_code=status, detail=payload or {"error": str(e)})
    raise
