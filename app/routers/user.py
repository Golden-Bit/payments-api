from fastapi import APIRouter, Depends, Body
from typing import Optional, Dict, Any
import stripe
from ..security import require_user_or_admin, Principal
from ..utils.errors import raise_from_stripe_error

router = APIRouter(prefix="/user", tags=["user"])

@router.post("/payment-intents")
def create_payment_intent(
    p: Principal = Depends(require_user_or_admin),
    payload: Dict[str, Any] = Body(..., example={
        "amount": 1999, "currency": "eur",
        "automatic_payment_methods": {"enabled": True},
        # opzionali: customer, payment_method, capture_method, metadata, setup_future_usage, etc. :contentReference[oaicite:25]{index=25}
    }),
):
    try:
        pi = stripe.PaymentIntent.create(**payload)
        return pi
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/payment-intents/{pi_id}/confirm")
def confirm_payment_intent(pi_id: str, p: Principal = Depends(require_user_or_admin), payload: Dict[str, Any] = Body(default={})):
    # Se necessario 3DS/SCA, lo stato passa a requires_action/next_action :contentReference[oaicite:26]{index=26}
    try:
        pi = stripe.PaymentIntent.confirm(pi_id, **payload)
        return pi
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/payment-intents/{pi_id}/capture")
def capture_payment_intent(pi_id: str, p: Principal = Depends(require_user_or_admin), payload: Dict[str, Any] = Body(default={})):
    # Cattura fondi quando status=requires_capture :contentReference[oaicite:27]{index=27}
    try:
        pi = stripe.PaymentIntent.capture(pi_id, **payload)
        return pi
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/payment-intents/{pi_id}/cancel")
def cancel_payment_intent(pi_id: str, p: Principal = Depends(require_user_or_admin), payload: Dict[str, Any] = Body(default={})):
    # Cancel è consentito in specifici stati :contentReference[oaicite:28]{index=28}
    try:
        pi = stripe.PaymentIntent.cancel(pi_id, **payload)
        return pi
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/checkout/sessions")
def create_checkout_session(
    p: Principal = Depends(require_user_or_admin),
    payload: Dict[str, Any] = Body(..., example={
        "mode": "payment",
        "success_url": "https://example.com/success?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": "https://example.com/cancel",
        "line_items": [{"price": "price_xxx", "quantity": 1}],
        # opz.: customer, locale, automatic_tax, etc.
    })
):
    # Crea Checkout Session (pagamento o subscription) :contentReference[oaicite:29]{index=29}
    try:
        import stripe as _s
        sess = _s.checkout.Session.create(**payload)
        return sess
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/billing-portal/sessions")
def create_billing_portal_session(
    p: Principal = Depends(require_user_or_admin),
    payload: Dict[str, Any] = Body(..., example={"customer": "cus_xxx", "return_url": "https://example.com/account"})
):
    # Portal per autogestione abbonamenti/fatture dal cliente
    try:
        sess = stripe.billing_portal.Session.create(**payload)
        return sess
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/subscriptions")
def create_subscription(p: Principal = Depends(require_user_or_admin),
                        payload: Dict[str, Any] = Body(..., example={"customer":"cus_xxx","items":[{"price":"price_xxx"}]})):
    try:
        sub = stripe.Subscription.create(**payload)
        return sub
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/refunds")
def create_refund(p: Principal = Depends(require_user_or_admin),
                  payload: Dict[str, Any] = Body(..., example={"payment_intent":"pi_xxx","amount":500})):
    # Rimborsi (totale o parziale)
    try:
        r = stripe.Refund.create(**payload)
        return r
    except Exception as e:
        raise_from_stripe_error(e)

@router.post("/payment-links")
def create_payment_link(p: Principal = Depends(require_user_or_admin),
                        payload: Dict[str, Any] = Body(..., example={"line_items":[{"price":"price_xxx","quantity":1}]})):
    # Payment Links via API :contentReference[oaicite:30]{index=30}
    try:
        link = stripe.PaymentLink.create(**payload)
        return link
    except Exception as e:
        raise_from_stripe_error(e)
