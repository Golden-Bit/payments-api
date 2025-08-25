import httpx
import stripe
from typing import Optional, Dict, Any, Tuple
from .config import settings

# Configurazione SDK ufficiale stripe-python
stripe.api_key = settings.STRIPE_SECRET_KEY
if settings.STRIPE_API_VERSION:
    stripe.api_version = settings.STRIPE_API_VERSION  # header Stripe-Version raccomandato :contentReference[oaicite:18]{index=18}
stripe.max_network_retries = 2  # retry su errori di rete (non 429 reali) :contentReference[oaicite:19]{index=19}

STRIPE_API_BASE = "https://api.stripe.com"
STRIPE_FILES_BASE = "https://files.stripe.com"

def _auth_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "Authorization": f"Bearer {settings.STRIPE_SECRET_KEY}",
    }
    if settings.STRIPE_API_VERSION:
        h["Stripe-Version"] = settings.STRIPE_API_VERSION
    if extra:
        h.update(extra)
    return h

async def forward_to_stripe(
    method: str,
    path: str,
    *,
    query: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    content_type: Optional[str] = None,
    stripe_account: Optional[str] = None,
    stripe_context: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """
    Proxy generico verso Stripe.
    - Per /v1/files usa base files.stripe.com e multipart/form-data.
    - Preserva Idempotency-Key se presente.
    - Imposta Authorization Bearer con la nostra Secret Key. Autenticazione Stripe :contentReference[oaicite:20]{index=20}
    """
    base = STRIPE_FILES_BASE if path.lstrip("/").startswith("v1/files") else STRIPE_API_BASE
    url = f"{base}/{path.lstrip('/')}"
    extra = {}
    if stripe_account:
        extra["Stripe-Account"] = stripe_account  # Connect server-side :contentReference[oaicite:21]{index=21}
    if stripe_context:
        extra["Stripe-Context"] = stripe_context  # header moderno che supera Stripe-Account :contentReference[oaicite:22]{index=22}

    # Idempotency-Key passthrough se fornita dal client
    if headers and "Idempotency-Key" in headers:
        extra["Idempotency-Key"] = headers["Idempotency-Key"]  # :contentReference[oaicite:23]{index=23}

    async with httpx.AsyncClient(timeout=40.0) as client:
        req_headers = _auth_headers(extra)
        if content_type:
            req_headers["Content-Type"] = content_type

        resp = await client.request(
            method=method.upper(),
            url=url,
            params=query,
            content=body,
            headers=req_headers,
        )
        # Stripe restituisce JSON per /v1 (anche sugli errori) :contentReference[oaicite:24]{index=24}
        return resp.status_code, resp.json()
