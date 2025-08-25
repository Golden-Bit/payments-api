from fastapi import APIRouter, Depends, Body
from typing import Dict, Any
import stripe
from ..security import require_admin, Principal
from ..utils.errors import raise_from_stripe_error

router = APIRouter(prefix="/admin", tags=["admin"])

# Customers CRUD
@router.post("/customers")
def create_customer(_: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    try: return stripe.Customer.create(**payload)
    except Exception as e: raise_from_stripe_error(e)

@router.get("/customers")
def list_customers(_: Principal = Depends(require_admin), limit: int = 10, starting_after: str | None = None):
    # Pagination: limit/starting_after/ending_before & has_more :contentReference[oaicite:31]{index=31}
    try: return stripe.Customer.list(limit=limit, starting_after=starting_after)
    except Exception as e: raise_from_stripe_error(e)

@router.get("/customers/{cus_id}")
def get_customer(cus_id: str, _: Principal = Depends(require_admin)):
    try: return stripe.Customer.retrieve(cus_id)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/customers/{cus_id}")
def update_customer(cus_id: str, _: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    try: return stripe.Customer.modify(cus_id, **payload)
    except Exception as e: raise_from_stripe_error(e)

@router.delete("/customers/{cus_id}")
def delete_customer(cus_id: str, _: Principal = Depends(require_admin)):
    try: return stripe.Customer.delete(cus_id)
    except Exception as e: raise_from_stripe_error(e)

# Products & Prices (catalogo)
@router.post("/products")
def create_product(_: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    try: return stripe.Product.create(**payload)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/prices")
def create_price(_: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    # prices per one-time o recurring; legati ai product :contentReference[oaicite:32]{index=32}
    try: return stripe.Price.create(**payload)
    except Exception as e: raise_from_stripe_error(e)

# Invoices
@router.post("/invoices")
def create_invoice(_: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    # Create -> finalize -> send/void/pay (flusso invoicing) :contentReference[oaicite:33]{index=33}
    try: return stripe.Invoice.create(**payload)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/invoices/{inv_id}/finalize")
def finalize_invoice(inv_id: str, _: Principal = Depends(require_admin)):
    try: return stripe.Invoice.finalize_invoice(inv_id)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/invoices/{inv_id}/send")
def send_invoice(inv_id: str, _: Principal = Depends(require_admin)):
    try: return stripe.Invoice.send_invoice(inv_id)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/invoices/{inv_id}/void")
def void_invoice(inv_id: str, _: Principal = Depends(require_admin)):
    try: return stripe.Invoice.void_invoice(inv_id)
    except Exception as e: raise_from_stripe_error(e)

# Subscriptions: admin management (cancel, update)
@router.post("/subscriptions/{sub_id}/cancel")
def cancel_subscription(sub_id: str, _: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(default={})):
    try: return stripe.Subscription.delete(sub_id, **payload)
    except Exception as e: raise_from_stripe_error(e)

# Disputes: list/update evidence (gestione chargeback) :contentReference[oaicite:34]{index=34}
@router.get("/disputes")
def list_disputes(_: Principal = Depends(require_admin), limit: int = 10):
    try: return stripe.Dispute.list(limit=limit)
    except Exception as e: raise_from_stripe_error(e)

@router.post("/disputes/{dispute_id}")
def update_dispute(dispute_id: str, _: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    try: return stripe.Dispute.modify(dispute_id, **payload)
    except Exception as e: raise_from_stripe_error(e)

# Files: carica evidenze (multipart) :contentReference[oaicite:35]{index=35}
@router.post("/files")
def upload_file(_: Principal = Depends(require_admin)):
    # usare form-data/multipart via SDK: stripe.File.create(purpose=..., file=open(..., 'rb'))
    return {"hint": "Usa SDK lato server con file locale: stripe.File.create(purpose='dispute_evidence', file=open('/path/file.pdf','rb'))"}

# Webhook endpoints (gestione da admin) :contentReference[oaicite:36]{index=36}
@router.post("/webhook-endpoints")
def create_webhook_endpoint(_: Principal = Depends(require_admin), payload: Dict[str, Any] = Body(...)):
    try: return stripe.WebhookEndpoint.create(**payload)
    except Exception as e: raise_from_stripe_error(e)
