from fastapi import APIRouter, Depends, Request, HTTPException
from ..security import require_admin, require_user_or_admin, Principal
from ..stripe_client import forward_to_stripe

admin_proxy = APIRouter(prefix="/admin/proxy", tags=["proxy-admin"])
user_proxy = APIRouter(prefix="/user/proxy", tags=["proxy-user"])

SAFE_USER_METHODS = {"GET"}  # per /user/proxy limitiamo a GET; POST/DELETE via endpoint specifici

async def _do_proxy(req: Request, allow_write: bool, p: Principal):
    method = req.method.upper()
    path = req.path_params["path"]
    if not allow_write and method != "GET":
        raise HTTPException(status_code=403, detail="Writes not allowed on user proxy")
    body = await req.body()
    ct = req.headers.get("content-type")
    # opzionale supporto Connect
    stripe_account = req.headers.get("x-stripe-account")  # verrà passato come Stripe-Account :contentReference[oaicite:37]{index=37}
    stripe_context = req.headers.get("x-stripe-context")  # passato come Stripe-Context :contentReference[oaicite:38]{index=38}
    status, data = await forward_to_stripe(
        method, path,
        query=dict(req.query_params),
        headers={"Idempotency-Key": req.headers.get("idempotency-key")} if req.headers.get("idempotency-key") else None,
        body=body if body else None,
        content_type=ct,
        stripe_account=stripe_account,
        stripe_context=stripe_context,
    )
    return {"status": status, "data": data}

@admin_proxy.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
async def admin_passthrough(path: str, req: Request, p: Principal = Depends(require_admin)):
    return await _do_proxy(req, allow_write=True, p=p)

@user_proxy.get("/{path:path}")
async def user_passthrough(path: str, req: Request, p: Principal = Depends(require_user_or_admin)):
    return await _do_proxy(req, allow_write=False, p=p)
