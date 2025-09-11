from fastapi import Header, HTTPException, status, Depends
from dataclasses import dataclass
from .config import settings

# app/security.py
from fastapi import Security, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader

# 🔒 Dai un nome UNIVOCO a ciascun security scheme
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="UserJWT",  # sarà la voce "JWT" nel modal Authorize
    description="Porta un Bearer JWT (Authorization: Bearer <token>)",
)

admin_api_key_scheme = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    scheme_name="AdminAPIKey",  # nome visualizzato in Authorize
    description="Chiave admin applicativa (header X-API-Key).",
)

stripe_connect_scheme = APIKeyHeader(
    name="x-stripe-account",
    auto_error=False,
    scheme_name="StripeConnectAccount",  # nome visualizzato in Authorize
    description="Header opzionale per Stripe Connect (x-stripe-account).",
)

idempotency_key_scheme = APIKeyHeader(
    name="Idempotency-Key",
    auto_error=False,
    scheme_name="IdempotencyKey",  # nome visualizzato in Authorize
    description="Header opzionale Idempotency-Key.",
)

# Importa i tuoi helper
from app.routers.utils.plans_utils import _require_bearer_token, _verify_and_get_user, _require_api_key

def require_jwt_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    # Se manca → 401 coerente in Swagger/clients
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    # I tuoi helper si aspettano "Bearer <token>": ricostruiamo l'header
    token_header_value = f"Bearer {credentials.credentials}"
    access_token = _require_bearer_token(token_header_value)
    user = _verify_and_get_user(access_token)

    # Salva su request.state per riuso negli endpoint senza passare parametri
    request.state.access_token = access_token
    request.state.user = user
    return True

def require_admin_api_key(
    request: Request,
    x_api_key: str | None = Security(admin_api_key_scheme),
):
    # Validazione con il tuo helper
    _require_api_key(x_api_key)
    # opzionale: salvalo se ti serve in futuro
    request.state.admin_api_key = x_api_key
    return True

def optional_stripe_connect_account(
    request: Request,
    stripe_account: str | None = Security(stripe_connect_scheme),
):
    # Non obbligatorio, serve solo a renderlo impostabile in Swagger
    # _opts_from_request continuerà a leggere le headers direttamente
    if stripe_account:
        request.state.stripe_account = stripe_account
    return True

def optional_idempotency_key(
    request: Request,
    idem_key: str | None = Security(idempotency_key_scheme),
):
    # Pure opzionale: se presente, la salvi anche in state (utile se vuoi loggarla)
    if idem_key:
        request.state.idempotency_key = idem_key
    return True


@dataclass
class Principal:
    api_key: str
    role: str  # "admin" | "user"

def get_principal(x_api_key: str = Header(None)) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key")
    mapping = settings.parsed_api_keys()
    role = mapping.get(x_api_key)
    if not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return Principal(api_key=x_api_key, role=role)

def require_admin(p: Principal = Depends(get_principal)) -> Principal:
    if p.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return p

def require_user_or_admin(p: Principal = Depends(get_principal)) -> Principal:
    return p
