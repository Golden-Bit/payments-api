from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .routers import user, admin, proxy, webhooks, plans

app = FastAPI(
    title="Stripe Gateway API (FastAPI)",
    version="1.0.0",
    description="""
API FastAPI che espone operazioni lato utente e lato admin su Stripe.
- Autenticazione con X-API-Key (ruoli)
- Endpoint specifici e proxy per coprire l'intera API Stripe (/v1, /files, Connect)
- Webhooks con verifica firma
""",
)

if settings.ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(user.router)
app.include_router(admin.router)
app.include_router(proxy.admin_proxy)
app.include_router(proxy.user_proxy)
app.include_router(webhooks.router)
app.include_router(plans.router)