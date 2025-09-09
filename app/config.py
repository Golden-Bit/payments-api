# app/config.py
from typing import Dict, List, Set
from urllib.parse import urlparse
from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    """
    Tutta la configurazione dell'app.
    Viene caricata da variabili di ambiente e dal file .env (env_file configurato sotto).
    """
    # API
    API_KEYS: str = ""

    # Stripe
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_API_VERSION: str = ""   # es. "2025-07-30.basil"
    ALLOW_TEST_MODE: bool = True

    # Auth microservice
    AUTH_API_BASE: str = ""

    # CORS e redirect
    ALLOWED_ORIGINS: str = ""           # "*" oppure CSV
    REDIRECT_ALLOWLIST: str = ""        # CSV di URL/origini

    # ---------------- Validators & helpers ----------------

    @field_validator("AUTH_API_BASE")
    @classmethod
    def _normalize_auth_api_base(cls, v: str) -> str:
        v = (v or "").strip()
        return v.rstrip("/") if v.endswith("/") else v

    def parsed_api_keys(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not self.API_KEYS:
            return out
        for pair in self.API_KEYS.split(","):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            k, r = pair.split(":", 1)
            k, r = k.strip(), r.strip()
            if k and r:
                out[k] = r
        return out

    def cors_origins_list(self) -> List[str]:
        """
        Ritorna:
          - ["*"] se ALLOWED_ORIGINS è "*"
          - altrimenti, lista pulita dal CSV
          - [] se vuoto
        """
        raw = (self.ALLOWED_ORIGINS or "").strip()
        if not raw:
            return []
        if raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    def redirect_allowlist_origins(self) -> Set[str]:
        """
        Converte REDIRECT_ALLOWLIST (CSV) in un set di ORIGINI normalizzate "scheme://host[:port]".
        Se in input arrivano URL con path/query, viene estratta solo l’origine.
        """
        out: Set[str] = set()
        raw = (self.REDIRECT_ALLOWLIST or "").strip()
        if not raw:
            return out
        for item in (x.strip() for x in raw.split(",") if x.strip()):
            pu = urlparse(item)
            if pu.scheme and pu.netloc:
                origin = f"{pu.scheme}://{pu.netloc}"
                out.add(origin)
            else:
                # Se arriva "https://tuo-sito.com" senza parsing, lo ri-aggiungo com'è
                out.add(item)
        return out

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Istanza globale importabile
settings = Settings()
