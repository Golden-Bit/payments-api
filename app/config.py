from typing import Dict, List
from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    """
    Configurazione applicativa letta da variabili d'ambiente (.env).
    """
    # Chiavi API interne (formato: "key:role" separate da virgole)
    # Esempio: "adminkey123:admin,userkey456:user"
    API_KEYS: str = ""

    # Stripe
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_API_VERSION: str = ""   # es. "2025-07-30.basil"
    ALLOW_TEST_MODE: bool = True

    # CORS
    ALLOWED_ORIGINS: List[str] = []

    # ▶️ Novità: base URL del servizio Auth (es. stesso host dell’API o microservizio separato)
    # Esempi validi: "http://localhost:8000", "https://auth.miosito.com"
    AUTH_API_BASE: str = ""

    # ---------- Validators ----------

    @field_validator("API_KEYS")
    @classmethod
    def _validate_api_keys(cls, v: str) -> str:
        # Lascia stringa vuota se non impostata; la parse avverrà in parsed_api_keys()
        return v or ""

    @field_validator("AUTH_API_BASE")
    @classmethod
    def _normalize_auth_api_base(cls, v: str) -> str:
        # Normalizza rimuovendo trailing slash. Consente stringa vuota.
        v = (v or "").strip()
        if v.endswith("/"):
            v = v.rstrip("/")
        return v

    # ---------- Helpers ----------

    def parsed_api_keys(self) -> Dict[str, str]:
        """
        Restituisce un dizionario {api_key: role}.
        Ignora coppie malformate che non contengono ":".
        Spazi attorno a chiavi/ruoli vengono rimossi.
        """
        out: Dict[str, str] = {}
        if not self.API_KEYS:
            return out
        for pair in self.API_KEYS.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if ":" not in pair:
                # coppia malformata: la saltiamo
                continue
            key, role = pair.split(":", 1)
            key = key.strip()
            role = role.strip()
            if key and role:
                out[key] = role
        return out

    class Config:
        env_file = ".env"


# Istanza globale importabile
settings = Settings()
