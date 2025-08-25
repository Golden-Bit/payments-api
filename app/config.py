from typing import Dict, List
from pydantic_settings import BaseSettings
from pydantic import field_validator

class Settings(BaseSettings):
    API_KEYS: str = ""  # "adminkey:admin,userkey:user"
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_API_VERSION: str = ""  # es. "2025-07-30.basil"
    ALLOW_TEST_MODE: bool = True
    ALLOWED_ORIGINS: List[str] = []

    @field_validator("API_KEYS")
    @classmethod
    def _validate_api_keys(cls, v: str) -> str:
        # formato "key:role" separato da virgole
        return v or ""

    def parsed_api_keys(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not self.API_KEYS:
            return out
        for pair in self.API_KEYS.split(","):
            pair = pair.strip()
            if not pair:
                continue
            key, role = pair.split(":")
            out[key.strip()] = role.strip()
        return out

    class Config:
        env_file = ".env"

settings = Settings()  # istanza globale
