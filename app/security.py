from fastapi import Header, HTTPException, status, Depends
from dataclasses import dataclass
from .config import settings

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
