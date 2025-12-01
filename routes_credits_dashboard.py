# routes_credits_dashboard.py

from datetime import datetime
from typing import List, Optional

import os
import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

# ===============================
# 🔑 CONFIG / ENV
# ===============================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("❌ SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY mancanti nelle env")

# Stesse env che usi in app.py
ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")


def load_private_key_for_dashboard():
    """
    Copia minimale della logica in app.py per poter verificare il JWT
    senza importare app (evitiamo import circolari).
    """
    path = os.getenv("AUTH_PRIVATE_KEY_ENC_PATH", "secrets/jwtRS256.key.enc")
    key_env = os.getenv("AUTH_ENC_KEY")
    if not key_env:
        raise RuntimeError("❌ Mancante AUTH_ENC_KEY nelle variabili d'ambiente.")
    from cryptography.fernet import Fernet

    fernet = Fernet(key_env.encode())
    enc_data = open(path, "rb").read()
    return fernet.decrypt(enc_data)


PRIVATE_KEY = load_private_key_for_dashboard()

router = APIRouter()


# ===============================
# 👤 CONTEXT UTENTE DAL JWT
# ===============================
class UserContext(BaseModel):
    user_id: str
    role: str


def get_current_user(authorization: str = Header(None)) -> UserContext:
    """
    Decodifica il JWT emesso da astrobot_auth_pub e ritorna user_id + role.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(
            token,
            PRIVATE_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    sub = payload.get("sub")
    role = payload.get("role", "free")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token (missing sub)")

    return UserContext(user_id=sub, role=role)


# ===============================
# 📊 MODELLI DI RISPOSTA
# ===============================
class CreditsStateResponse(BaseModel):
    user_id: str
    paid: int
    free_left: int
    total_available: int


class UsageItem(BaseModel):
    id: int
    when: datetime
    feature: str
    scope: Optional[str] = None
    tier: Optional[str] = None
    credits_used: int


class PurchaseItem(BaseModel):
    id: int
    when: datetime
    product: str
    amount: Optional[int] = None
    currency: Optional[str] = "EUR"
    credits_added: int


class UsageHistoryResponse(BaseModel):
    usage: List[UsageItem]
    purchases: List[PurchaseItem]


# ===============================
# 🔌 HELPER SUPABASE
# ===============================
async def supabase_get(path: str, params: Optional[dict] = None) -> list:
    """
    Helper per chiamare Supabase REST.
    Restituisce la lista JSON (o [] se vuota).
    """
    url = f"{SUPABASE_URL}{path}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, params=params)
    if resp.status_code not in (200, 206):
        raise HTTPException(
            status_code=500,
            detail=f"Errore Supabase GET {path}: {resp.status_code} {resp.text}",
        )
    if not resp.text:
        return []
    try:
        return resp.json()
    except Exception:
        return []


# ===============================
# 🧮 /credits/state
# ===============================
@router.get("/credits/state", response_model=CreditsStateResponse)
async def get_credits_state(user: UserContext = Depends(get_current_user)):
    """
    Restituisce lo stato crediti dell'utente loggato.
    Usa la tabella entitlements su Supabase.
    """
    # entitlements: user_id, credits, plan, ...
    ent_rows = await supabase_get(
        "/rest/v1/entitlements",
        params={"user_id": f"eq.{user.user_id}", "select": "credits"},
    )

    paid = 0
    if ent_rows:
        row = ent_rows[0]
        paid = row.get("credits", 0) or 0

    # free_left: se vuoi puoi leggere una tabella guests/free_tries;
    # per ora lo teniamo a 0 e lo potrai estendere riusando la tua logica credits_logic.
    free_left = 0

    total_available = paid + free_left

    return CreditsStateResponse(
        user_id=user.user_id,
        paid=paid,
        free_left=free_left,
        total_available=total_available,
    )


# ===============================
# 📜 /usage/history
# ===============================
@router.get("/usage/history", response_model=UsageHistoryResponse)
async def get_usage_history(user: UserContext = Depends(get_current_user)):
    """
    Restituisce ultimi usage_logs + purchases per la dashboard.
    """
    # usage_logs: prendo gli ultimi 20 record per l'utente
    usage_rows = await supabase_get(
        "/rest/v1/usage_logs",
        params={
            "user_id": f"eq.{user.user_id}",
            "order": "created_at.desc",
            "limit": 20,
        },
    )

    # purchases: ultimi 20 acquisti
    purchase_rows = await supabase_get(
        "/rest/v1/purchases",
        params={
            "user_id": f"eq.{user.user_id}",
            "order": "created_at.desc",
            "limit": 20,
        },
    )

    usage_items: List[UsageItem] = []
    for row in usage_rows:
        try:
            when = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
        except Exception:
            when = datetime.utcnow()

        usage_items.append(
            UsageItem(
                id=row.get("id", 0),
                when=when,
                feature=row.get("feature", "unknown"),
                scope=row.get("scope"),
                tier=row.get("tier"),
                credits_used=row.get("credits_used", 0) or 0,
            )
        )

    purchase_items: List[PurchaseItem] = []
    for row in purchase_rows:
        try:
            when = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
        except Exception:
            when = datetime.utcnow()

        purchase_items.append(
            PurchaseItem(
                id=row.get("id", 0),
                when=when,
                product=row.get("product", "unknown"),
                amount=row.get("amount"),
                currency=row.get("currency", "EUR"),
                credits_added=row.get("credits_added", 0) or 0,
            )
        )

    return UsageHistoryResponse(usage=usage_items, purchases=purchase_items)
