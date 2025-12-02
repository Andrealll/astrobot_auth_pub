# routes_user.py

from datetime import datetime
import os
import jwt
import httpx

from fastapi import APIRouter, Depends, Header, HTTPException

router = APIRouter()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")


# -------------------------------
# JWT Decoding (stessa logica dashboard)
# -------------------------------
class UserContext:
    def __init__(self, user_id: str, role: str):
        self.sub = user_id
        self.role = role


def get_current_user(authorization: str = Header(None)) -> UserContext:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()

    try:
        # Decodifica senza verifica firma, ma controlliamo iss/aud
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("iss") != ISSUER or payload.get("aud") != AUDIENCE:
        raise HTTPException(status_code=401, detail="Invalid token issuer/audience")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token (missing sub)")

    return UserContext(sub, payload.get("role", "free"))


# -------------------------------
# PATCH /user/privacy
# -------------------------------
@router.patch("/user/privacy")
async def update_privacy(settings: dict, user: UserContext = Depends(get_current_user)):
    """
    Aggiorna user_metadata.marketing_consent in auth.users.

    Payload:
    {
      "marketing_consent": true/false
    }
    """
    if "marketing_consent" not in settings:
        raise HTTPException(status_code=400, detail="Missing marketing_consent")

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase non configurato")

    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user.sub}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }

    patch_body = {
        "user_metadata": {
            "marketing_consent": settings["marketing_consent"],
            "marketing_consent_updated_at": datetime.utcnow().isoformat(),
        }
    }

    async with httpx.AsyncClient() as client:
        resp = await client.patch(url, headers=headers, json=patch_body)

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Supabase error: {resp.text}")

    return {"status": "ok"}


# -------------------------------
# DELETE /user/delete
# -------------------------------
@router.delete("/user/delete")
async def delete_user(user: UserContext = Depends(get_current_user)):
    """
    Anonimizza la mail dell'utente in auth.users.
    NON tocca entitlements, purchases, usage_logs, ecc.
    """
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase non configurato")

    # Email anonimizzata (mantiene il legame interno via user_id)
    anon_email = f"deleted_{user.sub}@dyana.app"

    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user.sub}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }

    body = {
        "email": anon_email,
        "user_metadata": {
            "deleted": True,
            "deleted_at": datetime.utcnow().isoformat(),
        },
    }

    async with httpx.AsyncClient() as client:
        resp = await client.patch(url, headers=headers, json=body)

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Supabase error: {resp.text}")

    return {"status": "deleted", "email": anon_email}
