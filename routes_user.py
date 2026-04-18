from datetime import datetime, timezone
import os

import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

router = APIRouter()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")


class UserContext(BaseModel):
    sub: str
    role: str


def get_current_user(authorization: str = Header(None)) -> UserContext:
    """
    Legge il JWT emesso da astrobot_auth_pub.
    Qui NON verifichiamo la firma: leggiamo il payload e validiamo manualmente
    i claim che ci interessano, come già fatto nella dashboard crediti.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    try:
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=["RS256"],
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if payload.get("iss") != ISSUER:
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    if payload.get("aud") != AUDIENCE:
        raise HTTPException(status_code=401, detail="Invalid token audience")

    sub = payload.get("sub")
    role = payload.get("role", "free")

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token (missing sub)")

    return UserContext(sub=sub, role=role)


def _require_supabase():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase non configurato")


def _admin_headers() -> dict:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


# -------------------------------
# PATCH /user/privacy
# -------------------------------
@router.patch("/user/privacy")
async def update_privacy(
    settings: dict,
    user: UserContext = Depends(get_current_user),
):
    """
    Aggiorna user_metadata.marketing_consent in auth.users.

    Payload:
    {
      "marketing_consent": true/false
    }
    """
    if "marketing_consent" not in settings:
        raise HTTPException(status_code=400, detail="Missing marketing_consent")

    _require_supabase()

    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user.sub}"
    body = {
        "user_metadata": {
            "marketing_consent": bool(settings["marketing_consent"]),
            "marketing_consent_updated_at": datetime.now(timezone.utc).isoformat(),
        }
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.put(url, headers=_admin_headers(), json=body)

    if resp.status_code not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error {resp.status_code}: {resp.text}",
        )

    return {"status": "ok"}


# -------------------------------
# DELETE /user/delete
# -------------------------------
@router.delete("/user/delete")
async def delete_user(user: UserContext = Depends(get_current_user)):
    """
    Pseudo-delete:
    anonimizza la mail dell'utente e marca deleted=true in user_metadata.
    NON tocca entitlements, purchases, usage_logs, ecc.
    """
    _require_supabase()

    anon_email = f"deleted_{user.sub}@dyana.app"
    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user.sub}"

    body = {
        "email": anon_email,
        "user_metadata": {
            "deleted": True,
            "deleted_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.put(url, headers=_admin_headers(), json=body)

    if resp.status_code not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error {resp.status_code}: {resp.text}",
        )

    return {"status": "ok"}


# -------------------------------
# POST /cookie/accept
# -------------------------------
@router.post("/cookie/accept")
async def accept_cookies(user: UserContext = Depends(get_current_user)):
    """
    Marca la cookie policy come accettata.

    - Se è un guest (sub = "anon-...") → aggiorna la riga in public.guests
      mettendo cookies_accepted = true, cookies_accepted_at = now().
    - Se è un utente registrato → per ora NON facciamo nulla.
    """
    if not user.sub.startswith("anon-"):
        return {"status": "ok", "is_guest": False}

    _require_supabase()

    guest_id = user.sub[5:]
    now_iso = datetime.now(timezone.utc).isoformat()

    url = f"{SUPABASE_URL}/rest/v1/guests"
    params = {
        "guest_id": f"eq.{guest_id}",
    }
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates",
    }
    body = {
        "cookies_accepted": True,
        "cookies_accepted_at": now_iso,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.patch(url, headers=headers, params=params, json=body)

    if resp.status_code not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error (cookie/accept): {resp.status_code} {resp.text}",
        )

    return {"status": "ok", "is_guest": True}