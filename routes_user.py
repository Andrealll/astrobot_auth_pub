# routes_user.py

from datetime import datetime, timezone
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
        # PRIMA: resp = await client.patch(...)
        resp = await client.put(url, headers=headers, json=patch_body)

    status = resp.status_code
    text = resp.text or "<vuoto>"

    # ✅ accettiamo 200, 201, 204 come success
    if status not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error {status}: {text}",
        )

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

    status = resp.status_code
    text = resp.text or "<vuoto>"

    # ✅ accettiamo 200, 201, 204 come success
    if status not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error {status}: {text}",
        )

    return {"status": "deleted", "email": anon_email}


@router.post("/cookie/accept")
async def accept_cookies(user: UserContext = Depends(get_current_user)):
    """
    Marca la cookie policy come accettata.

    - Se è un guest (sub = "anon-...") → aggiorna la riga in public.guests
      mettendo cookies_accepted = true, cookies_accepted_at = now().
    - Se è un utente registrato → per ora NON facciamo nulla (i free per loro
      sono gestiti dal marketing consent).
    """
    # 1) Se non è guest, per ora non facciamo nulla di speciale
    if not user.sub.startswith("anon-"):
        # In futuro potremo loggare anche per i registrati (user_metadata).
        return {"status": "ok", "is_guest": False}

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase non configurato.")

    guest_id = user.sub[5:]  # rimuove "anon-"
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

    async with httpx.AsyncClient() as client:
        resp = await client.patch(url, headers=headers, params=params, json=body)

    if resp.status_code not in (200, 201, 204):
        raise HTTPException(
            status_code=500,
            detail=f"Supabase error (cookie/accept): {resp.status_code} {resp.text}",
        )

    return {"status": "ok", "is_guest": True}
