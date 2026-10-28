from datetime import datetime, timezone
import hashlib
import hmac
import logging
import os

import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
ATTRIBUTION_OWNER_HMAC_KEY = os.getenv("ATTRIBUTION_OWNER_HMAC_KEY")

ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")


class UserContext(BaseModel):
    sub: str
    role: str


class CheckoutAttributionRevokeRequest(BaseModel):
    attribution_context_id: str


def _owner_subject_hash(subject: str) -> str:
    if not ATTRIBUTION_OWNER_HMAC_KEY:
        raise HTTPException(
            status_code=503,
            detail="Attribution revocation temporarily unavailable",
        )

    return hmac.new(
        ATTRIBUTION_OWNER_HMAC_KEY.encode("utf-8"),
        subject.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _load_public_key() -> bytes:
    """Carica la chiave pubblica RS256 condivisa dal servizio auth pubblico."""
    pem = os.getenv("AUTH_PUBLIC_KEY_PEM")
    if pem:
        normalized = pem.replace("\\n", "\n").strip()
        if "BEGIN PUBLIC KEY" not in normalized:
            normalized = (
                "-----BEGIN PUBLIC KEY-----\n"
                + normalized
                + "\n-----END PUBLIC KEY-----"
            )
        return normalized.encode("utf-8")

    path = os.getenv("AUTH_PUBLIC_KEY_PATH", "secrets/jwtRS256.key.pub")
    return open(path, "rb").read()


def get_current_user(authorization: str = Header(None)) -> UserContext:
    """
    Verifica il JWT emesso da astrobot_auth_pub.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")

    try:
        payload = jwt.decode(
            token,
            key=_load_public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["sub", "iss", "aud", "iat", "exp"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
            },
            leeway=30,
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

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
    if "marketing_consent" not in settings:
        raise HTTPException(status_code=400, detail="Missing marketing_consent")

    _require_supabase()

    consent = bool(settings["marketing_consent"])
    now_iso = datetime.now(timezone.utc).isoformat()

    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user.sub}"
    body = {
        "user_metadata": {
            "marketing_consent": consent,
            "marketing_consent_updated_at": now_iso,
        }
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.put(url, headers=_admin_headers(), json=body)

        if resp.status_code not in (200, 201, 204):
            raise HTTPException(
                status_code=500,
                detail=f"Supabase error {resp.status_code}: {resp.text}",
            )

        resp_profile = await client.post(
            f"{SUPABASE_URL}/rest/v1/user_marketing_profile?on_conflict=user_id",
            headers={
                **_admin_headers(),
                "Prefer": "resolution=merge-duplicates,return=minimal",
            },
            json={
                "user_id": user.sub,
                "marketing_consent": consent,
                "marketing_consent_updated_at": now_iso,
                "updated_at": now_iso,
            },
        )

        if resp_profile.status_code not in (200, 201, 204):
            raise HTTPException(
                status_code=500,
                detail=f"Marketing profile error {resp_profile.status_code}: {resp_profile.text}",
            )

    return {"status": "ok"}


# -------------------------------
# POST /privacy/checkout-attribution/revoke
# -------------------------------
@router.post("/privacy/checkout-attribution/revoke")
async def revoke_checkout_attribution(
    body: CheckoutAttributionRevokeRequest,
    user: UserContext = Depends(get_current_user),
):
    context_id = (body.attribution_context_id or "").strip()
    if not context_id or len(context_id) > 128:
        raise HTTPException(status_code=400, detail="Invalid request")

    _require_supabase()
    owner_hash = _owner_subject_hash(user.sub)
    now_iso = datetime.now(timezone.utc).isoformat()

    update_payload = {
        "gclid": None,
        "gbraid": None,
        "wbraid": None,
        "utm_source": None,
        "utm_medium": None,
        "utm_campaign": None,
        "utm_content": None,
        "utm_term": None,
        "ga4_client_id": None,
        "ga4_session_id": None,
        "revoked_at": now_iso,
        "revocation_source": "client_consent_revocation",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.patch(
                f"{SUPABASE_URL}/rest/v1/checkout_attribution",
                headers={
                    **_admin_headers(),
                    "Prefer": "return=minimal",
                },
                params={
                    "attribution_context_id": f"eq.{context_id}",
                    "owner_subject_hash": f"eq.{owner_hash}",
                    "revoked_at": "is.null",
                },
                json=update_payload,
            )
    except httpx.HTTPError:
        logger.error("[PRIVACY] checkout attribution revocation unavailable")
        raise HTTPException(
            status_code=503,
            detail="Attribution revocation temporarily unavailable",
        )

    if response.status_code not in (200, 204):
        logger.error(
            "[PRIVACY] checkout attribution revocation persistence failed status=%s",
            response.status_code,
        )
        raise HTTPException(
            status_code=503,
            detail="Attribution revocation temporarily unavailable",
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
