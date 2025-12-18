from datetime import datetime, timezone
from typing import List, Optional
import logging
import os
import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# 👇 IMPORT UNICO DA astrobot_auth (per la logica guest)
from astrobot_auth.credits_logic import (
    CreditsState,
    load_user_credits_state,
    _get_free_limits_for_state,  # se è funzione interna, valuta se esporla o ricopiarne la logica qui
)
from astrobot_auth.settings_credits import (
    USER_FREE_CREDITS_PER_PERIOD,
    USER_FREE_CREDITS_PERIOD_DAYS,
    INITIAL_SIGNUP_CREDITS,
)
# Limiti free definiti SOLO per la dashboard:
# - guest: 2 prove gratuite
# - utente registrato: 0 free
def get_free_credits_limits(state: CreditsState) -> tuple[int, int]:
    if getattr(state, "is_guest", False):
        # usa i valori REALI definiti in settings_credits
        return GUEST_FREE_CREDITS_PER_PERIOD, GUEST_FREE_CREDITS_PERIOD_DAYS
    return 0, 0


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


async def fetch_user_email_and_marketing(user_id: str):
    """
    Legge email e marketing_consent da Supabase auth.admin.
    Ritorna (email, marketing_consent | None).
    """
    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)

    if resp.status_code not in (200, 201):
        # niente eccezione: fallback silenzioso a (None, None)
        return None, None

    data = resp.json()
    email = data.get("email")
    user_metadata = data.get("user_metadata") or {}
    marketing = user_metadata.get("marketing_consent")
    return email, marketing


class UserContext(BaseModel):
    user_id: str
    role: str
    email: Optional[str] = None


def get_current_user(authorization: str = Header(None)) -> UserContext:
    """
    Decodifica il JWT emesso da astrobot_auth_pub e ritorna user_id + role (+ email se presente).
    Qui NON verifichiamo la firma, ma controlliamo iss e aud.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if payload.get("iss") != ISSUER or payload.get("aud") != AUDIENCE:
        raise HTTPException(status_code=401, detail="Invalid token issuer/audience")

    sub = payload.get("sub")
    role = payload.get("role", "free")
    email = payload.get("email")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token (missing sub)")

    return UserContext(user_id=sub, role=role, email=email)


# ===============================
# 📊 MODELLI DI RISPOSTA
# ===============================
class CreditsStateResponse(BaseModel):
    user_id: str
    email: str | None = None
    role: str | None = None

    # privacy/marketing
    privacy_accepted: bool
    marketing_consent: bool | None = None

    # wallets
    paid: int
    free_left: int
    total_available: int
    remaining_credits: int  # per UI: guest=trial(0/1), user=total

    # NEW: funnel/trial info
    is_guest: bool
    trial_available: int  # 1 se guest e trial non usato, altrimenti 0

    # NEW: parametri per frontend (N e X + bonus signup)
    free_grant_amount: int
    free_grant_interval_days: int
    signup_credits: int




class UsageItem(BaseModel):
    id: int
    when: datetime
    feature: str
    scope: Optional[str] = None
    tier: Optional[str] = None
    billing_mode: Optional[str] = None  # "free" / "paid" / ecc.
    cost_paid_credits: int = 0
    cost_free_credits: int = 0


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
# HELPER
# ===============================
async def _fetch_user_email_from_supabase(user_id: str) -> str | None:
    """
    Usa l'API admin di Supabase per leggere l'email dell'utente da auth.users.
    Ritorna None se qualcosa va storto (non rompe /credits/state).
    """
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return None

    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)

    if resp.status_code not in (200, 201):
        logger.warning(
            "[DASHBOARD] impossibile leggere email utente %s: %s %s",
            user_id,
            resp.status_code,
            resp.text,
        )
        return None

    data = resp.json()
    return data.get("email")



# ===============================
# 🧮 /credits/state
# ===============================
@router.get("/credits/state", response_model=CreditsStateResponse)
async def get_credits_state(user: UserContext = Depends(get_current_user)):
    """
    Stato crediti allineato al nuovo modello:

    - Guest: free trial one-shot (trial_available 1/0). Niente free_left periodico.
    - User: paid=credits, free_left=free_credits_balance (dopo lazy grant), total=paid+free_left.
    - Espone N, X e signup_credits al frontend.
    """

    class _AuthUserShim:
        def __init__(self, sub: str, role: str):
            self.sub = sub
            self.role = role

    shim = _AuthUserShim(sub=user.user_id, role=user.role)
    state = load_user_credits_state(shim)

    # Flags privacy/marketing dal CreditsState
    privacy_accepted = bool(getattr(state, "cookies_accepted", False))
    marketing_consent = getattr(state, "marketing_consent", None)

    # Email + marketing_consent da Supabase auth.users SOLO per utenti registrati
    email = None
    if not state.is_guest:
        try:
            email_from_auth, marketing_from_auth = await fetch_user_email_and_marketing(state.user_id)
            if email_from_auth:
                email = email_from_auth
            if marketing_from_auth is not None:
                if isinstance(marketing_from_auth, bool):
                    marketing_consent = marketing_from_auth
                elif isinstance(marketing_from_auth, str):
                    marketing_consent = marketing_from_auth.lower() == "true"
        except Exception as e:
            logger.warning("[DASHBOARD] errore lettura email/marketing user_id=%s: %r", state.user_id, e)

    # Ruolo esposto alla UI
    role_out = "guest" if state.is_guest else user.role

    # --- NEW MODEL ---
    if state.is_guest:
        # Guest: 1 free trial one-shot (non crediti)
        trial_available = 0 if getattr(state, "free_trial_used", False) else 1

        paid = 0
        free_left = trial_available   
        total_available = trial_available
        remaining_credits = trial_available

        # Parametri FE (N/X): per guest esponiamo i DEFAULT user (utile per UI/marketing)
        free_grant_amount = int(USER_FREE_CREDITS_PER_PERIOD or 0)
        free_grant_interval_days = int(USER_FREE_CREDITS_PERIOD_DAYS or 0)
        signup_credits = int(INITIAL_SIGNUP_CREDITS or 0)

    else:
        # User: credits + free periodic wallet
        paid = int(getattr(state, "paid_credits", 0) or 0)
        free_left = int(getattr(state, "free_credits_balance", 0) or 0)

        total_available = paid + free_left
        remaining_credits = total_available
        trial_available = 0

        # Parametri FE: idealmente quelli salvati in entitlements; fallback ai default env
        free_grant_amount = int(getattr(state, "free_grant_amount", USER_FREE_CREDITS_PER_PERIOD) or 0)
        free_grant_interval_days = int(getattr(state, "free_grant_interval_days", USER_FREE_CREDITS_PERIOD_DAYS) or 0)
        signup_credits = int(INITIAL_SIGNUP_CREDITS or 0)

    logger.info(
        "[AUTH] /credits/state user_id=%s is_guest=%s role=%s paid=%s free_left=%s trial_available=%s total=%s",
        state.user_id,
        state.is_guest,
        role_out,
        paid,
        free_left,
        trial_available,
        total_available,
    )

    return CreditsStateResponse(
        user_id=state.user_id,
        email=email,
        role=role_out,
        privacy_accepted=privacy_accepted,
        marketing_consent=marketing_consent,
        paid=paid,
        free_left=free_left,
        total_available=total_available,
        remaining_credits=remaining_credits,
        is_guest=bool(state.is_guest),
        trial_available=int(trial_available),
        free_grant_amount=int(free_grant_amount),
        free_grant_interval_days=int(free_grant_interval_days),
        signup_credits=int(signup_credits),
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
            when = datetime.utcnow().replace(tzinfo=timezone.utc)

        cost_paid = row.get("cost_paid_credits")
        cost_free = row.get("cost_free_credits")

        # compatibilità vecchia colonna cost_credits
        if cost_paid is None and "cost_credits" in row:
            cost_paid = row.get("cost_credits")

        usage_items.append(
            UsageItem(
                id=row.get("id", 0),
                when=when,
                feature=row.get("feature", "unknown"),
                scope=row.get("scope"),
                tier=row.get("tier"),
                billing_mode=row.get("billing_mode"),
                cost_paid_credits=int(cost_paid or 0),
                cost_free_credits=int(cost_free or 0),
            )
        )

    purchase_items: List[PurchaseItem] = []
    for row in purchase_rows:
        try:
            when = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
        except Exception:
            when = datetime.utcnow().replace(tzinfo=timezone.utc)

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
