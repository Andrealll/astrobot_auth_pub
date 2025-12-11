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

# Limiti free definiti SOLO per la dashboard:
# - guest: 2 prove gratuite
# - utente registrato: 0 free
def get_free_credits_limits(state: CreditsState) -> tuple[int, int]:
    """
    Ritorna (max_free_tries, free_credits_per_try) per il tipo di utente.

    Per ora:
    - guest: 2 tentativi free
    - registered: 0 free
    """
    if getattr(state, "is_guest", False):
        return 2, 1
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
    privacy_accepted: bool
    marketing_consent: bool | None = None
    paid: int
    free_left: int
    total_available: int


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
    Restituisce lo stato crediti dell'utente:

    - Per i guest (anon-...): usa credits_logic (tabella guests / fallback RAM)
    - Per gli utenti registrati: legge i crediti da entitlements
      (ramo non mostrato qui, resta invariato sotto l'if).
    """

    is_guest = user.user_id.startswith("anon-")

    # ==========================================
    # 1) GUEST → usiamo credits_logic
    # ==========================================
    if is_guest:
        # Shim per adattarsi alla firma di load_user_credits_state
        class _AuthUserShim:
            def __init__(self, sub: str, role: str):
                self.sub = sub
                self.role = role

        shim = _AuthUserShim(sub=user.user_id, role=user.role)

        # Stato completo (paid_credits, free_tries_used, cookies_accepted, ecc.)
        state = load_user_credits_state(shim)

        # Limiti free per questo stato (guest → GUEST_FREE_CREDITS_PER_PERIOD, ecc.)
        max_free_credits, _ = get_free_credits_limits(state)

        # Crediti gratuiti già usati nel periodo corrente
        free_used = state.free_tries_used or 0

        # Crediti gratuiti ancora disponibili
        free_left = max(0, max_free_credits - free_used)

        # Crediti pagati (per i guest sarà sempre 0)
        paid = state.paid_credits or 0

        # Totale disponibile = pagati + gratuiti rimanenti
        total_available = paid + free_left

        # Flag privacy / marketing dal CreditsState
        privacy_accepted = bool(getattr(state, "cookies_accepted", False))
        marketing_consent = getattr(state, "marketing_consent", None)
        logger.info(
            "[AUTH] /credits/state GUEST user_id=%s paid=%s free_used=%s max_free=%s free_left=%s total=%s",
            state.user_id,
            paid,
            free_used,
            max_free_credits,
            free_left,
            total_available,
        )
        return CreditsStateResponse(
            user_id=state.user_id,
            email=None,
            role="guest",
            privacy_accepted=privacy_accepted,
            marketing_consent=marketing_consent,
            paid=paid,
            free_left=free_left,
            total_available=total_available,
        )


    # ==========================================
    # 2) UTENTE REGISTRATO → entitlements REST
    # ==========================================
    # Leggi credits da entitlements
    ent_rows = await supabase_get(
        "/rest/v1/entitlements",
        params={
            "user_id": f"eq.{user.user_id}",
            "select": "credits",
        },
    )

    if ent_rows:
        row = ent_rows[0]
        paid = int(row.get("credits") or 0)
    else:
        # Nessuna riga in entitlements → 0 crediti
        paid = 0

    # Per ora, da dashboard non mostriamo free ricorrenti per i registrati
    free_left = 0
    total_available = paid + free_left

    # Email + marketing_consent da auth.users
    email = None
    marketing_consent = None
    try:
        email_from_auth, marketing_from_auth = await fetch_user_email_and_marketing(
            user.user_id
        )
        if email_from_auth:
            email = email_from_auth
        if marketing_from_auth is not None:
            if isinstance(marketing_from_auth, bool):
                marketing_consent = marketing_from_auth
            elif isinstance(marketing_from_auth, str):
                marketing_consent = marketing_from_auth.lower() == "true"
    except Exception as e:
        logger.warning(
            "[DASHBOARD] errore lettura email/marketing per user_id=%s: %r",
            user.user_id,
            e,
        )

    # privacy_accepted: per ora non hai un flag certo lato dashboard → False
    privacy_accepted = False

    return CreditsStateResponse(
        user_id=user.user_id,
        email=email,
        role=user.role,
        privacy_accepted=privacy_accepted,
        marketing_consent=marketing_consent,
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
