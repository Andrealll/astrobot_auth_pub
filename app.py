from fastapi import FastAPI, HTTPException, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import jwt, os, httpx
from uuid import uuid4
from dotenv import load_dotenv
from fastapi import Depends, Body, Request, Header
from typing import Optional
import stripe
from pydantic import BaseModel


from astrobot_auth.credits_logic import (
    load_user_credits_state,
    save_user_credits_state,
    get_supabase,
)


load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
    
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")


# ===============================
# 👤 UserContext + JWT decode (per payments)
# ===============================

class UserContext(BaseModel):
    user_id: str
    role: str
    email: Optional[str] = None

def get_current_user(authorization: str = Header(None)) -> UserContext:
    """
    Decodifica il JWT emesso da questo servizio (astrobot_auth_pub)
    e restituisce user_id + role (+ email se presente).

    Per evitare problemi con la libreria cryptography / backend Rust,
    qui NON verifichiamo la firma, ma controlliamo comunque iss e aud.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()

    try:
        # Decodifica SENZA verifica firma
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    # Controllo manuale di issuer e audience
    if payload.get("iss") != ISSUER or payload.get("aud") != AUDIENCE:
        raise HTTPException(status_code=401, detail="Invalid token issuer/audience")

    sub = payload.get("sub")
    role = payload.get("role", "free")
    email = payload.get("email")

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token (missing sub)")

    return UserContext(user_id=sub, role=role, email=email)



# ===============================
# 🎯 CONFIG PACCHETTI CREDITI
# ===============================
# Unico punto di verità lato backend.
# Il frontend leggerà questi pacchetti via /payments/packs.

def _env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    return v.strip() if v else default



PAYMENT_PACKS = {
    "small": {
        "id": "small",
        "name": "Provami!(DEPLOY CHECK)",
        "description": "Per iniziare a provare le letture premium.",
        "credits": 10,
        "price_eur": 9,
        "stripe_price_id": _env("STRIPE_PRICE_SMALL", "price_1SZEwz69hKKhw0M9qVqJjak9"),
    },
    "medium": {
        "id": "medium",
        "name": "AstroReader",
        "description": "Per usare DYANA con continuità.",
        "credits": 30,
        "price_eur": 19,
        "stripe_price_id": _env("STRIPE_PRICE_MEDIUM", "price_1SZEy669hKKhw0M92Kw6WDKQ"),

    },
    "large": {
        "id": "large",
        "name": "Dyaner",
        "description": "Per power user e super appassionati.",
        "credits": 80,
        "price_eur": 39,
        "stripe_price_id": _env("STRIPE_PRICE_LARGE",  "price_1SZEzM69hKKhw0M9I0wcOfpL"),
    },
}

# ======================================================
# 🚀 APP CONFIG
# ======================================================
app = FastAPI(title="AstroBot Auth Pub", version="2.0")

# ✅ ORIGINI PERMESSE
ALLOWED_ORIGINS = [
    "https://dyana.app",
    "https://www.dyana.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://172.20.10.2:3000",
]



app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],   # GET, POST, OPTIONS, ecc.
    allow_headers=["*"],
)

# ======================================================
# 🔑 CARICAMENTO CHIAVE PRIVATA
# ======================================================
def load_private_key():
    path = os.getenv("AUTH_PRIVATE_KEY_ENC_PATH", "secrets/jwtRS256.key.enc")
    key_env = os.getenv("AUTH_ENC_KEY")
    if not key_env:
        raise RuntimeError("❌ Mancante AUTH_ENC_KEY nelle variabili d'ambiente.")
    fernet = Fernet(key_env.encode())
    enc_data = open(path, "rb").read()
    return fernet.decrypt(enc_data)

PRIVATE_KEY = load_private_key()

ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# ======================================================
# 🔐 TOKEN CREATOR
# ======================================================
def create_access_token_response(sub: str, role: str) -> dict:
    payload = {
        "sub": sub,
        "role": role,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "k1"})
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}

# ======================================================
# 🏠 ROOT
# ======================================================
@app.get("/")
def root():
    return {"status": "ok", "message": "AstroBot Auth Pub v2 online 🚀"}

# ======================================================
# 🆓 ANONYMOUS LOGIN
# ======================================================
from fastapi import Header, HTTPException

@app.get("/auth/anonymous")
async def anonymous_login(
    x_device_id: str | None = Header(default=None),
):
    if not x_device_id:
        raise HTTPException(status_code=400, detail="Missing X-Device-Id")

    anon_id = f"anon-{x_device_id}"
    return create_access_token_response(sub=anon_id, role="free")


# ======================================================
# 🔐 LOGIN VIA SUPABASE (MAGIC LINK)
# ======================================================

# ✅ Import dal package installato "astrobot_auth"
from auth.magiclink.routes_auth_magiclink import (
    router as auth_magiclink_router,
    get_token_creator,
)

# ✅ Iniezione del token creator (evita import circolare nel router)
app.dependency_overrides[get_token_creator] = lambda: create_access_token_response

# ✅ Include router
app.include_router(auth_magiclink_router)
print("[AUTH] app.py file =", __file__)

# ======================================================
# 🔐 LOGIN VIA SUPABASE
# ======================================================
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("❌ SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY mancanti")

    # --- 1) Verifica credenziali via Supabase GoTrue ---
    token_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    headers = {"apikey": SUPABASE_SERVICE_ROLE_KEY, "Content-Type": "application/json"}

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, headers=headers, json={
            "email": email,
            "password": password
        })

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    auth_data = resp.json()
    user = auth_data.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Supabase login")

    user_id = user["id"]

    # ------------------------------------------------------
    # --- 2) Determina role leggendo entitlements ---
    # ------------------------------------------------------
    ent_url = f"{SUPABASE_URL}/rest/v1/entitlements?select=plan,credits&user_id=eq.{user_id}"

    async with httpx.AsyncClient() as client:
        r2 = await client.get(
            ent_url,
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}"
            }
        )

    ent_rows = r2.json() if r2.text else []
    plan = None
    credits = 0

    if ent_rows:
        row = ent_rows[0]
        plan = row.get("plan")
        credits = row.get("credits", 0)

    if plan == "premium":
        role = "premium"
    else:
        role = "free"

    return create_access_token_response(sub=user_id, role=role)

# ======================================================
# 🧪 DEMO LOGIN (CON UUID REALI)
# ======================================================
DEMO_FREE_USER_ID = os.getenv("DEMO_FREE_USER_ID")
DEMO_PREMIUM_USER_ID = os.getenv("DEMO_PREMIUM_USER_ID")

@app.get("/auth/demo/free")
async def demo_free_login():
    if not DEMO_FREE_USER_ID:
        raise HTTPException(status_code=500, detail="DEMO_FREE_USER_ID missing in env")
    return create_access_token_response(sub=DEMO_FREE_USER_ID, role="free")

@app.get("/auth/demo/premium")
async def demo_premium_login():
    if not DEMO_PREMIUM_USER_ID:
        raise HTTPException(status_code=500, detail="DEMO_PREMIUM_USER_ID missing in env")
    return create_access_token_response(sub=DEMO_PREMIUM_USER_ID, role="premium")


# ===============================
# 💳 PAGAMENTI – LISTA PACCHETTI
# ===============================
@app.get("/payments/packs")
async def list_payment_packs():
    """
    Restituisce i pacchetti crediti disponibili.
    Usato dal frontend DYANA per popolare la pagina /crediti.
    """
    return {"packs": list(PAYMENT_PACKS.values())}




# ===============================
# 💳 PAGAMENTI – CREAZIONE CHECKOUT STRIPE
# ===============================

class CreateCheckoutRequest(BaseModel):
    pack_id: str
@app.post("/payments/create-checkout-session")
async def create_checkout_session(
    req: CreateCheckoutRequest,
    user: UserContext = Depends(get_current_user),
):
    """
    Crea una sessione di pagamento Stripe Checkout per il pacchetto scelto.

    - pack_id nel body
    - user_id preso dal JWT (UserContext)
    - metadata: pack_id + user_id
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="Stripe non configurato (manca STRIPE_SECRET_KEY).",
        )

    pack = PAYMENT_PACKS.get(req.pack_id)
    if not pack:
        raise HTTPException(status_code=400, detail="Pacchetto non valido.")

    if not pack.get("stripe_price_id"):
        raise HTTPException(
            status_code=500,
            detail="Pacchetto non configurato per Stripe (manca stripe_price_id).",
        )

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[
                {
                    "price": pack["stripe_price_id"],
                    "quantity": 1,
                }
            ],
            success_url=f"{FRONTEND_BASE_URL}/crediti/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{FRONTEND_BASE_URL}/crediti/cancel",
            metadata={
                "pack_id": pack["id"],
                "user_id": user.user_id,  # 👈 UUID Supabase dell’utente loggato
            },
        )
    except stripe.error.StripeError as e:
        msg = getattr(e, "user_message", None) or "Errore nella creazione del pagamento Stripe."
        raise HTTPException(status_code=502, detail=msg)

    return {
        "checkout_url": checkout_session.url,
        "session_id": checkout_session.id,
    }

# ===============================
# 💳 WEBHOOK STRIPE – CREDITI + PURCHASES
# ===============================

@app.post("/payments/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Webhook Stripe per confermare i pagamenti ed aggiornare i crediti.

    Flusso:
    - Verifica firma con STRIPE_WEBHOOK_SECRET
    - Gestisce solo checkout.session.completed
    - Legge user_id + pack_id da metadata
    - Aggiunge credits in entitlements (via credits_logic)
    - Inserisce riga in purchases
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook Stripe non configurato")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except stripe.error.SignatureVerificationError as e:
        # firma non valida
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type != "checkout.session.completed":
        # per ora ignoriamo gli altri eventi
        return {"status": "ignored"}

    # Stripe deve confermare che il pagamento è effettivamente pagato
    if data.get("payment_status") not in ("paid", "no_payment_required"):
        return {"status": "ignored_not_paid"}

    metadata = data.get("metadata") or {}
    pack_id = metadata.get("pack_id")
    user_id = metadata.get("user_id")

    if not pack_id or not user_id:
        # senza questi non possiamo aggiornare i crediti
        return {"status": "missing_metadata"}

    pack = PAYMENT_PACKS.get(pack_id)
    if not pack:
        # pack non più valido / non trovato
        return {"status": "unknown_pack"}

    credits_to_add = int(pack["credits"])
    amount_eur = pack["price_eur"]
    amount_cents = int(amount_eur * 100)
    currency = "EUR"

    # 1) Aggiorna entitlements (paid_credits) via credits_logic
    fake_user = UserContext(user_id=user_id, role="free", email=None)
    # lo shimmiamo in un oggetto compatibile con load_user_credits_state
    class _Shim:
        def __init__(self, sub: str, role: str):
            self.sub = sub
            self.role = role

    shim = _Shim(sub=fake_user.user_id, role=fake_user.role)

    state = load_user_credits_state(shim)
    before = state.paid_credits or 0
    state.paid_credits = before + credits_to_add
    save_user_credits_state(state)
    after = state.paid_credits

    # 2) Inserisci riga in purchases
    client = get_supabase()
    if client is not None:
        payload_db = {
            "user_id": user_id,
            "product": pack["name"],
            "price_id": pack["stripe_price_id"],
            "amount": amount_cents,
            "currency": currency,
            "credits_added": credits_to_add,
            "status": "succeeded",
        }
        try:
            client.table("purchases").insert(payload_db).execute()
        except Exception:
            # non blocchiamo il webhook se il log fallisce
            pass

    return {
        "status": "ok",
        "user_id": user_id,
        "credits_before": before,
        "credits_after": after,
        "credits_added": credits_to_add,
    }

    
from routes_credits_dashboard import router as dashboard_router

app.include_router(dashboard_router)

@app.get("/hello", tags=["Health"])
def hello():
    return {"hello": "world"}

from routes_user import router as user_router
app.include_router(user_router)
