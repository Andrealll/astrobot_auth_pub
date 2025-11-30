from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import jwt, os, httpx
from uuid import uuid4
from dotenv import load_dotenv
from fastapi import Depends  # se non lo hai già
from fastapi import Body
from pydantic import BaseModel

load_dotenv()
# ===============================
# 🎯 CONFIG PACCHETTI CREDITI
# ===============================
# Unico punto di verità lato backend.
# Il frontend leggerà questi pacchetti via /payments/packs.
PAYMENT_PACKS = {
    "small": {
        "id": "small",
        "name": "Pacchetto Small",
        "description": "Per iniziare a provare le letture premium.",
        "credits": 10,
        "price_eur": 9,
        "stripe_price_id": None,  # TODO: imposta l'ID del prezzo Stripe quando lo crei
    },
    "medium": {
        "id": "medium",
        "name": "Pacchetto Medium",
        "description": "Per usare DYANA con continuità.",
        "credits": 30,
        "price_eur": 19,
        "stripe_price_id": None,  # TODO
    },
    "large": {
        "id": "large",
        "name": "Pacchetto Large",
        "description": "Per power user e super appassionati.",
        "credits": 80,
        "price_eur": 39,
        "stripe_price_id": None,  # TODO
    },
}

# ======================================================
# 🚀 APP CONFIG
# ======================================================
app = FastAPI(title="AstroBot Auth Pub", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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
@app.get("/auth/anonymous")
async def anonymous_login():
    anon_id = f"anon-{uuid4()}"
    return create_access_token_response(sub=anon_id, role="free")

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

    if plan == "premium" or (credits and credits > 0):
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
# 💳 PAGAMENTI – CREAZIONE CHECKOUT (PLACEHOLDER)
# ===============================
class CreateCheckoutRequest(BaseModel):
    pack_id: str


@app.post("/payments/create-checkout-session")
async def create_checkout_session(
    req: CreateCheckoutRequest,
):
    """
    Crea (o simula) una sessione di pagamento per un pacchetto crediti.

    Per ora è un placeholder senza Stripe reale:
    - valida il pack_id
    - restituisce una finta checkout_url
    Quando integrerai Stripe, qui userai la SDK ufficiale.
    """
    pack = PAYMENT_PACKS.get(req.pack_id)
    if not pack:
        raise HTTPException(status_code=400, detail="Pacchetto non valido.")

    # TODO: qui in futuro:
    # - leggere user_id dal JWT (sub)
    # - usare stripe.checkout.Session.create(...)
    # - impostare success_url/cancel_url
    # - restituire data["url"]

    fake_url = f"https://example.com/checkout/fake?pack_id={pack['id']}"

    return {
        "checkout_url": fake_url,
        "pack": {
            "id": pack["id"],
            "credits": pack["credits"],
            "price_eur": pack["price_eur"],
        },
        "mode": "placeholder",
    }