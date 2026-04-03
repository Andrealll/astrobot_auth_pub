from fastapi import FastAPI, HTTPException, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import jwt
import os
import httpx
from dotenv import load_dotenv

from auth.magiclink.routes_auth_magiclink import (
    router as auth_magiclink_router,
    get_token_creator,
)
from auth.billing.routes_billing import router as billing_router

load_dotenv()

app = FastAPI(title="AstroBot Auth Pub", version="2.0")

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
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def _load_public_key() -> bytes:
    pem = os.getenv("AUTH_PUBLIC_KEY_PEM")
    if pem:
        return pem.encode("utf-8")
    path = os.getenv("AUTH_PUBLIC_KEY_PATH", "secrets/jwtRS256.key.pub")
    return open(path, "rb").read()


PUBLIC_KEY = _load_public_key()


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


@app.get("/")
def root():
    return {"status": "ok", "message": "AstroBot Auth Pub v2 online 🚀"}


@app.get("/auth/anonymous")
async def anonymous_login(
    x_device_id: str | None = Header(default=None),
):
    if not x_device_id:
        raise HTTPException(status_code=400, detail="Missing X-Device-Id")

    x_device_id = x_device_id.strip()

    if len(x_device_id) < 16:
        raise HTTPException(status_code=400, detail="Invalid X-Device-Id")

    if len(x_device_id) > 128:
        raise HTTPException(status_code=400, detail="Invalid X-Device-Id")

    anon_id = f"anon-{x_device_id}"
    return create_access_token_response(sub=anon_id, role="free")


app.dependency_overrides[get_token_creator] = lambda: create_access_token_response
app.include_router(auth_magiclink_router)
print("[AUTH] app.py file =", __file__)


@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("❌ SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY mancanti")

    token_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            token_url,
            headers=headers,
            json={
                "email": email,
                "password": password,
            },
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    auth_data = resp.json()
    user = auth_data.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Supabase login")

    user_id = user["id"]

    ent_url = f"{SUPABASE_URL}/rest/v1/entitlements?select=plan,credits&user_id=eq.{user_id}"

    async with httpx.AsyncClient() as client:
        r2 = await client.get(
            ent_url,
            headers={
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            },
        )

    ent_rows = r2.json() if r2.text else []
    plan = None

    if ent_rows:
        row = ent_rows[0]
        plan = row.get("plan")

    role = "premium" if plan == "premium" else "free"
    return create_access_token_response(sub=user_id, role=role)


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

from auth.billing.payment_packs import PAYMENT_PACKS

@app.get("/payments/packs")
async def list_payment_packs():
    return {"packs": list(PAYMENT_PACKS.values())}
    
from routes_credits_dashboard import router as dashboard_router
app.include_router(dashboard_router)

from routes_user import router as user_router
app.include_router(user_router)

app.include_router(billing_router)


@app.get("/hello", tags=["Health"])
def hello():
    return {"hello": "world"}