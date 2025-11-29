from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import jwt, os, hashlib
from typing import Dict
from uuid import uuid4  # 👈 AGGIUNTO per anonymous

# ===============================
# 🚀 APP CONFIG
# ===============================
app = FastAPI(title="AstroBot Auth Pub", version="1.1")

# 🔓 CORS: permette a tutti i frontend di chiamare il servizio
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===============================
# 🔑 FUNZIONE DI CARICAMENTO CHIAVE PRIVATA
# ===============================
def load_private_key():
    path = os.getenv("AUTH_PRIVATE_KEY_ENC_PATH", "secrets/jwtRS256.key.enc")
    key_env = os.getenv("AUTH_ENC_KEY")
    if not key_env:
        raise RuntimeError("❌ Mancante AUTH_ENC_KEY nelle variabili d'ambiente.")
    fernet = Fernet(key_env.encode())
    enc_data = open(path, "rb").read()
    return fernet.decrypt(enc_data)

# Carica la chiave privata in memoria
PRIVATE_KEY = load_private_key()

ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")

# Salt per hashing password (per ambiente dev/prod puoi metterlo in env)
AUTH_PASSWORD_SALT = os.getenv("AUTH_PASSWORD_SALT", "change-me-dev-salt")

def hash_password(raw: str) -> str:
  data = (AUTH_PASSWORD_SALT + raw).encode("utf-8")
  return hashlib.sha256(data).hexdigest()

# ===============================
# 👤 UTENTI DEMO (preconfigurati)
# ===============================
DEMO_USERS = {
    # utente storico, resta compatibile
    "demo": {
        "password": "demo",
        "role": "free",
    },
    # utente free esplicito
    "demo_free": {
        "password": "demo",
        "role": "free",
    },
    # utente premium con crediti pagati (per test)
    "demo_premium": {
        "password": "demo",
        "role": "premium",
    },
}

# ===============================
# 👤 UTENTI REGISTRATI (IN-MEMORY)
# ===============================
# In produzione qui metterai un DB; per ora è in-memory.
REGISTERED_USERS: Dict[str, Dict[str, str]] = {}


def create_access_token_response(sub: str, role: str) -> dict:
    """
    Crea il payload JWT e restituisce la response standard token_type/expires_in.
    """
    payload = {
        "sub": sub,
        "role": role,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "k1"})
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


def authenticate_user(username: str, password: str) -> str:
    """
    Ritorna il ruolo ("free" / "premium") se username/password sono validi.
    Controlla prima gli utenti DEMO, poi quelli REGISTRATI.
    """
    # 1) demo users (password in chiaro: solo per test)
    demo_cfg = DEMO_USERS.get(username)
    if demo_cfg and demo_cfg["password"] == password:
        return demo_cfg["role"]

    # 2) utenti registrati (password hashata)
    reg_cfg = REGISTERED_USERS.get(username)
    if reg_cfg:
        expected_hash = reg_cfg["password_hash"]
        if expected_hash == hash_password(password):
            return reg_cfg["role"]

    # nessun match
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ===============================
# 🏠 ROUTE BASE
# ===============================
@app.get("/")
def root():
    return {"status": "ok", "message": "AstroBot Auth Pub online 🚀"}


# ===============================
# 🆕 ROUTE ANONYMOUS (GUEST)
# ===============================
@app.get("/auth/anonymous")
async def anonymous():
    """
    Genera un JWT per guest anonimo con:
    - sub = "anon-<uuid>"
    - role = "free"

    Viene usato dal frontend DYANA quando l'utente non è loggato.
    """
    anon_id = f"anon-{uuid4()}"
    return create_access_token_response(sub=anon_id, role="free")


# ===============================
# 🆕 REGISTRAZIONE UTENTE
# ===============================
@app.post("/register")
async def register(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("free"),
):
    """
    Crea un nuovo utente e restituisce subito un JWT valido.

    - username: stringa unica (es. email), case sensitive per semplicità
    - password: testo in chiaro (viene hashata lato server)
    - role: "free" o "premium" (default "free")
    """
    username = username.strip()
    role = role.strip().lower()

    if not username:
        raise HTTPException(status_code=400, detail="Username obbligatorio.")
    if role not in ("free", "premium"):
        raise HTTPException(status_code=400, detail="Ruolo non valido (usa free o premium).")

    if username in DEMO_USERS or username in REGISTERED_USERS:
        raise HTTPException(status_code=400, detail="Utente già esistente.")

    pwd_hash = hash_password(password)

    REGISTERED_USERS[username] = {
        "password_hash": pwd_hash,
        "role": role,
    }

    # Sub = username, role = role
    token_resp = create_access_token_response(sub=username, role=role)
    # puoi aggiungere info utente, utile per debug frontend
    token_resp["user"] = {"username": username, "role": role}
    return token_resp


# ===============================
# 🔐 LOGIN E GENERAZIONE TOKEN
# ===============================
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """
    Login che supporta:
    - utenti DEMO (demo, demo_free, demo_premium)
    - utenti registrati via /register

    Restituisce sempre un JWT con claim:
    - sub = username
    - role = "free" | "premium"
    """
    # Autenticazione (demo o registrato)
    role = authenticate_user(username, password)

    # Risposta standard con token
    return create_access_token_response(sub=username, role=role)

@app.get("/auth/anonymous")
async def anonymous_login():
    """
    Crea un utente anonimo con sub = "anon-<uuid>" e role="free".

    Questo è quello che DYANA usa per gli ospiti senza login.
    """
    anon_id = f"anon-{uuid4()}"
    return create_access_token_response(sub=anon_id, role="free")


@app.get("/auth/demo/free")
async def demo_free_login():
    """
    Utente demo con role="free".
    Utile per test rapido da frontend.
    """
    return create_access_token_response(sub="demo_free", role="free")


@app.get("/auth/demo/premium")
async def demo_premium_login():
    """
    Utente demo con role="premium".
    Utile per test crediti premium senza Stripe.
    """
    return create_access_token_response(sub="demo_premium", role="premium")


@app.get("/auth/demo/user/{user_id}")
async def demo_user_login(user_id: str):
    """
    Crea un token per un utente 'finto' con sub=user_id e role="free".

    Utile per debug mirato (es. collegare un certo user_id a Supabase).
    """
    return create_access_token_response(sub=user_id, role="free")