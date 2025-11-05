from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import jwt, os

# ===============================
# 🚀 APP CONFIG
# ===============================
app = FastAPI(title="AstroBot Auth Pub", version="1.0")

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

# ===============================
# 🏠 ROUTE BASE
# ===============================
@app.get("/")
def root():
    return {"status": "ok", "message": "AstroBot Auth Pub online 🚀"}

# ===============================
# 🔐 LOGIN E GENERAZIONE TOKEN
# ===============================
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    # Demo login (da sostituire con DB in futuro)
    if username != "demo" or password != "demo":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Costruisci il payload JWT
    payload = {
        "sub": username,
        "role": "free",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    # Firma il token
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "k1"})
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    }
