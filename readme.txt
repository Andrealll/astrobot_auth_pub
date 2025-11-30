 📘 README UFFICIALE — AUTENTICAZIONE DYANA / ASTROBOT

(Versione definitiva — Novembre 2025)

🔮 Panoramica

L’ecosistema DYANA/AstroBot usa un’architettura di autenticazione ibrida e sicura:

Supabase Auth
→ unico gestore delle identità (signup, email/password, conferma email, reset password)

astrobot_auth_pub
→ servizio pubblico che firma JWT RS256 con chiave privata per tutto AstroBot
→ DYANA lo usa per ottenere token validi per chatbot-test

chatbot-test (backend principale)
→ riceve i JWT
→ valida la firma RS256
→ usa sub = <uuid> per collegarsi a Supabase (entitlements, guests, usage_logs)

DYANA (Next.js)
→ fa signup/login/reset tramite Supabase
→ fa login tramite astrobot_auth_pub
→ salva il token e lo manda a chatbot-test

Questa architettura garantisce:

scalabilità

coerenza dei dati

controllo totale dei crediti

nessuna duplicazione utenti

JWT sicuri e firmati

🧩 1. Flusso utente completo
1. Iscrizione

DYANA → POST {SUPABASE_URL}/auth/v1/signup

Supabase invia email di conferma

L’utente clicca il link → account attivo

2. Login

DYANA raccoglie email/password

Chiamata a:
POST {AUTH_PUB}/login

astrobot_auth_pub:

verifica credenziali con Supabase GoTrue

carica entitlements

determina role: free | premium

firma JWT RS256 con:

sub = <uuid Supabase>
role = <role>
iss, aud, iat, exp


DYANA salva access_token localmente

3. Guest token

Se l’utente non è loggato, DYANA chiama:

GET {AUTH_PUB}/auth/anonymous


e riceve:

sub=anon-<uuid>
role=free

4. Uso delle funzionalità AI

DYANA → chatbot-test

Header:

Authorization: Bearer <jwt>


chatbot-test → credits_logic → Supabase → usage_logs

5. Reset password

/forgot-password invia POST {SUPABASE_URL}/auth/v1/recover

email Supabase → link a /reset-password#access_token=XYZ

DYANA aggiorna la password con:

PUT {SUPABASE_URL}/auth/v1/user
Authorization: Bearer <access_token>

🧩 2. Ruoli

Regola unica e definitiva:

if entitlements.plan == "premium" or entitlements.credits > 0:
    role = "premium"
else:
    role = "free"


Niente altro.

🧩 3. Architettura Servizi
[DYANA]
   │
   ├── Signup → Supabase Auth
   │
   ├── Login → astrobot_auth_pub → Supabase Auth → JWT RS256
   │
   ├── Guest → astrobot_auth_pub → JWT anon
   │
   └── API → chatbot-test → credits_logic → Supabase (entitlements, usage_logs)

🧩 4. Dettagli implementativi
4.1 astrobot_auth_pub
Endpoints implementati:
endpoint	funzione
POST /login	verifica email/password con Supabase → genera JWT
GET /auth/anonymous	token guest anon-uuid
GET /auth/demo/free	token demo con UUID reale Supabase
GET /auth/demo/premium	token demo premium
/	healthcheck
JWT generati:
{
  "sub": "<uuid>",
  "role": "free|premium",
  "iss": "astrobot-auth-pub",
  "aud": "chatbot-test",
  "iat": ...,
  "exp": ...
}

Variabili richieste
AUTH_PRIVATE_KEY_ENC_PATH
AUTH_ENC_KEY

SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY

DEMO_FREE_USER_ID
DEMO_PREMIUM_USER_ID

AUTH_ISSUER
AUTH_AUDIENCE

4.2 DYANA (Next.js 16)
File chiave:
lib/authClient.js

login con /login

signup con Supabase

reset password

guest token

token storage

lib/apiClient.js

wrapper per chiamate a chatbot-test con Authorization automatico

app/login/page.jsx

tab Accedi / Iscriviti

login + signup

app/forgot-password/page.jsx

invio email reset

app/reset-password/page.jsx

aggiornamento password

Variabili env (locale + prod)
NEXT_PUBLIC_AUTH_BASE_URL=https://astrobot-auth-pub.onrender.com
NEXT_PUBLIC_API_BASE_URL=https://chatbot-test-xxxx.onrender.com

NEXT_PUBLIC_SUPABASE_URL=https://xxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...

🧩 5. credits_logic (chatbot-test)

(non modificato)

Prende sub dal JWT:

se sub inizia con anon- → usa tabella guests

altrimenti → entitlements

E registra ogni chiamata in usage_logs.

🧩 6. Demo users

Non più finti.

Ora richiedono .env:

DEMO_FREE_USER_ID=<uuid reale supabase>
DEMO_PREMIUM_USER_ID=<uuid reale supabase>


E usano gli endpoint:

/auth/demo/free
/auth/demo/premium

🧩 7. Checklist Deployment
Render (astrobot_auth_pub)

Impostare:

SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
DEMO_FREE_USER_ID
DEMO_PREMIUM_USER_ID
AUTH_PRIVATE_KEY_ENC_PATH
AUTH_ENC_KEY

Vercel (dyana-web)
NEXT_PUBLIC_AUTH_BASE_URL=https://<render-app>.onrender.com
NEXT_PUBLIC_API_BASE_URL=https://<render-backend>.onrender.com
NEXT_PUBLIC_SUPABASE_URL=https://xxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...

🧩 8. Checklist test end-to-end
Locale

Signup → email ricevuta

Conferma account

Login → ricevi JWT RS256

/tema_ai → credits_logic OK

Logout → guest token OK

Forgot password → email OK

Reset password → login OK

Prod (Render + Vercel)

Signup → email Supabase OK

Login → JWT ok

/tema_ai (premium user) → consumo crediti OK

/tema_ai (free user) → free OK

Guest → OK

Reset password → OK

🧩 9. Regole permanenti del progetto

Niente utenti finti
Tutti gli utenti reali vivono in Supabase.

Token firmati solo da astrobot_auth_pub
Mai generati in DYANA.

Mai salvare password lato server DYANA o astrobot_auth_pub
Solo Supabase le gestisce.

Mai patch o fallback in-memory
Tutto deve essere coerente e tracciato.

credits_logic non si tocca
Riceve sempre JWT con sub=<uuid>.

🎯 Conclusione

Hai ora:

la documentazione ufficiale

con architettura completa

flussi chiari

file modificati

variabili richieste

test end-to-end

governata da Supabase come identity provider

Questo README è progettato per essere messo:

in astrobot_auth_pub/README.md

in dyana-web/docs/AUTH.md