"""Checkout e unlock del report Tema AI V2 gia' persistito."""

import logging
import os
from typing import Any

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from astrobot_auth.credits_logic import (
    apply_premium_consumption,
    decide_premium_mode,
    load_user_credits_state,
    save_user_credits_state,
)
from astrobot_auth.report_history import (
    get_report_history_by_id,
    update_report_history_tier,
)
from astrobot_auth.tema_ai_v2_chart_storage import create_tema_ai_v2_chart_signed_url
from auth.billing.emails import (
    _send_tema_ai_v2_credits_unlock_confirmation_email,
    _send_tema_ai_v2_premium_report_email,
)
from auth.billing.routes_billing import create_tema_ai_v2_guest_checkout


router = APIRouter(prefix="/billing", tags=["billing"])
logger = logging.getLogger(__name__)

TEMA_AI_V2_FEATURE = "tema_ai_v2"
TEMA_AI_V2_PREMIUM_COST = 4
ISSUER = os.getenv("AUTH_ISSUER", "astrobot-auth-pub")
AUDIENCE = os.getenv("AUTH_AUDIENCE", "chatbot-test")


class TemaAiV2ReportRequest(BaseModel):
    report_id: str
    attribution: Any = None


class TemaAiV2UserContext(BaseModel):
    sub: str
    role: str = "free"


def _load_v2_public_key() -> bytes:
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


def get_current_tema_ai_v2_user(
    authorization: str | None = Header(default=None),
) -> TemaAiV2UserContext:
    """Verifica crittograficamente il JWT solo per le route Tema AI V2."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Empty bearer token")

    try:
        payload = jwt.decode(
            token,
            key=_load_v2_public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["sub", "iss", "aud", "iat", "exp"], "verify_exp": True},
            leeway=30,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        logger.warning("[TEMA_AI_V2] JWT verification failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token without sub")
    return TemaAiV2UserContext(sub=sub, role=payload.get("role", "free") or "free")


def _is_guest(user: TemaAiV2UserContext) -> bool:
    return user.sub.startswith("anon-")


def _get_owned_report(report_id: str, user: TemaAiV2UserContext) -> dict[str, Any]:
    report = get_report_history_by_id(report_id)
    if not isinstance(report, dict):
        raise HTTPException(status_code=404, detail="Report non trovato.")
    if report.get("feature") != TEMA_AI_V2_FEATURE:
        raise HTTPException(status_code=404, detail="Report non trovato.")

    if _is_guest(user):
        request_json = report.get("request_json") or {}
        if (
            report.get("user_id") is not None
            or not isinstance(request_json, dict)
            or request_json.get("owner_sub") != user.sub
        ):
            raise HTTPException(status_code=403, detail="Report non autorizzato.")
    elif report.get("user_id") != user.sub:
        raise HTTPException(status_code=403, detail="Report non autorizzato.")
    return report


def _full_report_or_error(report: dict[str, Any]) -> dict[str, Any]:
    report_json = report.get("report_json") or {}
    full_report = report_json.get("full_report") if isinstance(report_json, dict) else None
    if not isinstance(full_report, dict):
        raise HTTPException(status_code=500, detail="Report V2 salvato non valido.")
    return full_report


def _tema_vis_for_response(report: dict[str, Any]) -> dict[str, Any] | None:
    """Espone il grafico solo se ancora disponibile, senza bloccare l'unlock."""
    report_json = report.get("report_json") or {}
    tema_vis = report_json.get("tema_vis") if isinstance(report_json, dict) else None
    if not isinstance(tema_vis, dict):
        return None

    response = {key: value for key, value in tema_vis.items() if key != "chart_storage"}
    chart_storage = tema_vis.get("chart_storage")
    if isinstance(chart_storage, dict):
        try:
            response["chart_url"] = create_tema_ai_v2_chart_signed_url(chart_storage)
        except Exception:
            logger.warning("[TEMA_AI_V2] grafico Storage non disponibile", exc_info=True)
    return response


def _send_tema_ai_v2_logged_unlock_notifications(report: dict[str, Any], full_report: dict[str, Any]) -> None:
    """Best-effort: uno sblocco con crediti non viene presentato come un pagamento Stripe."""
    email = str(report.get("email") or "").strip().lower()
    if not email or "@" not in email or "." not in email:
        logger.warning("[TEMA_AI_V2] email unlock logged non disponibile report_id=%r", report.get("id"))
        return
    lang = "en" if str(report.get("lang") or "it").strip().lower() == "en" else "it"
    try:
        _send_tema_ai_v2_credits_unlock_confirmation_email(email, lang)
    except Exception:
        logger.exception("[TEMA_AI_V2] email conferma crediti fallita report_id=%r", report.get("id"))
    try:
        _send_tema_ai_v2_premium_report_email(email, lang, full_report)
    except Exception:
        logger.exception("[TEMA_AI_V2] email Premium fallita report_id=%r", report.get("id"))


@router.post("/guest-orders/tema-ai-v2/checkout")
def create_tema_ai_v2_checkout(
    body: TemaAiV2ReportRequest,
    user: TemaAiV2UserContext = Depends(get_current_tema_ai_v2_user),
):
    if not _is_guest(user):
        raise HTTPException(status_code=403, detail="Checkout guest riservato agli utenti anonimi.")

    report = _get_owned_report(body.report_id, user)
    if report.get("tier") != "free":
        raise HTTPException(status_code=409, detail="Report non disponibile per checkout guest.")

    return create_tema_ai_v2_guest_checkout(
        report=report,
        owner_sub=user.sub,
        attribution=body.attribution,
    )


@router.post("/tema-ai-v2/unlock")
def unlock_tema_ai_v2(
    body: TemaAiV2ReportRequest,
    user: TemaAiV2UserContext = Depends(get_current_tema_ai_v2_user),
):
    report = _get_owned_report(body.report_id, user)
    full_report = _full_report_or_error(report)
    tema_vis = _tema_vis_for_response(report)
    tier = report.get("tier")

    if tier == "premium":
        return {
            "report_id": report["id"],
            "full_report": full_report,
            "tema_vis": tema_vis,
        }
    if tier != "free":
        raise HTTPException(status_code=409, detail="Tier report non valido.")
    if _is_guest(user):
        raise HTTPException(status_code=402, detail="PAYMENT_REQUIRED")

    state = load_user_credits_state(user)
    decision = decide_premium_mode(state, feature_cost=TEMA_AI_V2_PREMIUM_COST)
    apply_premium_consumption(state, decision, feature_cost=TEMA_AI_V2_PREMIUM_COST)
    save_user_credits_state(state)
    update_report_history_tier(body.report_id, "premium")
    _send_tema_ai_v2_logged_unlock_notifications(report, full_report)
    return {
        "report_id": report["id"],
        "full_report": full_report,
        "tema_vis": tema_vis,
    }
