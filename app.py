from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
import logging
import os
import stripe

from astrobot_auth.credits_logic import (
    add_paid_credits,
    get_supabase,
)

from auth.billing.payment_packs import PAYMENT_PACKS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if STRIPE_API_KEY:
    stripe.api_key = STRIPE_API_KEY
else:
    logger.warning("[BILLING] STRIPE_API_KEY non impostata; le chiamate Stripe falliranno.")


class CreateCheckoutSessionRequest(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str
    user_id: str
    pack_id: str | None = None


class CreateCheckoutSessionResponse(BaseModel):
    checkout_url: str


@router.post("/create-checkout-session", response_model=CreateCheckoutSessionResponse)
def create_checkout_session(body: CreateCheckoutSessionRequest):
    if not STRIPE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stripe non configurato lato server.",
        )

    metadata = {
        "user_id": body.user_id,
        "price_id": body.price_id,
    }

    if body.pack_id:
        metadata["pack_id"] = body.pack_id

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[
                {
                    "price": body.price_id,
                    "quantity": 1,
                }
            ],
            success_url=body.success_url,
            cancel_url=body.cancel_url,
            metadata=metadata,
        )
    except Exception as e:
        logger.exception("[BILLING] Errore creazione checkout session: %r", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Errore nella creazione della sessione di pagamento.",
        )

    return CreateCheckoutSessionResponse(checkout_url=session.url)


def _resolve_credits_from_price(price_id: str) -> tuple[int, str, int, str]:
    try:
        price = stripe.Price.retrieve(price_id, expand=["product"])
    except Exception as e:
        logger.exception("[BILLING] Errore retrieve Price %s: %r", price_id, e)
        return 0, "", 0, ""

    try:
        amount = int(price["unit_amount"] or 0)
    except Exception:
        amount = 0

    try:
        currency = str(price["currency"] or "eur").upper()
    except Exception:
        currency = "EUR"

    product_name = ""
    try:
        product_obj = price["product"]
        try:
            product_name = product_obj["name"] or ""
        except Exception:
            try:
                product = stripe.Product.retrieve(product_obj)
                product_name = product["name"] or ""
            except Exception as e:
                logger.warning("[BILLING] Errore retrieve Product %r: %r", product_obj, e)
    except Exception as e:
        logger.warning("[BILLING] Errore parsing product per price_id=%s: %r", price_id, e)

    metadata = {}
    try:
        raw_metadata = price["metadata"] if "metadata" in price else None
        if raw_metadata:
            metadata = dict(raw_metadata)
    except Exception:
        metadata = {}

    credits_raw = metadata.get("credits")
    try:
        credits_added = int(credits_raw) if credits_raw is not None else 0
    except Exception:
        logger.warning(
            "[BILLING] Metadato credits non valido per price_id=%s: %r",
            price_id,
            credits_raw,
        )
        credits_added = 0

    return credits_added, product_name, amount, currency


def _insert_purchase_row(
    user_id: str,
    product: str,
    price_id: str,
    amount: int,
    currency: str,
    credits_added: int,
    status: str,
    stripe_event_id: str | None = None,
    stripe_session_id: str | None = None,
) -> None:
    client = get_supabase()
    if client is None:
        logger.warning("[BILLING] Supabase non disponibile, purchases NON loggato.")
        return

    payload = {
        "user_id": user_id,
        "product": product or price_id,
        "price_id": price_id,
        "amount": amount,
        "currency": (currency or "EUR").upper(),
        "credits_added": credits_added,
        "status": status,
        "stripe_event_id": stripe_event_id,
        "stripe_session_id": stripe_session_id,
    }

    try:
        client.table("purchases").insert(payload).execute()
        logger.error(
            "[BILLING] PURCHASE INSERT OK user_id=%r product=%r price_id=%r credits_added=%r event_id=%r session_id=%r",
            user_id,
            product,
            price_id,
            credits_added,
            stripe_event_id,
            stripe_session_id,
        )
    except Exception as e:
        logger.exception("[BILLING] Errore insert purchases: %r", e)


def _purchase_already_processed(
    stripe_event_id: str | None = None,
    stripe_session_id: str | None = None,
) -> bool:
    client = get_supabase()
    if client is None:
        logger.warning("[BILLING] Supabase non disponibile, impossibile verificare idempotenza purchases.")
        return False

    try:
        if stripe_event_id:
            resp = (
                client.table("purchases")
                .select("id")
                .eq("stripe_event_id", stripe_event_id)
                .limit(1)
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            if rows:
                return True

        if stripe_session_id:
            resp = (
                client.table("purchases")
                .select("id")
                .eq("stripe_session_id", stripe_session_id)
                .limit(1)
                .execute()
            )
            rows = getattr(resp, "data", None) or []
            if rows:
                return True

        return False

    except Exception as e:
        logger.exception("[BILLING] Errore controllo idempotenza purchases: %r", e)
        return False


@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        logger.error("[BILLING] STRIPE_WEBHOOK_SECRET non configurato.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook Stripe non configurato.",
        )

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except stripe.error.SignatureVerificationError as e:
        logger.error("[BILLING] Firma webhook Stripe non valida: %r", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature non valida.",
        )
    except Exception as e:
        logger.exception("[BILLING] Errore parsing webhook: %r", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload webhook invalido.",
        )

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type != "checkout.session.completed":
        return {"received": True}

    event_id = event["id"]
    session_id = data["id"]

    if _purchase_already_processed(
        stripe_event_id=event_id,
        stripe_session_id=session_id,
    ):
        logger.error(
            "[BILLING] already processed event_id=%r session_id=%r",
            event_id,
            session_id,
        )
        return {"received": True, "status": "already_processed"}

    metadata = {}
    try:
        raw_metadata = data["metadata"] if "metadata" in data else None
        if raw_metadata:
            metadata = dict(raw_metadata)
    except Exception:
        metadata = {}

    user_id = metadata.get("user_id")
    price_id = metadata.get("price_id")
    pack_id = metadata.get("pack_id")

    pack = None
    if not price_id and pack_id:
        try:
            pack = PAYMENT_PACKS.get(pack_id)
            price_id = (pack or {}).get("stripe_price_id")
        except Exception as e:
            logger.exception("[BILLING] pack mapping error pack_id=%r err=%r", pack_id, e)
            price_id = None

    logger.error("[BILLING] DEBUG metadata=%r", metadata)
    logger.error("[BILLING] DEBUG user_id=%r", user_id)
    logger.error("[BILLING] DEBUG pack_id=%r", pack_id)
    logger.error("[BILLING] DEBUG pack=%r", pack)
    logger.error("[BILLING] DEBUG price_id=%r", price_id)

    if not user_id or not price_id:
        logger.error("[BILLING] metadata missing or unusable")
        return {"received": True}

    credits, product, amount, currency = _resolve_credits_from_price(price_id)

    logger.error(
        "[BILLING] DEBUG resolved credits=%r product=%r amount=%r currency=%r",
        credits,
        product,
        amount,
        currency,
    )

    if credits > 0:
        try:
            before, after = add_paid_credits(user_id=user_id, amount=credits)
            logger.error(
                "[BILLING] CREDITS UPDATED user_id=%r before=%r added=%r after=%r",
                user_id,
                before,
                credits,
                after,
            )
        except Exception as e:
            logger.exception(
                "[BILLING] Errore add_paid_credits user_id=%r credits=%r err=%r",
                user_id,
                credits,
                e,
            )
    else:
        logger.error("[BILLING] credits <= 0 for price_id=%r", price_id)

    _insert_purchase_row(
        user_id=user_id,
        product=product,
        price_id=price_id,
        amount=amount,
        currency=currency,
        credits_added=credits,
        status="succeeded",
        stripe_event_id=event_id,
        stripe_session_id=session_id,
    )

    return {"received": True}