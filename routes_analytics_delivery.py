"""Internal scheduler-only endpoint for server-side analytics delivery."""
import hmac
import os
from fastapi import APIRouter, Header, HTTPException, status
from auth.billing.analytics_purchase_delivery import deliver_confirmed_tema_v2_purchases

router = APIRouter(prefix="/internal/analytics", tags=["internal"])

@router.post("/deliver-confirmed-purchases")
def deliver_confirmed_purchases(x_analytics_delivery_secret: str | None = Header(default=None)):
    expected = os.getenv("ANALYTICS_DELIVERY_SECRET")
    if not expected or not x_analytics_delivery_secret or not hmac.compare_digest(expected, x_analytics_delivery_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return deliver_confirmed_tema_v2_purchases()
