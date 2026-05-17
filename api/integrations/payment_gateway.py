"""
Unified payment gateway adapter.
Supports: Paystack, Flutterwave, expressPay, Hubtel.
Default gateway is configured via settings.default_payment_gateway.

For MoMo collections and disbursements, prefer ghipss_mmi.py (GhIPSS network).
This adapter handles card payments and alternative channels.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import httpx

from api.config import settings

log = logging.getLogger(__name__)


@dataclass
class PaymentRequest:
    amount_ghs: Decimal
    customer_email: str
    customer_phone: str
    reference: str
    narration: str
    callback_url: str = ""
    metadata: dict | None = None


@dataclass
class PaymentResponse:
    success: bool
    gateway: str
    reference: str
    gateway_reference: str | None = None
    authorization_url: str | None = None   # redirect URL for hosted checkout
    status: str = "PENDING"
    error: str | None = None
    raw: dict | None = None


@dataclass
class VerifyResponse:
    success: bool
    gateway: str
    reference: str
    amount_ghs: Decimal | None = None
    status: str = ""
    paid_at: str | None = None
    channel: str | None = None
    error: str | None = None


class PaystackGateway:
    """Paystack payment gateway — https://paystack.com/docs/api/"""

    BASE = "https://api.paystack.co"

    def __init__(self):
        self._key = settings.paystack_secret_key
        self._headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }

    async def initiate(self, req: PaymentRequest) -> PaymentResponse:
        payload = {
            "amount": int(req.amount_ghs * 100),  # Paystack uses pesewas
            "email": req.customer_email,
            "reference": req.reference,
            "currency": "GHS",
            "callback_url": req.callback_url,
            "metadata": req.metadata or {},
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(f"{self.BASE}/transaction/initialize",
                                     headers=self._headers, json=payload)
            data = resp.json()

        if data.get("status"):
            return PaymentResponse(
                success=True,
                gateway="PAYSTACK",
                reference=req.reference,
                gateway_reference=data["data"].get("reference"),
                authorization_url=data["data"].get("authorization_url"),
                raw=data,
            )
        return PaymentResponse(success=False, gateway="PAYSTACK", reference=req.reference,
                               error=data.get("message"), raw=data)

    async def verify(self, reference: str) -> VerifyResponse:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{self.BASE}/transaction/verify/{reference}",
                                    headers=self._headers)
            data = resp.json()

        if data.get("status") and data["data"].get("status") == "success":
            amount_pesewas = data["data"].get("amount", 0)
            return VerifyResponse(
                success=True, gateway="PAYSTACK", reference=reference,
                amount_ghs=Decimal(str(amount_pesewas / 100)),
                status="SUCCESS",
                paid_at=data["data"].get("paid_at"),
                channel=data["data"].get("channel"),
            )
        return VerifyResponse(success=False, gateway="PAYSTACK", reference=reference,
                              status=data.get("data", {}).get("status", "FAILED"),
                              error=data.get("message"))

    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        computed = hmac.new(
            self._key.encode(), payload, hashlib.sha512
        ).hexdigest()
        return hmac.compare_digest(computed, signature)


class FlutterwaveGateway:
    """Flutterwave payment gateway — https://developer.flutterwave.com/"""

    BASE = "https://api.flutterwave.com/v3"

    def __init__(self):
        self._key = settings.flutterwave_secret_key
        self._headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }

    async def initiate(self, req: PaymentRequest) -> PaymentResponse:
        payload = {
            "tx_ref": req.reference,
            "amount": str(req.amount_ghs),
            "currency": "GHS",
            "redirect_url": req.callback_url,
            "customer": {
                "email": req.customer_email,
                "phone_number": req.customer_phone,
            },
            "customizations": {"title": "Crestline S&L Payment"},
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(f"{self.BASE}/payments", headers=self._headers, json=payload)
            data = resp.json()

        if data.get("status") == "success":
            return PaymentResponse(
                success=True, gateway="FLUTTERWAVE", reference=req.reference,
                authorization_url=data["data"].get("link"), raw=data,
            )
        return PaymentResponse(success=False, gateway="FLUTTERWAVE", reference=req.reference,
                               error=data.get("message"), raw=data)

    async def verify(self, transaction_id: str) -> VerifyResponse:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{self.BASE}/transactions/{transaction_id}/verify",
                                    headers=self._headers)
            data = resp.json()

        if data.get("status") == "success" and data["data"].get("status") == "successful":
            return VerifyResponse(
                success=True, gateway="FLUTTERWAVE", reference=data["data"].get("tx_ref", ""),
                amount_ghs=Decimal(str(data["data"].get("amount", 0))),
                status="SUCCESS", channel=data["data"].get("payment_type"),
            )
        return VerifyResponse(success=False, gateway="FLUTTERWAVE", reference="",
                              status="FAILED", error=data.get("message"))


class MockGateway:
    """Mock gateway for development and CI — always succeeds unless amount == 0."""

    async def initiate(self, req: PaymentRequest) -> PaymentResponse:
        if req.amount_ghs == 0:
            return PaymentResponse(success=False, gateway="MOCK", reference=req.reference,
                                   error="Amount cannot be zero")
        return PaymentResponse(
            success=True, gateway="MOCK", reference=req.reference,
            gateway_reference=f"MOCK-{secrets.token_hex(8).upper()}",
            authorization_url=f"http://localhost:3000/mock-payment?ref={req.reference}",
            status="PENDING",
        )

    async def verify(self, reference: str) -> VerifyResponse:
        return VerifyResponse(success=True, gateway="MOCK", reference=reference, status="SUCCESS")


class PaymentGatewayAdapter:
    """
    Unified adapter — selects gateway based on settings.default_payment_gateway.
    In development/CI, always uses MockGateway regardless of setting.
    """

    def __init__(self):
        env = settings.node_env
        gw = settings.default_payment_gateway.upper()

        if env in ("development", "test"):
            self._gw: Any = MockGateway()
            self._gw_name = "MOCK"
        elif gw == "PAYSTACK":
            self._gw = PaystackGateway()
            self._gw_name = "PAYSTACK"
        elif gw == "FLUTTERWAVE":
            self._gw = FlutterwaveGateway()
            self._gw_name = "FLUTTERWAVE"
        else:
            log.warning("Unknown gateway %s, falling back to Paystack", gw)
            self._gw = PaystackGateway()
            self._gw_name = "PAYSTACK"

    async def initiate(self, req: PaymentRequest) -> PaymentResponse:
        log.info("payment_initiate gateway=%s ref=%s amount=%.2f",
                 self._gw_name, req.reference, req.amount_ghs)
        return await self._gw.initiate(req)

    async def verify(self, reference: str) -> VerifyResponse:
        log.info("payment_verify gateway=%s ref=%s", self._gw_name, reference)
        return await self._gw.verify(reference)


# Module-level singleton
payment_gateway = PaymentGatewayAdapter()
