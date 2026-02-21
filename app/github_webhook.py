from __future__ import annotations

import hashlib
import hmac


def validate_webhook_signature(
    webhook_secret: str, payload: bytes, signature_header: str | None
) -> bool:
    """Validate GitHub webhook signature using X-Hub-Signature-256."""
    if not webhook_secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False

    received_digest = signature_header.split("=", maxsplit=1)[1]
    expected_digest = hmac.new(
        webhook_secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_digest, received_digest)
