from __future__ import annotations

import hashlib
import hmac


def validate_webhook_signature(
    webhook_secret: str,
    payload: bytes,
    signature_header: str | None,
    *,
    is_github_delivery: bool = True,
) -> bool:
    """
    Validate GitHub webhook signature using X-Hub-Signature-256.

    Args:
        webhook_secret: GitHub webhook secret (raw string, no quotes)
        payload: Raw request body bytes
        signature_header: Value of X-Hub-Signature-256 header
        is_github_delivery: Set False for local/manual tests (Windows-safe)

    Returns:
        True if signature is valid, False otherwise
    """

    # Basic validation
    if not webhook_secret or not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    # Windows / manual test fix:
    # GitHub sends exact bytes; PowerShell often appends CRLF
    if not is_github_delivery:
        payload = payload.rstrip(b"\r\n")

    # Compute expected digest
    expected_digest = hmac.new(
        webhook_secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Extract received digest (remove 'sha256=')
    received_digest = signature_header.split("=", 1)[1]

    # Constant-time comparison
    return hmac.compare_digest(expected_digest, received_digest)
