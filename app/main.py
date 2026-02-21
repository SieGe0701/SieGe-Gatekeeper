from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from app.analyzers import run_all_analyzers
from app.diff_parser import build_file_diffs
from app.github_client import GitHubApiError, GitHubAppClient
from app.github_webhook import validate_webhook_signature
from app.review_formatter import build_review_payload

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("siege-gatekeeper")

SUPPORTED_PR_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}
app = FastAPI(title="SieGe Gatekeeper", version="1.0.0")


@lru_cache(maxsize=1)
def get_github_client() -> GitHubAppClient:
    return GitHubAppClient.from_env()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook")
async def handle_webhook(
    request: Request,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str | None = Header(default=None),
) -> dict[str, Any]:
    payload_bytes = await request.body()
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail="Missing required environment variable: GITHUB_WEBHOOK_SECRET",
        )

    if not validate_webhook_signature(
        webhook_secret=webhook_secret,
        payload=payload_bytes,
        signature_header=x_hub_signature_256,
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if x_github_event != "pull_request":
        return {
            "ignored": True,
            "reason": "unsupported_event",
            "event": x_github_event,
        }

    action = payload.get("action")
    if action not in SUPPORTED_PR_ACTIONS:
        return {
            "ignored": True,
            "reason": "unsupported_action",
            "action": action,
        }

    pull_request = payload.get("pull_request") or {}
    if pull_request.get("draft"):
        return {"ignored": True, "reason": "draft_pull_request"}

    repository = payload.get("repository") or {}
    owner = ((repository.get("owner") or {}).get("login") or "").strip()
    repo = (repository.get("name") or "").strip()
    pr_number = pull_request.get("number") or payload.get("number")
    commit_sha = ((pull_request.get("head") or {}).get("sha") or "").strip()
    installation_id = ((payload.get("installation") or {}).get("id")) or 0

    if not owner or not repo or not pr_number or not commit_sha or not installation_id:
        raise HTTPException(
            status_code=400,
            detail="Missing required pull request or installation metadata",
        )

    client = get_github_client()

    try:
        installation_token = client.get_installation_token(int(installation_id))
        pr_files = client.get_pull_request_files(
            owner=owner,
            repo=repo,
            pr_number=int(pr_number),
            installation_token=installation_token,
        )
        file_diffs = build_file_diffs(pr_files)
        findings = run_all_analyzers(file_diffs)
        review_body, inline_comments = build_review_payload(findings, file_diffs)

        review_response = client.post_pull_request_review(
            owner=owner,
            repo=repo,
            pr_number=int(pr_number),
            commit_sha=commit_sha,
            installation_token=installation_token,
            review_body=review_body,
            inline_comments=inline_comments,
        )
    except GitHubApiError as exc:
        logger.exception("GitHub API request failed during webhook processing")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except RuntimeError as exc:
        logger.exception("Runtime error during webhook processing")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "ok": True,
        "repository": f"{owner}/{repo}",
        "pull_request": int(pr_number),
        "files_analyzed": len(file_diffs),
        "changed_lines_analyzed": sum(len(d.changed_lines) for d in file_diffs),
        "findings": len(findings),
        "inline_comments_posted": len(inline_comments),
        "review_id": review_response.get("id"),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
    )
