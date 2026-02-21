from __future__ import annotations

import os
import time
from typing import Any

import httpx
import jwt


class GitHubApiError(RuntimeError):
    """Raised when GitHub API returns an error response."""


class GitHubAppClient:
    def __init__(
        self,
        app_id: str,
        private_key: str,
        webhook_secret: str,
        api_url: str = "https://api.github.com",
        timeout_seconds: float = 20.0,
    ) -> None:
        self.app_id = app_id
        self.private_key = private_key
        self.webhook_secret = webhook_secret
        self.api_url = api_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls) -> "GitHubAppClient":
        app_id = os.getenv("GITHUB_APP_ID")
        private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")
        webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        api_url = os.getenv("GITHUB_API_URL", "https://api.github.com")
        timeout_seconds = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20"))

        missing = [
            name
            for name, value in {
                "GITHUB_APP_ID": app_id,
                "GITHUB_APP_PRIVATE_KEY": private_key,
                "GITHUB_WEBHOOK_SECRET": webhook_secret,
            }.items()
            if not value
        ]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

        normalized_private_key = private_key.replace("\\n", "\n")
        return cls(
            app_id=str(app_id),
            private_key=normalized_private_key,
            webhook_secret=str(webhook_secret),
            api_url=api_url,
            timeout_seconds=timeout_seconds,
        )

    def _create_app_jwt(self) -> str:
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 9 * 60,
            "iss": self.app_id,
        }
        token = jwt.encode(payload, self.private_key, algorithm="RS256")
        return str(token)

    def _request(
        self,
        method: str,
        path: str,
        *,
        app_auth: bool = False,
        installation_token: str | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        expected_statuses: set[int] | None = None,
    ) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "siege-gatekeeper",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if app_auth:
            headers["Authorization"] = f"Bearer {self._create_app_jwt()}"
        elif installation_token:
            headers["Authorization"] = f"Bearer {installation_token}"

        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.request(
                method=method,
                url=f"{self.api_url}{path}",
                headers=headers,
                params=params,
                json=json_body,
            )

        expected = expected_statuses or set()
        if expected:
            if response.status_code not in expected:
                raise GitHubApiError(self._build_error_message(method, path, response))
        elif response.status_code >= 400:
            raise GitHubApiError(self._build_error_message(method, path, response))

        if response.text:
            try:
                return response.json()
            except ValueError:
                return {}
        return {}

    @staticmethod
    def _build_error_message(method: str, path: str, response: httpx.Response) -> str:
        details = response.text.strip()
        if len(details) > 500:
            details = f"{details[:500]}..."
        return (
            f"GitHub API error for {method} {path}: "
            f"status={response.status_code}, body={details}"
        )

    def get_installation_token(self, installation_id: int) -> str:
        response_json = self._request(
            method="POST",
            path=f"/app/installations/{installation_id}/access_tokens",
            app_auth=True,
            expected_statuses={201},
        )
        token = response_json.get("token")
        if not token:
            raise GitHubApiError("GitHub API did not return an installation token")
        return str(token)

    def get_pull_request_files(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        installation_token: str,
    ) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        page = 1
        while True:
            page_files = self._request(
                method="GET",
                path=f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                installation_token=installation_token,
                params={"per_page": 100, "page": page},
                expected_statuses={200},
            )
            if not isinstance(page_files, list):
                raise GitHubApiError(
                    "Unexpected response while fetching pull request files"
                )
            files.extend(page_files)
            if len(page_files) < 100:
                break
            page += 1
        return files

    def post_pull_request_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        installation_token: str,
        review_body: str,
        inline_comments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "commit_id": commit_sha,
            "event": "COMMENT",
            "body": review_body,
        }
        if inline_comments:
            payload["comments"] = inline_comments

        response_json = self._request(
            method="POST",
            path=f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            installation_token=installation_token,
            json_body=payload,
            expected_statuses={200, 201},
        )
        if not isinstance(response_json, dict):
            raise GitHubApiError("Unexpected response while posting pull request review")
        return response_json
