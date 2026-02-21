# SieGe Gatekeeper (GitHub App) - Test render review

SieGe Gatekeeper is a **GitHub App** webhook service that:

1. Listens to `pull_request` webhooks.
2. Fetches PR file diffs from the GitHub REST API.
3. Runs static analysis on **changed lines only**.
4. Posts **one structured review** back to the PR.

## Project Structure

```text
app/
  main.py                 # FastAPI webhook server
  github_webhook.py       # Signature verification
  github_client.py        # GitHub App auth + API calls
  diff_parser.py          # Unified diff parsing and changed-line extraction
  review_formatter.py     # Single structured review + inline comments
  analyzers/
    lint.py               # Style and common anti-pattern checks
    python_ast.py         # Python security-pattern checks
    complexity.py         # Heuristic complexity checks
```

## Environment Variables

Copy `.env.example` to `.env` and set values:

- `GITHUB_APP_ID`: GitHub App ID.
- `GITHUB_APP_PRIVATE_KEY`: App private key (use `\n` for newlines if single-line).
- `GITHUB_WEBHOOK_SECRET`: Webhook secret configured in your GitHub App.
- `GITHUB_API_URL`: Defaults to `https://api.github.com`.
- `HTTP_TIMEOUT_SECONDS`: HTTP timeout for GitHub API calls.
- `LOG_LEVEL`: Logging level (default `INFO`).
- `MAX_INLINE_COMMENTS`: Upper bound for inline comments in one review.
- `MAX_LINE_LENGTH`: Max line-length threshold used by lint analyzer.
- `PORT`: Web server port.

## Local Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health endpoint:

```text
GET /healthz
```

Webhook endpoint:

```text
POST /webhook
```

## Docker

```bash
docker-compose up --build
```

## GitHub App Configuration

Create/configure a **GitHub App** (not GitHub Action):

1. Go to GitHub Settings -> Developer settings -> GitHub Apps -> New GitHub App.
2. Set **Webhook URL** to your deployed endpoint, e.g. `https://your-domain/webhook`.
3. Set **Webhook secret** and use the same value for `GITHUB_WEBHOOK_SECRET`.
4. Permissions:
   - Repository `Pull requests`: **Read & write**
   - Repository `Contents`: **Read-only**
   - Repository `Metadata`: **Read-only**
5. Subscribe to events:
   - `Pull request`
6. Generate private key and set it in `GITHUB_APP_PRIVATE_KEY`.
7. Install the app on the target repository/org.

## Review Behavior

For `pull_request` actions `opened`, `reopened`, `synchronize`, and `ready_for_review`, the app:

1. Validates webhook signature.
2. Exchanges app JWT for an installation token.
3. Fetches PR file patches.
4. Parses added lines from unified diffs.
5. Runs analyzers against those changed lines only.
6. Posts one review containing:
   - Markdown summary table
   - Severity breakdown
   - Optional inline comments (capped by `MAX_INLINE_COMMENTS`)
