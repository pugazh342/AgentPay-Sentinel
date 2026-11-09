# AgentPay Sentinel - Milestone 04

A production-minded, deterministic authorization core for AI-agent payments,
extended with advisory Gemini threat intelligence, a durable PayPal Orders v2
workflow in **sandbox mode only**, and a repeatable adversarial security
simulation framework.

**This is a local-development foundation, not a production-secure payment
gateway.** It has no production user authentication, no frontend and no
production deployment hardening. Live PayPal execution is deliberately not
configurable.

## What it does

AgentPay Sentinel stores user-authored purchase intents and deterministically
checks payment requests against them. Optional contextual threat analysis uses
Gemini to surface prompt injection, intent manipulation and related risks. An
eligible request can then be approved, converted into a PayPal sandbox order and
captured after the buyer approves inside PayPal. The AI model is advisory only:
it never authorizes payments, never creates orders, never captures transactions
and never modifies intents.

- Immutable purchase intents with UUIDs and exact `Decimal` money.
- HMAC-SHA256 fingerprints over canonical security-relevant intent fields.
- Deterministic policy engine with stable reason codes.
- Advisory Gemini contextual threat analysis behind a provider port.
- Durable payment state machine with conditional, version-checked transitions.
- PayPal Orders v2 sandbox integration with cached OAuth tokens, bounded
  timeouts/retries and `PayPal-Request-Id` idempotency keys.
- Signature-verified, deduplicated PayPal webhook reconciliation.
- Repeatable adversarial simulation covering policy, authorization, integrity,
  replay, prompt-injection, payment, webhook, concurrency, state-machine and
  live-endpoint attacks, with machine-readable evidence.
- Persisted transaction decisions, payments, threat analyses and security audit
  events.
- Fail-closed behavior when the HMAC secret, AI analysis or PayPal configuration
  is unavailable.
- FastAPI OpenAPI/Swagger documentation.


## Deterministic policy

Rules are evaluated in this fixed order:

| Condition | Result | Reason code |
|---|---|---|
| Unknown intent | BLOCK | `UNKNOWN_INTENT` |
| Wrong user | BLOCK | `USER_MISMATCH` |
| Expired intent (`now >= expires_at`) | BLOCK | `INTENT_EXPIRED` |
| Intent fingerprint invalid | BLOCK | `INVALID_INTENT_FINGERPRINT` |
| Merchant mismatch | BLOCK | `MERCHANT_MISMATCH` |
| Currency mismatch | BLOCK | `CURRENCY_MISMATCH` |
| Amount > intent maximum | BLOCK | `AMOUNT_EXCEEDS_MAXIMUM` |
| Quantity > intent maximum | BLOCK | `QUANTITY_EXCEEDS_MAXIMUM` |
| Product category mismatch (all hard checks pass) | REVIEW_REQUIRED | `PRODUCT_CATEGORY_MISMATCH` |
| All hard checks pass and category matches | ALLOW_FOR_APPROVAL | `ALL_CHECKS_PASSED` |

`ALLOW_FOR_APPROVAL` is an approval-eligibility result only. It is **not**
permission to capture, settle or execute a payment. `risk_level` is descriptive
metadata only and never participates in authorization.

Hard failures take precedence over category review. Reason codes are returned in
the order above.

## AI threat analysis (advisory only)

Threat analysis runs only when `analysis_context` is explicitly supplied on
`POST /api/v1/transactions/evaluate`, or when
`POST /api/v1/analysis/transactions/{transaction_id}` is called. Omitting the
context preserves the Milestone 01 deterministic-only response exactly.

The provider receives the purchase purpose, authorized category, merchant id,
amount, currency, quantity and the bounded untrusted context fields
(`product_title`, `product_description`, `merchant_name`, `agent_reasoning`,
`transaction_context`). Untrusted text is clearly delimited as data in the
prompt. The prompt is never logged, the API key is never returned or logged, and
the model has no tools or function-calling capability.

Structured output is validated with Pydantic against a closed schema:

- `analysis_status`: `COMPLETED`, `UNAVAILABLE`, `INVALID_RESPONSE`
- `threat_level`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `risk_score`: `0`-`100`, descriptive only
- `detected_threats[]`: `category`, `severity`, `evidence`
- `evidence[]`, `suspicious_instructions[]`
- `intent_alignment`: `ALIGNED`, `DEVIATES`, `UNCLEAR`
- `explanation`, `recommended_handling`
- `model_name`, `analyzed_at`

Threat categories: `PROMPT_INJECTION`, `INTENT_MANIPULATION`,
`MERCHANT_SUBSTITUTION`, `PRICE_ANOMALY`, `QUANTITY_MANIPULATION`,
`INSTRUCTION_HIERARCHY_ATTACK`, `SUSPICIOUS_PRODUCT_CONTENT`, `OTHER`.
Finding severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### Reconciliation guarantees

The deterministic policy remains the only authorization source of truth.

| Deterministic result | AI result | Final result |
|---|---|---|
| `BLOCK` | anything | `BLOCK` unchanged |
| `REVIEW_REQUIRED` | clean | `REVIEW_REQUIRED` unchanged |
| `REVIEW_REQUIRED` | unavailable/invalid | `REVIEW_REQUIRED` + `AI_ANALYSIS_UNAVAILABLE` |
| `ALLOW_FOR_APPROVAL` | clean, low risk | `ALLOW_FOR_APPROVAL` |
| `ALLOW_FOR_APPROVAL` | high risk | `REVIEW_REQUIRED` + `AI_THREAT_ESCALATION` |
| `ALLOW_FOR_APPROVAL` | unavailable/invalid | `REVIEW_REQUIRED` + `AI_ANALYSIS_UNAVAILABLE` |

Escalation is driven by a `HIGH`/`CRITICAL` threat level, a high/critical
finding, `intent_alignment=DEVIATES`, or any recorded suspicious instruction.
`risk_score` alone never escalates anything. The AI can never downgrade a
decision or independently produce `ALLOW_FOR_APPROVAL`.

Provider outcomes are sanitized before persistence/return: `OK`,
`NOT_CONFIGURED`, `TIMEOUT`, `RATE_LIMITED`, `PROVIDER_ERROR`,
`INVALID_RESPONSE`. Timeouts, rate limits, network errors and malformed output
all fail closed to human review.

Standalone analysis persisted via the analysis endpoints is advisory and does
**not** change the stored transaction decision.

## PayPal sandbox payment workflow

PayPal integration is **sandbox-only**. The API base URL is fixed to
`https://api-m.sandbox.paypal.com`; `PAYPAL_ENVIRONMENT` must be `sandbox` and
the HTTP client rejects any other base URL at construction time. There is no
configuration switch that enables live payments.

### Durable states

The closed state machine is:

`PENDING_SECURITY`, `REVIEW_REQUIRED`, `BLOCKED`, `PENDING_USER_APPROVAL`,
`PAYPAL_ORDER_CREATED`, `BUYER_APPROVED`, `CAPTURE_PENDING`, `COMPLETED`,
`FAILED`, `EXPIRED`.

`REVIEW_REQUIRED`, `BLOCKED`, `COMPLETED`, `FAILED` and `EXPIRED` cannot reach
`CAPTURE_PENDING`. Every transition is checked against an explicit allowed-edge
table and applied with a conditional `UPDATE ... WHERE state = ? AND version = ?`.
A concurrent writer that read an older version cannot overwrite a newer state;
one payment exists per transaction (`transaction_id` is unique).

### Checkout flow

1. `POST /api/v1/transactions/evaluate` returns `ALLOW_FOR_APPROVAL`.
2. `POST /api/v1/payments` with the server-side `transaction_id` binds one
   payment and moves it to `PENDING_USER_APPROVAL`. The request accepts **no**
   amount, currency, merchant or PayPal identifiers.
3. `POST /api/v1/payments/{payment_id}/approve` records the demo approval
   identity, revalidates the stored decision, intent fingerprint, expiry,
   amount, currency, merchant and product category, then creates a PayPal
   sandbox order and returns a `state` of `PAYPAL_ORDER_CREATED` with an
   `approval_url`.
4. The buyer opens `approval_url` in a PayPal sandbox account and approves.
5. `POST /api/v1/payments/{payment_id}/buyer-return` ignores all browser return
   parameters, fetches the order directly from PayPal and advances to
   `BUYER_APPROVED` only when PayPal reports `APPROVED`.
6. `POST /api/v1/payments/{payment_id}/capture` revalidates again, claims
   `BUYER_APPROVED -> CAPTURE_PENDING` durably, then captures with
   `PayPal-Request-Id: agentpay-capture-{payment_id}`. A definitive rejection
   becomes `FAILED`; an ambiguous timeout/server outcome stays `CAPTURE_PENDING`
   for verified webhook reconciliation.

Order creation uses `PayPal-Request-Id: agentpay-order-{payment_id}` and binds
each provider order to the internal transaction through `custom_id`. The
configured return/cancel URLs are supplied only as buyer redirect hints; they
are never used as proof of payment.

### Webhook verification and reconciliation

`POST /api/v1/paypal/webhooks` always calls PayPal's official
`/v1/notifications/verify-webhook-signature` endpoint with the configured
webhook ID and the `PayPal-Transmission-*` headers. Unverified events are
rejected with `400 WEBHOOK_SIGNATURE_INVALID` before any event row is written.

Verified events are deduplicated by PayPal event ID. A verified
`PAYMENT.CAPTURE.COMPLETED` can complete a payment only when:

- the payment is already `CAPTURE_PENDING` (a durable capture claim exists),
- the event references the stored PayPal order ID, and
- the capture amount and currency exactly match the authorized payment.

Unmatched or mismatched events are acknowledged and recorded without changing
payment state. Verified capture failure/reversal events move a claimed capture
to `FAILED`. Webhooks can never create an order or complete an unclaimed
payment.

### Related endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/payments` | Bind one payment to a persisted transaction evaluation |
| `GET` | `/api/v1/payments/{payment_id}` | Retrieve payment state and audit fields |
| `POST` | `/api/v1/payments/{payment_id}/approve` | Demo approval + create PayPal sandbox order |
| `POST` | `/api/v1/payments/{payment_id}/buyer-return` | Re-verify the buyer's return directly with PayPal |
| `POST` | `/api/v1/payments/{payment_id}/capture` | Revalidate and capture a buyer-approved order |
| `POST` | `/api/v1/paypal/webhooks` | Verify, deduplicate and reconcile PayPal events |

## Architecture

```
backend/
  app/
    ai/                 Gemini provider adapter and structured-output schemas
    api/                FastAPI routes, dependency injection, error envelope
    application/        Intent, transaction, threat-analysis and payment use cases
    domain/             Entities, money rules, policy, payment state machine, ports, enums
    paypal/             PayPal Orders v2 sandbox HTTP adapter (OAuth, orders, webhooks)
    persistence/        SQLAlchemy models, repositories, SQLite database
    schemas/            Pydantic v2 request/response models
    security/           HMAC fingerprinting and audit event logging
    security_testing/   Attack/result/invariant models and deterministic reporting
    config.py           Environment-backed settings (SecretStr)
    logging_config.py   Allowlisted structured JSON logging
    main.py             App factory and ASGI entrypoint
  scripts/
    run_adversarial.py  Repeatable CLI runner for the adversarial simulation
  reports/              Committed machine-readable and Markdown adversarial reports
  tests/                pytest unit, API, persistence and fail-closed tests
    adversarial/        Attack fixtures, harness, executors and adversarial tests
```

The framework models and report renderers live in `app/security_testing/`, while
attack fixtures and executors live in `tests/adversarial/`. Production business
logic never imports test-side attack definitions.

## Requirements

- Python 3.12+
- SQLite (bundled with Python)
- A Gemini API key only if you want live AI analysis
- PayPal **sandbox** REST app credentials only if you want to exercise the
  checkout flow; the automated test suite needs no PayPal credentials and makes
  no network calls.

## Installation

From the repository root (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements-dev.txt
```

POSIX shells:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements-dev.txt
```

## Configuration

Create `backend/.env` from the example:

```powershell
cd backend
Copy-Item .env.example .env
```

Generate a development-only HMAC secret (at least 32 bytes):

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value in `.env`:

```dotenv
AGENTPAY_HMAC_SECRET=<paste-generated-secret>
AGENTPAY_DATABASE_URL=sqlite:///./agentpay.db
AGENTPAY_ENVIRONMENT=local
AGENTPAY_LOG_LEVEL=INFO

# Optional: omit or leave blank to disable live AI analysis.
GEMINI_API_KEY=<paste-gemini-key>
GEMINI_MODEL=gemini-2.5-flash
AGENTPAY_GEMINI_TIMEOUT_MS=15000
AGENTPAY_GEMINI_MAX_RETRIES=1
AGENTPAY_GEMINI_RETRY_BACKOFF_SECONDS=0.5

# PayPal Orders v2 SANDBOX ONLY. Leave blank to run everything except order
# creation/capture. Any environment other than "sandbox" is rejected.
PAYPAL_ENVIRONMENT=sandbox
PAYPAL_CLIENT_ID=<sandbox-rest-app-client-id>
PAYPAL_CLIENT_SECRET=<sandbox-rest-app-secret>
PAYPAL_WEBHOOK_ID=<sandbox-webhook-id>
PAYPAL_RETURN_URL=http://127.0.0.1:8000/docs
PAYPAL_CANCEL_URL=http://127.0.0.1:8000/docs
AGENTPAY_PAYPAL_TIMEOUT_MS=15000
AGENTPAY_PAYPAL_MAX_RETRIES=1
AGENTPAY_PAYPAL_RETRY_BACKOFF_SECONDS=0.5
AGENTPAY_PAYPAL_TOKEN_SKEW_SECONDS=60
```

`GEMINI_API_KEY` and `GEMINI_MODEL` accept the unprefixed names shown above;
the remaining Gemini settings use the `AGENTPAY_GEMINI_*` prefix. Secrets are
wrapped in `SecretStr`, never returned by the API, and never serialized into
logs. Do not commit `.env`; the repository `.gitignore` excludes it.

`PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` and `PAYPAL_WEBHOOK_ID` accept the
unprefixed names shown above; the remaining PayPal settings use the
`AGENTPAY_PAYPAL_*` prefix. They are wrapped in `SecretStr` and are never
returned by the API or written to logs. Access tokens are cached in memory and
refreshed shortly before expiry.

### Sandbox setup

1. Sign in at <https://developer.paypal.com/dashboard/applications/sandbox>.
2. Create (or reuse) a sandbox REST app and copy its **sandbox** client ID and
   secret into `.env`. Never use live credentials.
3. Create a sandbox webhook pointing at your publicly reachable endpoint
   (`https://<host>/api/v1/paypal/webhooks`) and copy its webhook ID. Subscribe
   to at least `CHECKOUT.ORDER.APPROVED`, `PAYMENT.CAPTURE.COMPLETED`,
   `PAYMENT.CAPTURE.DENIED`, `PAYMENT.CAPTURE.DECLINED`,
   `PAYMENT.CAPTURE.FAILED` and `PAYMENT.CAPTURE.REVERSED`.
4. To test buyer approval locally, open the returned `approval_url` in a browser
   while signed into a **sandbox personal** account, or use a sandbox test
   account. Paying with a sandbox account moves no real money.
5. `PAYPAL_RETURN_URL`/`PAYPAL_CANCEL_URL` are redirect hints only. Because
   there is no frontend in this milestone, call
   `POST /api/v1/payments/{payment_id}/buyer-return` yourself after approving so
   the server can re-verify the order directly with PayPal.

If PayPal credentials are absent, evaluation and all non-payment endpoints keep
working; `approve`, `buyer-return` and `capture` fail closed with
`503 PAYPAL_NOT_CONFIGURED`. If the webhook ID or verification call is
unavailable, webhook events are rejected rather than trusted.

If the HMAC secret is missing, blank, has leading/trailing whitespace, or is
shorter than 32 bytes, the application starts in **fail-closed degraded mode**:
`GET /health` returns `503`, and all intent, transaction, analysis, payment,
webhook and security-event endpoints return
`503 SECURITY_CONFIGURATION_INVALID`.

If Gemini is not configured, deterministic-only evaluation still works.
Requests that supply `analysis_context` fail closed to `REVIEW_REQUIRED` with
`AI_ANALYSIS_UNAVAILABLE`, and standalone analysis returns a persisted
`UNAVAILABLE` assessment instead of a clean result.

## Run locally

From `backend/`:

```powershell
uvicorn app.main:app --reload --port 8000
```

- API base: <http://127.0.0.1:8000>
- Swagger UI: <http://127.0.0.1:8000/docs>
- OpenAPI JSON: <http://127.0.0.1:8000/openapi.json>
- Health: <http://127.0.0.1:8000/health>

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/intents` | Create an immutable purchase intent (`201`) |
| `GET` | `/api/v1/intents/{intent_id}` | Retrieve an intent (`200`, `404`) |
| `POST` | `/api/v1/transactions/evaluate` | Deterministically evaluate a transaction, optionally with advisory AI (`200`) |
| `GET` | `/api/v1/transactions/{transaction_id}` | Retrieve a persisted evaluation (`200`, `404`) |
| `POST` | `/api/v1/analysis/transactions/{transaction_id}` | Run and persist advisory threat analysis (`200`, `404`) |
| `GET` | `/api/v1/analysis/transactions/{transaction_id}` | Retrieve the latest advisory analysis (`200`, `404`) |
| `POST` | `/api/v1/payments` | Bind one durable payment to a transaction (`200`, `404`) |
| `GET` | `/api/v1/payments/{payment_id}` | Retrieve payment state (`200`, `404`) |
| `POST` | `/api/v1/payments/{payment_id}/approve` | Demo approval + PayPal sandbox order creation (`200`, `409`, `502`, `503`) |
| `POST` | `/api/v1/payments/{payment_id}/buyer-return` | Re-verify buyer approval with PayPal (`200`, `409`, `502`, `503`) |
| `POST` | `/api/v1/payments/{payment_id}/capture` | Capture a buyer-approved sandbox order (`200`, `409`, `502`, `503`) |
| `POST` | `/api/v1/paypal/webhooks` | Verify and reconcile PayPal webhooks (`200`, `400`) |
| `GET` | `/api/v1/security/events` | Recent audit events (`200`) |
| `GET` | `/health` | Service and security-config health (`200`, `503`) |

Unknown intents are a policy outcome (`BLOCK` with `UNKNOWN_INTENT`), not a
`404`. Invalid/malformed input returns `422` with a consistent error envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "details": [{"field": "amount", "message": "Input should be greater than 0"}]
  }
}
```

### Example flow

Create an intent:

```powershell
$intent = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/intents `
  -ContentType 'application/json' `
  -Body (@{
    user_id = 'user_123'
    purpose = 'Purchase one pair of running shoes'
    merchant_id = 'merchant_shoes'
    product_category = 'footwear'
    max_amount = '800.00'
    currency = 'USD'
    max_quantity = 1
    require_approval = $true
    expires_at = (Get-Date).ToUniversalTime().AddHours(2).ToString('o')
  } | ConvertTo-Json)
```

Evaluate a transaction deterministically:

```powershell
$decision = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/transactions/evaluate `
  -ContentType 'application/json' `
  -Body (@{
    user_id = 'user_123'
    intent_id = $intent.intent_id
    merchant_id = 'merchant_shoes'
    product_category = 'footwear'
    amount = '800.00'
    currency = 'USD'
    quantity = 1
    request_id = 'req_2026_0001'
  } | ConvertTo-Json)
```

Change `amount` to `'1200.00'` to receive `BLOCK` with
`AMOUNT_EXCEEDS_MAXIMUM`.

Evaluate with advisory AI analysis by adding `analysis_context`:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/transactions/evaluate `
  -ContentType 'application/json' `
  -Body (@{
    user_id = 'user_123'
    intent_id = $intent.intent_id
    merchant_id = 'merchant_shoes'
    product_category = 'footwear'
    amount = '800.00'
    currency = 'USD'
    quantity = 1
    request_id = 'req_2026_0002'
    analysis_context = @{
      product_title = 'Trail running shoes'
      product_description = 'Lightweight neutral running shoes.'
      merchant_name = 'Example Shoes'
      agent_reasoning = 'Matches the authorized footwear category.'
      transaction_context = 'One pair, within the authorized maximum.'
    }
  } | ConvertTo-Json -Depth 4)
```

Run standalone analysis against an existing transaction:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/analysis/transactions/$($decision.transaction_id)" `
  -ContentType 'application/json' `
  -Body (@{ agent_reasoning = 'Matches the authorized category.' } | ConvertTo-Json)
```

Standalone analysis never changes the stored decision.

Continue an eligible evaluation into the PayPal sandbox (requires sandbox
credentials and a reachable webhook for reconciliation):

```powershell
# 1. Bind one durable payment to the evaluated transaction.
$payment = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/payments `
  -ContentType 'application/json' `
  -Body (@{ transaction_id = $decision.transaction_id } | ConvertTo-Json)

# 2. Demo approval + PayPal sandbox order creation. approved_by is NOT an
#    authenticated production identity.
$order = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/payments/$($payment.payment_id)/approve" `
  -ContentType 'application/json' `
  -Body (@{ approved_by = 'demo_operator' } | ConvertTo-Json)

# 3. Open $order.approval_url in a PayPal sandbox buyer account and approve.

# 4. The server re-fetches the order from PayPal; browser parameters are ignored.
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/payments/$($payment.payment_id)/buyer-return"

# 5. Capture only after PayPal reports the order as APPROVED.
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/payments/$($payment.payment_id)/capture"
```

If capture returns `502` with an unknown-outcome message, the payment remains
`CAPTURE_PENDING`. Do not retry blindly; wait for a verified
`PAYMENT.CAPTURE.COMPLETED` webhook, which reconciles by stored order ID and
exact amount/currency.

## Tests

From `backend/`:

```powershell
..\.venv\Scripts\python.exe -m pytest
```

Current result on this repository: `318 passed, 4 skipped`. The four skips are
the two optional live smoke tests (`test_gemini_live.py`, `test_paypal_live.py`)
and the two optional live adversarial AI evaluations, all gated behind explicit
opt-in environment variables.

If the virtualenv is active and the project is installed or `backend/` is the
current directory:

```powershell
python -m pytest
```

Run with verbose output or a single module:

```powershell
python -m pytest -v
python -m pytest tests/test_analysis_api.py -v
```

The suite uses an injectable `MutableClock`, a deterministic stub AI provider and
an async `StubPayPalGateway`; normal tests never contact Gemini or PayPal and
require no credentials. Coverage includes valid authorization, all
manipulation/block paths, category review, fingerprint field tampering, malformed
input, decimal precision, expiry, unknown intent, wrong user, missing HMAC
secret, database persistence and security-event generation, prompt injection,
intent deviation, merchant substitution, price/quantity manipulation, provider
timeout/rate-limit/invalid-response handling, block preservation and
non-downgrade guarantees.

Payment coverage adds OAuth success/failure and token refresh, order creation,
buyer approval, amount/currency mismatch, wrong order ID, expired intents, BLOCK
and REVIEW_REQUIRED ineligibility, duplicate/concurrent capture claims, provider
timeout/server errors, missing PayPal configuration, invalid webhook signatures,
duplicate webhook delivery, unclaimed-payment events, and verified
amount/currency reconciliation.

The Milestone 04 suite adds deterministic adversarial scenarios and reporting
tests without weakening any existing control.

### Adversarial security simulation

Run every scenario and regenerate the committed reports from `backend/`:

```powershell
..\.venv\Scripts\python.exe scripts/run_adversarial.py
```

This writes:

- `reports/adversarial_report.json` - machine-readable scenarios, actual results,
  per-check evidence, counts and invariant verification.
- `reports/adversarial_report.md` - concise human-readable summary that calls out
  every failed or errored scenario.

Run only the adversarial tests:

```powershell
..\.venv\Scripts\python.exe -m pytest tests/adversarial -v
```

The runner creates an isolated SQLite database and a fresh application instance
per scenario. It executes real routes, services, repositories and state
transitions; only Gemini and PayPal are replaced by deterministic doubles. No
scenario contacts the network, uses PayPal credentials or moves money.

Scenario categories:

| Category | Examples |
|---|---|
| `POLICY` | amount/merchant/currency/quantity manipulation, category deviation, expiry, wrong user, unknown intent, fingerprint tampering |
| `AUTHORIZATION` | missing/invalid approval identity, approval-token replay |
| `INTEGRITY` | intent and transaction record tampering after buyer approval |
| `REPLAY` | reused transaction `request_id` |
| `AI` | direct/indirect prompt injection, "ignore previous rules", merchant alteration, secret disclosure, nested/obfuscated instructions, conflicting reasoning, mixed legitimate/malicious content, provider failure |
| `PAYMENT` | client-supplied payment fields, forged browser return parameters, wrong order ID, incorrect order/capture amount or currency, timeout, ambiguous capture, duplicate capture, capture after expiry |
| `WEBHOOK` | forged signature, duplicate event, wrong order binding, amount/currency mismatch, unclaimed payment, unexpected capture status |
| `CONCURRENCY` | competing capture claims and competing payment-row inserts |
| `STATE_MACHINE` | illegal transitions, capture too early, unexpected PayPal order status |
| `LIVE_ENDPOINT` | rejection of live PayPal environment/base URL |

`test_status` is never authored by hand: a scenario passes only when every check
produced by its executor is true **and** the observed decision, reason codes and
payment state match the declared expectation. Reports contain no wall-clock
timestamps or random identifiers, so repeated runs over unchanged code produce
byte-identical files. The runner refuses to write a report that contains any
configured secret value.

Verified invariants from the current run:

1. AI output cannot override a deterministic `BLOCK`.
2. AI output cannot downgrade `REVIEW_REQUIRED`.
3. AI output cannot independently authorize, approve, create an order or capture.
4. Expired or modified intents cannot reach capture.
5. A webhook cannot complete a payment without signature verification.
6. Duplicate or concurrent captures cannot execute a second provider capture.
7. AI provider failure cannot produce a clean authorization.
8. Browser return parameters cannot establish payment success.
9. No payment operation can use a live PayPal endpoint.
10. Deterministic policy is the sole authority for amount, merchant, currency,
    quantity, user, intent existence and intent integrity.
11. A transaction owns at most one payment; approval replay cannot create a
    second order.
12. PayPal order/capture responses must match the stored order, transaction,
    amount and currency.
13. Webhooks can only complete a payment already claimed as `CAPTURE_PENDING`.
14. Illegal payment state transitions are rejected before persistence.

These are verifiable guarantees for the scenarios in this suite, not a claim of
complete protection against every possible attack.

Optional live adversarial AI evaluation (never part of standard CI, no payment
action, deterministic guarantees still come from the offline suite):

```powershell
$env:AGENTPAY_RUN_GEMINI_ADVERSARIAL = '1'
$env:GEMINI_API_KEY = '<your-key>'
python -m pytest tests/adversarial/test_live_gemini_adversarial.py -v
```

Optional live smoke tests are gated and never run by default:

```powershell
# Gemini (requires an API key)
$env:GEMINI_API_KEY = '<your-key>'
python -m pytest tests/test_gemini_live.py -v

# PayPal sandbox order creation + lookup only (no capture)
$env:AGENTPAY_RUN_PAYPAL_LIVE = '1'
python -m pytest tests/test_paypal_live.py -v
```

The PayPal live test additionally skips itself when sandbox credentials are not
configured. It creates and reads one sandbox order and never captures, so no
funds move.

## Security notes and milestone limitations

Implemented:

- Server-side HMAC-SHA256 integrity fingerprints verified with
  `hmac.compare_digest`.
- No API response or log contains the HMAC secret, Gemini API key or PayPal
  client secret/access token.
- Prompt text and raw provider errors are never logged or returned; PayPal
  errors are reduced to a stable status and safe name.
- Untrusted context is bounded and explicitly delimited as data, with
  prompt-injection resistance instructions and no model tools.
- Intent rows are insert/read only; there is no update endpoint.
- Evaluation and analysis only read intents; they never modify them.
- Exact decimal persistence as strings; no float is used for money.
- Client-supplied `risk_score`, `approval_status`, `decision` and similar fields
  are rejected as unknown fields (`extra="forbid"`).
- Payment requests accept only a server-side `transaction_id`; amount, currency,
  merchant and product category always come from persisted evaluation records.
- Order creation requires `ALLOW_FOR_APPROVAL` and revalidates fingerprint,
  expiry, limits, merchant and category first.
- Capture requires a verified PayPal `APPROVED` order, exact amount/currency,
  stored order binding and the durable `BUYER_APPROVED -> CAPTURE_PENDING` claim.
- One payment per transaction; state changes are conditional on state and
  version, so duplicate/concurrent capture claims cannot both execute.
- PayPal base URL is fixed to the sandbox; a live client cannot be constructed.
- Webhooks are signature-verified before persistence, deduplicated by event ID,
  reconciled against stored order IDs, and cannot complete an unclaimed payment.
- Structured logs use an allowlist and omit user/merchant identifiers, purpose
  text, analysis input, credentials and tokens.
- A repeatable adversarial simulation exercises the controls above with real
  services and mocked external providers; its reports are generated from actual
  results and contain no secrets.

Not implemented:

- Production user authentication/authorization, API keys, OAuth or multi-tenancy.
  The `approved_by` field is a **demo-only, unauthenticated audit label**.
- A frontend checkout page; return/cancel URLs are redirect hints only.
- Intent revocation, approval workflow UI, or separation-of-duties enforcement.
- Rate limiting, WAF, TLS termination, secrets manager/KMS integration.
- Refunds, voiding, partial captures, multiple captures per order or settlement
  reconciliation.
- Production database migrations (schema is created automatically for local
  development) or multi-instance token-cache coordination.
- Durable audit export, SIEM integration, retention policy or tamper-evident
  audit chaining.

Known limitations:

- The adversarial suite demonstrates the listed guarantees for its deterministic
  scenarios. It does not prove complete protection against every present or
  future attack, and passing scenarios are not a security certification.
- LLM threat detection is probabilistic and cannot guarantee discovery of every
  attack. It is defense-in-depth signal only; deterministic policy remains the
  authorization authority.
- Provider availability is external. When Gemini is unavailable, contextual
  requests safely degrade to human review rather than proceeding.
- An ambiguous PayPal capture outcome remains `CAPTURE_PENDING` until a verified
  webhook reconciles it. Until then, retries are refused to avoid double
  capture; operators must resolve it from PayPal's record.
- If order creation fails ambiguously after the durable claim, the payment is
  marked `FAILED`. An orphan sandbox order may exist at PayPal, but a `FAILED`
  payment can never be captured, so no money can move.
- Webhook delivery depends on PayPal reaching the endpoint and on the configured
  webhook ID remaining valid.
- The in-process retry/backoff, SQLite configuration and in-memory token cache
  are suitable for local development, not multi-instance production deployment.

**Do not deploy this milestone as a production payment gateway.** It is a
deterministic, testable foundation for later authenticated approval and
production payment integrations. It performs sandbox-only money movement and has
no production user authentication.
