# AgentPay Sentinel

**Zero-trust authorization gateway for AI-agent payments** — an independent hackathon project (not officially affiliated with PayPal).

AgentPay Sentinel demonstrates how AI-driven payment actions can be constrained by deterministic policy, immutable user intent, explicit approval, exact PayPal binding, and auditable security evidence in a controlled **PayPal Sandbox** demo.

## Problem
AI agents can be manipulated (prompt injection, coercion, misalignment) or can make unsafe payment decisions. Letting an AI model directly authorize or execute payments creates unacceptable risk: payment actions must be bounded by user intent, policy, and verifiable controls.

## Solution and differentiators
- **Zero-trust control plane:** deterministic authorization is the sole authority for payment progression.
- **AI is advisory only:** Groq threat analysis provides risk signals/context but **cannot authorize, approve, capture, or override deterministic policy**.
- **Immutable purchase intent + HMAC fingerprint:** intents are fingerprinted server-side and revalidated to detect tampering.
- **Exact payment binding:** transaction/payment linkage and PayPal identifiers (including `custom_id`/order-capture binding checks) must match exactly.
- **Explicit approval workflow:** buyer approval, return verification, and capture follow controlled state transitions.
- **Verified webhooks:** PayPal webhook verification/reconciliation handled with sandbox-only controls.
- **Auditability:** security events and audit explorer surfaces for traceable decisions.
- **Adversarial security lab:** offline, deterministic/stubbed attack simulation harness with evidence reporting.

## Architecture and components
| Component | Purpose |
|---|---|
| **Backend (FastAPI, Python 3.12+)** | Intent creation, deterministic transaction evaluation, threat-analysis integration, PayPal Sandbox Orders v2 orchestration, auth/CSRF/session controls, persistence, security events, adversarial report API |
| **Frontend (Next.js, TypeScript, Tailwind)** | Operator dashboard: login, overview, payments, purchase intents, transactions, threat intelligence, approval workflow, audit explorer, adversarial lab, settings |
| **SQLite (local)** | Durable local demo storage (`backend/agentpay.db`, not committed) |
| **PayPal Sandbox Orders v2** | Sandbox-only order/create-approve-capture flow and webhook verification |
| **Groq (advisory AI)** | Threat/risk analysis provider (configurable; deterministic policy remains authoritative) |

Repository layout (high level):
- `backend/app/` — API routes, schemas, domain logic/policy, application services, PayPal client, persistence, security
- `backend/tests/` — backend test suite and adversarial harness/scenarios
- `backend/scripts/` — utilities (e.g. operator provisioning, adversarial runner)
- `backend/reports/` — selected evidence/report artifacts included for submission (validated adversarial report)
- `frontend/src/` — Next.js app, dashboard pages, UI components, API client/utilities
- `skills/` — reference security/agent playbooks (documentation/reference material)

## PayPal + AI usage (clear)
### PayPal (Sandbox only)
- **Integration:** PayPal Orders v2 in **sandbox** mode only.
- **Controls:** sandbox configuration enforced; order creation, buyer approval/return verification, capture, and webhook verification are bound to deterministic application state and exact identifiers.
- **Evidence:** includes a verified **$5.00 USD** sandbox end-to-end completed payment evidence:
  - Payment: `dc0beb4e-fec6-4a18-aac2-30a73a34dbea` (`COMPLETED`)
  - PayPal order: `37J20171MC6168443`
  - PayPal capture: `1JC83947MJ785141R`

### AI (Groq, advisory only)
- **Provider/model:** Groq advisory analysis using `openai/gpt-oss-120b` (configurable via environment).
- **Role:** produces advisory threat/risk analysis signals for operator/security context.
- **Hard boundary:** AI output **cannot** override deterministic authorization policy, cannot approve/capture payments, and cannot bypass intent/fingerprint/binding/state controls.

## Verified security/test evidence (from project QA artifacts)
- **Adversarial (offline, stub/mock-only harness):** `52/52` scenarios passed, `0` failed/errors/skipped, **10 attack categories**, **14/14 invariants** verified (`all_passed=true`). See `backend/reports/adversarial_report.json` and `backend/reports/adversarial_report.md`.
- **Backend tests:** `424 passed, 4 skipped, 0 failed` (428 total).
- **Frontend tests:** `46 passed, 0 failed`.
- **Local sandbox demo posture:** controlled localhost-only demo; not production-ready.

## Windows setup and run (functional local build)

### Prerequisites
- **Python 3.12+** (`py -3.12` recommended)
- **Node.js 18+** and npm
- Windows PowerShell
- (Optional, for full PayPal/Groq demo) PayPal Developer Sandbox REST app credentials and a Groq API key

### 1) Clone and create Python environment
From repository root:
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements-dev.txt
```

### 2) Backend configuration (`backend/.env`)
```powershell
cd backend
Copy-Item .env.example .env
```
Edit `backend/.env` and set **at minimum** (names only; never commit real values):
- `AGENTPAY_HMAC_SECRET` — required, >= 32 bytes (example generator):  
  `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- `AGENTPAY_DATABASE_URL=sqlite:///./agentpay.db`
- `AGENTPAY_ENVIRONMENT=local`
- `PAYPAL_ENVIRONMENT=sandbox`

For **operator login** (local demo auth), provision credentials locally (interactive; do not pass secrets on CLI):
```powershell
# from backend/ with venv active
..\.venv\Scripts\python.exe scripts/provision_local_operator.py
```
This updates `backend/.env` safely with `AGENTPAY_OPERATOR_*` values (username/hash/session secret). Keep `AGENTPAY_AUTH_ENABLED=true` for protected dashboard/API flows.

**Optional integrations (sandbox/demo):**
- **Groq advisory AI:** `AGENTPAY_AI_PROVIDER=groq`, `GROQ_API_KEY`, `AGENTPAY_GROQ_MODEL=openai/gpt-oss-120b`
- **PayPal Sandbox:** `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID` (sandbox app), and return/cancel URLs as needed

> See `backend/.env.example` for all supported environment variable names and local defaults.

### 3) Frontend configuration (`frontend/.env.local`)
In a new terminal from repo root:
```powershell
cd frontend
Copy-Item .env.example .env.local
```
Ensure `NEXT_PUBLIC_API_BASE_URL` points to the backend you run (e.g. `http://127.0.0.1:8002`).

### 4) Install frontend dependencies
```powershell
npm install
```

### 5) Run backend (localhost)
From `backend/` with venv active (example used in local demo):
```powershell
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8002
```
- API: `http://127.0.0.1:8002`
- Docs: `http://127.0.0.1:8002/docs`
- Health: `http://127.0.0.1:8002/health`

(You may use port `8000` instead; keep frontend `NEXT_PUBLIC_API_BASE_URL` consistent.)

### 6) Run frontend
Development:
```powershell
cd frontend
npm run dev
```
Production build + start (localhost example):
```powershell
npm run build
npx next start -H 127.0.0.1 -p 3002
```
Open the dashboard URL shown (e.g. `http://127.0.0.1:3002` or `http://localhost:3000` for dev) and log in with the locally provisioned operator credentials.

## How judges can reproduce a functional LOCAL demo
1. Complete Windows setup above (backend + frontend running, `NEXT_PUBLIC_API_BASE_URL` aligned).
2. Configure `AGENTPAY_HMAC_SECRET` and provision local operator auth; start backend and frontend.
3. Log in and navigate dashboard pages (Overview, Intents, Transactions, Payments, Threat Intelligence, Approval Workflow, Audit Explorer, Adversarial Lab, Settings).
4. **Deterministic/offline checks (no external credentials required):**
   - Run backend tests and frontend tests/build (see below).
   - Review included adversarial evidence: `backend/reports/adversarial_report.json` and `.md` (52/52, 10 categories, 14/14 invariants).
5. **PayPal Sandbox end-to-end (requires your own sandbox credentials):** configure `PAYPAL_CLIENT_ID/SECRET/WEBHOOK_ID` in `backend/.env`, restart backend, and use the approval workflow with PayPal sandbox buyer accounts. **No real credentials are provided in this repository.**
6. **Groq advisory analysis (requires your own API key):** set `GROQ_API_KEY` and provider/model env vars, restart backend, and run threat analysis flows. **No API keys are provided.**

## Sandbox test account setup (no real credentials)
- Create a PayPal Developer account and a **Sandbox REST app** to obtain sandbox `Client ID` / `Secret` and configure webhook as needed.
- Create/use **sandbox buyer/seller test accounts** in PayPal Developer Dashboard for approval/capture testing.
- Enter credentials only in your local `backend/.env` (never commit). This repo ships **`.env.example` templates only**.

## Running tests and checks
### Backend (from `backend/`, venv active)
```powershell
..\.venv\Scripts\python.exe -m pytest -q
```
Verified baseline in this project state: **424 passed, 4 skipped, 0 failed**.

### Frontend (from `frontend/`)
```powershell
npm test
npx tsc --noEmit
npx eslint .
npm run build
```
Verified baseline in this project state: **46 passed**, TypeScript/lint/build successful.

### Offline adversarial report regeneration (optional, local/stubbed)
From `backend/`:
```powershell
..\.venv\Scripts\python.exe scripts/run_adversarial.py --json reports/adversarial_report.json --markdown reports/adversarial_report.md
```
Runs the offline stub/mock harness (no live PayPal/Groq). Use isolated temp output paths if you want to avoid overwriting published evidence.

## Troubleshooting
- **`401/403` or redirect to login:** ensure operator auth is provisioned/enabled in `backend/.env`, backend restarted, and frontend points to correct backend URL.
- **`503` / HMAC configuration errors:** set a valid `AGENTPAY_HMAC_SECRET` (>= 32 bytes) and restart backend.
- **Frontend cannot reach API:** verify `frontend/.env.local` `NEXT_PUBLIC_API_BASE_URL`, backend host/port, and that backend is running.
- **PayPal actions fail or are unavailable:** confirm sandbox credentials/webhook ID and `PAYPAL_ENVIRONMENT=sandbox`; check backend logs (local only) and sandbox account state.
- **AI analysis unavailable:** set `GROQ_API_KEY` (or selected provider key) and restart; deterministic flows remain available per policy behavior.
- **Port conflicts:** change uvicorn/Next ports and keep frontend API base URL aligned.

## Known limitations (controlled demo)
- **Localhost-only, single-operator demo** (no RBAC/multi-tenancy, limited session revocation/production auth hardening).
- **Not production-ready**: additional security, compliance, secret management, monitoring, scaling, and operational controls required.
- **SQLite local storage** and in-memory/runtime constraints suitable for demo only.
- **Adversarial runner** is bounded/gated for local demo; timeout does not forcibly cancel in-process work in all cases.
- Some environment-specific checks (manual browser viewport/console spot checks, live sandbox operations) depend on local setup and credentials.

## License and attribution
- Licensed under the MIT License. See [`LICENSE`](LICENSE).
- **Independent project; not officially affiliated with PayPal.** PayPal is referenced only for sandbox integration compatibility in this demo.

## Additional notes
- No real credentials, `.env` files, databases, cookies, or private logs are included.
- Screenshots are not bundled in this repository snapshot; UI can be viewed by running the frontend locally.
- Local security/reference playbooks are included under `skills/` for context; core project evidence is in `backend/tests/`, `backend/scripts/run_adversarial.py`, and `backend/reports/adversarial_report.*`.
