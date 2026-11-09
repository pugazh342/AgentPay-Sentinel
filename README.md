# AgentPay Sentinel

Milestone 03 of a zero-trust authorization gateway for AI-agent payments.

The implementation, setup instructions, security model, API documentation and
test commands live in [`backend/README.md`](backend/README.md).

Quick start from the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements-dev.txt
cd backend
Copy-Item .env.example .env
# set AGENTPAY_HMAC_SECRET in .env (>= 32 bytes)
uvicorn app.main:app --reload
```

Run tests from `backend/`:

```powershell
..\.venv\Scripts\python.exe -m pytest
```

PayPal Orders v2 checkout is implemented in **sandbox mode only**; configure
sandbox credentials in `.env` to exercise it (see `backend/README.md`). This
remains a local-development foundation with no production user authentication,
and it is not ready to deploy as a production payment gateway. The AI model can
never authorize, create or capture a payment.
