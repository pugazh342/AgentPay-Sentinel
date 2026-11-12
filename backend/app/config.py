"""Environment-backed configuration.

The HMAC secret is wrapped in ``SecretStr`` so accidental repr/logging cannot
reveal it. There is no default secret: absence means fail-closed operation.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PAYPAL_SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTPAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    hmac_secret: SecretStr | None = Field(
        default=None,
        description="Server-side HMAC-SHA256 secret, minimum 32 bytes.",
    )
    database_url: str = Field(
        default="sqlite:///./agentpay.db",
        description="SQLAlchemy database URL. Local milestone uses SQLite.",
    )
    environment: str = Field(default="local")
    log_level: str = Field(default="INFO")

    # AI Provider selection
    ai_provider: str = Field(
        default="groq",
        validation_alias=AliasChoices(
            "AI_PROVIDER",
            "AGENTPAY_AI_PROVIDER",
        ),
        description="Active AI provider: 'groq' or 'gemini'.",
    )

    # Groq provider settings
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GROQ_API_KEY",
            "AGENTPAY_GROQ_API_KEY",
        ),
        description="Groq API key. Never logged or returned.",
    )
    groq_model: str = Field(
        default="llama-3.3-70b-versatile",
        validation_alias=AliasChoices(
            "GROQ_MODEL",
            "AGENTPAY_GROQ_MODEL",
        ),
        description="Groq model identifier; must support structured JSON output.",
    )

    # Gemini provider settings (kept for optional fallback)
    gemini_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GEMINI_API_KEY",
            "AGENTPAY_GEMINI_API_KEY",
        ),
        description="Google GenAI API key. Never logged or returned.",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        validation_alias=AliasChoices(
            "GEMINI_MODEL",
            "AGENTPAY_GEMINI_MODEL",
        ),
        description="Gemini model identifier; not hardcoded in business logic.",
    )

    # Shared provider settings (reused for both providers)
    ai_timeout_ms: int = Field(
        default=15_000,
        ge=1_000,
        le=120_000,
        validation_alias=AliasChoices(
            "AI_TIMEOUT_MS",
            "AGENTPAY_AI_TIMEOUT_MS",
            "GEMINI_TIMEOUT_MS",
            "AGENTPAY_GEMINI_TIMEOUT_MS",
        ),
        description="Provider request timeout in milliseconds.",
    )
    ai_max_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        validation_alias=AliasChoices(
            "AI_MAX_RETRIES",
            "AGENTPAY_AI_MAX_RETRIES",
            "GEMINI_MAX_RETRIES",
            "AGENTPAY_GEMINI_MAX_RETRIES",
        ),
        description="Bounded transient-failure retries (additional attempts).",
    )
    ai_retry_backoff_seconds: float = Field(
        default=0.5,
        ge=0.0,
        le=5.0,
        validation_alias=AliasChoices(
            "AI_RETRY_BACKOFF_SECONDS",
            "AGENTPAY_AI_RETRY_BACKOFF_SECONDS",
            "GEMINI_RETRY_BACKOFF_SECONDS",
            "AGENTPAY_GEMINI_RETRY_BACKOFF_SECONDS",
        ),
        description="Initial exponential-backoff delay for retries.",
    )

    paypal_environment: str = Field(
        default="sandbox",
        validation_alias=AliasChoices(
            "PAYPAL_ENVIRONMENT",
            "AGENTPAY_PAYPAL_ENVIRONMENT",
        ),
        description="Must remain 'sandbox'. Live payment execution is prohibited.",
    )
    paypal_client_id: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "PAYPAL_CLIENT_ID",
            "AGENTPAY_PAYPAL_CLIENT_ID",
        ),
        description="PayPal sandbox REST app client ID. Never logged.",
    )
    paypal_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "PAYPAL_CLIENT_SECRET",
            "AGENTPAY_PAYPAL_CLIENT_SECRET",
        ),
        description="PayPal sandbox REST app secret. Never logged.",
    )
    paypal_webhook_id: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "PAYPAL_WEBHOOK_ID",
            "AGENTPAY_PAYPAL_WEBHOOK_ID",
        ),
        description="PayPal webhook ID used for verify-webhook-signature.",
    )
    paypal_return_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "PAYPAL_RETURN_URL",
            "AGENTPAY_PAYPAL_RETURN_URL",
        ),
        description="Sandbox buyer return URL supplied to PayPal.",
    )
    paypal_cancel_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "PAYPAL_CANCEL_URL",
            "AGENTPAY_PAYPAL_CANCEL_URL",
        ),
        description="Sandbox buyer cancel URL supplied to PayPal.",
    )
    paypal_timeout_ms: int = Field(
        default=15_000,
        ge=1_000,
        le=60_000,
        description="PayPal HTTP timeout in milliseconds.",
    )
    paypal_max_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Bounded retries for transient PayPal failures.",
    )
    paypal_retry_backoff_seconds: float = Field(
        default=0.5,
        ge=0.0,
        le=5.0,
        description="Initial exponential-backoff delay for PayPal retries.",
    )
    paypal_token_skew_seconds: int = Field(
        default=60,
        ge=0,
        le=300,
        description="Refresh PayPal tokens this many seconds before expiry.",
    )

    # --- Operator auth (single-operator hackathon demo boundary) ---
    operator_username: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OPERATOR_USERNAME",
            "AGENTPAY_OPERATOR_USERNAME",
        ),
        description="Single operator username. Required to enable auth.",
    )
    operator_password_hash: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OPERATOR_PASSWORD_HASH",
            "AGENTPAY_OPERATOR_PASSWORD_HASH",
        ),
        description=(
            "PBKDF2-SHA256 password hash in format "
            "pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>."
        ),
    )
    operator_session_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OPERATOR_SESSION_SECRET",
            "AGENTPAY_OPERATOR_SESSION_SECRET",
        ),
        description="Secret used to sign operator session and CSRF tokens.",
    )
    operator_session_ttl_seconds: int = Field(
        default=3600,
        ge=300,
        le=86400,
        validation_alias=AliasChoices(
            "OPERATOR_SESSION_TTL_SECONDS",
            "AGENTPAY_OPERATOR_SESSION_TTL_SECONDS",
        ),
        description="Operator session lifetime in seconds.",
    )
    operator_cookie_secure: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "OPERATOR_COOKIE_SECURE",
            "AGENTPAY_OPERATOR_COOKIE_SECURE",
        ),
        description="Set Secure flag on auth cookies (required for HTTPS/prod).",
    )
    auth_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "AUTH_ENABLED",
            "AGENTPAY_AUTH_ENABLED",
        ),
        description="Enable operator authentication enforcement.",
    )

    # --- Adversarial runner (local demo only, explicitly enabled) ---
    adversarial_runner_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "ADVERSARIAL_RUNNER_ENABLED",
            "AGENTPAY_ADVERSARIAL_RUNNER_ENABLED",
        ),
        description=(
            "Explicitly enable the local adversarial runner endpoint. "
            "Disabled by default."
        ),
    )
    adversarial_runner_timeout_seconds: int = Field(
        default=300,
        ge=30,
        le=1800,
        validation_alias=AliasChoices(
            "ADVERSARIAL_RUNNER_TIMEOUT_SECONDS",
            "AGENTPAY_ADVERSARIAL_RUNNER_TIMEOUT_SECONDS",
        ),
        description="Bounded execution time for adversarial runner requests.",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be a standard logging level")
        return normalized

    @field_validator("gemini_model")
    @classmethod
    def validate_gemini_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("gemini_model must not be blank")
        return normalized

    @field_validator("paypal_environment")
    @classmethod
    def validate_paypal_environment(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized != "sandbox":
            raise ValueError(
                "paypal_environment must be 'sandbox'; live payments are prohibited"
            )
        return normalized

    @field_validator("paypal_return_url", "paypal_cancel_url")
    @classmethod
    def validate_paypal_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if not normalized.startswith(("https://", "http://")):
            raise ValueError("PayPal redirect URLs must be absolute http(s) URLs")
        return normalized

    @property
    def hmac_secret_value(self) -> str | None:
        """Explicit accessor; callers must never log the returned value."""

        return self.hmac_secret.get_secret_value() if self.hmac_secret else None

    @property
    def gemini_api_key_value(self) -> str | None:
        """Explicit accessor; callers must never log the returned value."""

        return (
            self.gemini_api_key.get_secret_value()
            if self.gemini_api_key
            else None
        )

    @property
    def paypal_client_id_value(self) -> str | None:
        """Explicit accessor; callers must never log the returned value."""

        return (
            self.paypal_client_id.get_secret_value().strip()
            if self.paypal_client_id
            else None
        )

    @property
    def paypal_client_secret_value(self) -> str | None:
        """Explicit accessor; callers must never log the returned value."""

        return (
            self.paypal_client_secret.get_secret_value().strip()
            if self.paypal_client_secret
            else None
        )

    @property
    def paypal_webhook_id_value(self) -> str | None:
        return (
            self.paypal_webhook_id.get_secret_value().strip()
            if self.paypal_webhook_id
            else None
        )

    @property
    def paypal_base_url(self) -> str:
        """Fixed sandbox API origin. There is deliberately no live override."""

        return PAYPAL_SANDBOX_BASE_URL

    @property
    def paypal_configured(self) -> bool:
        return bool(
            self.paypal_client_id_value and self.paypal_client_secret_value
        )

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"groq", "gemini"}:
            raise ValueError("ai_provider must be 'groq' or 'gemini'")
        return normalized

    @field_validator("groq_model")
    @classmethod
    def validate_groq_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("groq_model must not be blank")
        return normalized

    @property
    def groq_api_key_value(self) -> str | None:
        """Explicit accessor; callers must never log the returned value."""

        return self.groq_api_key.get_secret_value() if self.groq_api_key else None

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key_value)

    @property
    def active_provider(self) -> str:
        """Returns the currently configured AI provider name."""
        return self.ai_provider

    @property
    def active_model(self) -> str:
        """Returns the model name for the currently active provider."""
        if self.ai_provider == "groq":
            return self.groq_model
        return self.gemini_model

    @property
    def active_provider_configured(self) -> bool:
        """Returns whether the currently active provider is configured."""
        if self.ai_provider == "groq":
            return self.groq_configured
        return self.gemini_api_key_value is not None

    @property
    def operator_username_value(self) -> str | None:
        v = self.operator_username.strip() if self.operator_username else None
        return v or None

    @property
    def operator_password_hash_value(self) -> str | None:
        return (
            self.operator_password_hash.get_secret_value()
            if self.operator_password_hash
            else None
        )

    @property
    def operator_session_secret_value(self) -> str | None:
        return (
            self.operator_session_secret.get_secret_value()
            if self.operator_session_secret
            else None
        )

    @property
    def operator_auth_configured(self) -> bool:
        return bool(
            self.auth_enabled
            and self.operator_username_value
            and self.operator_password_hash_value
            and self.operator_session_secret_value
            and len((self.operator_session_secret_value or "").encode("utf-8")) >= 32
        )
