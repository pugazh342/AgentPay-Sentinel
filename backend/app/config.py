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
    gemini_timeout_ms: int = Field(
        default=15_000,
        ge=1_000,
        le=120_000,
        description="Provider request timeout in milliseconds.",
    )
    gemini_max_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Bounded transient-failure retries (additional attempts).",
    )
    gemini_retry_backoff_seconds: float = Field(
        default=0.5,
        ge=0.0,
        le=5.0,
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
