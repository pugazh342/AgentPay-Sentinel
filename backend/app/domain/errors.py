"""Domain and application-level errors.

Errors carry a stable public code and safe message. They never carry secrets,
raw exception payloads or client-supplied identity data.
"""

from __future__ import annotations

from app.domain.enums import PayPalStatus


class AppError(Exception):
    """Base class for errors that map to a consistent API error envelope."""

    status_code: int = 500
    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class ValidationFailure(AppError):
    """A domain validation rule rejected an otherwise well-formed request."""

    status_code = 422
    code = "VALIDATION_ERROR"


class NotFoundFailure(AppError):
    """The requested resource does not exist."""

    status_code = 404
    code = "NOT_FOUND"


class SecurityConfigurationFailure(AppError):
    """Fail-closed condition: the gateway cannot perform security checks."""

    status_code = 503
    code = "SECURITY_CONFIGURATION_INVALID"


class PaymentStateFailure(AppError):
    """The requested payment action is not legal in the current state."""

    status_code = 409
    code = "PAYMENT_STATE_INVALID"


class PaymentNotEligible(AppError):
    """Deterministic policy does not permit the requested payment action."""

    status_code = 409
    code = "PAYMENT_NOT_ELIGIBLE"


class CaptureInProgress(AppError):
    """Another request already claimed this payment's capture."""

    status_code = 409
    code = "CAPTURE_IN_PROGRESS"


class PayPalNotConfigured(AppError):
    """PayPal sandbox credentials are absent; payment operations fail closed."""

    status_code = 503
    code = "PAYPAL_NOT_CONFIGURED"


class PayPalProviderFailure(AppError):
    """A PayPal call failed or returned something that cannot be trusted."""

    status_code = 502
    code = "PAYPAL_PROVIDER_ERROR"


class WebhookVerificationFailure(AppError):
    """A webhook could not be verified and must not be reconciled."""

    status_code = 400
    code = "WEBHOOK_SIGNATURE_INVALID"


class AuthenticationFailure(AppError):
    """Missing or invalid operator authentication."""

    status_code = 401
    code = "UNAUTHORIZED"


class AuthorizationFailure(AppError):
    """Authenticated but not permitted to perform the action."""

    status_code = 403
    code = "FORBIDDEN"


class CsrfFailure(AppError):
    """CSRF validation failed for a state-changing request."""

    status_code = 403
    code = "CSRF_INVALID"


class RateLimitFailure(AppError):
    """Too many authentication attempts."""

    status_code = 429
    code = "RATE_LIMITED"


class ConfigurationFailure(Exception):
    """Raised when the fingerprint service cannot be constructed safely."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PayPalGatewayError(Exception):
    """Sanitized provider error raised by the PayPal adapter.

    ``ambiguous`` is true when the provider may have processed the request even
    though no trustworthy response was received. Capture handling uses this to
    avoid declaring a payment failed when it might have succeeded.
    """

    def __init__(
        self,
        message: str,
        *,
        status: PayPalStatus,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.ambiguous = ambiguous
