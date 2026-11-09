"""Closed enums used by the deterministic authorization core."""

from enum import StrEnum


class Decision(StrEnum):
    """Outcome of a deterministic policy evaluation.

    ALLOW_FOR_APPROVAL is an eligibility result only. It is not permission to
    capture, settle or execute a payment.
    """

    ALLOW_FOR_APPROVAL = "ALLOW_FOR_APPROVAL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCK = "BLOCK"


class RiskLevel(StrEnum):
    """Descriptive metadata for operators. Never used for authorization."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ReasonCode(StrEnum):
    """Stable machine-readable reason codes.

    Deterministic policy codes are never produced or replaced by the AI layer.
    AI-specific codes are appended only where reconciliation keeps or raises
    the deterministic outcome.
    """

    ALL_CHECKS_PASSED = "ALL_CHECKS_PASSED"
    UNKNOWN_INTENT = "UNKNOWN_INTENT"
    USER_MISMATCH = "USER_MISMATCH"
    INTENT_EXPIRED = "INTENT_EXPIRED"
    INVALID_INTENT_FINGERPRINT = "INVALID_INTENT_FINGERPRINT"
    MERCHANT_MISMATCH = "MERCHANT_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    AMOUNT_EXCEEDS_MAXIMUM = "AMOUNT_EXCEEDS_MAXIMUM"
    QUANTITY_EXCEEDS_MAXIMUM = "QUANTITY_EXCEEDS_MAXIMUM"
    PRODUCT_CATEGORY_MISMATCH = "PRODUCT_CATEGORY_MISMATCH"
    AI_THREAT_ESCALATION = "AI_THREAT_ESCALATION"
    AI_ANALYSIS_UNAVAILABLE = "AI_ANALYSIS_UNAVAILABLE"


class EventType(StrEnum):
    """Security audit event types."""

    INTENT_CREATED = "INTENT_CREATED"
    TRANSACTION_EVALUATED = "TRANSACTION_EVALUATED"


class ThreatCategory(StrEnum):
    """Closed set of contextual threat categories."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    INTENT_MANIPULATION = "INTENT_MANIPULATION"
    MERCHANT_SUBSTITUTION = "MERCHANT_SUBSTITUTION"
    PRICE_ANOMALY = "PRICE_ANOMALY"
    QUANTITY_MANIPULATION = "QUANTITY_MANIPULATION"
    INSTRUCTION_HIERARCHY_ATTACK = "INSTRUCTION_HIERARCHY_ATTACK"
    SUSPICIOUS_PRODUCT_CONTENT = "SUSPICIOUS_PRODUCT_CONTENT"
    OTHER = "OTHER"


class ThreatLevel(StrEnum):
    """Overall contextual threat level. Advisory only."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatSeverity(StrEnum):
    """Severity attached to an individual detected threat."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IntentAlignment(StrEnum):
    """Whether the proposed transaction still matches the user's intent."""

    ALIGNED = "ALIGNED"
    DEVIATES = "DEVIATES"
    UNCLEAR = "UNCLEAR"


class AnalysisStatus(StrEnum):
    """Outcome of the threat-analysis attempt."""

    COMPLETED = "COMPLETED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"


class ProviderStatus(StrEnum):
    """Sanitized provider outcome recorded for audit purposes."""

    OK = "OK"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"


class PaymentState(StrEnum):
    """Durable payment workflow state.

    The deterministic decision made at evaluation time is never sufficient on
    its own to reach ``CAPTURE_PENDING`` or ``COMPLETED``. Every transition is
    checked against ``ALLOWED_TRANSITIONS`` and applied conditionally.
    """

    PENDING_SECURITY = "PENDING_SECURITY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCKED = "BLOCKED"
    PENDING_USER_APPROVAL = "PENDING_USER_APPROVAL"
    PAYPAL_ORDER_CREATED = "PAYPAL_ORDER_CREATED"
    BUYER_APPROVED = "BUYER_APPROVED"
    CAPTURE_PENDING = "CAPTURE_PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class PayPalStatus(StrEnum):
    """Sanitized PayPal outcome recorded for audit purposes.

    Raw provider payloads, credentials and tokens are never stored here.
    """

    OK = "OK"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    REJECTED = "REJECTED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
