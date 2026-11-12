/**
 * AgentPay Sentinel - Typed API Client
 *
 * Centralized typed API client for the backend.
 * Backend URL configured via NEXT_PUBLIC_API_BASE_URL.
 * Secrets are never exposed through NEXT_PUBLIC variables.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000';

export interface ErrorDetail {
  field: string;
  message: string;
}

export interface ErrorBody {
  code: string;
  message: string;
  details?: ErrorDetail[];
}

export interface ErrorResponse {
  error: ErrorBody;
}

export function isErrorResponse(data: unknown): data is ErrorResponse {
  return (
    typeof data === 'object' &&
    data !== null &&
    'error' in data &&
    typeof (data as Record<string, unknown>).error === 'object'
  );
}

export function formatError(error: ErrorResponse): string {
  const details = error.error.details
    ?.map((d) => `${d.field}: ${d.message}`)
    .join('; ');
  return `${error.error.code}: ${error.error.message}${details ? ` (${details})` : ''}`;
}

function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Generic API request helper with error handling
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const method = (options.method || 'GET').toUpperCase();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = getCookie('aps_csrf');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && typeof window !== 'undefined') {
      // Expired/invalid session - redirect to login (except when already on login/auth endpoints)
      if (!window.location.pathname.startsWith('/login') && !endpoint.startsWith('/api/v1/auth/login')) {
        window.location.href = '/login';
      }
    }
    if (isErrorResponse(data)) {
      throw new Error(formatError(data));
    }
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return data as T;
}

// Auth
export interface AuthStatusResponse {
  authenticated: boolean;
  operator?: string | null;
}

export async function loginOperator(username: string, password: string): Promise<AuthStatusResponse> {
  return apiRequest<AuthStatusResponse>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export async function logoutOperator(): Promise<AuthStatusResponse> {
  return apiRequest<AuthStatusResponse>('/api/v1/auth/logout', {
    method: 'POST',
  });
}

export async function getAuthSession(): Promise<AuthStatusResponse> {
  return apiRequest<AuthStatusResponse>('/api/v1/auth/session');
}

/**
 * Common types matching backend schemas
 */

export interface HealthChecks {
  database: string;
  hmac_configuration: string;
  ai_provider?: string;
  ai_model?: string;
  ai_status?: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  checks: HealthChecks;
}

export interface IntentCreateRequest {
  user_id: string;
  purpose: string;
  merchant_id: string;
  product_category: string;
  max_amount: string; // Decimal string
  currency: string;
  max_quantity: number;
  require_approval?: boolean;
  expires_at: string; // ISO datetime
}

export interface IntentResponse {
  intent_id: string;
  user_id: string;
  purpose: string;
  merchant_id: string;
  product_category: string;
  max_amount: string; // Decimal string
  currency: string;
  max_quantity: number;
  require_approval: boolean;
  created_at: string;
  expires_at: string;
}

export type Decision = 'BLOCK' | 'REVIEW_REQUIRED' | 'ALLOW_FOR_APPROVAL';

export type ReasonCode =
  | 'UNKNOWN_INTENT'
  | 'USER_MISMATCH'
  | 'INTENT_EXPIRED'
  | 'INVALID_INTENT_FINGERPRINT'
  | 'MERCHANT_MISMATCH'
  | 'CURRENCY_MISMATCH'
  | 'AMOUNT_EXCEEDS_MAXIMUM'
  | 'QUANTITY_EXCEEDS_MAXIMUM'
  | 'PRODUCT_CATEGORY_MISMATCH'
  | 'ALL_CHECKS_PASSED'
  | 'AI_THREAT_ESCALATION'
  | 'AI_ANALYSIS_UNAVAILABLE';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EventType =
  | 'INTENT_CREATED'
  | 'TRANSACTION_EVALUATED'
  | 'THREAT_ANALYSIS_COMPLETED'
  | 'THREAT_ANALYSIS_FAILED'
  | 'PAYMENT_PREPARED'
  | 'PAYMENT_APPROVED'
  | 'PAYMENT_BUYER_RETURN_VERIFIED'
  | 'PAYMENT_CAPTURED'
  | 'PAYMENT_CAPTURE_FAILED'
  | 'PAYMENT_FAILED'
  | 'WEBHOOK_RECEIVED'
  | 'WEBHOOK_VERIFICATION_FAILED';

export interface ThreatFindingResponse {
  category: string;
  severity: string;
  evidence: string;
}

export interface ThreatAnalysisResponse {
  analysis_id: string;
  transaction_id: string;
  analysis_status: 'COMPLETED' | 'UNAVAILABLE' | 'INVALID_RESPONSE';
  provider_status: string;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  detected_threats: ThreatFindingResponse[];
  evidence: string[];
  suspicious_instructions: string[];
  intent_alignment: 'ALIGNED' | 'DEVIATES' | 'UNCLEAR';
  explanation: string;
  recommended_handling: string;
  model_name: string;
  analyzed_at: string;
}

export interface DecisionResponse {
  decision_id: string;
  transaction_id: string;
  intent_id: string;
  decision: Decision;
  reason_codes: ReasonCode[];
  explanation: string;
  evaluated_at: string;
  risk_level: RiskLevel;
  analysis?: ThreatAnalysisResponse;
}

export interface TransactionEvaluationRequest {
  user_id: string;
  intent_id: string;
  merchant_id: string;
  product_category: string;
  amount: string; // Decimal string
  currency: string;
  quantity: number;
  request_id: string;
  analysis_context?: AnalysisContextRequest;
}

export interface AnalysisContextRequest {
  product_title?: string;
  product_description?: string;
  merchant_name?: string;
  agent_reasoning?: string;
  transaction_context?: string;
}

export interface TransactionResponse {
  transaction_id: string;
  request_id: string;
  user_id: string;
  intent_id: string;
  merchant_id: string;
  product_category: string;
  amount: string;
  currency: string;
  quantity: number;
  decision: DecisionResponse;
}

export interface PaymentPrepareRequest {
  transaction_id: string;
}

export interface PaymentApprovalRequest {
  approved_by: string;
}

export type PaymentState =
  | 'PENDING_SECURITY'
  | 'REVIEW_REQUIRED'
  | 'BLOCKED'
  | 'PENDING_USER_APPROVAL'
  | 'PAYPAL_ORDER_CREATED'
  | 'BUYER_APPROVED'
  | 'CAPTURE_PENDING'
  | 'COMPLETED'
  | 'FAILED'
  | 'EXPIRED';

export interface PaymentResponse {
  payment_id: string;
  transaction_id: string;
  intent_id: string;
  amount: string;
  currency: string;
  merchant_id: string;
  product_category: string;
  state: PaymentState;
  paypal_order_id: string | null;
  approval_url: string | null;
  paypal_capture_id: string | null;
  paypal_status: string | null;
  approved_by: string | null;
  approved_at: string | null;
  buyer_approved_at: string | null;
  completed_at: string | null;
  failure_reason: string | null;
  created_at: string;
  updated_at: string;
  version?: number;
}

/**
 * Payment response for listing endpoints - approval_url excluded for security
 */
export interface PaymentResponseSafe {
  payment_id: string;
  transaction_id: string;
  intent_id: string;
  amount: string;
  currency: string;
  merchant_id: string;
  product_category: string;
  state: PaymentState;
  paypal_order_id: string | null;
  paypal_capture_id: string | null;
  paypal_status: string | null;
  approved_by: string | null;
  approved_at: string | null;
  buyer_approved_at: string | null;
  completed_at: string | null;
  failure_reason: string | null;
  created_at: string;
  updated_at: string;
  version?: number;
}

export interface SecurityEventResponse {
  event_id: string;
  transaction_id?: string;
  event_type: string;
  decision?: Decision;
  reason_codes: ReasonCode[];
  timestamp: string;
}

export interface SecurityEventListResponse {
  items: SecurityEventResponse[];
  count: number;
  total_count: number;
  limit: number;
}

/**
 * API Functions
 */

// Health
export async function getHealth(): Promise<HealthResponse> {
  return apiRequest<HealthResponse>('/health');
}

// Intents
export async function createIntent(payload: IntentCreateRequest): Promise<IntentResponse> {
  return apiRequest<IntentResponse>('/api/v1/intents', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getIntent(intentId: string): Promise<IntentResponse> {
  return apiRequest<IntentResponse>(`/api/v1/intents/${intentId}`);
}

export interface IntentListResponse {
  total_count: number;
  limit: number;
  offset: number;
  results: IntentResponse[];
}

export async function listIntents(params?: {
  limit?: number;
  offset?: number;
}): Promise<IntentListResponse> {
  const searchParams = new URLSearchParams();
  if (params?.limit) searchParams.set('limit', String(params.limit));
  if (params?.offset) searchParams.set('offset', String(params.offset));
  const query = searchParams.toString();
  return apiRequest<IntentListResponse>(
    `/api/v1/intents${query ? `?${query}` : ''}`
  );
}

// Transactions
export async function evaluateTransaction(
  payload: TransactionEvaluationRequest
): Promise<DecisionResponse> {
  return apiRequest<DecisionResponse>('/api/v1/transactions/evaluate', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getTransaction(transactionId: string): Promise<TransactionResponse> {
  return apiRequest<TransactionResponse>(`/api/v1/transactions/${transactionId}`);
}

// Analysis
export async function analyzeTransaction(
  transactionId: string,
  payload?: AnalysisContextRequest
): Promise<ThreatAnalysisResponse> {
  return apiRequest<ThreatAnalysisResponse>(
    `/api/v1/analysis/transactions/${transactionId}`,
    {
      method: 'POST',
      body: JSON.stringify(payload ?? {}),
    }
  );
}

export async function getTransactionAnalysis(
  transactionId: string
): Promise<ThreatAnalysisResponse> {
  return apiRequest<ThreatAnalysisResponse>(
    `/api/v1/analysis/transactions/${transactionId}`
  );
}

// Payments
export async function preparePayment(
  payload: PaymentPrepareRequest
): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>('/api/v1/payments', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getPayment(paymentId: string): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>(`/api/v1/payments/${paymentId}`);
}

export async function approvePayment(
  paymentId: string,
  payload: PaymentApprovalRequest
): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>(`/api/v1/payments/${paymentId}/approve`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function buyerReturn(paymentId: string): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>(`/api/v1/payments/${paymentId}/buyer-return`, {
    method: 'POST',
  });
}

export async function capturePayment(paymentId: string): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>(`/api/v1/payments/${paymentId}/capture`, {
    method: 'POST',
  });
}

// Payments Listing
export interface PaymentListResponse {
  total_count: number;
  limit: number;
  offset: number;
  results: PaymentResponseSafe[];
}

export interface PaymentsFilter {
  state?: PaymentState;
  intent_id?: string;
  transaction_id?: string;
  limit?: number;
  offset?: number;
}

export async function listPayments(
  filter?: PaymentsFilter
): Promise<PaymentListResponse> {
  const searchParams = new URLSearchParams();
  if (filter?.state) searchParams.set('state', filter.state);
  if (filter?.intent_id) searchParams.set('intent_id', filter.intent_id);
  if (filter?.transaction_id) searchParams.set('transaction_id', filter.transaction_id);
  if (filter?.limit) searchParams.set('limit', String(filter.limit));
  if (filter?.offset) searchParams.set('offset', String(filter.offset));

  const query = searchParams.toString();
  return apiRequest<PaymentListResponse>(
    `/api/v1/payments${query ? `?${query}` : ''}`
  );
}

export async function getPaymentDetails(paymentId: string): Promise<PaymentResponse> {
  return apiRequest<PaymentResponse>(`/api/v1/payments/${paymentId}`);
}

// Security Events
export async function getSecurityEvents(params?: {
  limit?: number;
  event_type?: string;
  decision?: Decision;
}): Promise<SecurityEventListResponse> {
  const searchParams = new URLSearchParams();
  if (params?.limit) searchParams.set('limit', String(params.limit));
  if (params?.event_type) searchParams.set('event_type', params.event_type);
  if (params?.decision) searchParams.set('decision', params.decision);

  const query = searchParams.toString();
  return apiRequest<SecurityEventListResponse>(
    `/api/v1/security/events${query ? `?${query}` : ''}`
  );
}

// Adversarial Lab - execute via server-side route
export interface AdversarialReport {
  schema_version: number;
  milestone: string;
  summary: {
    all_passed: boolean;
    errors: number;
    failed: number;
    invariants_total: number;
    invariants_verified: number;
    passed: number;
    scenarios_total: number;
    skipped: number;
  };
  invariants: Array<{
    invariant_id: string;
    description: string;
    evidence: string[];
    scenario_ids: string[];
    verified: boolean;
  }>;
  scenarios: Array<{
    attack_id: string;
    name: string;
    category: string;
    description: string;
    attack_input: Record<string, unknown>;
    expected_security_decision: string;
    expected_payment_state: string | null;
    expected_reason_codes: string[];
    actual_result: {
      security_decision: string;
      payment_state: string | null;
      reason_codes: string[];
      checks: Record<string, boolean>;
      details: Record<string, unknown>;
    };
    test_status: 'PASSED' | 'FAILED' | 'ERROR' | 'SKIPPED';
  }>;
}

export async function getAdversarialReport(): Promise<AdversarialReport> {
  // This will be implemented as a server-side route that runs the adversarial runner
  return apiRequest<AdversarialReport>('/api/adversarial/report');
}

export async function runAdversarialScenarios(): Promise<AdversarialReport> {
  return apiRequest<AdversarialReport>('/api/adversarial/run', {
    method: 'POST',
  });
}

// Re-export utility functions
export {
  formatCurrency,
  formatDate,
  formatRelativeTime,
  getDecisionBadgeClass,
  getPaymentStateBadgeClass,
  getThreatLevelBadgeClass,
  getSeverityBadgeClass,
  getStatusBadgeClass,
  truncateAddress,
} from './utils';