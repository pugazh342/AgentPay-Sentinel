"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { isValidApprovalUrl, displayApprovalUrl } from "@/lib/paypal-approval-url";

import {
  CheckSquare,
  Shield,
  Clock,
  CreditCard,
  Eye,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  evaluateTransaction,
  preparePayment,
  approvePayment,
  buyerReturn,
  capturePayment,
  getPayment,
  getTransaction,
  DecisionResponse,
  TransactionResponse,
  PaymentResponse,
  PaymentState,
  formatCurrency,
  getDecisionBadgeClass,
  getPaymentStateBadgeClass,
} from "@/lib/api";

type WorkflowStep = "evaluate" | "prepare" | "approve" | "buyer-return" | "capture";

export default function ApprovalWorkflowPage() {
  const router = useRouter();
  const [step, setStep] = useState<WorkflowStep>("evaluate");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data state
  const [decision, setDecision] = useState<DecisionResponse | null>(null);
  const [transaction, setTransaction] = useState<TransactionResponse | null>(null);
  const [payment, setPayment] = useState<PaymentResponse | null>(null);

  // PayPal buyer-return correlation (client-side only, never authorization)
  const [returnToken, setReturnToken] = useState<string | null>(null);
  const [correlatedPaymentId, setCorrelatedPaymentId] = useState<string | null>(null);
  const [correlationError, setCorrelationError] = useState<string | null>(null);
  const [returnLoading, setReturnLoading] = useState(false);
  const [returnMessage, setReturnMessage] = useState<string | null>(null);
  const processedReturnRef = useRef(false);

  // Forms
  const [evalForm, setEvalForm] = useState({
    user_id: "user_123",
    intent_id: "",
    merchant_id: "merchant_shoes",
    product_category: "footwear",
    amount: "800.00",
    currency: "USD",
    quantity: 1,
    request_id: "",
  });

  useEffect(() => {
    const timer = setTimeout(() => {
      setEvalForm((prev) => ({ ...prev, request_id: `req_${Date.now()}` }));
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // Recognize PayPal buyer-return parameters without trusting them as proof.
  useEffect(() => {
    if (processedReturnRef.current) return;
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    if (!token) return;
    processedReturnRef.current = true;

    // Validate token format (PayPal order id).
    const validFormat = /^[A-Za-z0-9-]{1,128}$/.test(token);

    let storedPaymentId: string | null = null;
    let storedOrderId: string | null = null;
    try {
      storedPaymentId = sessionStorage.getItem('agentpay_return_payment_id');
      storedOrderId = sessionStorage.getItem('agentpay_return_order_id');
    } catch {
      storedPaymentId = null;
      storedOrderId = null;
    }

    // Remove sensitive params from the URL regardless of outcome.
    window.history.replaceState({}, '', window.location.pathname);

    const timer = setTimeout(() => {
      if (!validFormat) {
        setCorrelationError('Invalid return parameters.');
        return;
      }
      setReturnToken(token);

      if (!storedPaymentId || !storedOrderId) {
        setCorrelationError('No matching payment session found. Locate the payment manually in Payments.');
        return;
      }
      if (storedOrderId !== token) {
        setCorrelationError('Return token does not match the expected order. Verification aborted.');
        try {
          sessionStorage.removeItem('agentpay_return_payment_id');
          sessionStorage.removeItem('agentpay_return_order_id');
        } catch {
          // ignore
        }
        return;
      }
      setCorrelatedPaymentId(storedPaymentId);
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // Fetch the correlated payment's status (read-only) once correlated.
  useEffect(() => {
    if (!correlatedPaymentId) return;
    (async () => {
      setReturnLoading(true);
      setReturnMessage(null);
      try {
        const p = await getPayment(correlatedPaymentId);
        setPayment(p);
        if (p.state === 'BUYER_APPROVED' || p.state === 'COMPLETED' || p.state === 'CAPTURE_PENDING') {
          setReturnMessage('Approval already verified by the server. No redundant verification performed.');
          try {
            sessionStorage.removeItem('agentpay_return_payment_id');
            sessionStorage.removeItem('agentpay_return_order_id');
          } catch {
            // ignore
          }
        } else if (p.state === 'PAYPAL_ORDER_CREATED') {
          setReturnMessage('Buyer return received. Click "Verify Approval" to re-verify with PayPal.');
        } else {
          setReturnMessage(`Payment is in state ${p.state}. No buyer verification available.`);
        }
      } catch (err) {
        setCorrelationError((err instanceof Error ? err.message : '') || 'Failed to load payment status.');
      } finally {
        setReturnLoading(false);
      }
    })();
  }, [correlatedPaymentId]);

  const handleVerifyApproval = async () => {
    if (!correlatedPaymentId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await buyerReturn(correlatedPaymentId);
      setPayment(result);
      if (result.state === 'BUYER_APPROVED' || result.state === 'COMPLETED' || result.state === 'CAPTURE_PENDING') {
        setReturnMessage('Approval verified by PayPal. Proceed to capture when ready.');
      } else if (result.state === 'FAILED') {
        setReturnMessage(result.failure_reason || 'Buyer return verification failed.');
      }
      try {
        sessionStorage.removeItem('agentpay_return_payment_id');
        sessionStorage.removeItem('agentpay_return_order_id');
      } catch {
        // ignore
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : '') || 'Buyer return verification failed.');
    } finally {
      setLoading(false);
    }
  };

  const [paymentIdInput, setPaymentIdInput] = useState("");
  const [approvedBy, setApprovedBy] = useState("demo_operator");

  async function handleEvaluate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await evaluateTransaction(evalForm);
      setDecision(result);
      setTransaction(null);
      setPayment(null);
      setStep("prepare");
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Evaluation failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handlePrepare() {
    if (!decision?.transaction_id) return;
    setLoading(true);
    setError(null);
    try {
      const result = await preparePayment({ transaction_id: decision.transaction_id });
      setPayment(result);

      // CRITICAL: Only advance to approve step if payment is in a valid state.
      // BLOCKED, REVIEW_REQUIRED, FAILED, EXPIRED must NOT advance the workflow.
      if (result.state === "PENDING_USER_APPROVAL") {
        setStep("approve");
      } else {
        // Show error message for blocked/review/ineligible payments
        const stateMessage: Record<PaymentState, string> = {
          PENDING_SECURITY: "Payment requires security review.",
          REVIEW_REQUIRED: "Transaction requires human review.",
          BLOCKED: "Transaction blocked by deterministic policy.",
          PENDING_USER_APPROVAL: "User approval required.",
          PAYPAL_ORDER_CREATED: "PayPal order created.",
          BUYER_APPROVED: "Buyer approved.",
          CAPTURE_PENDING: "Capture pending.",
          COMPLETED: "Payment completed.",
          FAILED: result.failure_reason || "Payment preparation failed.",
          EXPIRED: "Purchase intent has expired.",
        };
        setError(stateMessage[result.state] || `Payment in unexpected state: ${result.state}`);
        setStep("evaluate");
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Payment preparation failed.");
      setStep("evaluate");
    } finally {
      setLoading(false);
    }
  }

  async function handleApprove() {
    if (!payment?.payment_id) return;
    setLoading(true);
    setError(null);
    try {
      const result = await approvePayment(payment.payment_id, { approved_by: approvedBy });
      setPayment(result);

      // Validate the returned payment state after approval
      if (result.state === "PAYPAL_ORDER_CREATED" && result.approval_url) {
        setStep("buyer-return");
      } else {
        setError(`Approval did not create valid PayPal order. State: ${result.state}`);
        setStep("evaluate");
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Approval failed.");
      setStep("evaluate");
    } finally {
      setLoading(false);
    }
  }

  async function handleBuyerReturn() {
    if (!payment?.payment_id) return;
    setLoading(true);
    setError(null);
    try {
      const result = await buyerReturn(payment.payment_id);
      setPayment(result);

      // Only advance to capture if we have BUYER_APPROVED state with a capture_id
      if (result.state === "BUYER_APPROVED") {
        setStep("capture");
      } else if (result.state === "COMPLETED") {
        // Payment completed early (via webhook)
        setStep("capture");
      } else if (result.state === "FAILED") {
        setError(result.failure_reason || "Buyer return verification failed.");
        setStep("evaluate");
      } else {
        // Stay on buyer-return step for PAYPAL_ORDER_CREATED state
        // The buyer may need to click through again
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Buyer return verification failed.");
      setStep("buyer-return");
    } finally {
      setLoading(false);
    }
  }

  async function handleCapture() {
    if (!payment?.payment_id) return;
    setLoading(true);
    setError(null);
    try {
      const result = await capturePayment(payment.payment_id);
      setPayment(result);

      // Validate capture result
      if (result.state === "COMPLETED") {
        // Capture successful - stay on capture page or show completion message
      } else if (result.state === "FAILED") {
        setError(result.failure_reason || "Capture failed.");
        setStep("buyer-return");
      } else if (result.state === "CAPTURE_PENDING") {
        // Expected for new capture attempts
      } else {
        setError(`Capture returned unexpected state: ${result.state}`);
        setStep("buyer-return");
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Capture failed.");
      setStep("buyer-return");
    } finally {
      setLoading(false);
    }
  }

  async function handleFetchPayment(e: React.FormEvent) {
    e.preventDefault();
    if (!paymentIdInput.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const result = await getPayment(paymentIdInput.trim());
      setPayment(result);

      // Validate payment state before routing to next step.
      // BLOCKED, REVIEW_REQUIRED, FAILED, EXPIRED are terminal states.
      if (result.state === "BLOCKED") {
        setError("Payment is blocked.");
        setStep("evaluate");
      } else if (result.state === "REVIEW_REQUIRED") {
        setError("Payment requires human review.");
        setStep("evaluate");
      } else if (result.state === "FAILED" && result.failure_reason) {
        setError(`Payment failed: ${result.failure_reason}`);
        setStep("evaluate");
      } else if (result.state === "EXPIRED") {
        setError("Payment intent has expired.");
        setStep("evaluate");
      } else {
        // Determine step based on valid payment state
        switch (result.state) {
          case "PENDING_USER_APPROVAL":
            setStep("approve");
            break;
          case "PAYPAL_ORDER_CREATED":
            setStep("buyer-return");
            break;
          case "BUYER_APPROVED":
          case "CAPTURE_PENDING":
            setStep("capture");
            break;
          default:
            setStep("evaluate");
        }
      }
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Payment not found.");
    } finally {
      setLoading(false);
    }
  }

  const steps: { key: WorkflowStep; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { key: "evaluate", label: "1. Evaluate", icon: Shield },
    { key: "prepare", label: "2. Prepare", icon: CreditCard },
    { key: "approve", label: "3. Approve", icon: CheckSquare },
    { key: "buyer-return", label: "4. Buyer Return", icon: RefreshCw },
    { key: "capture", label: "5. Capture", icon: Clock },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Approval Workflow</h1>
        <p className="text-muted-foreground">
          Deterministic authorization → PayPal sandbox order → Buyer verification → Capture.
          All operations revalidate server-side state. Browser parameters are never trusted.
        </p>
      </div>

      {correlationError && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 flex items-center justify-between gap-4">
          <div>
            <p className="font-semibold">Return correlation failed</p>
            <p className="text-sm text-red-600 mt-1">{correlationError}</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => router.push('/payments')} className="border-red-700 text-red-700">
            Go to Payments
          </Button>
        </div>
      )}

      {returnToken && (
        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-blue-900 space-y-3">
          <p className="font-semibold">PayPal buyer return detected</p>
          {returnLoading ? (
            <p className="text-sm text-accent">Loading payment status...</p>
          ) : returnMessage ? (
            <p className="text-sm text-accent">{returnMessage}</p>
          ) : null}
          {correlatedPaymentId && payment && payment.state === 'PAYPAL_ORDER_CREATED' && (
            <Button onClick={handleVerifyApproval} disabled={loading} className="bg-primary hover:bg-primary/90">
              {loading ? 'Verifying...' : 'Verify Approval'}
            </Button>
          )}
          {payment && (payment.state === 'BUYER_APPROVED' || payment.state === 'COMPLETED' || payment.state === 'CAPTURE_PENDING') && (
            <p className="text-xs text-accent">Approval already verified by the server. No redundant verification performed.</p>
          )}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-red-600" />
            <p className="font-semibold">Error</p>
          </div>
          <p className="text-sm text-red-600 mt-1">{error}</p>
        </div>
      )}

      {/* Progress Steps */}
      <Card className="border-border bg-card">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            {steps.map((s, idx) => {
              const isActive = step === s.key;
              const isCompleted = steps.slice(0, steps.indexOf(s)).some(
                (_, i) => steps[i].key === step
              ) || steps.indexOf(s) < steps.findIndex((st) => st.key === step);

              return (
                <React.Fragment key={s.key}>
                  <div className="flex flex-col items-center">
                    <div
                      className={`flex h-10 w-10 items-center justify-center rounded-full text-sm font-medium ${
                        isActive
                          ? "bg-primary text-white"
                          : isCompleted
                          ? "bg-green-600 text-white"
                          : "bg-secondary text-muted-foreground"
                      }`}
                    >
                      {isCompleted && !isActive ? (
                        <CheckCircle2 className="h-5 w-5" />
                      ) : (
                        <s.icon className="h-5 w-5" />
                      )}
                    </div>
                    <span className={`text-xs mt-1 ${isActive ? "text-foreground" : "text-muted-foreground"}`}>
                      {s.label}
                    </span>
                  </div>
                  {idx < steps.length - 1 && (
                    <div
                      className={`flex-1 h-1 mx-2 ${isCompleted ? "bg-green-600" : "bg-secondary"}`}
                    />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left: Evaluation Form */}
        {step === "evaluate" && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Step 1: Evaluate Transaction</CardTitle>
              <CardDescription>
                Run deterministic policy evaluation against an immutable purchase intent.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleEvaluate} className="space-y-4 max-w-2xl">
                <div>
                  <label className="text-xs font-medium text-muted-foreground block mb-1">Intent ID (UUID)</label>
                  <Input
                    value={evalForm.intent_id}
                    onChange={(e) => setEvalForm({ ...evalForm, intent_id: e.target.value })}
                    placeholder="e.g. 0f8fad5b-d9cb-469f-a165-70867728950e"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">User ID</label>
                    <Input
                      value={evalForm.user_id}
                      onChange={(e) => setEvalForm({ ...evalForm, user_id: e.target.value })}
                      required
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Merchant ID</label>
                    <Input
                      value={evalForm.merchant_id}
                      onChange={(e) => setEvalForm({ ...evalForm, merchant_id: e.target.value })}
                      required
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Amount</label>
                    <Input
                      value={evalForm.amount}
                      onChange={(e) => setEvalForm({ ...evalForm, amount: e.target.value })}
                      required
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Currency</label>
                    <Input
                      value={evalForm.currency}
                      onChange={(e) => setEvalForm({ ...evalForm, currency: e.target.value })}
                      required
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Category</label>
                    <Input
                      value={evalForm.product_category}
                      onChange={(e) => setEvalForm({ ...evalForm, product_category: e.target.value })}
                      required
                    />
                  </div>
                </div>

                <Button type="submit" disabled={loading} className="w-full bg-primary hover:bg-primary/90">
                  {loading ? "Evaluating..." : "Run Deterministic Evaluation"}
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Right: Decision Result */}
        {decision && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Evaluation Result</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-center gap-4">
                <Badge variant="outline" className={getDecisionBadgeClass(decision.decision)}>
                  {decision.decision}
                </Badge>
                <span className="text-xs text-muted-foreground">Txn: {decision.transaction_id}</span>
                <span className="text-xs text-muted-foreground">Reasons: {decision.reason_codes.join(", ")}</span>
              </div>
              <p className="text-sm text-foreground/80 mt-2">{decision.explanation}</p>
            </CardContent>
          </Card>
        )}

        {/* Middle: Payment Preparation */}
        {step === "prepare" && decision && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Step 2: Prepare Payment</CardTitle>
              <CardDescription>
                Bind a durable payment to the evaluated transaction.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-center gap-4">
                {decision.decision === "ALLOW_FOR_APPROVAL" ? (
                  <>
                    <p className="text-sm text-green-700">
                      Transaction <span className="font-mono text-foreground">{decision.transaction_id}</span> is eligible for payment.
                    </p>
                    <Button onClick={handlePrepare} disabled={loading} className="bg-primary hover:bg-primary/90">
                      {loading ? "Preparing..." : "Prepare Payment"}
                    </Button>
                  </>
                ) : decision.decision === "BLOCK" ? (
                  <p className="text-sm text-red-600">
                    <span className="font-mono text-foreground">{decision.transaction_id}</span> - BLOCKED: {decision.reason_codes.join(", ")}
                  </p>
                ) : decision.decision === "REVIEW_REQUIRED" ? (
                  <p className="text-sm text-amber-800">
                    <span className="font-mono text-foreground">{decision.transaction_id}</span> - REVIEW_REQUIRED: {decision.reason_codes.join(", ")}
                  </p>
                ) : (
                  <p className="text-sm text-foreground/80">
                    Transaction in state: {decision.decision}
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Payment Details */}
        {payment && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
                Payment Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap items-center gap-4">
                <Badge variant="outline" className={getPaymentStateBadgeClass(payment.state)}>
                  {payment.state}
                </Badge>
                <span className="text-xs text-muted-foreground">Payment ID: {payment.payment_id}</span>
                {payment.paypal_order_id && (
                  <span className="text-xs text-muted-foreground">PayPal Order: {payment.paypal_order_id}</span>
                )}
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Amount</p>
                  <p className="font-mono text-foreground">{formatCurrency(payment.amount, payment.currency)}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Merchant</p>
                  <p className="font-mono text-foreground">{payment.merchant_id}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Category</p>
                  <p className="font-mono text-foreground">{payment.product_category}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Approved By</p>
                  <p className="font-mono text-foreground">{payment.approved_by || "—"}</p>
                </div>
              </div>

              {payment.approval_url && isValidApprovalUrl(payment.approval_url) && payment.state === 'PAYPAL_ORDER_CREATED' && (
                <div className="border border-blue-200 rounded-lg p-4 bg-blue-50">
                  <p className="text-xs text-accent mb-2 flex items-center gap-1">
                    <Eye className="h-3 w-3" />
                    PayPal Sandbox Approval URL
                  </p>
                  <p className="text-xs text-accent truncate">
                    {displayApprovalUrl(payment.approval_url)}
                  </p>
                  <p className="text-xs text-accent mt-1">
                    Open in sandbox buyer account. Browser return is untrusted - server re-verifies directly with PayPal.
                  </p>
                  <Button
                    asChild
                    className="mt-2 w-full"
                  >
                    <a
                      href={payment.approval_url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Complete Payment at PayPal
                    </a>
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Approve Step */}
        {step === "approve" && payment && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Step 3: Demo Approval</CardTitle>
              <CardDescription>
                Demo-only approval identity. No production authentication in this milestone.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <label className="text-xs font-medium text-muted-foreground block mb-1">Approved By</label>
                  <Input
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    placeholder="demo_operator"
                  />
                </div>
                <Button onClick={handleApprove} disabled={loading} className="h-10 bg-green-600 hover:bg-green-700">
                  {loading ? "Approving..." : "Approve & Create PayPal Order"}
                </Button>
              </div>

              <div className="border border-amber-200 rounded-lg p-3 bg-amber-50">
                <p className="text-xs text-amber-700">
                  <strong>Security Note:</strong> This revalidates intent fingerprint, expiry, amount, currency, merchant, and category
                  before creating any PayPal order. The approved_by field is a demo audit label only.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Buyer Return Step */}
        {step === "buyer-return" && payment && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Step 4: Buyer Return Verification</CardTitle>
              <CardDescription>
                Server re-verifies PayPal order directly. Browser parameters are ignored.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <Button onClick={handleBuyerReturn} disabled={loading} className="bg-primary hover:bg-primary/90">
                  {loading ? "Verifying..." : "Verify with PayPal"}
                </Button>
                <p className="text-sm text-muted-foreground">
                  Opens the stored PayPal order and checks for APPROVED status directly.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Capture Step */}
        {step === "capture" && payment && (
          <Card className="border-border bg-card lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Step 5: Capture Payment</CardTitle>
              <CardDescription>
                Claims CAPTURE_PENDING state durably, then captures with idempotency key.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <Button onClick={handleCapture} disabled={loading} className="bg-green-600 hover:bg-green-700">
                  {loading ? "Capturing..." : "Capture Payment"}
                </Button>
                <p className="text-sm text-muted-foreground">
                  Requires BUYER_APPROVED state. Revalidates all constraints before capture.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Payment Lookup */}
        <Card className="border-border bg-card lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Lookup Existing Payment</CardTitle>
            <CardDescription>Enter a Payment ID to resume workflow at the correct step.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleFetchPayment} className="flex gap-2">
              <Input
                value={paymentIdInput}
                onChange={(e) => setPaymentIdInput(e.target.value)}
                placeholder="Payment ID (UUID)"
                className="flex-1"
              />
              <Button type="submit" disabled={loading} variant="outline" className="border-border">
                Lookup
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}