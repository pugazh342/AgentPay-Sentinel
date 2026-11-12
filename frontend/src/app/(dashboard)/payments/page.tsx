"use client";

import React, { useState, useEffect, useRef } from "react";
import { isValidApprovalUrl } from "@/lib/paypal-approval-url";

/**
 * Extracts a user-friendly error message from various error types
 */
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as { message: unknown }).message);
  }
  return "An unexpected error occurred.";
}

// All payment states for filter dropdown
const PAYMENT_STATES: string[] = [
  'All',
  'PENDING_SECURITY',
  'REVIEW_REQUIRED',
  'BLOCKED',
  'PENDING_USER_APPROVAL',
  'PAYPAL_ORDER_CREATED',
  'BUYER_APPROVED',
  'CAPTURE_PENDING',
  'COMPLETED',
  'FAILED',
  'EXPIRED',
];

import { Eye, Calendar } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationPrevious,
  PaginationNext,
} from "@/components/ui/pagination";
import {
  listPayments,
  getPaymentDetails,
  PaymentResponse,
  PaymentResponseSafe,
  formatCurrency,
  formatDate,
  getPaymentStateBadgeClass,
  type PaymentState,
} from "@/lib/api";

export default function PaymentsPage() {
  const [payments, setPayments] = useState<PaymentResponseSafe[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [limit] = useState(100);
  const [offset, setOffset] = useState(0);
  const [stateFilter, setStateFilter] = useState<string>('All');
  const [listLoading, setListLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [listRetryCount, setListRetryCount] = useState(0);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [retryDetailId, setRetryDetailId] = useState<string | null>(null);
  const [selectedPayment, setSelectedPayment] = useState<PaymentResponse | null>(null);
  const listRequestIdRef = useRef(0);
  const listInFlightRef = useRef(false);

  // Convert state filter to PaymentState | undefined for API
  const apiStateFilter = stateFilter === 'All' ? undefined : (stateFilter as PaymentState);

  // Reset offset to 0 when filter changes
  const [prevFilter, setPrevFilter] = useState(stateFilter);
  if (prevFilter !== stateFilter) {
    setPrevFilter(stateFilter);
    setOffset(0);
  }

  // Fetch payments - with cleanup to prevent memory leaks and stale responses
  useEffect(() => {
    let cancelled = false;
    const requestId = ++listRequestIdRef.current;
    listInFlightRef.current = true;
    async function loadPayments() {
      setListLoading(true);
      setError(null);
      try {
        const result = await listPayments({
          limit,
          offset,
          state: apiStateFilter,
        });
        if (!cancelled && requestId === listRequestIdRef.current) {
          setPayments(result.results);
          setTotalCount(result.total_count);
        }
      } catch (err) {
        if (!cancelled && requestId === listRequestIdRef.current) {
          setError(getErrorMessage(err) || "Failed to load payments.");
        }
      } finally {
        if (requestId === listRequestIdRef.current) {
          listInFlightRef.current = false;
          if (!cancelled) {
            setListLoading(false);
          }
        }
      }
    }
    loadPayments();
    return () => { cancelled = true; };
    // We need offset in deps, but resetting it when filter changes is intentional
  }, [limit, offset, apiStateFilter, listRetryCount]);

  const handleRetryList = () => {
    if (listInFlightRef.current) return;
    setListRetryCount((count) => count + 1);
  };

  // Handle detail fetch for dialog - separate from list loading
  const handleOpenDetails = async (paymentId: string) => {
    setDetailError(null);
    try {
      const details = await getPaymentDetails(paymentId);
      setSelectedPayment(details);
    } catch (err) {
      setDetailError(getErrorMessage(err) || "Failed to load payment details.");
      setRetryDetailId(paymentId);
    }
  };

  const handleRetryDetails = () => {
    if (retryDetailId) handleOpenDetails(retryDetailId);
  };

  const totalPages = Math.ceil(totalCount / limit);

  const handlePageChange = (newOffset: number) => {
    setOffset(newOffset);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Payments</h1>
        <p className="text-muted-foreground">
          View and manage payment transactions. Results are ordered by creation time.
        </p>
      </div>

      {/* State Filter */}
      <div className="flex items-center gap-4">
        <Select value={stateFilter} onValueChange={setStateFilter}>
          <SelectTrigger className="w-[180px] bg-secondary border-border">
            <SelectValue placeholder="Filter by state" />
          </SelectTrigger>
          <SelectContent>
            {PAYMENT_STATES.map((state) => (
              <SelectItem key={state} value={state}>
                {state === 'All' ? 'All States' : state.replace('_', ' ')}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {stateFilter !== 'All' && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setStateFilter('All')}
            className="border-border text-foreground/80 hover:text-foreground"
          >
            Clear Filter
          </Button>
        )}
      </div>

      {detailError && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 flex items-center justify-between gap-4">
          <span>{detailError}</span>
          <Button variant="outline" size="sm" onClick={handleRetryDetails} className="border-red-700 text-red-700">
            Retry
          </Button>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 flex items-center justify-between gap-4">
          <span>{error}</span>
          <Button variant="outline" size="sm" onClick={handleRetryList} className="border-red-700 text-red-700">
            Retry
          </Button>
        </div>
      )}

      {/* Payments Table */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground">
            Payment History
          </CardTitle>
          <CardDescription>
            {totalCount} total payments • {limit} results per page
            {stateFilter !== 'All' && ` • Filtered by: ${stateFilter.replace('_', ' ')}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {listLoading && payments.length === 0 ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>
          ) : payments.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm text-muted-foreground">No payments found.</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-secondary">
                      <TableHead className="text-muted-foreground">Payment ID</TableHead>
                      <TableHead className="text-muted-foreground">Amount</TableHead>
                      <TableHead className="text-muted-foreground">State</TableHead>
                      <TableHead className="text-muted-foreground">Merchant</TableHead>
                      <TableHead className="text-muted-foreground">Created</TableHead>
                      <TableHead className="text-muted-foreground"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {payments.map((payment) => (
                      <TableRow
                        key={payment.payment_id}
                        className="border-border hover:bg-secondary"
                      >
                        <TableCell className="font-mono text-xs text-foreground/80">
                          {payment.payment_id.slice(0, 8)}...{payment.payment_id.slice(-4)}
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-foreground">
                            {formatCurrency(payment.amount, payment.currency)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge className={getPaymentStateBadgeClass(payment.state)}>
                            {payment.state}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-foreground/80">
                          {payment.merchant_id}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {formatDate(payment.created_at)}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleOpenDetails(payment.payment_id)}
                            className="text-muted-foreground hover:text-foreground"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center">
          <Pagination>
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  onClick={() => {
                    if (offset > 0) handlePageChange(Math.max(0, offset - limit));
                  }}
                  disabled={offset === 0}
                />
              </PaginationItem>
              <PaginationItem>
                <span className="text-sm text-muted-foreground">
                  Page {Math.floor(offset / limit) + 1} of {totalPages}
                </span>
              </PaginationItem>
              <PaginationItem>
                <PaginationNext
                  onClick={() => {
                    if (offset + limit < totalCount) handlePageChange(offset + limit);
                  }}
                  disabled={offset + limit >= totalCount}
                />
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        </div>
      )}

      {/* Payment Details Dialog */}
      <Dialog open={!!selectedPayment} onOpenChange={(open) => !open && setSelectedPayment(null)}>
        {selectedPayment && (
          <DialogContent className="bg-card border-border max-w-2xl">
            <DialogHeader>
              <DialogTitle className="text-foreground">
                Payment Details
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              {/* Payment State Badge */}
              <div className="flex items-center gap-3">
                <Badge className={getPaymentStateBadgeClass(selectedPayment.state)}>
                  {selectedPayment.state}
                </Badge>
                <span className="text-sm text-muted-foreground font-mono">
                  {selectedPayment.payment_id.slice(0, 8)}...{selectedPayment.payment_id.slice(-4)}
                </span>
              </div>

              {/* Payment Details Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Amount</p>
                  <p className="font-mono text-foreground">
                    {formatCurrency(selectedPayment.amount, selectedPayment.currency)}
                  </p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Currency</p>
                  <p className="font-mono text-foreground">{selectedPayment.currency}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Merchant ID</p>
                  <p className="font-mono text-foreground">{selectedPayment.merchant_id}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Product Category</p>
                  <p className="font-mono text-foreground">{selectedPayment.product_category}</p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Transaction ID</p>
                  <p className="font-mono text-foreground text-xs">
                    {selectedPayment.transaction_id.slice(0, 8)}...{selectedPayment.transaction_id.slice(-4)}
                  </p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Intent ID</p>
                  <p className="font-mono text-foreground text-xs">
                    {selectedPayment.intent_id.slice(0, 8)}...{selectedPayment.intent_id.slice(-4)}
                  </p>
                </div>
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">PayPal Order ID</p>
                  <p className="font-mono text-foreground text-xs">
                    {selectedPayment.paypal_order_id || "—"}
                  </p>
                </div>
                {selectedPayment.version !== undefined && (
                  <div className="border border-border rounded-lg p-3 bg-background">
                    <p className="text-xs text-muted-foreground">Version</p>
                    <p className="font-mono text-foreground">{selectedPayment.version}</p>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div className="border border-border rounded-lg p-4 bg-background">
                <h4 className="text-sm font-medium text-foreground mb-3">Timeline</h4>
                <div className="space-y-2">
                  {selectedPayment.approved_at && (
                    <div className="flex items-center gap-3">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-xs text-muted-foreground">Approved</p>
                        <p className="text-sm text-foreground">{formatDate(selectedPayment.approved_at)}</p>
                      </div>
                    </div>
                  )}
                  {selectedPayment.buyer_approved_at && (
                    <div className="flex items-center gap-3">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-xs text-muted-foreground">Buyer Approved</p>
                        <p className="text-sm text-foreground">{formatDate(selectedPayment.buyer_approved_at)}</p>
                      </div>
                    </div>
                  )}
                  {selectedPayment.completed_at && (
                    <div className="flex items-center gap-3">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-xs text-muted-foreground">Completed</p>
                        <p className="text-sm text-foreground">{formatDate(selectedPayment.completed_at)}</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Approval URL - for buyer redirect - with URL validation and STATE GATING for security */}
              {selectedPayment.state === 'PAYPAL_ORDER_CREATED' &&
               selectedPayment.approval_url &&
               isValidApprovalUrl(selectedPayment.approval_url) && (
                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-medium text-foreground mb-3">Buyer Actions</h4>
                  <Button
                    asChild
                    className="w-full"
                  >
                    <a
                      href={selectedPayment.approval_url}
                      target="_blank"
                      rel="noopener noreferrer"
                       onClick={() => {
                         if (selectedPayment.paypal_order_id) {
                           try {
                             sessionStorage.setItem('agentpay_return_payment_id', selectedPayment.payment_id);
                             sessionStorage.setItem('agentpay_return_order_id', selectedPayment.paypal_order_id);
                           } catch {
                             // sessionStorage unavailable; correlation will fail safely.
                           }
                         }
                       }}
                    >
                      Complete Payment at PayPal
                    </a>
                  </Button>
                  <p className="text-xs text-muted-foreground mt-2">
                    This link will direct the buyer to PayPal to complete their payment.
                  </p>
                </div>
              )}

              {/* PayPal Capture ID */}
              {selectedPayment.paypal_capture_id && (
                <div className="border border-border rounded-lg p-3 bg-background col-span-2">
                  <p className="text-xs text-muted-foreground">PayPal Capture ID</p>
                  <p className="font-mono text-xs text-foreground break-all">
                    {selectedPayment.paypal_capture_id}
                  </p>
                </div>
              )}

              {/* PayPal Status */}
              {selectedPayment.paypal_status && (
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">PayPal Status</p>
                  <p className="font-mono text-sm text-foreground">{selectedPayment.paypal_status}</p>
                </div>
              )}

              {/* Failure Reason */}
              {selectedPayment.failure_reason && (
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Failure Reason</p>
                  <p className="font-mono text-sm text-foreground text-red-600">
                    {selectedPayment.failure_reason}
                  </p>
                </div>
              )}

              {/* Approved By */}
              {selectedPayment.approved_by && (
                <div className="border border-border rounded-lg p-3 bg-background">
                  <p className="text-xs text-muted-foreground">Approved By</p>
                  <p className="font-mono text-sm text-foreground">{selectedPayment.approved_by}</p>
                </div>
              )}
            </div>
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}