"use client";

import React from "react";
import {
  CreditCard,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { formatCurrency, getPaymentStateBadgeClass, type PaymentState } from "@/lib/api";
import { isValidApprovalUrl, displayApprovalUrl } from "@/lib/paypal-approval-url";

// States eligible for buyer checkout (pending approval states only)
const isBuyerCheckoutEligible = (state: PaymentState): boolean => {
  // Buyer checkout is only legitimate once the PayPal order (and its
  // approval_url) has been created. PENDING_USER_APPROVAL has no order yet.
  return state === 'PAYPAL_ORDER_CREATED';
};

interface PaymentDetailsCardProps {
  paymentId: string;
  state: PaymentState;
  amount: string;
  currency: string;
  merchant_id: string;
  product_category: string;
  transaction_id?: string;
  intent_id?: string;
  paypal_order_id?: string | null;
  approval_url?: string | null;
  paypal_capture_id?: string | null;
  paypal_status?: string | null;
  approved_by?: string | null;
  failure_reason?: string | null;
  version?: number;
  className?: string;
}

export function PaymentDetailsCard({
  paymentId,
  state,
  amount,
  currency,
  merchant_id,
  product_category,
  transaction_id,
  intent_id,
  paypal_order_id,
  approval_url,
  paypal_capture_id,
  paypal_status,
  approved_by,
  failure_reason,
  version,
  className,
}: PaymentDetailsCardProps) {
  const isValidUrl = approval_url ? isValidApprovalUrl(approval_url) : false;
  const isEligibleForCheckout = isBuyerCheckoutEligible(state);

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-lg font-semibold text-foreground">
          <div className="flex items-center gap-2">
            <CreditCard className="h-5 w-5 text-primary" />
            Payment Details
          </div>
        </CardTitle>
        <Badge className={getPaymentStateBadgeClass(state)}>
          {state}
        </Badge>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div className="border border-border rounded-lg p-3 bg-secondary/30">
            <p className="text-xs text-muted-foreground">Payment ID</p>
            <p className="font-mono text-xs text-foreground truncate">
              {paymentId.slice(0, 8)}...{paymentId.slice(-4)}
            </p>
          </div>
          <div className="border border-border rounded-lg p-3 bg-secondary/30">
            <p className="text-xs text-muted-foreground">Amount</p>
            <p className="font-mono text-sm text-foreground">
              {formatCurrency(amount, currency)}
            </p>
          </div>
          <div className="border border-border rounded-lg p-3 bg-secondary/30">
            <p className="text-xs text-muted-foreground">Merchant</p>
            <p className="font-mono text-sm text-foreground truncate">
              {merchant_id}
            </p>
          </div>
          <div className="border border-border rounded-lg p-3 bg-secondary/30">
            <p className="text-xs text-muted-foreground">Category</p>
            <p className="font-mono text-sm text-foreground truncate">
              {product_category}
            </p>
          </div>
          {transaction_id && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">Transaction</p>
              <p className="font-mono text-xs text-foreground truncate">
                {transaction_id.slice(0, 8)}...{transaction_id.slice(-4)}
              </p>
            </div>
          )}
          {intent_id && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">Intent ID</p>
              <p className="font-mono text-xs text-foreground truncate">
                {intent_id.slice(0, 8)}...{intent_id.slice(-4)}
              </p>
            </div>
          )}
          {version !== undefined && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">Version</p>
              <p className="font-mono text-sm text-foreground">{version}</p>
            </div>
          )}
          {paypal_order_id && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">PayPal Order ID</p>
              <p className="font-mono text-xs text-foreground break-all">
                {paypal_order_id}
              </p>
            </div>
          )}
          {paypal_capture_id && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">PayPal Capture ID</p>
              <p className="font-mono text-xs text-foreground break-all">
                {paypal_capture_id}
              </p>
            </div>
          )}
          {paypal_status && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">PayPal Status</p>
              <p className="font-mono text-sm text-foreground">{paypal_status}</p>
            </div>
          )}
          {approved_by && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30">
              <p className="text-xs text-muted-foreground">Approved By</p>
              <p className="font-mono text-sm text-foreground">{approved_by}</p>
            </div>
          )}
          {failure_reason && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30 col-span-2">
              <p className="text-xs text-muted-foreground">Failure Reason</p>
              <p className="font-mono text-sm text-foreground text-red-600">
                {failure_reason}
              </p>
            </div>
          )}
          {isValidUrl && approval_url && isEligibleForCheckout && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30 col-span-2">
              <p className="text-xs text-muted-foreground">Buyer Action</p>
              <Button
                asChild
                className="w-full"
              >
                <a
                  href={approval_url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Complete Payment at PayPal
                </a>
              </Button>
            </div>
          )}
          {!isValidUrl && approval_url && (
            <div className="border border-border rounded-lg p-3 bg-secondary/30 col-span-2">
              <p className="text-xs text-muted-foreground">Approval URL (invalid)</p>
              <p className="font-mono text-xs text-red-600 break-all">
                URL validation failed - not shown for security
              </p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}