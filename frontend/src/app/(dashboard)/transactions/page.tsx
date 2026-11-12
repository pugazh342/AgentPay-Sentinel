"use client";

import React, { useState, useEffect } from "react";
import { Search, Filter, ShieldAlert, CheckCircle2, Clock, Eye } from "lucide-react";
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
  evaluateTransaction,
  getTransaction,
  DecisionResponse,
  TransactionResponse,
  formatCurrency,
  formatDate,
  getDecisionBadgeClass,
} from "@/lib/api";

export default function TransactionsPage() {
  const [transactionIdInput, setTransactionIdInput] = useState("");
  const [evaluatedDecision, setEvaluatedDecision] = useState<DecisionResponse | null>(null);
  const [selectedTransaction, setSelectedTransaction] = useState<TransactionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form for testing quick evaluation
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

  async function handleEvaluate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setEvaluatedDecision(null);

    try {
      const decision = await evaluateTransaction(evalForm);
      setEvaluatedDecision(decision);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to evaluate transaction.");
    } finally {
      setLoading(false);
    }
  }

  async function handleFetchTransaction(e: React.FormEvent) {
    e.preventDefault();
    if (!transactionIdInput.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const tx = await getTransaction(transactionIdInput.trim());
      setSelectedTransaction(tx);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Transaction not found.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Transactions</h1>
        <p className="text-muted-foreground">
          Deterministic payment evaluation against immutable purchase intents.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <p className="font-semibold">Error</p>
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}

      {/* Grid Layout */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Evaluate Transaction Form */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Evaluate Transaction</CardTitle>
            <CardDescription>
              Submit a payment request for deterministic authorization.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleEvaluate} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-muted-foreground">Intent ID (UUID)</label>
                <Input
                  value={evalForm.intent_id}
                  onChange={(e) => setEvalForm({ ...evalForm, intent_id: e.target.value })}
                  placeholder="e.g. 0f8fad5b-d9cb-469f-a165-70867728950e"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">User ID</label>
                  <Input
                    value={evalForm.user_id}
                    onChange={(e) => setEvalForm({ ...evalForm, user_id: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Merchant ID</label>
                  <Input
                    value={evalForm.merchant_id}
                    onChange={(e) => setEvalForm({ ...evalForm, merchant_id: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Amount</label>
                  <Input
                    value={evalForm.amount}
                    onChange={(e) => setEvalForm({ ...evalForm, amount: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Currency</label>
                  <Input
                    value={evalForm.currency}
                    onChange={(e) => setEvalForm({ ...evalForm, currency: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Category</label>
                  <Input
                    value={evalForm.product_category}
                    onChange={(e) => setEvalForm({ ...evalForm, product_category: e.target.value })}
                    required
                  />
                </div>
              </div>

              <Button type="submit" disabled={loading} className="w-full bg-primary hover:bg-primary/90">
                {loading ? "Evaluating..." : "Run Evaluation"}
              </Button>
            </form>

            {/* Evaluation Result */}
            {evaluatedDecision && (
              <div className="mt-6 rounded-lg border border-border bg-background p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-foreground/80">Decision Outcome</span>
                  <Badge variant="outline" className={getDecisionBadgeClass(evaluatedDecision.decision)}>
                    {evaluatedDecision.decision}
                  </Badge>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Transaction ID: </span>
                  <span className="text-xs font-mono text-accent">{evaluatedDecision.transaction_id}</span>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Reason Codes: </span>
                  <span className="text-xs text-foreground">{evaluatedDecision.reason_codes.join(", ")}</span>
                </div>
                <p className="text-xs text-muted-foreground border-t border-border pt-2">{evaluatedDecision.explanation}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Lookup Transaction */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Lookup Persisted Transaction</CardTitle>
            <CardDescription>Retrieve a recorded transaction by ID.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleFetchTransaction} className="flex gap-2">
              <Input
                value={transactionIdInput}
                onChange={(e) => setTransactionIdInput(e.target.value)}
                placeholder="Enter Transaction ID (UUID)"
                className="flex-1"
              />
              <Button type="submit" disabled={loading} variant="outline" className="border-border">
                Lookup
              </Button>
            </form>

            {selectedTransaction && (
              <div className="rounded-lg border border-border bg-background p-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-foreground">{selectedTransaction.merchant_id}</h4>
                    <p className="text-xs text-muted-foreground">Category: {selectedTransaction.product_category}</p>
                  </div>
                  <Badge variant="outline" className={getDecisionBadgeClass(selectedTransaction.decision.decision)}>
                    {selectedTransaction.decision.decision}
                  </Badge>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs border-t border-b border-border py-3">
                  <div>
                    <span className="text-muted-foreground">Amount: </span>
                    <span className="text-foreground">{formatCurrency(selectedTransaction.amount, selectedTransaction.currency)}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">User ID: </span>
                    <span className="text-foreground">{selectedTransaction.user_id}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Request ID: </span>
                    <span className="text-foreground">{selectedTransaction.request_id}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Quantity: </span>
                    <span className="text-foreground">{selectedTransaction.quantity}</span>
                  </div>
                </div>

                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">Policy Explanation</p>
                  <p className="text-xs text-foreground/80">{selectedTransaction.decision.explanation}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}