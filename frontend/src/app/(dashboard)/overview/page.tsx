"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  ArrowUpRight,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  CreditCard,
} from "lucide-react";
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
  getSecurityEvents,
  getHealth,
  listPayments,
  HealthResponse,
  SecurityEventResponse,
  formatRelativeTime,
  getDecisionBadgeClass,
  getPaymentStateBadgeClass,
  PaymentState,
} from "@/lib/api";

export default function OverviewPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [events, setEvents] = useState<SecurityEventResponse[]>([]);
  const [paymentStats, setPaymentStats] = useState<{
    total: number;
    completed: number;
    pending: number;
    failed: number;
  }>({ total: 0, completed: 0, pending: 0, failed: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        const [healthData, eventsData, paymentsData] = await Promise.all([
          getHealth(),
          getSecurityEvents({ limit: 10 }),
          listPayments({ limit: 1000 }),
        ]);
        setHealth(healthData);
        setEvents(eventsData.items);

        // Calculate payment statistics
        const total = paymentsData.total_count;
        const completed = paymentsData.results.filter(p => p.state === "COMPLETED").length;
        const pending = paymentsData.results.filter(p =>
          ["PENDING_USER_APPROVAL", "PAYPAL_ORDER_CREATED", "BUYER_APPROVED", "CAPTURE_PENDING"].includes(p.state)
        ).length;
        const failed = paymentsData.results.filter(p => p.state === "FAILED").length;
        setPaymentStats({ total, completed, pending, failed });
      } catch (err) {
        setError((err instanceof Error ? err.message : "") || "Failed to connect to backend API.");
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Security Command Center</h1>
        <p className="text-muted-foreground">
          Zero-trust payment authorization, Gemini threat intelligence, and PayPal sandbox governance.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <div className="flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
            <div>
              <p className="font-semibold">Backend Connection Warning</p>
              <p className="text-sm text-red-600">{error}. Ensure the FastAPI backend is running on http://127.0.0.1:8000.</p>
            </div>
          </div>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">System Status</CardTitle>
            <ShieldCheck className="h-5 w-5 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">
              {loading ? "Loading..." : health?.status === "ok" ? "Operational" : "Degraded"}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Environment: {health?.environment || "sandbox"}
            </p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">HMAC Integrity</CardTitle>
            <Lock className="h-5 w-5 text-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">
              {loading ? "Loading..." : health?.checks.hmac_configuration === "configured" ? "Verified" : "Invalid"}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Server-side SHA256 fingerprinting
            </p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Database Storage</CardTitle>
            <Activity className="h-5 w-5 text-indigo-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">
              {loading ? "Loading..." : health?.checks.database === "ok" ? "Connected" : "Error"}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              SQLite durable storage
            </p>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Payments</CardTitle>
            <CreditCard className="h-5 w-5 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-foreground">
              {loading ? "Loading..." : paymentStats.total}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {paymentStats.completed} completed, {paymentStats.pending} pending
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Recent Security Events */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Recent Security Events</CardTitle>
            <CardDescription>Audit timeline of authorization decisions and threat escalations.</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading audit events...</p>
            ) : events.length === 0 ? (
              <p className="text-sm text-muted-foreground">No security events recorded yet.</p>
            ) : (
              <div className="space-y-4">
                {events.slice(0, 5).map((event) => (
                  <div key={event.event_id} className="flex flex-wrap items-start justify-between gap-2 border-b border-border pb-3 last:border-0 last:pb-0 sm:flex-nowrap sm:items-center">
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-sm text-foreground break-words">{event.event_type}</span>
                        {event.decision && (
                          <Badge variant="outline" className={`${getDecisionBadgeClass(event.decision)} shrink-0`}>
                            {event.decision}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground break-words">
                        Reasons: {event.reason_codes.join(", ")}
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground shrink-0 sm:self-auto">{formatRelativeTime(event.timestamp)}</span>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-4 pt-2">
              <Button asChild variant="outline" className="w-full border-border text-foreground/80 hover:bg-secondary">
                <Link href="/audit-explorer">
                  View Full Audit Explorer <ArrowUpRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions & Security Guarantees */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Zero-Trust Security Guarantees</CardTitle>
            <CardDescription>Core architectural constraints protecting AI agent payments.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-foreground">AI Cannot Authorize Payments</p>
                <p className="text-xs text-muted-foreground">Gemini threat intelligence is advisory only and never executes payments or overrides policy.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-foreground">Deterministic Policy Authority</p>
                <p className="text-xs text-muted-foreground">Amount, currency, merchant, and fingerprint checks are strictly deterministic.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-foreground">Sandbox-Only PayPal Isolation</p>
                <p className="text-xs text-muted-foreground">Live PayPal endpoints are permanently prohibited at the code level.</p>
              </div>
            </div>

            <div className="pt-4 flex gap-2">
              <Button asChild className="flex-1 bg-primary hover:bg-primary/90">
                <Link href="/purchase-intents">Create Intent</Link>
              </Button>
              <Button asChild variant="outline" className="flex-1 border-border hover:bg-secondary">
                <Link href="/adversarial-lab">Adversarial Lab</Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}