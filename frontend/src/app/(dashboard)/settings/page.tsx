"use client";

import React, { useState, useEffect } from "react";
import {
  Shield,
  Server,
  Brain,
  CreditCard,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Info,
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
import { Separator } from "@/components/ui/separator";
import {
  getHealth,
  HealthResponse,
} from "@/lib/api";

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadHealth();
  }, []);

  async function loadHealth() {
    setLoading(true);
    setError(null);
    try {
      const data = await getHealth();
      setHealth(data);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to load system health.");
    } finally {
      setLoading(false);
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "ok":
        return <CheckCircle2 className="h-5 w-5 text-green-600" />;
      case "configured":
        return <CheckCircle2 className="h-5 w-5 text-green-600" />;
      case "error":
        return <XCircle className="h-5 w-5 text-red-600" />;
      case "invalid":
        return <XCircle className="h-5 w-5 text-red-600" />;
      case "degraded":
        return <AlertCircle className="h-5 w-5 text-amber-700" />;
      default:
        return <AlertCircle className="h-5 w-5 text-amber-700" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "ok":
      case "configured":
        return (
          <Badge variant="success" className="text-xs">
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        );
      case "error":
      case "invalid":
        return (
          <Badge variant="destructive" className="text-xs">
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        );
      case "degraded":
        return (
          <Badge variant="warning" className="text-xs">
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        );
      default:
        return (
          <Badge variant="secondary" className="text-xs">
            {status}
          </Badge>
        );
    }
  };

  // Determine AI provider display info
  const aiProvider = health?.checks.ai_provider || "gemini";
  const aiModel = health?.checks.ai_model || "gemini-2.5-flash";
  const aiStatus = health?.checks.ai_status || "unknown";
  const isGroq = aiProvider === "groq";

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Settings</h1>
        <p className="text-muted-foreground">
          System configuration, provider status, and security environment overview.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <p className="font-semibold">Error</p>
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}

      {/* Environment Banner */}
      <Card className="border-amber-200 bg-amber-50">
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-amber-900/50">
              <Info className="h-6 w-6 text-amber-700" />
            </div>
            <div>
              <h3 className="font-semibold text-amber-900">Sandbox Environment Only</h3>
              <p className="text-sm text-amber-800 mt-1">
                This is a local-development foundation with no production user authentication.
                Live PayPal execution is permanently prohibited at the code level.
                The <code className="font-mono text-xs bg-card px-1 rounded">approved_by</code> field is a demo-only audit label.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* System Health */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Server className="h-5 w-5 text-accent" />
              System Health
            </CardTitle>
            <CardDescription>
              Liveness and security-configuration health check.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {loading ? (
              <div className="flex items-center gap-3">
                <Loader2 className="h-5 w-5 text-accent animate-spin" />
                <span className="text-muted-foreground">Loading health check...</span>
              </div>
            ) : health ? (
              <>
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(health.status)}
                    <div>
                      <p className="font-medium text-foreground">Service Status</p>
                      <p className="text-xs text-muted-foreground">AgentPay Sentinel v{health.version}</p>
                    </div>
                  </div>
                  {getStatusBadge(health.status)}
                </div>

                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(health.checks.database)}
                    <div>
                      <p className="font-medium text-foreground">Database</p>
                      <p className="text-xs text-muted-foreground">SQLite connection</p>
                    </div>
                  </div>
                  {getStatusBadge(health.checks.database)}
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(health.checks.hmac_configuration)}
                    <div>
                      <p className="font-medium text-foreground">HMAC Configuration</p>
                      <p className="text-xs text-muted-foreground">Server-side SHA256 fingerprinting</p>
                    </div>
                  </div>
                  {getStatusBadge(health.checks.hmac_configuration)}
                </div>
              </>
            ) : (
              <p className="text-muted-foreground">No health data available.</p>
            )}

            <Button onClick={loadHealth} variant="outline" className="w-full border-border mt-4">
              <Loader2 className="mr-2 h-4 w-4" />
              Refresh Health
            </Button>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
              {isGroq ? (
                <span className="h-5 w-5 text-orange-400" style={{ background: 'linear-gradient(135deg, #f97316, #ea580c)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Groq</span>
              ) : (
                <Brain className="h-5 w-5 text-purple-400" />
              )}
              AI Provider ({isGroq ? "Groq" : "Gemini"})
            </CardTitle>
            <CardDescription>
              Advisory threat intelligence configuration.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-3">
                {isGroq ? (
                  <span className="h-5 w-5 text-orange-400" style={{ background: 'linear-gradient(135deg, #f97316, #ea580c)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Groq</span>
                ) : (
                  <Brain className="h-5 w-5 text-purple-400" />
                )}
                <div>
                  <p className="font-medium text-foreground">{isGroq ? "Groq Provider" : "Gemini Provider"}</p>
                  <p className="text-xs text-muted-foreground">
                    {aiStatus === "configured" ? "Configured" : "Not Configured"}
                  </p>
                </div>
              </div>
              <Badge variant="secondary" className="text-xs">
                Advisory Only
              </Badge>
            </div>

            <div className="text-sm space-y-2">
                <p className="text-muted-foreground">
                  <strong>Model:</strong> {aiModel}
                </p>
                <p className="text-muted-foreground">
                  <strong>Provider:</strong> {isGroq ? "Groq (via AGENTPAY_AI_PROVIDER=groq)" : "Gemini (via AGENTPAY_AI_PROVIDER=gemini)"}
                </p>
                <p className="text-muted-foreground">
                  <strong>Timeout:</strong> {isGroq ? "AGENTPAY_AI_TIMEOUT_MS" : "AGENTPAY_GEMINI_TIMEOUT_MS"} (shared)
                </p>
                <p className="text-muted-foreground">
                  <strong>Retries:</strong> {isGroq ? "AGENTPAY_AI_MAX_RETRIES" : "AGENTPAY_GEMINI_MAX_RETRIES"} with backoff (shared)
                </p>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground font-semibold">Status:</span>
                  {getStatusBadge(aiStatus === "configured" ? "configured" : "not_configured")}
                </div>
              </div>

            <div className="border border-amber-200 rounded-lg p-3 bg-amber-50 mt-4">
              <p className="text-xs text-amber-700">
                <strong>Security:</strong> AI output is advisory only and never authorizes, creates, or captures payments.
                Deterministic policy remains the sole authorization authority. AI can only preserve decisions or escalate to review.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
              <CreditCard className="h-5 w-5 text-green-600" />
              PayPal Sandbox
            </CardTitle>
            <CardDescription>
              PayPal Orders v2 sandbox integration status.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-3">
                <CreditCard className="h-5 w-5 text-green-600" />
                <div>
                  <p className="font-medium text-foreground">PayPal Environment</p>
                  <p className="text-xs text-muted-foreground">Sandbox Only (Hardcoded)</p>
                </div>
              </div>
              <Badge variant="success" className="text-xs">Sandbox</Badge>
            </div>

            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">
                <strong>Base URL:</strong> https://api-m.sandbox.paypal.com
              </p>
              <p className="text-muted-foreground">
                <strong>OAuth Token Cache:</strong> In-memory with 60s skew
              </p>
              <p className="text-muted-foreground">
                <strong>Timeout:</strong> 15s with 1 retry
              </p>
              <p className="text-muted-foreground">
                <strong>Webhook Verification:</strong> Official PayPal signature verification
              </p>
            </div>

            <div className="border border-red-200 rounded-lg p-3 bg-red-950/30 mt-4">
              <p className="text-xs text-red-600">
                <strong>Hard Constraint:</strong> Live PayPal endpoints are permanently prohibited.
                The PayPalClient constructor rejects any base URL other than the sandbox origin.
                PAYPAL_ENVIRONMENT must be &quot;sandbox&quot; — any other value raises ValidationError.
              </p>
            </div>

            <div className="border border-amber-200 rounded-lg p-3 bg-amber-50 mt-4">
              <p className="text-xs text-amber-700">
                <strong>Configuration Required:</strong> Set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, and PAYPAL_WEBHOOK_ID
                in backend/.env to enable PayPal order creation, approval, and capture workflows.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Shield className="h-5 w-5 text-red-600" />
              Security Configuration
            </CardTitle>
            <CardDescription>
              Core security settings and operational constraints.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">HMAC Secret</span>
                <Badge variant={health?.checks.hmac_configuration === "configured" ? "success" : "destructive"}>
                  {health?.checks.hmac_configuration === "configured" ? "Configured" : "Missing/Invalid"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Minimum Secret Length</span>
                <span className="text-foreground/80">32 bytes</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Fingerprint Algorithm</span>
                <span className="text-foreground/80">HMAC-SHA256</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Intent Immutability</span>
                <Badge variant="success">Enforced</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Decimal Precision</span>
                <span className="text-foreground/80">Exact (string serialization)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Client Field Rejection</span>
                <Badge variant="success">Enabled (extra=&quot;forbid&quot;)</Badge>
              </div>
            </div>

            <Separator />

            <div className="space-y-2 text-xs text-muted-foreground">
                <p><strong>Fail-Closed Behavior:</strong> Missing/invalid HMAC secret → 503 on all mutating endpoints</p>
                <p><strong>AI Unavailable:</strong> Requests with analysis_context → REVIEW_REQUIRED + AI_ANALYSIS_UNAVAILABLE</p>
                <p><strong>PayPal Unconfigured:</strong> approve/buyer-return/capture → 503 PAYPAL_NOT_CONFIGURED</p>
                <p><strong>Webhook ID Missing:</strong> Events rejected rather than trusted</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Links */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground">Backend Configuration</CardTitle>
          <CardDescription>
            Edit backend/.env to configure providers. Restart the FastAPI server after changes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="border border-border rounded-lg p-4 bg-background">
              <h4 className="font-medium text-foreground mb-2">Required</h4>
              <ul className="space-y-1 text-xs text-muted-foreground">
                <li>AGENTPAY_HMAC_SECRET (min 32 bytes)</li>
                <li>AGENTPAY_DATABASE_URL</li>
              </ul>
            </div>
            <div className="border border-border rounded-lg p-4 bg-background">
              <h4 className="font-medium text-foreground mb-2">Optional: AI</h4>
              <ul className="space-y-1 text-xs text-muted-foreground">
                <li>AGENTPAY_AI_PROVIDER (groq|gemini)</li>
                {isGroq ? (
                  <>
                    <li>GROQ_API_KEY</li>
                    <li>AGENTPAY_GROQ_MODEL</li>
                  </>
                ) : (
                  <>
                    <li>GEMINI_API_KEY</li>
                    <li>GEMINI_MODEL</li>
                  </>
                )}
                <li>AGENTPAY_AI_TIMEOUT_MS</li>
                <li>AGENTPAY_AI_MAX_RETRIES</li>
                <li>AGENTPAY_AI_RETRY_BACKOFF_SECONDS</li>
              </ul>
            </div>
            <div className="border border-border rounded-lg p-4 bg-background">
              <h4 className="font-medium text-foreground mb-2">Optional: PayPal</h4>
              <ul className="space-y-1 text-xs text-muted-foreground">
                <li>PAYPAL_CLIENT_ID</li>
                <li>PAYPAL_CLIENT_SECRET</li>
                <li>PAYPAL_WEBHOOK_ID</li>
                <li>PAYPAL_RETURN_URL</li>
                <li>PAYPAL_CANCEL_URL</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}