"use client";

import React, { useState, useEffect } from "react";
import { ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Loader2, Brain, Search, Filter } from "lucide-react";
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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  analyzeTransaction,
  getTransactionAnalysis,
  ThreatAnalysisResponse,
  formatRelativeTime,
  getThreatLevelBadgeClass,
  getSeverityBadgeClass,
} from "@/lib/api";

export default function ThreatIntelligencePage() {
  const [transactionIdInput, setTransactionIdInput] = useState("");
  const [analysis, setAnalysis] = useState<ThreatAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"run" | "history">("run");

  const handleTabChange = (value: "run" | "history") => {
    setActiveTab(value);
  };

  async function handleAnalyze(e: React.FormEvent) {
    e.preventDefault();
    if (!transactionIdInput.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const result = await analyzeTransaction(transactionIdInput.trim());
      setAnalysis(result);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to run threat analysis.");
    } finally {
      setLoading(false);
    }
  }

  async function handleFetchAnalysis(e: React.FormEvent) {
    e.preventDefault();
    if (!transactionIdInput.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const result = await getTransactionAnalysis(transactionIdInput.trim());
      setAnalysis(result);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Analysis not found for this transaction.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-foreground">Threat Intelligence</h1>
        <p className="text-muted-foreground">
          Advisory AI threat analysis for payment transactions.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <p className="font-semibold">Error</p>
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-3">
        {/* Input & Actions */}
        <Card className="border-border bg-card md:col-span-3">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground">Run Advisory Analysis</CardTitle>
            <CardDescription>
              Submit a transaction ID to run or retrieve advisory AI threat analysis.
              Analysis is advisory only and never authorizes payments.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <label className="text-xs font-medium text-muted-foreground block mb-1">Transaction ID (UUID)</label>
                <Input
                  value={transactionIdInput}
                  onChange={(e) => setTransactionIdInput(e.target.value)}
                  placeholder="e.g. 0f8fad5b-d9cb-469f-a165-70867728950e"
                />
              </div>
              <div className="flex gap-2">
                <Button type="submit" disabled={loading} className="bg-primary hover:bg-primary/90">
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {loading ? "Analyzing..." : "Run Analysis"}
                </Button>
                <Button type="button" variant="outline" onClick={handleFetchAnalysis} disabled={loading} className="border-border">
                  Fetch Existing
                </Button>
              </div>
            </form>

            <Tabs value={activeTab} onValueChange={handleTabChange} className="mt-4">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="run">New Analysis</TabsTrigger>
                <TabsTrigger value="history">Retrieve Existing</TabsTrigger>
              </TabsList>
              <TabsContent value="run">
                <p className="text-xs text-muted-foreground mt-2">
                  Runs a fresh advisory analysis with optional context. Results are persisted but never override deterministic policy.
                </p>
              </TabsContent>
              <TabsContent value="history">
                <p className="text-xs text-muted-foreground mt-2">
                  Retrieves the most recent persisted analysis for this transaction. Analysis output is advisory only.
                </p>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Analysis Results */}
        {analysis && (
          <Card className="border-border bg-card md:col-span-3">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground">Threat Assessment</CardTitle>
              <CardDescription>Advisory AI threat analysis. Never a payment authorization.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Top-level summary */}
              <div className="flex flex-wrap items-center gap-4 border border-border rounded-lg p-4 bg-background">
                <div className="flex items-center gap-3">
                  <Brain className="h-6 w-6 text-accent" />
                  <div>
                    <p className="text-sm font-medium text-foreground">Model: {analysis.model_name}</p>
                    <p className="text-xs text-muted-foreground">Analyzed: {formatRelativeTime(analysis.analyzed_at)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={getThreatLevelBadgeClass(analysis.threat_level)}>
                    Threat Level: {analysis.threat_level}
                  </Badge>
                  <Badge variant="outline" className={getThreatLevelBadgeClass(analysis.provider_status)}>
                    Provider: {analysis.provider_status}
                  </Badge>
                  <Badge variant="outline" className={getSeverityBadgeClass(analysis.intent_alignment)}>
                    Alignment: {analysis.intent_alignment}
                  </Badge>
                </div>
              </div>

              {/* Risk Score */}
              <div className="grid grid-cols-3 gap-4">
                <div className="border border-border rounded-lg p-4 bg-background">
                  <p className="text-xs text-muted-foreground">Risk Score</p>
                  <p className="text-3xl font-bold text-foreground">{analysis.risk_score}/100</p>
                  <p className="text-xs text-muted-foreground mt-1">Descriptive only, never used for authorization</p>
                </div>
                <div className="border border-border rounded-lg p-4 bg-background">
                  <p className="text-xs text-muted-foreground">Detected Threats</p>
                  <p className="text-3xl font-bold text-foreground">{analysis.detected_threats.length}</p>
                  <p className="text-xs text-muted-foreground mt=1">Categorized findings</p>
                </div>
                <div className="border border-border rounded-lg p-4 bg-background">
                  <p className="text-xs text-muted-foreground">Analysis Status</p>
                  <p className="text-3xl font-bold text-foreground">{analysis.analysis_status}</p>
                  <p className="text-xs text-muted-foreground mt-1">{analysis.provider_status} outcome</p>
                </div>
              </div>

              {/* Threats Table */}
              {analysis.detected_threats.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-foreground/80 mb-3">Detected Threats</h4>
                  <div className="space-y-2">
                    {analysis.detected_threats.map((threat, idx) => (
                      <div key={idx} className="border border-border rounded-lg p-3 bg-background">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium text-foreground capitalize">{threat.category.replace(/_/g, " ")}</span>
                          <Badge variant="outline" className={getSeverityBadgeClass(threat.severity)}>
                            {threat.severity}
                          </Badge>
                        </div>
                        <p className="text-xs text-foreground/80">{threat.evidence}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suspicious Instructions */}
              {analysis.suspicious_instructions.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-foreground/80 mb-3">Suspicious Instructions</h4>
                  <div className="space-y-1">
                    {analysis.suspicious_instructions.map((instr, idx) => (
                      <div key={idx} className="border-l-2 border-amber-600 pl-3 py-1 bg-background/50">
                        <p className="text-xs text-amber-800">{instr}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidence */}
              {analysis.evidence.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold text-foreground/80 mb-3">Evidence</h4>
                  <div className="space-y-1">
                    {analysis.evidence.map((ev, idx) => (
                      <div key={idx} className="border border-border rounded-lg p-2 bg-background text-xs text-foreground/80">
                        {ev}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Explanation & Recommendation */}
              <div className="grid md:grid-cols-2 gap-4">
                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-semibold text-foreground/80 mb-2">Explanation</h4>
                  <p className="text-xs text-foreground/80">{analysis.explanation}</p>
                </div>
                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-semibold text-foreground/80 mb-2">Recommended Handling</h4>
                  <p className="text-xs text-foreground/80">{analysis.recommended_handling}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Empty State */}
        {!analysis && !loading && !error && (
          <Card className="border-border bg-card md:col-span-3">
            <CardContent className="py-12 text-center">
              <ShieldAlert className="mx-auto h-12 w-12 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">No Analysis Data</h3>
              <p className="text-muted-foreground">Run a threat analysis on a transaction to see advisory intelligence.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}