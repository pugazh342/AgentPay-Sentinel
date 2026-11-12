"use client";

import React, { useState, useEffect } from "react";
import {
  FlaskConical,
  ShieldCheck,
  Loader2,
  Play,
  Eye,
  Search,
  Filter,
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
import { Input } from "@/components/ui/input";
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
  getAdversarialReport,
  runAdversarialScenarios,
  AdversarialReport,
  formatRelativeTime,
  getStatusBadgeClass,
} from "@/lib/api";

const CATEGORIES = [
  "AI",
  "AUTHORIZATION",
  "CONCURRENCY",
  "INTEGRITY",
  "LIVE_ENDPOINT",
  "PAYMENT",
  "POLICY",
  "REPLAY",
  "STATE_MACHINE",
  "WEBHOOK",
];

export default function AdversarialLabPage() {
  const [report, setReport] = useState<AdversarialReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedScenario, setSelectedScenario] = useState<AdversarialReport["scenarios"][0] | null>(null);

  async function loadReport() {
    setLoading(true);
    setError(null);
    try {
      const data = await getAdversarialReport();
      setReport(data);
    } catch (err) {
      // If the API route doesn't exist yet, show a helpful message
      setError("Adversarial report API not available. Ensure the backend is running and the /api/adversarial/report endpoint is implemented.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => {
      loadReport();
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  async function handleRunScenarios() {
    setRunning(true);
    setError(null);
    try {
      const data = await runAdversarialScenarios();
      setReport(data);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to run adversarial scenarios. The server-side endpoint may need to be implemented.");
    } finally {
      setRunning(false);
    }
  }

  const filteredScenarios = report?.scenarios.filter((s) => {
    const matchesCategory = filterCategory === "all" || s.category === filterCategory;
    const matchesStatus = filterStatus === "all" || s.test_status === filterStatus;
    const matchesSearch =
      searchQuery === "" ||
      s.attack_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesStatus && matchesSearch;
  }) || [];

  const categoriesPresent = [...new Set(report?.scenarios.map((s) => s.category) || [])].sort();

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">Adversarial Security Lab</h1>
            <p className="text-muted-foreground mt-1">
              Deterministic attack simulation and invariant verification.
            </p>
          </div>
          <Button onClick={handleRunScenarios} disabled={running} className="bg-primary hover:bg-primary/90">
            {running ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Running...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                Run Full Suite
              </>
            )}
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <p className="font-semibold">Error</p>
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}

      {/* Summary Stats */}
      {report && (
        <div className="grid gap-4 md:grid-cols-5">
          <Card className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="text-3xl font-bold text-foreground">{report.summary.scenarios_total}</div>
              <p className="text-xs text-muted-foreground">Total Scenarios</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="text-3xl font-bold text-green-600">{report.summary.passed}</div>
              <p className="text-xs text-muted-foreground">Passed</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="text-3xl font-bold text-red-600">{report.summary.failed}</div>
              <p className="text-xs text-muted-foreground">Failed</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="text-3xl font-bold text-amber-700">{report.summary.errors}</div>
              <p className="text-xs text-muted-foreground">Errors</p>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="text-3xl font-bold text-accent">
                {report.summary.invariants_verified}/{report.summary.invariants_total}
              </div>
              <p className="text-xs text-muted-foreground">Invariants Verified</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Content */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Invariants Panel */}
        {report && (
          <Card className="min-w-0 border-border bg-card lg:col-span-1">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-green-600" />
                Security Invariants
              </CardTitle>
              <CardDescription>
                Verified by execution evidence. {report.summary.invariants_verified}/{report.summary.invariants_total} verified.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {report.invariants.map((inv) => (
                <div
                  key={inv.invariant_id}
                  className={`border-l-4 p-3 rounded-r-lg bg-background ${
                    inv.verified ? "border-green-600" : "border-red-600"
                  }`}
                >
                  <div className="flex flex-wrap items-start justify-between gap-2 sm:flex-nowrap">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground break-words">{inv.invariant_id}</p>
                      <p className="text-xs text-muted-foreground mt-0.5 break-words">{inv.description}</p>
                    </div>
                    <Badge
                      variant="outline"
                      className={`${inv.verified ? "text-green-600 border-green-600" : "text-red-600 border-red-600"} shrink-0`}
                    >
                      {inv.verified ? "Verified" : "Failed"}
                    </Badge>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Scenarios Panel */}
        <Card className="min-w-0 border-border bg-card lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
              <FlaskConical className="h-5 w-5 text-accent" />
              Attack Scenarios
            </CardTitle>
            <CardDescription>
              {filteredScenarios.length} of {report?.scenarios.length || 0} scenarios displayed.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Filters */}
            <div className="flex flex-col sm:flex-row gap-4 mb-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search scenarios..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="h-10 w-full sm:w-40 rounded-md border border-border bg-card px-3 py-2 text-sm ring-offset-gray-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 text-foreground"
              >
                <option value="all">All Categories</option>
                {categoriesPresent.map((cat) => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="h-10 w-full sm:w-32 rounded-md border border-border bg-card px-3 py-2 text-sm ring-offset-gray-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 text-foreground"
              >
                <option value="all">All Statuses</option>
                <option value="PASSED">Passed</option>
                <option value="FAILED">Failed</option>
                <option value="ERROR">Error</option>
                <option value="SKIPPED">Skipped</option>
              </select>
            </div>

            {/* Scenarios Table */}
            {loading ? (
              <div className="text-center py-8 text-muted-foreground">Loading adversarial report...</div>
            ) : report && report.scenarios.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">No scenarios found. Run the adversarial suite to generate results.</div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[30%]">Attack ID</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="w-[10%]">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredScenarios.map((scenario) => (
                      <TableRow key={scenario.attack_id} onClick={() => setSelectedScenario(scenario)} className="cursor-pointer">
                        <TableCell>
                          <div className="font-mono text-xs text-foreground">{scenario.attack_id}</div>
                          <div className="text-xs text-muted-foreground truncate max-w-[200px]">{scenario.name}</div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="text-xs">
                            {scenario.category}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={getStatusBadgeClass(scenario.test_status)}>
                            {scenario.test_status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-center text-muted-foreground">
                          <Eye className="h-4 w-4 mx-auto" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scenario Detail Dialog */}
        {selectedScenario && (
          <Dialog open onOpenChange={(open) => !open && setSelectedScenario(null)}>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-auto">
              <DialogHeader>
                <DialogTitle className="flex items-center justify-between">
                  <div>
                    <Badge variant="secondary" className="mr-2">{selectedScenario.category}</Badge>
                    {selectedScenario.attack_id}
                  </div>
                  <Badge variant="outline" className={getStatusBadgeClass(selectedScenario.test_status)}>
                    {selectedScenario.test_status}
                  </Badge>
                </DialogTitle>
                <DialogDescription>{selectedScenario.description}</DialogDescription>
              </DialogHeader>

              <div className="space-y-6">
                {/* Attack Input */}
                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-semibold text-foreground/80 mb-2">Attack Input</h4>
                  <pre className="text-xs text-foreground/80 overflow-auto max-h-48">
                    {JSON.stringify(selectedScenario.attack_input, null, 2)}
                  </pre>
                </div>

                {/* Expected Results */}
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <h4 className="text-sm font-semibold text-foreground/80 mb-2">Expected Decision</h4>
                    <p className="font-mono text-sm text-foreground">{selectedScenario.expected_security_decision}</p>
                  </div>
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <h4 className="text-sm font-semibold text-foreground/80 mb-2">Expected Payment State</h4>
                    <p className="font-mono text-sm text-foreground">
                      {selectedScenario.expected_payment_state || "N/A"}
                    </p>
                  </div>
                </div>

                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-semibold text-foreground/80 mb-2">Expected Reason Codes</h4>
                  <div className="flex flex-wrap gap-1">
                    {selectedScenario.expected_reason_codes.map((code, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {code}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Actual Results */}
                <div className="border border-border rounded-lg p-4 bg-background">
                  <h4 className="text-sm font-semibold text-foreground/80 mb-3">Actual Result</h4>
                  <div className="grid md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Security Decision</p>
                      <p className="font-mono text-sm text-foreground">{selectedScenario.actual_result.security_decision}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Payment State</p>
                      <p className="font-mono text-sm text-foreground">
                        {selectedScenario.actual_result.payment_state || "N/A"}
                      </p>
                    </div>
                  </div>

                  {selectedScenario.actual_result.reason_codes.length > 0 && (
                    <div className="mb-4">
                      <p className="text-xs text-muted-foreground mb-2">Reason Codes</p>
                      <div className="flex flex-wrap gap-1">
                        {selectedScenario.actual_result.reason_codes.map((code, idx) => (
                          <Badge key={idx} variant="outline" className="text-xs">
                            {code}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Checks */}
                  <div>
                    <h4 className="text-sm font-semibold text-foreground/80 mb-2">Validation Checks</h4>
                    <div className="grid gap-2 md:grid-cols-2">
                      {Object.entries(selectedScenario.actual_result.checks).map(([check, passed]) => (
                        <div key={check} className="flex items-center justify-between text-xs py-1 border-b border-border last:border-0">
                          <span className="text-muted-foreground capitalize">{check.replace(/_/g, " ")}</span>
                          <Badge variant={passed ? "success" : "destructive"}>
                            {passed ? "PASS" : "FAIL"}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </div>
  );
}