"use client";

import React, { useState, useEffect, useRef } from "react";
import { Search, Filter, Gavel, ShieldAlert, CheckCircle2, XCircle, Loader2, ChevronDown, ChevronUp } from "lucide-react";
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
  getSecurityEvents,
  listPayments,
  SecurityEventResponse,
  SecurityEventListResponse,
  Decision,
  ReasonCode,
  EventType,
  formatDate,
  getDecisionBadgeClass,
} from "@/lib/api";

const DECISIONS: Decision[] = ["BLOCK", "REVIEW_REQUIRED", "ALLOW_FOR_APPROVAL"];
// Only event types actually emitted by the backend (verified against the DB).
// Other EventType values exist in the enum but are never recorded; filtering by
// them always returns empty results.
const EVENT_TYPES: EventType[] = [
  "INTENT_CREATED",
  "TRANSACTION_EVALUATED",
];

export default function AuditExplorerPage() {
  const [events, setEvents] = useState<SecurityEventResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [limit, setLimit] = useState(50);
  const [retryCount, setRetryCount] = useState(0);
  const requestIdRef = useRef(0);
  const inFlightRef = useRef(false);
  const [filterEventType, setFilterEventType] = useState<string>("all");
  const [filterDecision, setFilterDecision] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventResponse | null>(null);
  const [paymentEvidence, setPaymentEvidence] = useState<Array<{ payment_id: string; state: string; paypal_capture_id: string | null; paypal_status: string | null }>>([]);

  useEffect(() => {
    let cancelled = false;
    const requestId = ++requestIdRef.current;
    inFlightRef.current = true;
    async function loadEvents() {
      setLoading(true);
      setError(null);
      try {
        const data = await getSecurityEvents({
          limit,
          event_type: filterEventType !== "all" ? filterEventType : undefined,
          decision: filterDecision !== "all" ? (filterDecision as Decision) : undefined,
        });
        if (!cancelled && requestId === requestIdRef.current) {
          setEvents(data.items);
          setTotalCount(data.total_count);
        }
      } catch (err) {
        if (!cancelled && requestId === requestIdRef.current) {
          setError((err instanceof Error ? err.message : "") || "Failed to load security events.");
        }
      } finally {
        if (requestId === requestIdRef.current) {
          inFlightRef.current = false;
          if (!cancelled) setLoading(false);
        }
      }
    }
    loadEvents();
    return () => { cancelled = true; };
  }, [limit, filterEventType, filterDecision, retryCount]);

  const handleRetry = () => {
    if (inFlightRef.current) return;
    setRetryCount((c) => c + 1);
  };

  useEffect(() => {
    (async () => {
      try {
        const data = await listPayments({ limit: 100 });
        setPaymentEvidence(
          data.results.map((p) => ({
            payment_id: p.payment_id,
            state: p.state,
            paypal_capture_id: p.paypal_capture_id,
            paypal_status: p.paypal_status,
          }))
        );
      } catch {
        // Non-critical; leave empty.
      }
    })();
  }, []);

  const filteredEvents = events.filter((event) => {
    const matchesSearch =
      searchQuery === "" ||
      event.event_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (event.transaction_id?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false) ||
      event.event_type.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSearch;
  });

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">Audit Explorer</h1>
            <p className="text-muted-foreground mt-1">
              Security event timeline with transaction decisions, payment state changes, and webhook reconciliations.
            </p>
          </div>
          <Button variant="outline" onClick={handleRetry} className="border-border">
            <Loader2 className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 flex items-center justify-between gap-4">
          <div>
            <p className="font-semibold">Error</p>
            <p className="text-sm text-red-600">{error}</p>
          </div>
          <Button variant="outline" size="sm" onClick={handleRetry} className="border-red-700 text-red-700">
            Retry
          </Button>
        </div>
      )}

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="text-3xl font-bold text-foreground">{totalCount}</div>
            <p className="text-xs text-muted-foreground">Total Events</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="text-3xl font-bold text-accent">
              {events.filter((e) => e.decision === "BLOCK").length}
            </div>
            <p className="text-xs text-muted-foreground">Blocked</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="text-3xl font-bold text-amber-700">
              {events.filter((e) => e.decision === "REVIEW_REQUIRED").length}
            </div>
            <p className="text-xs text-muted-foreground">Review Required</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="text-3xl font-bold text-green-600">
              {events.filter((e) => e.decision === "ALLOW_FOR_APPROVAL").length}
            </div>
            <p className="text-xs text-muted-foreground">Allowed for Approval</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card className="border-border bg-card">
        <CardContent className="pt-6">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search events..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <select
              value={filterEventType}
              onChange={(e) => setFilterEventType(e.target.value)}
              className="h-10 w-full sm:w-52 rounded-md border border-border bg-card px-3 py-2 text-sm ring-offset-gray-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 text-foreground"
            >
              <option value="all">All Event Types</option>
              {EVENT_TYPES.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
            <select
              value={filterDecision}
              onChange={(e) => setFilterDecision(e.target.value)}
              className="h-10 w-full sm:w-44 rounded-md border border-border bg-card px-3 py-2 text-sm ring-offset-gray-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 text-foreground"
            >
              <option value="all">All Decisions</option>
              {DECISIONS.map((d) => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="h-10 w-full sm:w-32 rounded-md border border-border bg-card px-3 py-2 text-sm ring-offset-gray-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 text-foreground"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Gavel className="h-5 w-5 text-accent" />
            Security Events
          </CardTitle>
          <CardDescription>
            Showing {filteredEvents.length} of {events.length} events (limit: {limit}).
            Events contain no secrets, credentials, or unnecessary personal data.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading audit events...</div>
          ) : filteredEvents.length === 0 ? (
            <div className="text-center py-12">
              <Gavel className="mx-auto h-12 w-12 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">No Security Events</h3>
              <p className="text-muted-foreground">
                {events.length === 0
                  ? "No events recorded yet. Run some transactions to generate audit data."
                  : "No events match the current filters."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[140px]">Timestamp</TableHead>
                    <TableHead className="w-[180px]">Event Type</TableHead>
                    <TableHead className="w-[120px]">Decision</TableHead>
                    <TableHead>Reason Codes</TableHead>
                    <TableHead className="w-[160px]">Transaction ID</TableHead>
                    <TableHead className="w-[80px]">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEvents.map((event) => (
                    <TableRow
                      key={event.event_id}
                      onClick={() => setSelectedEvent(event)}
                      className="cursor-pointer hover:bg-secondary/50"
                    >
                      <TableCell>
                        <span className="text-xs font-mono text-foreground/80">{formatDate(event.timestamp)}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">{event.event_type}</Badge>
                      </TableCell>
                      <TableCell>
                        {event.decision ? (
                          <Badge variant="outline" className={getDecisionBadgeClass(event.decision)}>
                            {event.decision}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {event.reason_codes.map((code, idx) => (
                            <Badge key={idx} variant="outline" className="text-xs">
                              {code}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        {event.transaction_id ? (
                          <span className="font-mono text-xs text-foreground truncate max-w-[140px]">
                            {event.transaction_id}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-center text-muted-foreground">
                        <ChevronDown className="h-4 w-4 mx-auto" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Payment Lifecycle Evidence (read-only, source: payments API) */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
            Payment Lifecycle Evidence
          </CardTitle>
          <CardDescription>
            Read-only payment state and capture evidence from the payments API. Source: payments.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {paymentEvidence.length === 0 ? (
            <p className="text-sm text-muted-foreground">No payment evidence available.</p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Payment ID</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Capture ID</TableHead>
                    <TableHead>PayPal Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paymentEvidence.map((p) => (
                    <TableRow key={p.payment_id}>
                      <TableCell className="font-mono text-xs text-foreground">{p.payment_id.slice(0, 8)}...{p.payment_id.slice(-4)}</TableCell>
                      <TableCell><Badge variant="secondary" className="text-xs">{p.state}</Badge></TableCell>
                      <TableCell className="font-mono text-xs text-foreground">{p.paypal_capture_id || "—"}</TableCell>
                      <TableCell className="text-xs text-foreground/80">{p.paypal_status || "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Event Detail Dialog */}
      {selectedEvent && (
        <Dialog open onOpenChange={() => setSelectedEvent(null)}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center justify-between">
                <div>
                  <Badge variant="secondary" className="mr-2">{selectedEvent.event_type}</Badge>
                  {selectedEvent.event_id}
                </div>
              </DialogTitle>
              <DialogDescription>
                Recorded at {formatDate(selectedEvent.timestamp)}
              </DialogDescription>
            </DialogHeader>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1">Event ID</p>
                    <p className="font-mono text-xs text-foreground">{selectedEvent.event_id}</p>
                  </div>
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1">Timestamp</p>
                    <p className="font-mono text-xs text-foreground">{formatDate(selectedEvent.timestamp)}</p>
                  </div>
                </div>

                {selectedEvent.transaction_id && (
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1">Transaction ID</p>
                    <p className="font-mono text-xs text-foreground">{selectedEvent.transaction_id}</p>
                  </div>
                )}

                {selectedEvent.decision && (
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1">Decision</p>
                    <Badge variant="outline" className={getDecisionBadgeClass(selectedEvent.decision!)}>
                      {selectedEvent.decision}
                    </Badge>
                  </div>
                )}

                {selectedEvent.reason_codes.length > 0 && (
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-2">Reason Codes</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedEvent.reason_codes.map((code, idx) => (
                        <Badge key={idx} variant="outline" className="text-xs">
                          {code}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </DialogContent>
          </Dialog>
        )}
    </div>
  );
}