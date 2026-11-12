"use client";

import React, { useState, useEffect, useRef } from "react";
import { Plus, CreditCard, Loader2, CheckCircle2, XCircle, Eye, Calendar, DollarSign, Building2, Shield } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationPrevious,
  PaginationNext,
} from "@/components/ui/pagination";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  createIntent,
  getIntent,
  listIntents,
  IntentCreateRequest,
  IntentResponse,
  formatCurrency,
  formatDate,
} from "@/lib/api";

export default function PurchaseIntentsPage() {
  const [intents, setIntents] = useState<IntentResponse[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [listLoading, setListLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [listRetryCount, setListRetryCount] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedIntent, setSelectedIntent] = useState<IntentResponse | null>(null);
  const listRequestIdRef = useRef(0);
  const listInFlightRef = useRef(false);

  // Form state
  const [formData, setFormData] = useState<IntentCreateRequest>({
    user_id: "user_123",
    purpose: "",
    merchant_id: "merchant_shoes",
    product_category: "footwear",
    max_amount: "800.00",
    currency: "USD",
    max_quantity: 1,
    require_approval: true,
    expires_at: "",
  });

  useEffect(() => {
    const timer = setTimeout(() => {
      setFormData((prev) => ({
        ...prev,
        expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
      }));
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // Fetch persisted intents (backend-backed history)
  useEffect(() => {
    let cancelled = false;
    const requestId = ++listRequestIdRef.current;
    listInFlightRef.current = true;
    async function loadIntents() {
      setListLoading(true);
      setError(null);
      try {
        const result = await listIntents({ limit, offset });
        if (!cancelled && requestId === listRequestIdRef.current) {
          setIntents(result.results);
          setTotalCount(result.total_count);
        }
      } catch (err) {
        if (!cancelled && requestId === listRequestIdRef.current) {
          setError((err instanceof Error ? err.message : '') || 'Failed to load intents.');
        }
      } finally {
        if (requestId === listRequestIdRef.current) {
          listInFlightRef.current = false;
          if (!cancelled) setListLoading(false);
        }
      }
    }
    loadIntents();
    return () => { cancelled = true; };
  }, [limit, offset, listRetryCount]);

  const handleRetryIntents = () => {
    if (listInFlightRef.current) return;
    setListRetryCount((c) => c + 1);
  };

  async function fetchIntent(intentId: string) {
    try {
      const intent = await getIntent(intentId);
      setSelectedIntent(intent);
      setDialogOpen(true);
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to fetch intent.");
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);

    try {
      const intent = await createIntent(formData);
      setOffset(0);
      setListRetryCount((c) => c + 1);
      setDialogOpen(false);
      // Reset form
      setFormData({
        user_id: "user_123",
        purpose: "",
        merchant_id: "merchant_shoes",
        product_category: "footwear",
        max_amount: "800.00",
        currency: "USD",
        max_quantity: 1,
        require_approval: true,
        expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
      });
    } catch (err) {
      setError((err instanceof Error ? err.message : "") || "Failed to create intent.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">Purchase Intents</h1>
            <p className="text-muted-foreground mt-1">
              Create and manage immutable purchase authorizations.
            </p>
          </div>
          <Button onClick={() => setDialogOpen(true)} className="bg-primary hover:bg-primary/90">
            <Plus className="mr-2 h-4 w-4" />
            Create Intent
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          <p className="font-semibold">Error</p>
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}

      {/* Create Intent Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Create Purchase Intent</DialogTitle>
            <DialogDescription>
              Define an immutable purchase authorization. All fields are validated and fingerprinted.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreate} className="space-y-4">
            <div className="grid gap-4">
              <div>
                <Label htmlFor="user_id">User ID</Label>
                <Input
                  id="user_id"
                  value={formData.user_id}
                  onChange={(e) => setFormData({ ...formData, user_id: e.target.value })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="purpose">Purchase Purpose</Label>
                <Input
                  id="purpose"
                  value={formData.purpose}
                  onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
                  placeholder="e.g. Purchase one pair of running shoes"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="merchant_id">Merchant ID</Label>
                  <Input
                    id="merchant_id"
                    value={formData.merchant_id}
                    onChange={(e) => setFormData({ ...formData, merchant_id: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="product_category">Product Category</Label>
                  <Input
                    id="product_category"
                    value={formData.product_category}
                    onChange={(e) => setFormData({ ...formData, product_category: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="max_amount">Maximum Amount</Label>
                  <Input
                    id="max_amount"
                    type="text"
                    value={formData.max_amount}
                    onChange={(e) => setFormData({ ...formData, max_amount: e.target.value })}
                    placeholder="800.00"
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="currency">Currency</Label>
                  <Input
                    id="currency"
                    value={formData.currency}
                    onChange={(e) => setFormData({ ...formData, currency: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="max_quantity">Max Quantity</Label>
                  <Input
                    id="max_quantity"
                    type="number"
                    value={formData.max_quantity}
                    onChange={(e) => setFormData({ ...formData, max_quantity: parseInt(e.target.value) || 1 })}
                    min="1"
                    max="1000000"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="expires_at">Expires At</Label>
                  <Input
                    id="expires_at"
                    type="datetime-local"
                    value={formData.expires_at.slice(0, 16)}
                    onChange={(e) => setFormData({ ...formData, expires_at: new Date(e.target.value).toISOString() })}
                    required
                  />
                </div>
                <div className="flex items-end">
                  <Label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.require_approval}
                      onChange={(e) => setFormData({ ...formData, require_approval: e.target.checked })}
                      className="h-4 w-4 rounded border-border text-blue-600 focus:ring-ring"
                    />
                    <span className="text-sm text-foreground/80">Require Approval</span>
                  </Label>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-border">
              <Button type="button" variant="outline" onClick={() => setDialogOpen(false)} className="border-border">
                Cancel
              </Button>
              <Button type="submit" disabled={creating} className="bg-primary hover:bg-primary/90">
                {creating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : "Create Intent"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Intent Detail Dialog */}
      {selectedIntent && (
        <Dialog open onOpenChange={() => setSelectedIntent(null)}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center justify-between">
                <div>
                  <Badge variant="secondary" className="mr-2">{selectedIntent.product_category}</Badge>
                  {selectedIntent.intent_id}
                </div>
              </DialogTitle>
              <DialogDescription>
                {selectedIntent.purpose}
              </DialogDescription>
            </DialogHeader>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                      <Building2 className="h-3 w-3" /> Merchant
                    </p>
                    <p className="font-mono text-sm text-foreground">{selectedIntent.merchant_id}</p>
                  </div>
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                      <Shield className="h-3 w-3" /> Category
                    </p>
                    <p className="font-mono text-sm text-foreground">{selectedIntent.product_category}</p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                      <DollarSign className="h-3 w-3" /> Max Amount
                    </p>
                    <p className="font-mono text-sm text-foreground">{formatCurrency(selectedIntent.max_amount, selectedIntent.currency)}</p>
                  </div>
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                      <Building2 className="h-3 w-3" /> Max Quantity
                    </p>
                    <p className="font-mono text-sm text-foreground">{selectedIntent.max_quantity}</p>
                  </div>
                  <div className="border border-border rounded-lg p-4 bg-background">
                    <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> Expires
                    </p>
                    <p className="font-mono text-sm text-foreground">{formatDate(selectedIntent.expires_at)}</p>
                  </div>
                </div>

                <div className="border border-border rounded-lg p-4 bg-background">
                  <p className="text-xs text-muted-foreground mb-1">Created At</p>
                  <p className="font-mono text-sm text-foreground">{formatDate(selectedIntent.created_at)}</p>
                </div>

                <div className="border border-amber-200 rounded-lg p-4 bg-amber-50">
                  <p className="text-xs text-amber-700 mb-2 flex items-center gap-1">
                    <Shield className="h-3 w-3" /> Security Note
                  </p>
                  <p className="text-xs text-amber-800">
                    This intent is immutable and fingerprinted with HMAC-SHA256.
                    It cannot be modified after creation. Evaluation enforces fingerprint integrity.
                  </p>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 flex items-center justify-between gap-4">
          <span>{error}</span>
          <Button variant="outline" size="sm" onClick={handleRetryIntents} className="border-red-700 text-red-700">
            Retry
          </Button>
        </div>
      )}

      {/* Intents Table */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-foreground">Intents</CardTitle>
          <CardDescription>
            {totalCount} intent{totalCount !== 1 ? "s" : ""} persisted.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {listLoading && intents.length === 0 ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>
          ) : intents.length === 0 ? (
            <div className="text-center py-12">
              <CreditCard className="mx-auto h-12 w-12 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">No Purchase Intents</h3>
              <p className="text-muted-foreground mb-4">Create an immutable purchase intent to get started.</p>
              <Button onClick={() => setDialogOpen(true)} className="bg-primary hover:bg-primary/90">
                <Plus className="mr-2 h-4 w-4" />
                Create First Intent
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Intent ID</TableHead>
                    <TableHead>Purpose</TableHead>
                    <TableHead>Merchant</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Max Amount</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead className="w-[80px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {intents.map((intent) => (
                    <TableRow key={intent.intent_id}>
                      <TableCell>
                        <div className="font-mono text-xs text-foreground">{intent.intent_id}</div>
                      </TableCell>
                      <TableCell>
                        <div className="truncate max-w-[200px] text-sm text-foreground">{intent.purpose}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{intent.merchant_id}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{intent.product_category}</Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-sm text-foreground">{formatCurrency(intent.max_amount, intent.currency)}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-foreground/80">{formatDate(intent.expires_at)}</span>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => fetchIntent(intent.intent_id)}
                          aria-label="View intent details"
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {Math.ceil(totalCount / limit) > 1 && (
        <div className="flex justify-center">
          <Pagination>
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  onClick={() => {
                    if (offset > 0) setOffset(Math.max(0, offset - limit));
                  }}
                  disabled={offset === 0}
                />
              </PaginationItem>
              <PaginationItem>
                <span className="text-sm text-muted-foreground">
                  Page {Math.floor(offset / limit) + 1} of {Math.ceil(totalCount / limit)}
                </span>
              </PaginationItem>
              <PaginationItem>
                <PaginationNext
                  onClick={() => {
                    if (offset + limit < totalCount) setOffset(offset + limit);
                  }}
                  disabled={offset + limit >= totalCount}
                />
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        </div>
      )}
    </div>
  );
}