"use client";

import React from "react";
import {
  Shield,
  AlertTriangle,
  XCircle,
  Clock,
  CreditCard,
  CheckCircle2,
  Calendar,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type PaymentState =
  | "PENDING_SECURITY"
  | "REVIEW_REQUIRED"
  | "BLOCKED"
  | "EXPIRED"
  | "PENDING_USER_APPROVAL"
  | "PAYPAL_ORDER_CREATED"
  | "BUYER_APPROVED"
  | "CAPTURE_PENDING"
  | "COMPLETED"
  | "FAILED";

interface LifecycleStep {
  key: PaymentState;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  order: number;
}

const LIFECYCLE_STEPS: LifecycleStep[] = [
  { key: "PENDING_SECURITY", label: "Pending Security", icon: Shield, color: "bg-indigo-600", order: 0 },
  { key: "REVIEW_REQUIRED", label: "Review Required", icon: AlertTriangle, color: "bg-amber-600", order: 1 },
  { key: "BLOCKED", label: "Blocked", icon: XCircle, color: "bg-red-600", order: 2 },
  { key: "EXPIRED", label: "Expired", icon: Calendar, color: "bg-gray-600", order: 3 },
  { key: "PENDING_USER_APPROVAL", label: "Awaiting Approval", icon: Clock, color: "bg-primary", order: 4 },
  { key: "PAYPAL_ORDER_CREATED", label: "PayPal Order Created", icon: CreditCard, color: "bg-primary", order: 5 },
  { key: "BUYER_APPROVED", label: "Buyer Approved", icon: CheckCircle2, color: "bg-green-600", order: 6 },
  { key: "CAPTURE_PENDING", label: "Capture Pending", icon: Clock, color: "bg-primary", order: 7 },
  { key: "COMPLETED", label: "Completed", icon: CheckCircle2, color: "bg-green-600", order: 8 },
  { key: "FAILED", label: "Failed", icon: XCircle, color: "bg-red-600", order: 9 },
];

interface PaymentLifecycleProps {
  currentState: PaymentState;
  className?: string;
}

export function PaymentLifecycle({ currentState, className }: PaymentLifecycleProps) {
  const currentIndex = LIFECYCLE_STEPS.findIndex(step => step.key === currentState);
  const isTerminalState = ["COMPLETED", "FAILED", "EXPIRED", "BLOCKED", "REVIEW_REQUIRED"].includes(currentState);

  const getStepClass = (step: LifecycleStep, index: number) => {
    const isActive = step.key === currentState;
    const isCompleted = index < currentIndex && !isTerminalState;
    const isInPath = index <= currentIndex;

    if (isActive) return "bg-primary text-white";
    if (isCompleted) return "bg-green-600 text-white";
    if (isInPath) return "bg-primary/20 text-primary";
    return "bg-secondary text-muted-foreground";
  };

  // Filter to only show relevant steps (those before or at current state, plus terminal states)
  const relevantSteps = LIFECYCLE_STEPS.filter(step => {
    if (step.key === currentState) return true;
    if (step.order <= currentIndex) return true;
    // For terminal states, show all steps up to and including it
    if (isTerminalState && step.order <= currentIndex) return true;
    return false;
  });

  return (
    <div className={cn("w-full", className)}>
      {/* Horizontal Flow */}
      <div className="flex items-center justify-between mb-6">
        {relevantSteps.map((step, index) => {
          const isActive = step.key === currentState;
          const isCompleted = step.order < currentIndex;
          const stepClass = getStepClass(step, step.order);
          const Icon = step.icon;

          return (
            <React.Fragment key={step.key}>
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    "flex h-12 w-12 items-center justify-center rounded-full text-sm font-medium",
                    stepClass
                  )}
                >
                  <Icon className="h-5 w-5" />
                  <span className="sr-only">{step.label}</span>
                </div>
                <span
                  className={cn(
                    "mt-2 text-xs font-medium",
                    isActive ? "text-foreground" : "text-muted-foreground"
                  )}
                >
                  {step.label}
                </span>
              </div>
              {index < relevantSteps.length - 1 && (
                <div
                  className={cn(
                    "h-2 flex-1",
                    isCompleted ? "bg-green-600" : "bg-secondary"
                  )}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Current State Indicator */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-3">
          <Badge
            className={cn(
              "text-xs font-medium",
              currentState === "COMPLETED" && "bg-green-900/30 text-green-600 border-green-200",
              currentState === "FAILED" && "bg-red-900/30 text-red-600 border-red-200",
              currentState === "BLOCKED" && "bg-red-900/30 text-red-600 border-red-200",
              currentState === "EXPIRED" && "bg-card/30 text-muted-foreground border-border",
              currentState === "REVIEW_REQUIRED" && "bg-amber-900/30 text-amber-700 border-amber-200",
              currentState === "PENDING_SECURITY" && "bg-slate-50 text-slate-700 border-slate-200",
              ["PENDING_USER_APPROVAL", "PAYPAL_ORDER_CREATED", "BUYER_APPROVED", "CAPTURE_PENDING"].includes(currentState) &&
                "bg-blue-900/30 text-accent border-blue-200"
            )}
          >
            {currentState}
          </Badge>
          <span className="text-sm text-muted-foreground">
            Current payment state
          </span>
        </div>
      </div>
    </div>
  );
}