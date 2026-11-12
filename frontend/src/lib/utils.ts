/**
 * Utility functions for the frontend
 */

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatCurrency(amount: string, currency: string): string {
  const num = parseFloat(amount);
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(num);
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(dateString);
}

export function getDecisionBadgeClass(decision: string): string {
  switch (decision) {
    case 'ALLOW_FOR_APPROVAL':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'BLOCK':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'REVIEW_REQUIRED':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700';
  }
}

export function getPaymentStateBadgeClass(state: string): string {
  switch (state) {
    case 'COMPLETED':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'FAILED':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'BLOCKED':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'REVIEW_REQUIRED':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'EXPIRED':
      return 'border-slate-300 bg-slate-100 text-slate-700';
    case 'PENDING_USER_APPROVAL':
      return 'border-sky-200 bg-sky-50 text-sky-700';
    case 'PAYPAL_ORDER_CREATED':
      return 'border-blue-200 bg-blue-50 text-[hsl(var(--primary))]';
    case 'BUYER_APPROVED':
      return 'border-indigo-200 bg-indigo-50 text-indigo-700';
    case 'CAPTURE_PENDING':
      return 'border-violet-200 bg-violet-50 text-violet-700';
    case 'PENDING_SECURITY':
      return 'border-slate-200 bg-slate-50 text-slate-700';
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700';
  }
}

export function getThreatLevelBadgeClass(level: string): string {
  switch (level) {
    case 'CRITICAL':
      return 'border-red-300 bg-red-100 text-red-800';
    case 'HIGH':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'MEDIUM':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'LOW':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'NONE':
    case 'INDETERMINATE':
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700';
  }
}

export function getSeverityBadgeClass(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'border-red-300 bg-red-100 text-red-800';
    case 'HIGH':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'MEDIUM':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'LOW':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'ALIGNED':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'MISALIGNED':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'AMBIGUOUS':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'INSUFFICIENT_CONTEXT':
      return 'border-slate-200 bg-slate-50 text-slate-700';
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700';
  }
}

export function getStatusBadgeClass(status: string): string {
  switch (status) {
    case 'PASSED':
    case 'VERIFIED':
    case 'COMPLETED':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'FAILED':
    case 'BLOCKED':
    case 'CRITICAL':
    case 'ERROR':
      return 'border-red-200 bg-red-50 text-red-700';
    case 'REVIEW_REQUIRED':
    case 'WARNING':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'SKIPPED':
    case 'PENDING':
      return 'border-slate-200 bg-slate-50 text-slate-700';
    case 'LOW':
      return 'border-green-200 bg-green-50 text-green-700';
    case 'MEDIUM':
      return 'border-amber-200 bg-amber-50 text-amber-800';
    case 'HIGH':
      return 'border-red-200 bg-red-50 text-red-700';
    default:
      return 'border-slate-200 bg-slate-50 text-slate-700';
  }
}

export function truncateAddress(address: string, chars = 8): string {
  if (address.length <= chars * 2) return address;
  return `${address.slice(0, chars)}...${address.slice(-chars)}`;
}