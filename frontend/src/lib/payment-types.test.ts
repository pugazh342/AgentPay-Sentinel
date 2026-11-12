/**
 * Tests for payment response types
 *
 * Verifies that TypeScript type definitions match the expected API contract.
 */

import { describe, it, expect } from 'vitest';
import type { PaymentResponse, PaymentResponseSafe } from './api';

describe('PaymentResponse type', () => {
  it('should have all required fields', () => {
    const payment: PaymentResponse = {
      payment_id: 'payment-123',
      transaction_id: 'txn-456',
      intent_id: 'intent-789',
      amount: '100.00',
      currency: 'USD',
      merchant_id: 'merchant-123',
      product_category: 'electronics',
      state: 'PENDING_USER_APPROVAL',
      paypal_order_id: 'order-123',
      approval_url: 'https://www.sandbox.paypal.com/checkout?token=ABC',
      paypal_capture_id: 'capture-123',
      paypal_status: 'COMPLETED',
      approved_by: 'user@example.com',
      approved_at: '2024-01-01T12:00:00Z',
      buyer_approved_at: '2024-01-01T12:05:00Z',
      completed_at: '2024-01-01T12:10:00Z',
      failure_reason: null,
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:10:00Z',
      version: 1,
    };

    expect(payment.payment_id).toBe('payment-123');
    expect(payment.amount).toBe('100.00');
    expect(payment.state).toBe('PENDING_USER_APPROVAL');
  });

  it('should accept null values for nullable fields', () => {
    const payment: PaymentResponse = {
      payment_id: 'payment-456',
      transaction_id: 'txn-789',
      intent_id: 'intent-012',
      amount: '50.00',
      currency: 'EUR',
      merchant_id: 'merchant-456',
      product_category: 'books',
      state: 'COMPLETED',
      paypal_order_id: null,
      approval_url: null,
      paypal_capture_id: null,
      paypal_status: 'COMPLETED',
      approved_by: null,
      approved_at: null,
      buyer_approved_at: null,
      completed_at: '2024-01-01T12:00:00Z',
      failure_reason: null,
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:00:00Z',
      // version is optional
    };

    expect(payment.paypal_order_id).toBeNull();
    expect(payment.approval_url).toBeNull();
    expect(payment.paypal_status).toBe('COMPLETED');
  });

  it('should accept undefined for version field', () => {
    const paymentWithoutVersion: PaymentResponse = {
      payment_id: 'payment-789',
      transaction_id: 'txn-012',
      intent_id: 'intent-345',
      amount: '25.00',
      currency: 'GBP',
      merchant_id: 'merchant-789',
      product_category: 'clothing',
      state: 'FAILED',
      paypal_order_id: 'order-456',
      approval_url: null,
      paypal_capture_id: null,
      paypal_status: null,
      approved_by: null,
      approved_at: null,
      buyer_approved_at: null,
      completed_at: null,
      failure_reason: 'Payment declined',
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:00:00Z',
    };

    expect(paymentWithoutVersion.version).toBeUndefined();
  });
});

describe('PaymentResponseSafe type', () => {
  it('should exclude approval_url field', () => {
    const safePayment: PaymentResponseSafe = {
      payment_id: 'payment-123',
      transaction_id: 'txn-456',
      intent_id: 'intent-789',
      amount: '100.00',
      currency: 'USD',
      merchant_id: 'merchant-123',
      product_category: 'electronics',
      state: 'COMPLETED',
      paypal_order_id: 'order-123',
      paypal_capture_id: 'capture-123',
      paypal_status: 'COMPLETED',
      approved_by: 'user@example.com',
      approved_at: '2024-01-01T12:00:00Z',
      buyer_approved_at: '2024-01-01T12:05:00Z',
      completed_at: '2024-01-01T12:10:00Z',
      failure_reason: null,
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:10:00Z',
    };

    // approval_url should not exist on PaymentResponseSafe
    expect('approval_url' in safePayment).toBe(false);
  });

  it('should have same nullable field types as PaymentResponse', () => {
    const safePayment: PaymentResponseSafe = {
      payment_id: 'payment-456',
      transaction_id: 'txn-789',
      intent_id: 'intent-012',
      amount: '50.00',
      currency: 'EUR',
      merchant_id: 'merchant-456',
      product_category: 'books',
      state: 'PENDING_USER_APPROVAL',
      paypal_order_id: null,
      paypal_capture_id: null,
      paypal_status: null,
      approved_by: null,
      approved_at: null,
      buyer_approved_at: null,
      completed_at: null,
      failure_reason: null,
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:00:00Z',
    };

    expect(safePayment.paypal_order_id).toBeNull();
    expect(safePayment.paypal_capture_id).toBeNull();
  });

  it('should make version optional', () => {
    const safePayment: PaymentResponseSafe = {
      payment_id: 'payment-789',
      transaction_id: 'txn-012',
      intent_id: 'intent-345',
      amount: '25.00',
      currency: 'GBP',
      merchant_id: 'merchant-789',
      product_category: 'clothing',
      state: 'BUYER_APPROVED',
      paypal_order_id: 'order-456',
      paypal_capture_id: 'capture-789',
      paypal_status: 'PENDING_CAPTURE',
      approved_by: 'buyer@example.com',
      approved_at: '2024-01-01T12:00:00Z',
      buyer_approved_at: '2024-01-01T12:05:00Z',
      completed_at: null,
      failure_reason: null,
      created_at: '2024-01-01T12:00:00Z',
      updated_at: '2024-01-01T12:00:00Z',
    };

    expect(safePayment.paypal_status).toBe('PENDING_CAPTURE');
  });
});