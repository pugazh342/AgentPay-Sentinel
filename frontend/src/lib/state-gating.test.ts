/**
 * Tests for payment state gating
 *
 * Verifies that checkout actions are only available for PAYPAL_ORDER_CREATED,
 * which is the state in which a PayPal order (and its approval_url) actually
 * exists and the buyer has not yet approved it. PENDING_USER_APPROVAL has no
 * order yet, so no checkout action is possible there.
 */
import { describe, it, expect } from 'vitest';

const CHECKOUT_ELIGIBLE_STATE = 'PAYPAL_ORDER_CREATED';
const NON_CHECKOUT_STATES = [
  'PENDING_USER_APPROVAL',
  'PENDING_SECURITY',
  'REVIEW_REQUIRED',
  'BLOCKED',
  'BUYER_APPROVED',
  'CAPTURE_PENDING',
  'COMPLETED',
  'FAILED',
  'EXPIRED',
];

function isBuyerCheckoutEligible(state: string): boolean {
  return state === CHECKOUT_ELIGIBLE_STATE;
}

describe('payment state gating', () => {
  describe('checkout eligibility', () => {
    it('allows checkout for PAYPAL_ORDER_CREATED', () => {
      expect(isBuyerCheckoutEligible('PAYPAL_ORDER_CREATED')).toBe(true);
    });

    it('rejects checkout for PENDING_USER_APPROVAL (no order yet)', () => {
      expect(isBuyerCheckoutEligible('PENDING_USER_APPROVAL')).toBe(false);
    });

    it('rejects checkout for COMPLETED', () => {
      expect(isBuyerCheckoutEligible('COMPLETED')).toBe(false);
    });

    it('rejects checkout for BUYER_APPROVED', () => {
      expect(isBuyerCheckoutEligible('BUYER_APPROVED')).toBe(false);
    });

    it('rejects checkout for CAPTURE_PENDING', () => {
      expect(isBuyerCheckoutEligible('CAPTURE_PENDING')).toBe(false);
    });

    it('rejects checkout for FAILED', () => {
      expect(isBuyerCheckoutEligible('FAILED')).toBe(false);
    });

    it('rejects checkout for BLOCKED', () => {
      expect(isBuyerCheckoutEligible('BLOCKED')).toBe(false);
    });

    it('rejects checkout for EXPIRED', () => {
      expect(isBuyerCheckoutEligible('EXPIRED')).toBe(false);
    });

    it('rejects checkout for REVIEW_REQUIRED', () => {
      expect(isBuyerCheckoutEligible('REVIEW_REQUIRED')).toBe(false);
    });

    it('rejects checkout for PENDING_SECURITY', () => {
      expect(isBuyerCheckoutEligible('PENDING_SECURITY')).toBe(false);
    });

    it('rejects checkout for unknown states', () => {
      expect(isBuyerCheckoutEligible('UNKNOWN_STATE')).toBe(false);
      expect(isBuyerCheckoutEligible('')).toBe(false);
    });
  });

  describe('regression - already acted or terminal states never show checkout', () => {
    it('rejects checkout for all non-eligible states', () => {
      NON_CHECKOUT_STATES.forEach((state) => {
        expect(isBuyerCheckoutEligible(state)).toBe(false);
      });
    });
  });
});