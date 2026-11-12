/**
 * Tests for URL validation in payments
 *
 * These tests verify the URL validation logic prevents XSS attacks
 * and enforces the exact approved PayPal Sandbox hostname.
 */

import { describe, it, expect } from 'vitest';
import { isValidApprovalUrl, displayApprovalUrl } from './paypal-approval-url';

describe('approval URL validation', () => {
  describe('valid PayPal sandbox URLs', () => {
    it('accepts https://www.sandbox.paypal.com with path and query', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com/checkoutnow?token=ABC123')).toBe(true);
    });

    it('accepts https://www.sandbox.paypal.com/checkoutnow (no query)', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com/checkoutnow')).toBe(true);
    });

    it('accepts explicit default port 443 (normalized by URL)', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com:443/checkoutnow?token=ABC123')).toBe(true);
    });
  });

  describe('invalid URLs - protocol', () => {
    it('rejects http:// URLs', () => {
      expect(isValidApprovalUrl('http://www.sandbox.paypal.com/checkout')).toBe(false);
    });

    it('rejects javascript: URLs', () => {
      expect(isValidApprovalUrl('javascript:alert(1)')).toBe(false);
    });

    it('rejects data: URLs', () => {
      expect(isValidApprovalUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    });

    it('rejects ftp: URLs', () => {
      expect(isValidApprovalUrl('ftp://www.sandbox.paypal.com/checkout')).toBe(false);
    });

    it('rejects void: URLs', () => {
      expect(isValidApprovalUrl('void(alert(1))')).toBe(false);
    });
  });

  describe('invalid URLs - hostname', () => {
    it('rejects production paypal.com', () => {
      expect(isValidApprovalUrl('https://paypal.com/checkout')).toBe(false);
    });

    it('rejects www.paypal.com', () => {
      expect(isValidApprovalUrl('https://www.paypal.com/checkout')).toBe(false);
    });

    it('rejects evil.paypal.com', () => {
      expect(isValidApprovalUrl('https://evil.paypal.com/checkout')).toBe(false);
    });

    it('rejects suffix-attack host', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com.attacker.example/checkout')).toBe(false);
    });

    it('rejects path-attack host', () => {
      expect(isValidApprovalUrl('https://attacker.example/www.sandbox.paypal.com')).toBe(false);
    });

    it('rejects userinfo-host-attack', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com@attacker.example/checkout')).toBe(false);
    });

    it('rejects evil subdomain', () => {
      expect(isValidApprovalUrl('https://evil.www.sandbox.paypal.com/checkout')).toBe(false);
    });

    it('rejects bare sandbox host (no www)', () => {
      expect(isValidApprovalUrl('https://sandbox.paypal.com/order')).toBe(false);
    });

    it('rejects edge-suffix host', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com.some.edge.com/checkout')).toBe(false);
    });

    it('rejects unknown hosts', () => {
      expect(isValidApprovalUrl('https://attacker.com/steal')).toBe(false);
    });

    it('rejects trailing-dot host', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com./checkout')).toBe(false);
    });
  });

  describe('invalid URLs - credentials', () => {
    it('rejects URLs with userinfo', () => {
      expect(isValidApprovalUrl('https://user:pass@www.sandbox.paypal.com')).toBe(false);
    });

    it('rejects username-only userinfo', () => {
      expect(isValidApprovalUrl('https://user@www.sandbox.paypal.com/checkout')).toBe(false);
    });
  });

  describe('invalid URLs - port', () => {
    it('rejects non-default port 8443', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com:8443')).toBe(false);
    });

    it('rejects arbitrary port', () => {
      expect(isValidApprovalUrl('https://www.sandbox.paypal.com:9999/checkout')).toBe(false);
    });
  });

  describe('malformed URLs', () => {
    it('rejects malformed URLs', () => {
      expect(isValidApprovalUrl('://not-a-url')).toBe(false);
    });

    it('rejects empty strings', () => {
      expect(isValidApprovalUrl('')).toBe(false);
    });

    it('rejects non-string input', () => {
      expect(isValidApprovalUrl(undefined as unknown as string)).toBe(false);
    });
  });

  describe('displayApprovalUrl sanitization', () => {
    it('strips query and fragment', () => {
      expect(displayApprovalUrl('https://www.sandbox.paypal.com/checkoutnow?token=SECRET')).toBe(
        'https://www.sandbox.paypal.com/checkoutnow'
      );
    });

    it('returns empty string for invalid URL', () => {
      expect(displayApprovalUrl('https://evil.example/steal?token=SECRET')).toBe('');
    });
  });
});
