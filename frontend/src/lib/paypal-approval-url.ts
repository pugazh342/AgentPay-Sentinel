/**
 * Strict validation + sanitization for PayPal sandbox approval URLs.
 *
 * Single source of truth shared by all payment surfaces.
 * Fail-closed: any malformed/ambiguous value is rejected.
 */

const APPROVED_HOST = "www.sandbox.paypal.com";

export function isValidApprovalUrl(url: string): boolean {
  if (typeof url !== "string" || url.trim() === "") return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  // HTTPS only
  if (parsed.protocol !== "https:") return false;
  // Exact host only (no subdomains, no suffix tricks)
  if (parsed.hostname.toLowerCase() !== APPROVED_HOST) return false;
  // No embedded credentials
  if (parsed.username !== "" || parsed.password !== "") return false;
  // Default port only (empty string === default for the scheme)
  if (parsed.port !== "") return false;
  return true;
}

export function displayApprovalUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (!isValidApprovalUrl(url)) return "";
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "";
  }
}
