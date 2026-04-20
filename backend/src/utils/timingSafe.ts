import { timingSafeEqual } from 'crypto';

/**
 * @description Compares two secret buffers using constant-time semantics.
 * @algorithm Constant-time comparison (crypto.timingSafeEqual)
 * @reference Node.js Crypto API - timingSafeEqual
 * @security Returns false when lengths differ to avoid throwing; callers should normalize encodings before comparison.
 * @param left First secret value as Buffer.
 * @param right Second secret value as Buffer.
 * @returns True when both secrets are equal, otherwise false.
 */
export function timingSafeCompare(left: Buffer, right: Buffer): boolean {
  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}

/**
 * @description Compares two UTF-8 strings in constant-time by converting them to buffers.
 * @algorithm Constant-time comparison (crypto.timingSafeEqual)
 * @reference Node.js Crypto API - timingSafeEqual
 * @security This helper should be used only for short secret values represented as strings.
 * @param left First secret string.
 * @param right Second secret string.
 * @returns True when both secrets are equal, otherwise false.
 */
export function timingSafeCompareString(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');

  return timingSafeCompare(leftBuffer, rightBuffer);
}
