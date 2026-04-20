/**
 * @description Overwrites all bytes in a buffer with zeroes to reduce key material lifetime in memory.
 * @algorithm Memory sanitization (byte overwrite)
 * @reference NIST SP 800-57 (key lifecycle handling guidance)
 * @security Best-effort only in managed runtimes; always call this immediately after sensitive use.
 * @param buffer Sensitive buffer to wipe.
 * @returns The same buffer instance after being zeroed.
 */
export function zeroBuffer(buffer: Buffer): Buffer {
  buffer.fill(0);
  return buffer;
}

/**
 * @description Safely zeroes a buffer-like value when present.
 * @algorithm Memory sanitization (byte overwrite)
 * @reference NIST SP 800-57 (key lifecycle handling guidance)
 * @security Use in finally blocks to avoid leaving keys in memory during thrown-error paths.
 * @param buffer Optional sensitive buffer.
 * @returns Void.
 */
export function zeroBufferIfPresent(buffer: Buffer | null | undefined): void {
  if (!buffer) {
    return;
  }

  zeroBuffer(buffer);
}
