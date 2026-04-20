export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: string | null;
  requestId: string;
  timestamp: string;
}

export type ApiErrorResponse = ApiResponse<null>;

export interface AuditLog {
  operation: string;
  algorithm: string;
  duration_ms: number;
  ip: string;
  requestId: string;
  success: boolean;
  timestamp: string;
  statusCode?: number;
  event?: 'CRYPTO_OPERATION';
  level?: 'info' | 'warn' | 'error' | 'debug';
}

export class ApiError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: unknown;

  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;

    Object.setPrototypeOf(this, ApiError.prototype);
  }
}

/**
 * Creates a standardized API response object that matches the project response contract.
 */
export function createApiResponse<T>(params: {
  success: boolean;
  data: T | null;
  error: string | null;
  requestId: string;
  timestamp?: string;
}): ApiResponse<T> {
  return {
    success: params.success,
    data: params.data,
    error: params.error,
    requestId: params.requestId,
    timestamp: params.timestamp ?? new Date().toISOString(),
  };
}
