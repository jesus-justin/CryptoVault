import axios, { AxiosError, AxiosInstance } from 'axios';

export interface NormalizedApiError {
  code: string;
  message: string;
  field?: string;
}

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';

export const api: AxiosInstance = axios.create({
  baseURL: apiBaseUrl,
  timeout: 15_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const headers = config.headers;
  const requestId = typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `${Date.now()}`;

  headers['X-Request-ID'] = requestId;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (error instanceof AxiosError) {
      const data = error.response?.data as
        | {
            error?: string;
            details?: Array<{ field?: string; message?: string }>;
          }
        | undefined;

      const normalized: NormalizedApiError = {
        code: `HTTP_${error.response?.status ?? 500}`,
        message: data?.error ?? error.message,
        field: data?.details?.[0]?.field,
      };

      return Promise.reject(normalized);
    }

    return Promise.reject({
      code: 'UNKNOWN_ERROR',
      message: 'An unexpected error occurred.',
    } satisfies NormalizedApiError);
  },
);

export async function postApi<TResponse, TRequest>(url: string, body: TRequest): Promise<TResponse> {
  const response = await api.post<TResponse>(url, body);
  return response.data;
}

export async function getApi<TResponse>(url: string): Promise<TResponse> {
  const response = await api.get<TResponse>(url);
  return response.data;
}
