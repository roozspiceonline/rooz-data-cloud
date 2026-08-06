import type { ApiErrorEnvelope } from "@rdc/shared-types";

export class RdcApiError extends Error {
  readonly code: string;
  readonly requestId: string;
  readonly status: number;

  constructor(status: number, payload: ApiErrorEnvelope) {
    super(payload.error.message);
    this.name = "RdcApiError";
    this.code = payload.error.code;
    this.requestId = payload.request_id;
    this.status = status;
  }
}

export function createRdcApiClient(options: { baseUrl: string; getCsrfToken?: () => string | null }) {
  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = options.getCsrfToken?.();
      if (csrf) headers.set("X-RDC-CSRF", csrf);
    }
    const response = await fetch(`${options.baseUrl}${path}`, {
      ...init,
      credentials: "include",
      headers,
    });
    if (!response.ok) {
      const payload = (await response.json()) as ApiErrorEnvelope;
      throw new RdcApiError(response.status, payload);
    }
    return (await response.json()) as T;
  }
  return { request };
}
