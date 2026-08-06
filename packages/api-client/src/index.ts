import type {
  ApiErrorEnvelope,
  ApiKeySummary,
  ApiSuccess,
  OrganizationSummary,
  ProjectSummary,
  SessionData,
} from "@rdc/shared-types";

export class RdcApiError extends Error {
  readonly code: string;
  readonly requestId: string;
  readonly status: number;

  constructor(status: number, payload: ApiErrorEnvelope) {
    super(payload.error.message);
    this.name = "RdcApiError";
    this.code = payload.error.code;
    this.requestId = payload.error.request_id;
    this.status = status;
  }
}

export interface RdcApiClientOptions {
  baseUrl: string;
}

export function createRdcApiClient(options: RdcApiClientOptions) {
  let csrfToken: string | null = null;

  async function request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");

    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    if (
      !["GET", "HEAD", "OPTIONS"].includes(method) &&
      csrfToken
    ) {
      headers.set("X-RDC-CSRF", csrfToken);
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

    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  }

  async function session(): Promise<SessionData> {
    const response = await request<ApiSuccess<SessionData>>(
      "/auth/session",
    );
    csrfToken = response.data.csrf_token;
    return response.data;
  }

  async function login(
    email: string,
    password: string,
  ): Promise<SessionData> {
    const response = await request<ApiSuccess<SessionData>>(
      "/auth/login",
      {
        method: "POST",
        body: JSON.stringify({ email, password }),
      },
    );
    csrfToken = response.data.csrf_token;
    return response.data;
  }

  async function logout(): Promise<void> {
    await request<void>("/auth/logout", { method: "POST" });
    csrfToken = null;
  }

  async function organizations(): Promise<
    ReadonlyArray<OrganizationSummary>
  > {
    const response = await request<
      ApiSuccess<ReadonlyArray<OrganizationSummary>>
    >("/organizations");
    return response.data;
  }

  async function projects(
    organizationId: string,
  ): Promise<ReadonlyArray<ProjectSummary>> {
    const response = await request<
      ApiSuccess<ReadonlyArray<ProjectSummary>>
    >(`/organizations/${organizationId}/projects`);
    return response.data;
  }

  async function apiKeys(
    organizationId: string,
  ): Promise<ReadonlyArray<ApiKeySummary>> {
    const response = await request<
      ApiSuccess<ReadonlyArray<ApiKeySummary>>
    >(`/organizations/${organizationId}/api-keys`);
    return response.data;
  }

  return {
    apiKeys,
    login,
    logout,
    organizations,
    projects,
    request,
    session,
  };
}
