import type {
  AgentSummary,
  AgentVersionDetail,
  AgentVersionSummary,
  ApiCollectionSuccess,
  ApiErrorEnvelope,
  ApiKeySummary,
  ApiPageMeta,
  ApiSuccess,
  CreateAgentInput,
  CreateAgentVersionInput,
  BuildSummary,
  CreateProjectSecretInput,
  ProjectSecretSummary,
  ReplaceProjectSecretInput,
  CreateRunInput,
  ExecutionArtifactSummary,
  ExecutionLeaseSummary,
  RunSummary,
  OrganizationSummary,
  ProjectSummary,
  SessionData,
  UpdateAgentInput,
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

export interface CollectionResult<T> {
  data: ReadonlyArray<T>;
  page: ApiPageMeta;
}

export interface AgentResource {
  agent: AgentSummary;
  etag: string;
}

export function createRdcApiClient(options: RdcApiClientOptions) {
  let csrfToken: string | null = null;

  async function requestResponse<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<{ payload: T; response: Response }> {
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
      return { payload: undefined as T, response };
    }

    return { payload: (await response.json()) as T, response };
  }

  async function request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const result = await requestResponse<T>(path, init);
    return result.payload;
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
    >(`/organizations/${encodeURIComponent(organizationId)}/projects`);
    return response.data;
  }

  async function apiKeys(
    organizationId: string,
  ): Promise<ReadonlyArray<ApiKeySummary>> {
    const response = await request<
      ApiSuccess<ReadonlyArray<ApiKeySummary>>
    >(`/organizations/${encodeURIComponent(organizationId)}/api-keys`);
    return response.data;
  }

  async function agents(
    projectId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<AgentSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<
      ApiCollectionSuccess<AgentSummary>
    >(`/projects/${encodeURIComponent(projectId)}/agents${query}`);
    return { data: response.data, page: response.meta.page };
  }

  async function createAgent(
    projectId: string,
    input: CreateAgentInput,
  ): Promise<AgentResource> {
    const result = await requestResponse<ApiSuccess<AgentSummary>>(
      `/projects/${encodeURIComponent(projectId)}/agents`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    return {
      agent: result.payload.data,
      etag: result.response.headers.get("ETag") ?? "",
    };
  }

  async function agent(agentId: string): Promise<AgentResource> {
    const result = await requestResponse<ApiSuccess<AgentSummary>>(
      `/agents/${encodeURIComponent(agentId)}`,
    );
    return {
      agent: result.payload.data,
      etag: result.response.headers.get("ETag") ?? "",
    };
  }

  async function updateAgent(
    agentId: string,
    input: UpdateAgentInput,
    etag: string,
  ): Promise<AgentResource> {
    const result = await requestResponse<ApiSuccess<AgentSummary>>(
      `/agents/${encodeURIComponent(agentId)}`,
      {
        method: "PATCH",
        headers: { "If-Match": etag },
        body: JSON.stringify(input),
      },
    );
    return {
      agent: result.payload.data,
      etag: result.response.headers.get("ETag") ?? "",
    };
  }

  async function agentVersions(
    agentId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<AgentVersionSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<
      ApiCollectionSuccess<AgentVersionSummary>
    >(`/agents/${encodeURIComponent(agentId)}/versions${query}`);
    return { data: response.data, page: response.meta.page };
  }

  async function createAgentVersion(
    agentId: string,
    input: CreateAgentVersionInput,
  ): Promise<AgentVersionDetail> {
    const response = await request<ApiSuccess<AgentVersionDetail>>(
      `/agents/${encodeURIComponent(agentId)}/versions`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    return response.data;
  }

  async function agentVersion(
    versionId: string,
  ): Promise<AgentVersionDetail> {
    const response = await request<ApiSuccess<AgentVersionDetail>>(
      `/agent-versions/${encodeURIComponent(versionId)}`,
    );
    return response.data;
  }


  async function projectSecrets(
    projectId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<ProjectSecretSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<
      ApiCollectionSuccess<ProjectSecretSummary>
    >(`/projects/${encodeURIComponent(projectId)}/secrets${query}`);
    return { data: response.data, page: response.meta.page };
  }

  async function createProjectSecret(
    projectId: string,
    input: CreateProjectSecretInput,
  ): Promise<ProjectSecretSummary> {
    const response = await request<ApiSuccess<ProjectSecretSummary>>(
      `/projects/${encodeURIComponent(projectId)}/secrets`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    return response.data;
  }

  async function replaceProjectSecret(
    secretId: string,
    input: ReplaceProjectSecretInput,
    etag: string,
    idempotencyKey: string,
  ): Promise<ProjectSecretSummary> {
    const response = await request<ApiSuccess<ProjectSecretSummary>>(
      `/secrets/${encodeURIComponent(secretId)}`,
      {
        method: "PUT",
        headers: {
          "Idempotency-Key": idempotencyKey,
          "If-Match": etag,
        },
        body: JSON.stringify(input),
      },
    );
    return response.data;
  }

  async function deleteProjectSecret(secretId: string): Promise<void> {
    await request<void>(`/secrets/${encodeURIComponent(secretId)}`, {
      method: "DELETE",
    });
  }

  async function createBuild(
    versionId: string,
    idempotencyKey: string,
  ): Promise<BuildSummary> {
    const response = await request<ApiSuccess<BuildSummary>>(
      `/agent-versions/${encodeURIComponent(versionId)}/builds`,
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
      },
    );
    return response.data;
  }

  async function build(buildId: string): Promise<BuildSummary> {
    const response = await request<ApiSuccess<BuildSummary>>(
      `/builds/${encodeURIComponent(buildId)}`,
    );
    return response.data;
  }

  async function agentBuilds(
    agentId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<BuildSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<ApiCollectionSuccess<BuildSummary>>(
      `/agents/${encodeURIComponent(agentId)}/builds${query}`,
    );
    return { data: response.data, page: response.meta.page };
  }


  async function createRun(
    versionId: string,
    input: CreateRunInput,
    idempotencyKey: string,
  ): Promise<RunSummary> {
    const response = await request<ApiSuccess<RunSummary>>(
      `/agent-versions/${encodeURIComponent(versionId)}/runs`,
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(input),
      },
    );
    return response.data;
  }

  async function run(runId: string): Promise<RunSummary> {
    const response = await request<ApiSuccess<RunSummary>>(
      `/runs/${encodeURIComponent(runId)}`,
    );
    return response.data;
  }

  async function projectRuns(
    projectId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<RunSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<ApiCollectionSuccess<RunSummary>>(
      `/projects/${encodeURIComponent(projectId)}/runs${query}`,
    );
    return { data: response.data, page: response.meta.page };
  }

  async function projectExecutionLeases(
    projectId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<ExecutionLeaseSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<
      ApiCollectionSuccess<ExecutionLeaseSummary>
    >(`/projects/${encodeURIComponent(projectId)}/execution-leases${query}`);
    return { data: response.data, page: response.meta.page };
  }

  async function projectExecutionArtifacts(
    projectId: string,
    cursor: string | null = null,
  ): Promise<CollectionResult<ExecutionArtifactSummary>> {
    const query = cursor
      ? `?cursor=${encodeURIComponent(cursor)}`
      : "";
    const response = await request<
      ApiCollectionSuccess<ExecutionArtifactSummary>
    >(`/projects/${encodeURIComponent(projectId)}/execution-artifacts${query}`);
    return { data: response.data, page: response.meta.page };
  }

  async function cancelRun(
    runId: string,
    idempotencyKey: string,
  ): Promise<RunSummary> {
    const response = await request<ApiSuccess<RunSummary>>(
      `/runs/${encodeURIComponent(runId)}/cancel`,
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
      },
    );
    return response.data;
  }

  function runEventsUrl(
    runId: string,
    lastEventId = 0,
  ): string {
    const query = lastEventId > 0
      ? `?last_event_id=${encodeURIComponent(String(lastEventId))}`
      : "";
    return `${options.baseUrl}/runs/${encodeURIComponent(runId)}/events${query}`;
  }

  return {
    agent,
    agentBuilds,
    agentVersion,
    agentVersions,
    agents,
    apiKeys,
    build,
    createAgent,
    createAgentVersion,
    createBuild,
    createProjectSecret,
    createRun,
    login,
    logout,
    organizations,
    projects,
    projectExecutionArtifacts,
    projectExecutionLeases,
    projectRuns,
    projectSecrets,
    request,
    run,
    runEventsUrl,
    session,
    cancelRun,
    deleteProjectSecret,
    replaceProjectSecret,
    updateAgent,
  };
}
