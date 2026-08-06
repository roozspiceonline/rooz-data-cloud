export interface ApiFieldError {
  code: string;
  field: string;
  message: string;
}

export interface ApiErrorEnvelope {
  error: {
    code: string;
    details: Record<string, unknown>;
    field_errors: ReadonlyArray<ApiFieldError>;
    message: string;
    request_id: string;
  };
}

export interface ApiSuccess<T> {
  data: T;
  meta: {
    request_id: string;
  };
}

export interface ApiPageMeta {
  has_more: boolean;
  next_cursor: string | null;
}

export interface ApiCollectionSuccess<T> {
  data: ReadonlyArray<T>;
  meta: {
    request_id: string;
    page: ApiPageMeta;
  };
}

export interface MembershipSummary {
  id: string;
  organization_id: string;
  role: string;
  status: string;
  version: number;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  status: string;
  version: number;
}

export interface ProjectSummary {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description: string | null;
  status: string;
  version: number;
}

export interface SessionData {
  user: {
    id: string;
    email: string;
    display_name: string;
  };
  memberships: ReadonlyArray<MembershipSummary>;
  organizations: ReadonlyArray<OrganizationSummary>;
  csrf_token: string;
}

export interface ApiKeySummary {
  id: string;
  organization_id: string;
  name: string;
  public_prefix: string;
  last_four: string;
  scopes: ReadonlyArray<string>;
  environment: "live" | "test";
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface AgentSummary {
  id: string;
  organization_id: string;
  project_id: string;
  name: string;
  slug: string;
  description: string | null;
  status: "ACTIVE" | "ARCHIVED";
  created_at: string;
  updated_at: string;
  version: number;
}

export interface CreateAgentInput {
  name: string;
  slug: string;
  description: string | null;
}

export interface UpdateAgentInput {
  name?: string;
  slug?: string;
  description?: string | null;
  status?: "ACTIVE" | "ARCHIVED";
}

export interface AgentManifestRuntime {
  kind: "container";
  entrypoint: ReadonlyArray<string>;
}

export interface AgentManifestSchemas {
  input: string;
  output: string;
  dataset?: string;
}

export interface AgentManifestCapabilities {
  network: "none" | "web-egress";
  browser: boolean;
  dataset: boolean;
  keyValueStore: boolean;
  requestQueue: boolean;
}

export interface AgentManifestResources {
  memoryMb: number;
  cpuUnits: number;
  timeoutSeconds: number;
  maxProcesses: number;
  ephemeralDiskMb: number;
}

export interface AgentManifest {
  protocol: "rooz.agent/v1";
  name: string;
  version: string;
  runtime: AgentManifestRuntime;
  schemas: AgentManifestSchemas;
  capabilities: AgentManifestCapabilities;
  resources: AgentManifestResources;
  secrets?: ReadonlyArray<string>;
  extensions?: Record<string, unknown>;
}

export interface CreateAgentVersionInput {
  manifest: AgentManifest;
  release_notes: string | null;
}

export interface AgentVersionSummary {
  id: string;
  organization_id: string;
  project_id: string;
  agent_id: string;
  version_number: number;
  protocol: string;
  semantic_version: string;
  manifest_schema_version: string;
  manifest_digest: string;
  release_notes: string | null;
  created_at: string;
}

export interface AgentVersionDetail extends AgentVersionSummary {
  manifest: AgentManifest;
}


export type SecretEnvironment =
  | "development"
  | "test"
  | "staging"
  | "production";

export interface ProjectSecretSummary {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  environment: SecretEnvironment;
  has_value: true;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  version: number;
  etag: string;
}

export interface CreateProjectSecretInput {
  name: string;
  value: string;
  description: string | null;
  environment: SecretEnvironment;
}

export interface ReplaceProjectSecretInput {
  value: string;
  description: string | null;
  environment?: SecretEnvironment;
}

export type BuildStatus =
  | "QUEUED"
  | "STARTING"
  | "RUNNING"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED"
  | "TIMED_OUT";

export interface BuildSummary {
  id: string;
  organization_id: string;
  project_id: string;
  agent_id: string;
  agent_version_id: string;
  manifest_digest: string;
  status: BuildStatus;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  artifact_digest: string | null;
  error_code: string | null;
  error_message: string | null;
  status_url: string;
}

export type RunStatus =
  | "DRAFT"
  | "READY"
  | "QUEUED"
  | "STARTING"
  | "RUNNING"
  | "PAUSING"
  | "PAUSED"
  | "SUCCEEDED"
  | "PARTIALLY_SUCCEEDED"
  | "FAILED"
  | "TIMING_OUT"
  | "TIMED_OUT"
  | "ABORTING"
  | "ABORTED";

export interface RunRuntimeConfiguration {
  memory_mb: number;
  cpu_millis: number;
  timeout_seconds: number;
}

export interface CreateRunInput {
  build_id: string;
  input: Record<string, unknown>;
  runtime: {
    memory_mb?: number;
    cpu_millis?: number;
    timeout_seconds?: number;
  };
}

export interface RunSummary {
  id: string;
  organization_id: string;
  project_id: string;
  agent_id: string;
  agent_version_id: string;
  build_id: string;
  status: RunStatus;
  input_reference: {
    kind: "inline";
    value: Record<string, unknown>;
  };
  runtime_configuration: RunRuntimeConfiguration;
  memory_mb: number;
  cpu_millis: number;
  timeout_seconds: number;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested_at: string | null;
  failure_code: string | null;
  failure_summary: string | null;
  created_at: string;
  updated_at: string;
  version: number;
  status_url: string;
  events_url: string;
  cancel_url: string;
}

export type RunEventType =
  | "run.connected"
  | "run.status"
  | "run.log"
  | "run.metric"
  | "run.warning"
  | "run.completed"
  | "run.failed"
  | "run.heartbeat"
  | "run.replay_reset";

export interface RunEventEnvelope {
  schema_version: "1";
  event_type: RunEventType;
  run_id: string;
  sequence: number;
  timestamp: string;
  payload: Record<string, unknown>;
}


export type ExecutionWorkKind = "BUILD" | "RUN_START" | "RUN_CANCEL";

export type ExecutionLeaseStatus =
  | "ACTIVE"
  | "COMPLETED"
  | "FAILED"
  | "EXPIRED"
  | "CANCELLED";

export interface ExecutionLeaseSummary {
  id: string;
  worker_id: string;
  organization_id: string;
  project_id: string;
  work_kind: ExecutionWorkKind;
  build_id: string | null;
  run_id: string | null;
  status: ExecutionLeaseStatus;
  attempt: number;
  claimed_at: string;
  expires_at: string;
  completed_at: string | null;
  failure_code: string | null;
  failure_summary: string | null;
}

export type ExecutionArtifactKind =
  | "CONTAINER_IMAGE"
  | "SBOM"
  | "PROVENANCE"
  | "RUN_OUTPUT"
  | "LOG_BUNDLE";

export type ExecutionArtifactStatus =
  | "AVAILABLE"
  | "QUARANTINED"
  | "REJECTED"
  | "DELETED";

export type ExecutionArtifactScanStatus =
  | "PENDING"
  | "PASSED"
  | "FAILED"
  | "NOT_REQUIRED";

export interface ExecutionArtifactSummary {
  id: string;
  organization_id: string;
  project_id: string;
  build_id: string | null;
  run_id: string | null;
  lease_id: string;
  kind: ExecutionArtifactKind;
  digest_algorithm: string;
  digest: string;
  object_key: string;
  media_type: string;
  size_bytes: number;
  status: ExecutionArtifactStatus;
  scan_status: ExecutionArtifactScanStatus;
  provenance: Record<string, unknown>;
  created_at: string;
}
