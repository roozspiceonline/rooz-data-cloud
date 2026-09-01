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

export interface ProjectDiagnosticsSummary {
  observed_at: string;
  execution: {
    active_leases: number;
    build_dispatch_ready: number;
    run_commands_ready: number;
  };
  schedules: {
    due: number;
  };
  request_queues: {
    ready: number;
    claimed: number;
    failed: number;
  };
  credential_canaries: {
    ready: number;
    claimed: number;
    failed: number;
  };
  webhook_deliveries: {
    ready: number;
    claimed: number;
    dead_lettered: number;
  };
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
  source_object_id: string;
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
  source_object_id: string | null;
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
  source_object_id: string | null;
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

export type StorageObjectStatus =
  | "PENDING_UPLOAD"
  | "QUARANTINED"
  | "AVAILABLE"
  | "REJECTED"
  | "DELETED";

export type StorageScanStatus =
  | "PENDING"
  | "PASSED"
  | "FAILED"
  | "NOT_REQUIRED";

export interface StorageObjectSummary {
  id: string;
  organization_id: string;
  project_id: string;
  agent_id: string | null;
  kind: "AGENT_SOURCE";
  provider: string;
  bucket: string;
  object_key: string;
  file_name: string;
  media_type: string;
  expected_size_bytes: number;
  size_bytes: number | null;
  expected_sha256_digest: string;
  sha256_digest: string | null;
  status: StorageObjectStatus;
  scan_status: StorageScanStatus;
  rejection_code: string | null;
  created_at: string;
  uploaded_at: string | null;
  available_at: string | null;
}

export interface CreateSourceUploadInput {
  file_name: string;
  media_type: "application/zip" | "application/x-zip-compressed";
  size_bytes: number;
  sha256_digest: string;
}

export interface SourceUploadIntent {
  object: StorageObjectSummary;
  upload: {
    url: string;
    fields: Record<string, string>;
    expires_at: string;
  };
}

export interface StorageDownloadGrant {
  grant_id: string;
  object_id: string;
  url: string;
  expires_at: string;
  headers: Record<string, string>;
}

export interface SandboxActivation {
  mode: "canary";
  agent_version_id: string;
  worker_name: string;
  attestation_digest: string;
  sandbox_policy_digest: string;
  constraints_digest: string;
  no_secrets: true;
  capability_profile: "offline-minimal";
  max_concurrency: 1;
}

export interface SandboxClaimPolicy {
  schema_version: "rdc.sandbox/v1";
  attestation_digest: string;
  runtime: "containerd-rootless";
  builder: "buildkit-rootless";
  network_policy: "deny-all";
  rootless: true;
  no_host_docker_socket: true;
  no_new_privileges: true;
  read_only_rootfs: true;
  drop_all_capabilities: true;
  seccomp_profile: "rdc-default";
  memory_mb: number;
  cpu_millis: number;
  pids: number;
  ephemeral_disk_mb: number;
  timeout_seconds: number;
  max_output_bytes: number;
}
