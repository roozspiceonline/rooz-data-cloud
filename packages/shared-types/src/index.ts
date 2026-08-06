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
