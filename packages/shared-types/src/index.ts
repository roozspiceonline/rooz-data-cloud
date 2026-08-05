export interface ApiErrorEnvelope {
  error: {
    code: string;
    field_errors?: ReadonlyArray<{ code: string; field: string; message: string }>;
    message: string;
  };
  request_id: string;
}

export interface CursorPage<T> {
  data: ReadonlyArray<T>;
  has_more: boolean;
  next_cursor: string | null;
}

export type FoundationServiceStatus = "configured" | "degraded" | "ready" | "unavailable";
