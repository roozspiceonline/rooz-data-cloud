import { createRdcApiClient } from "@rdc/api-client";

export const rdcApi = createRdcApiClient({
  baseUrl:
    process.env.NEXT_PUBLIC_RDC_API_BASE_URL ??
    "http://localhost:8000/api/v1",
});
