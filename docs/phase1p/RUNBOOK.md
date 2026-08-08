# Phase 1P runbook

Apply migration `20260809_0015` before enabling request queue APIs. Verify that
all four queue tables have RLS enabled and the `rdc_request_queue_org` resolver
exists. Do not expose claim/complete worker endpoints until the worker identity,
lease, DNS, egress, retry, and reclaim controls are completed and tested.

For an enqueue replay, return the original receipt only when its canonical
request digest matches. Treat a digest mismatch or cross-tenant lookup as an
incident and retain immutable transition history for investigation.

Authenticated queue readers can retrieve bounded transition history. Treat it
as forensic data: it is immutable and should not be edited or deleted.
