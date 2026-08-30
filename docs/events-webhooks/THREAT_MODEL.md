# Events/Webhooks threat model

The event table is a tenant data boundary. Organization lineage is overwritten
from the referenced Project by a security-definer trigger; Run and Build
subjects plus payload identifiers must match that Project. RLS reads require
the authenticated organization membership and the exact server-set Project
context. A caller cannot select an event from another Project by changing a
cursor because cursors are signed and Project/filter bound.

Events are immutable and their JSON payload is intentionally small. Both the
service and PostgreSQL reject unsupported types, unexpected fields, excessive
nesting/size, and keys shaped like Authorization, token, cookie, password,
secret, credential, database, Redis, or object-storage credentials. Agents and
Chromium receive neither event-table access nor any new capability.

Outbound webhooks remain unimplemented. A later delivery boundary must add
HTTPS-only destination validation, DNS rebinding and connected-peer checks,
verified TLS/SNI, disabled or strictly bounded redirects, write-only signing
secrets, claim fencing, bounded retries/timeouts/bodies, immutable delivery
lineage and adversarial SSRF/replay tests before any network gate can activate.

Destination admission is defense in depth, not delivery authorization. It
rejects obvious SSRF URL shapes and stores only normalized HTTPS metadata, but
DNS resolution is intentionally absent. Any later delivery worker must resolve
and pin public addresses, validate every connected peer and redirect, enforce
TLS/SNI and revalidate immediately before each connection.
