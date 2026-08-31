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

General outbound webhooks remain disabled. The trusted canary implements the
network boundary for pending verification only: HTTPS hostname admission,
public DNS-set validation, exact-address connection, connected-peer rebinding
checks, verified TLS/SNI, no redirects/proxies/failover, and bounded request,
response, timeout, concurrency, claim, and attempt dimensions.

Destination admission is defense in depth, not delivery authorization. It
rejects obvious SSRF URL shapes and stores only normalized HTTPS metadata, but
DNS resolution is intentionally absent. Any later delivery worker must resolve
and pin public addresses, validate every connected peer and redirect, enforce
TLS/SNI and revalidate immediately before each connection.

Delivery intent and immutable snapshots exist before network execution. Only a
SHA-256 digest of each 256-bit claim token is persisted; transition history
contains no raw token. Claim-scoped security-definer functions couple exact
encrypted secret-version access and completion to one live lease. Attempts are
capped at eight and backoff at one hour.

Issue #107 completes the false-by-default canary boundary with canonical
bounded bodies, timestamped HMAC-SHA256, claim-fenced secret custody, direct
peer-pinned TLS transport, generic error outcomes, plaintext zeroing, a
least-credentialed runner service, and adversarial database/network tests.
Residual risk remains Medium until live deployment-network review; general
activation, replay tooling, and failure disablement are still absent.
