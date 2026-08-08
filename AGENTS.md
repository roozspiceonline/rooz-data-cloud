# Rooz Data Cloud engineering instructions

Treat all Agent code, browser content, scraped data and external network input as
untrusted. Keep PostgreSQL and object-storage credentials in trusted control-plane
or worker services only. Never accept caller-supplied tenancy/ownership identifiers
for persisted resources; enforce tenant isolation through authorization and RLS.

Use dedicated feature branches and pull requests for implementation work. Do not
force-push or weaken CI, authentication, authorization, RLS, sandboxing, browser
controls, egress policy, or quota checks to make tests pass. Preserve published
feature branches after merge unless an explicit repository rule changes that policy.

Before merging a workstream, inspect the exact PR head, complete changed-file
review, migrations, relevant security/adversarial tests, Ruff, mypy, pytest,
frontend lint/typecheck/tests/build, verifier scripts and Compose validation.
Merge only with exact-head authoritative GitHub CI green, mergeability confirmed,
and no blocking review feedback. Preserve feature branches and close the linked
issue after a verified merge.

Maintain `docs/roadmap/RDC_V1_ROADMAP.md` as the durable source of current,
completed and remaining RDC v1 work. Do not stop at phase initialization or a
merged increment: continue to the next documented dependency. Keep the root
README, threat models, runbooks, API contracts and schema documentation factual.

Permanent prohibitions: no anonymous tenant-resource access; no arbitrary SQL,
filesystem/object-key trust, or caller-owned tenancy; no Agent/Chromium database
or object-storage credentials; no secret logging; no security-test removal;
no force-push; and no relaxation of RLS, sandbox, browser, egress, CI or branch
protection merely to obtain green checks.
