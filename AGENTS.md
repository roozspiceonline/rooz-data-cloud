# Rooz Data Cloud engineering instructions

Treat all Agent code, browser content, scraped data and external network input as
untrusted. Keep PostgreSQL and object-storage credentials in trusted control-plane
or worker services only. Never accept caller-supplied tenancy/ownership identifiers
for persisted resources; enforce tenant isolation through authorization and RLS.

Use dedicated feature branches and pull requests for implementation work. Do not
force-push or weaken CI, authentication, authorization, RLS, sandboxing, browser
controls, egress policy, or quota checks to make tests pass. Preserve published
feature branches after merge unless an explicit repository rule changes that policy.

Before merging a phase, run its verifier plus relevant tests, lint and type checks;
then verify required GitHub checks are green for the exact PR head. Keep docs,
threat models and runbooks aligned with shipped behavior, and do not claim a
capability is enabled until its security boundary is actually enforced.
