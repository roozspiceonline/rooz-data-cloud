# Execution workers

Build and Agent runtime workers are deliberately absent from Phase 1A.

Untrusted code must never execute inside `apps/api`. Later worker modules run in separate processes
and enforce resource, network, time, credential, and cleanup boundaries.
