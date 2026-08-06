# Domain services

Phase 1A reserves this directory for domain-oriented backend modules. Product domains must not be
implemented as miscellaneous route code inside `apps/api`.

Planned domains include authentication, organizations, projects, Agents, Builds, Runs, API keys,
audit, and secrets. Each domain receives explicit ownership, repositories, permission checks, and
tenant tests in its assigned module.
