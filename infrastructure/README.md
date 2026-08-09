# Infrastructure

`docker-compose.yml` is the local engineering baseline; its defaults are not a
production deployment. Local database, cache, and object-storage ports bind to
`127.0.0.1` only.

Production operations use the checked-in [systemd contracts](systemd/README.md),
strictly separated [environment templates](environments/README.md), and
[recovery SLO alerts](monitoring/README.md). Database backup/restore plus
Alembic rollback rehearsal and versioned object recovery are executable through
the scripts documented by those modules. Secret values remain in the deployment
secret manager and never enter repository templates or unit files.
