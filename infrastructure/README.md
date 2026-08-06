# Infrastructure

`docker-compose.yml` is the local engineering baseline. Production deployment manifests,
observability, backup automation, registry integration, and execution-plane infrastructure enter
later modules. Local database, cache, and object-storage ports bind to `127.0.0.1` only.
