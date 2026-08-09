# Environment separation

Staging and production have distinct deployment IDs, PostgreSQL databases,
Redis instances, object-storage endpoints/buckets, signing material, encryption
key versions, worker tokens, and rootless containerd namespaces. Application
configuration rejects non-HTTPS browser origins/public object endpoints,
environment-mismatched deployment IDs, object buckets, and master-key versions,
local credentials, and insecure session cookies outside development/test.

Examples contain references only. Resolve every `REQUIRED_FROM_*` value from the
environment's secret manager into root-owned service environment files. Never
reuse a staging database, bucket, key version, worker identity, backup location,
or canary namespace in production.

Backup, restore-drill, and object-recovery credentials are separate from
application credentials and from each other. Grant the periodic backup identity
only the PostgreSQL privileges required by `pg_dump`; grant disposable database
creation/deletion only to the operator-held restore-drill identity. Restrict the
object-recovery identity to the generated `recovery-drill/<deployment>/` prefix
and bucket-version inspection.
