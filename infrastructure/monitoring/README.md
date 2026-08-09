# Execution recovery monitoring

Scrape the API's hidden `/metrics/recovery` endpoint from the trusted monitoring
network. It contains global counters/gauges only and never emits tenant, Project,
worker, lease, payload, token, or secret identifiers.

Load `rdc-execution-recovery.rules.yml` into Prometheus-compatible alerting. The
production objectives are:

- completed recovery heartbeat no older than 120 seconds;
- recovery unavailable/stale for two minutes is critical;
- no worker remains cleanup-pending for more than five minutes;
- any recovery failure increase in ten minutes is critical;
- more than three detected worker losses in ten minutes is a warning burst.

Route critical alerts to the production on-call and warnings to the execution
operations queue. Alert receivers and credentials are deployment-owned and are
not stored in this repository.
