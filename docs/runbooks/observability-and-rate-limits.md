# Observability and rate-limit operations

MVP-013 implements correlated JSON request logs, a protected Prometheus
endpoint, dependency readiness, and PostgreSQL-backed fixed-window limits. The
exact-source suite at commit `94231d7e...` covers contracts, redaction,
request-tier/actor-tier charging, proxy attribution, and bounded cleanup.
Deployed capacity/abuse and telemetry-pipeline acceptance remain pending, and
the metrics are process-local.

## Configuration

Review these variables before production use:

- `ANVA_METRICS_TOKEN`: bearer token required by production settings;
- `ANVA_RATE_LIMIT_ENABLED`;
- `ANVA_RATE_LIMIT_WINDOW_SECONDS`;
- `ANVA_RATE_LIMIT_API_REQUESTS`, `ANVA_RATE_LIMIT_MCP_REQUESTS`,
  `ANVA_RATE_LIMIT_WEB_REQUESTS`, and `ANVA_RATE_LIMIT_PREAUTH_REQUESTS`; and
- `ANVA_TRUSTED_PROXY_IPS`: exact proxies allowed to supply forwarded client
  addresses.

Keep the metrics token out of command history and logs. An empty token fails
closed: `/metrics` returns `404`, even outside production. Do not trust
forwarded addresses or protocol metadata from arbitrary clients. Anva accepts
`X-Forwarded-For` and `X-Forwarded-Proto` only when the immediate peer address
exactly matches an IP in `ANVA_TRUSTED_PROXY_IPS`; ranges and hostnames are not
accepted. An empty or incorrect list can collapse many users onto the proxy
address or break HTTPS recognition, depending on deployment topology.

## Health and metrics

Use liveness only to detect a responsive process. Use readiness to decide
whether the instance can serve traffic; it checks a bounded database query,
current Django migration state, and an authenticated signed request to the exact
configured object-storage bucket.

The `/metrics` endpoint accepts:

```http
Authorization: Bearer <ANVA_METRICS_TOKEN>
```

Scrape over HTTPS through the controlled proxy boundary. The metrics route is
not exempt from the production HTTPS redirect. A missing or incorrect bearer
token receives the same `404` response, avoiding an unauthenticated endpoint
oracle.

Series include build/readiness gauges and HTTP request, error,
rate-limit, in-flight, and duration metrics. Counters and histograms are held in
each application process: scraping one process is not a cluster aggregate and a
restart resets its series. Dashboards, recording rules, alert thresholds, and an
external metrics pipeline are not shipped or verified.

## Correlation and tracing

Preserve the request ID and W3C `traceparent` returned by the service when
investigating a failure. Logs are structured for correlation. This is
trace-context propagation, not a demonstrated distributed-tracing exporter or
complete cross-service span graph.

Avoid placing secrets, tokens, source contents, query bodies, or personal data
in labels or log fields. Treat organization, route, and actor dimensions as
potentially sensitive and control access to telemetry.

Gunicorn and Uvicorn access logs are disabled to avoid duplicate request data;
the application emits its own allowlisted structured request records. Server
errors remain on standard error at error severity, and Compose's application
log driver bounds retained files. Disabling access logs is not permission to
discard error output or to expose Docker logs without access control.

## Rate-limit response

For `429 Too Many Requests`:

1. capture request ID, route/channel, organization or pre-auth identity, and the
   response's retry information;
2. check whether the traffic is abusive, a retry storm, a shared-proxy identity
   collision, or expected load;
3. verify trusted proxy handling before increasing a limit;
4. mitigate the caller/retry behavior first; and
5. change limits deliberately, record the reason, and watch errors and latency.

Do not disable limits globally as a routine incident response. Limits
use database state, so also inspect database health and expired-bucket cleanup.
The exact-source suite covers API, MCP, web, and pre-auth
enforcement, stable `429`/`Retry-After`, proxy attribution, bucket isolation,
reset, and retention cleanup. The live MCP lane separately passed both write and
actual read-only services. Multi-process capacity and a deployed abuse drill
remain unverified.

Each MCP HTTP request consumes one pre-auth request-tier allowance before
protocol dispatch, including valid-token `initialize` and `ping`. Tools and
resources additionally retain their authenticated actor/tenant allowance; the
request tier is charged once and does not replace or duplicate the handler tier.
Only a normalized peer address, or a normalized forwarded address from an exact
trusted proxy, contributes to the keyed digest. Raw tokens, addresses, and
forwarding headers are not stored in rate-limit buckets.

Run installation-scoped cleanup explicitly or from a controlled scheduler:

```sh
make rate-limit-cleanup
```

One invocation removes at most 1,000 oldest expired `organization=NULL`
pre-auth buckets. It never deletes tenant buckets or an unexpired/current
window, is safe to repeat, and intentionally returns no bucket or tenant count.
Repeat bounded invocations when retiring a backlog. This local management
command has no HTTP endpoint; restrict access to the operator environment.

## Minimal incident triage

Correlate readiness transitions, request/error/rate-limit rates, latency,
database/object-store reachability, migration state, deploy image digest, and
recent administrative operations. Preserve relevant logs and metrics with UTC
timestamps. If telemetry is absent or ambiguous, state that gap in the incident
record rather than inferring a healthy service.
