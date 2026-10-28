# Backend API reference

Base path `/api/v1`. Interactive docs at `http://127.0.0.1:8000/docs`. All routes except
`/auth/register`, `/auth/login` and `/api/health` need `Authorization: Bearer <token>`.
Errors: `{"error": {"code", "message", "details?"}}` with codes `unauthorized` 401, `forbidden` 403,
`not_found` 404, `conflict` 409, `validation_error`/`scope_violation` 422, `rate_limited` 429.

| Area | Routes |
|---|---|
| Auth | `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /auth/sessions`, `DELETE /auth/sessions/{id}` |
| Targets | `POST/GET /targets`, `GET/DELETE /targets/{id}`, `POST /targets/{id}/spec-preview` |
| Auth profiles | `POST/GET /targets/{id}/auth-profiles`, `DELETE /targets/{id}/auth-profiles/{pid}` |
| Scans | `POST/GET /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/endpoints` |
| Findings | `GET /scans/{id}/findings`, `GET /findings`, `GET /findings/{id}` (filters: `severity`, `status`, `category`, `search`, `scan_id`, `limit`, `offset`) |
| Reports | `GET /scans/{id}/report?format=json\|html` (finished scans only) |
| Catalog | `GET /scanner/catalog` (modules, OWASP coverage, limits), `GET /dashboard/summary` |

## Create a scan
```http
POST /api/v1/scans
{
  "target_id": "<uuid>",
  "modules": ["misconfig", "auth", "sqli", "bola", "bfla", "rate_limit", "inventory"],
  "auth_profile_ids": ["<uuid>", "<uuid>"],
  "authorization_confirmed": true,
  "settings": {
    "timeout_seconds": 10, "max_requests": 300, "max_concurrency": 3, "max_duration_seconds": 600,
    "rate_limit": {"requests": 30, "path": "/api/ping"},
    "bola_objects": [{"path": "/api/orders/1", "owner": "<profile uuid>"}],
    "bfla_rules": [{"method": "GET", "path": "/api/admin/users", "allowed": ["<admin uuid>"], "forbidden": ["<user uuid>"]}]
  }
}
```
Returns `201` with the scan (`status: queued`). Poll `GET /scans/{id}`; `progress` holds the stage,
percentage and per-module status. Limits are validated server-side (see `/scanner/catalog`).

## Scan states
`queued -> running -> completed | failed | cancelled`. Cancelling a queued scan stops it before it
starts; a running scan stops at the next safe point. On server start, scans left queued/running by a
previous process are marked `failed` ("Interrupted by a server restart").
