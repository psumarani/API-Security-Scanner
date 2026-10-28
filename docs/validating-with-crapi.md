# Validating against OWASP crAPI (or the bundled lab)

## Option A - bundled lab (no Docker)
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m lab.vuln_lab --port 8099
```
Set `ALLOW_LOCAL_LAB_TARGETS=true` in `.env`, restart the backend, then add a target:
base URL `http://127.0.0.1:8099`, spec URL `http://127.0.0.1:8099/openapi.json`, tick **Local lab**.
Add bearer profiles `lab-token-alice`, `lab-token-bob`, `lab-token-admin`. In *New scan* add the BOLA
object `/api/orders/1` owned by alice and the BFLA rule `GET /api/admin/users` forbidden for alice,
allowed for admin. Expected: confirmed BOLA, BFLA, missing authentication, SQL injection and CORS
findings; no findings on the `/api/safe/...`, `/api/profile` and `/api/admin/secure-users` controls.
The automated tests (`backend/tests/test_scanner_lab.py`, `test_scans_api.py`) assert exactly this.

## Option B - OWASP crAPI
Follow the crAPI project's own instructions to start it locally with Docker (see
https://github.com/OWASP/crAPI). Then:
1. Register two crAPI users through its web UI and copy each user's bearer token (log in via the
   API and take the token from the response).
2. Add the crAPI API origin as a target with **Local lab** enabled and `ALLOW_LOCAL_LAB_TARGETS=true`.
3. If crAPI publishes an OpenAPI file in its repository, host it or save it where the target origin
   serves it (the spec URL must be on the target's origin).
4. Add one auth profile per user, list known objects (for example a vehicle or mechanic report
   that user A owns) for BOLA, and run the scan.
Do not scan any system you do not own or have written permission to test.
