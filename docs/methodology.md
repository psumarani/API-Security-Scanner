# Scanner methodology

The scanner is a defensive assessment tool. It only talks to targets whose owner has confirmed
authorization, and every request passes the same scope and safety checks.

## Pipeline
1. **Pre-flight** - the target origin is re-validated (DNS may have changed since it was saved).
2. **Discovery** - the OpenAPI 3.x / Swagger 2.0 document is fetched through the scope-enforcing
   client and parsed (local `$ref`s only, depth/cycle limited, endpoint cap). Declared security
   becomes `authentication_required` (true / false / unknown).
3. **Credentials** - auth profiles are decrypted in memory only. Test accounts with a `login_path`
   are exchanged for a bearer token.
4. **Modules** run one at a time. A module failure is recorded and does not stop the scan.
   Cancellation and the time limit are checked before every request.
5. **Persistence** - endpoints and findings are stored as each module finishes, so the UI shows
   progress. Findings are de-duplicated by a fingerprint of (check, endpoint, discriminator).

## Validation vocabulary
| Status | Meaning |
|---|---|
| Confirmed | The evidence itself demonstrates the weakness (two independent signals, or an observed result that contradicts an explicit expectation you supplied). |
| Potential | Suspicious behaviour that needs manual verification. |
| Informational | Observation or hardening gap, not a demonstrated vulnerability (for example a missing header). |
| Inconclusive | A test could not be completed; listed in the report, not reported as a flaw. |

Severity is capped by status: informational findings never exceed *low*; low-confidence potential
findings never exceed *medium*.

## Modules
| Module | Method | Confirmed when |
|---|---|---|
| `misconfig` | Header, CORS, banner, OPTIONS and 404-page inspection | CORS reflects an untrusted origin with credentials, or a stack trace is shown. Missing headers are informational. |
| `auth` | Anonymous, malformed-token and `alg=none` requests to endpoints declared protected, compared with an authenticated baseline | The anonymous/invalid-token response matches the authenticated response. |
| `sqli` | Quote probes (error-based) and true/false conditions (boolean differential, repeated) on GET query/path parameters | A database error signature absent from the baseline **and** a reproducible boolean differential are both seen. One signal = potential. |
| `bola` | Owner vs. every other test account on objects you list | A non-owner gets an equivalent 2xx response. Identifiers are never guessed. |
| `bfla` | Calls operations as accounts your rules forbid | A forbidden account gets 2xx. Unsafe methods are skipped unless enabled. |
| `rate_limit` | One bounded burst (default 30, max 100) | Never confirmed: absence of limits is *potential, low confidence*; 429 or rate-limit headers are informational. |
| `inventory` | Deprecated operations still active, several versions, public spec | Advisory only. |

## Safety controls (all enforced in `app/scanner/`)
Scope = exact scheme+host+port. Every resolved address must be public (loopback/private only in
opt-in "local lab" mode; link-local/metadata never). Redirects are re-validated hop by hop. TCP
connections are pinned to the vetted address (anti DNS-rebinding). Budgets: requests, concurrency,
timeout, duration, redirects, response size. State-changing methods are off by default. Evidence is
redacted (Authorization, cookies, JWTs, `password=`/`token=` patterns) and bodies are summarized.

## Known limitations
* Blind/time-based SQL injection, POST/JSON body injection and header/cookie injection are not tested.
* OWASP API3, API6, API7 and API10 are not automated (see the Coverage page).
* Authentication checks do not test password policy, brute-force protection or MFA.
* Rate-limit results are indicators, not proof.
* The in-memory rate limiter and the thread-based scan runner are per process (single instance).
* Scope is origin-level; an http target that redirects to https must be saved with its https URL.
