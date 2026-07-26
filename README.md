# flask-auth-service

A self-contained authentication microservice built in Flask, focused on
the security decisions that separate a demo login form from something
closer to production-grade: JWT sessions with a revocable, rotating
refresh token; account lockout; role-based access control; CSRF
protection on the cookie-carried parts of the flow; rate limiting;
structured audit logging; and hardened error handling that doesn't leak
implementation detail or let an attacker enumerate accounts.

It intentionally does one thing -- register, authenticate, and manage
sessions -- rather than growing into a full user-management platform.
That scope keeps every security decision below inspectable in one
sitting.

## Architecture

The app follows Flask's app-factory pattern (`create_app(config_name)`
in `app/__init__.py`) instead of a module-level `app = Flask(...)`.
That's not just style: it's what lets the test suite build a fresh,
fully isolated app per test run against an in-memory SQLite database,
with its own config, rather than sharing global state with whatever
config the dev server happens to be running.

```
app/
  __init__.py          app factory: wires config, extensions, blueprints,
                        error handlers, and the security-headers hook
  config.py             environment-based config classes + fail-fast
                        SECRET_KEY validation for production
  extensions.py          shared SQLAlchemy + Flask-Limiter singletons
  errors.py               generic, enumeration-resistant error handlers
  cli.py                  `flask init-db`, `flask seed-admin`
  models/
    user.py               User: email, password hash, lockout state
    role.py                Role + user_roles association table (RBAC)
    refresh_token.py       revocable, rotating refresh-token records
    audit_log.py           append-only security event log
  schemas/
    auth_schemas.py        marshmallow request validation
  security/
    passwords.py           bcrypt hashing
    password_policy.py     password strength rules
    tokens.py               JWT access / refresh / password-reset tokens
    decorators.py           auth_required, roles_required
    lockout.py               failed-login counting + temporary lockout
    csrf.py                  double-submit-cookie CSRF protection
    headers.py               security response headers
    audit.py                 structured audit-event recording
  routes/
    auth.py                  register, login, /me, refresh, logout
    password_reset.py        password reset request/confirm
    admin.py                  admin-only user listing (RBAC demo)
tests/                     one file per concern; see below
.github/workflows/ci.yml   ruff, bandit, pip-audit, pytest, docker build
Dockerfile, docker-compose.yml
```

## Running it

**Locally, with SQLite (no external services):**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export FLASK_APP=wsgi.py FLASK_ENV=development
flask init-db
flask run
```

**With Docker Compose (app + Postgres):**

```bash
docker compose up --build
```

`docker-compose.yml` runs `flask init-db` before starting gunicorn, so a
fresh `docker compose up` is immediately usable -- no separate migration
step. There is no real migration tool wired up (see "Scope tradeoffs"
below); `init-db` only ever creates missing tables.

**Running tests:**

```bash
pip install -r requirements-dev.txt
pytest --cov=app --cov-report=term-missing
```

## Authentication flow

1. **Register** (`POST /auth/register`) creates an account. Passwords
   are checked against a strength policy *before* hashing (so a weak
   password never reaches bcrypt, let alone the database) and hashed
   with bcrypt.
2. **Login** (`POST /auth/login`) verifies credentials and, on success,
   returns a short-lived **access token** in the JSON body and sets a
   longer-lived **refresh token** as an httpOnly cookie, plus a
   JS-readable CSRF token cookie (see below).
3. **Authenticated requests** send the access token as
   `Authorization: Bearer <token>`. `auth_required` decodes and
   verifies it, loads the user, and rejects the request if the token is
   invalid, expired, or the account no longer exists/is inactive.
4. **Refresh** (`POST /auth/refresh`) exchanges the refresh cookie for a
   new access token *and* a new refresh token -- the old refresh token
   is revoked in the same request (rotation; see below). Requires a
   valid CSRF header, since the refresh token is a cookie the browser
   attaches automatically.
5. **Logout** (`POST /auth/logout`) revokes the current refresh token
   and clears both cookies. Also CSRF-protected.

## Security decisions and threat model

Each of these is a deliberate answer to a specific question an attacker
(or a code reviewer) would ask.

**Why is the refresh token a cookie but the access token isn't?**
The access token is short-lived and sent explicitly by the client on
every request via an `Authorization` header -- headers aren't
auto-attached by the browser to third-party requests, so this isn't a
CSRF target. The refresh token needed to survive across page loads
without JavaScript holding onto it (so an XSS bug can't just read it
out of `localStorage`), which means httpOnly cookie -- but a cookie
*is* auto-attached to requests, which is exactly what CSRF exploits.
That trade is why refresh and logout carry CSRF protection and login
and register don't: only the cookie-driven routes are a CSRF target.

**Why rotate the refresh token on every refresh?**
JWTs are stateless and self-verifying -- there's no way to make one
"used up" without external state. `RefreshToken` rows in the database,
keyed by the token's `jti` claim, are that external state: every
refresh revokes the presented token's row and creates a new one. A
leaked refresh token is only useful until its next legitimate use,
after which the original is a dead end. Logout revokes the row
directly, so a stolen-then-logged-out token can't be replayed either.

**Why can't a reset token be replayed, without a separate revocation
table?**
A password-reset token embeds a truncated fingerprint (SHA-256, first
16 hex chars) of the user's *current* password hash at issue time, not
the hash itself. Confirming a reset recomputes and compares that
fingerprint. Since confirming a reset changes the password hash, the
fingerprint stops matching immediately after first use -- no revocation
table needed, and any reset token issued before an unrelated password
change also auto-invalidates for free.

**Why does login always call `verify_password`, even for an unknown
email?** bcrypt's check is the slow part of login. If it only ran for
existing accounts, an attacker could measure response time to learn
which emails have accounts without ever seeing a different error
message -- a timing side channel around the same enumeration the error
message itself is designed to avoid. Login always hashes-and-compares
against either the real stored hash or a fixed, hash-shaped dummy value,
so the timing profile is the same either way.

**Why does the password-reset-request endpoint always return the same
response?** Same principle: if the response (or its shape) differed
based on whether the email had an account, the endpoint becomes an
oracle for enumerating registered emails. It always returns
`{"message": "If that email is registered, a reset token has been
issued."}` and only *additionally* includes the actual token when an
account exists -- see the scope tradeoff below on why that's still not
quite production-safe.

**What does the double-submit CSRF cookie actually prevent?** On login,
a random token is set in two places: the httpOnly refresh cookie (the
attack target) and a second, JS-readable cookie. The frontend reads the
second cookie and echoes its value in an `X-CSRF-Token` header on
refresh/logout. A cross-site attacker's page can trick a victim's
browser into *sending* the refresh cookie (browsers do that
automatically for same-site requests to this origin) but same-origin
policy stops the attacker's page from *reading* the CSRF cookie to
forge a matching header -- so a forged request has the right cookie but
a missing or wrong header, and gets rejected.

**Why is `auth_required` unable to revoke an access token?** By design.
Access tokens are short-lived specifically so that revocation isn't
needed for them -- the exposure window from a stolen access token is
bounded by its TTL, not by whether anyone revokes it. Only refresh
tokens, which are long-lived, get the DB-backed revocation machinery.
This is visible in `test_integration_e2e.py`: an access token obtained
before logout still authenticates `/me` after logout, on purpose.

**What does the audit log capture, and why isn't it exposed via an
API?** Every login attempt (success, wrong password, and unknown-email
failures separately), registration, logout, token refresh, and
password-reset request/confirm gets an `AuditLog` row with an event
type, the acting user (when known), the email involved (even when no
account exists, for spotting credential-stuffing sweeps against
nonexistent accounts), source IP, and a timestamp. There's no admin
endpoint to browse it in this project's scope -- the point was to prove
the events are captured correctly (`test_audit_logging.py` reads the
table directly), not to build a full audit-viewer UI.

**What do the security response headers protect against, given this is
a JSON API with no pages to render?** Mostly defense-in-depth against
this API being embedded, sniffed, or probed from a browser context:
`X-Frame-Options: DENY` and a `frame-ancestors 'none'` CSP block
clickjacking-style framing; `X-Content-Type-Options: nosniff` stops a
response being MIME-sniffed into something executable; `Referrer-Policy:
no-referrer` keeps this origin's URLs out of outbound `Referer` headers;
`Strict-Transport-Security` closes the window for a downgrade attack on
the first request once deployed over HTTPS. None of these matter if the
only consumer is a trusted backend service calling this API directly,
but a JSON API is not always guaranteed to stay backend-only.

## Scope tradeoffs (what a real deployment would need to change)

This project prioritizes runnability and inspectability of the security
logic over being a complete production system. These are the known,
deliberate gaps, documented rather than hidden:

- **Password reset tokens are returned in the API response, not
  emailed.** There's no email-sending integration wired up. A real
  deployment must email the token/link instead -- returning it in the
  response leaks it to anyone who can observe that response, not only
  the account owner.
- **No real migration tool.** `flask init-db` calls
  `db.create_all()`, which only ever adds missing tables -- it can't
  alter an existing one. Fine for a demo that always starts from a
  clean database; not fine for a service with real data to preserve
  across schema changes. A real deployment needs Alembic/Flask-Migrate.
- **Rate limiting storage is in-process memory** (Flask-Limiter's
  default), which means limits reset on restart and aren't shared
  across multiple app instances. A real multi-instance deployment needs
  a shared backend (Redis, typically) via `RATELIMIT_STORAGE_URI`.
- **Password policy is a fixed rule list plus a small common-password
  set**, not a breach-corpus check (e.g. the Have I Been Pwned Pwned
  Passwords API). That kind of check is a reasonable production
  upgrade, left out here to keep the project runnable without external
  services.
- **No email verification on registration.** An account is usable
  immediately after registering with any syntactically valid email
  address.

## API reference

All responses are JSON. All error responses share the shape
`{"error": "..."}` (validation errors use `{"errors": {...}}` with
per-field messages).

| Method & path | Auth required | Notes |
|---|---|---|
| `POST /auth/register` | no | 10/hour rate limit. `{"email", "password"}` -> `201` |
| `POST /auth/login` | no | 10/minute rate limit. Sets refresh + CSRF cookies. |
| `GET /auth/me` | Bearer access token | Returns the current user's id/email. |
| `POST /auth/refresh` | refresh cookie + CSRF header | Rotates both tokens. |
| `POST /auth/logout` | refresh cookie + CSRF header | Idempotent; always clears cookies. |
| `POST /auth/password-reset/request` | no | 5/hour rate limit. Enumeration-safe response. |
| `POST /auth/password-reset/confirm` | reset token (in body) | `{"token", "new_password"}` |
| `GET /admin/users` | Bearer access token + `admin` role | Lists users (no password hashes). |

## Testing philosophy

Each test file targets one concern in isolation (`test_login.py`,
`test_csrf.py`, `test_lockout.py`, `test_rate_limiting.py`, ...) with
fresh state per test, so a failure points at exactly one mechanism.
`test_integration_e2e.py` is the deliberate exception: one continuous
client session walking the full register -> login -> me -> refresh ->
logout -> post-logout-me flow, to catch the failure mode isolated tests
can't -- pieces that pass individually but don't actually compose (e.g.
the cookie login sets not being the one refresh reads).

Security-critical pure-Python logic (password hashing, JWT encode/decode
and type confusion, CSRF token comparison) was verified against the
real `bcrypt`/`PyJWT` libraries during development, independent of the
full Flask test suite. `.github/workflows/ci.yml` runs `ruff` (lint),
`bandit` (static security analysis), `pip-audit` (dependency
vulnerability scanning), and `pytest --cov` on every push.
