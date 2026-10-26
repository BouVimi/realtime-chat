# Delivery verification — 2026-10-25

Verified locally:

- Drogon 1.9.11 (tag commit a22956b82b6b221ceeff83913c3014ce0d048555), built from source with C++20 and libpq support.
- Application built successfully with GCC 13.3.0 and CMake 4.4.4.
- CTest configuration suite: 1/1 passed (multiple configuration assertions).
- Python migration discovery/integrity tests: 3/3 passed.
- HTTP tests against the compiled backend with the database unavailable: 3/3 passed
  (503 JSON readiness, no session cookie, no static source/config serving, JSON 404).
- Base JSON and Compose/CI YAML parse successfully.

Not verified locally:

- PostgreSQL available / HTTP 200 path.
- Database migration idempotency, tamper checks and transactional rollback integration tests.
- Docker Compose startup and the GitHub Actions workflow.

The execution environment cannot switch to a non-root OS user to start PostgreSQL,
and does not provide Docker. DB integration tests are included, explicitly opt-in,
and wired into CI, but their inclusion is not a claim that they have passed.
The local dependency extraction is a test-environment workaround; normal setup
uses installed development packages as documented in README.md.
