# Phase 0 HTTP contract

`GET /api/v1/health` — public database readiness, no cookie required.

200:
```json
{"status":"ok","database":"ok"}
```

503 (DB unavailable or failed probe):
```json
{"error":{"code":"DATABASE_UNAVAILABLE","message":"Service temporarily unavailable"}}
```

Both have `Content-Type: application/json` and `Cache-Control: no-store`.
The framework's HTTP errors use the same envelope with `HTTP_<status>` codes;
unhandled application exceptions use `INTERNAL_ERROR` (500). Invalid TCP/TLS or
malformed requests rejected below the application layer may close the connection.
No DB error detail reaches clients. No auth, user, chat or WebSocket API exists yet.
