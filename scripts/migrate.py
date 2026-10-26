#!/usr/bin/env python3
"""Transactional, checksum-verified forward migrations. Run from any directory."""
import hashlib
import os
from pathlib import Path
import re
import sys
import psycopg

ROOT = Path(__file__).resolve().parents[1] / "backend" / "migrations"
LOCK_ID = 739182647  # Stable application-specific PostgreSQL advisory lock.

def discover(root):
    migrations = []
    versions = set()
    for path in sorted(root.glob("*.sql")):
        match = re.fullmatch(r"([0-9]{4})_[a-z][a-z0-9_]*\.sql", path.name)
        if not match:
            raise ValueError("Invalid migration filename")
        version = int(match[1])
        if version in versions:
            raise ValueError("Duplicate migration version")
        versions.add(version)
        content = path.read_bytes()
        migrations.append((version, path.name, hashlib.sha256(content).hexdigest(), content.decode("utf-8")))
    if not migrations:
        raise ValueError("No migrations found")
    return migrations

def migrate(root=ROOT):
    migrations = discover(root)
    # Separate connection arguments avoid URL interpolation and password escaping bugs.
    with psycopg.connect(host=os.getenv("DB_HOST", "127.0.0.1"),
        port=os.getenv("DB_PORT", "5433"), dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5, autocommit=True) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                version integer PRIMARY KEY, name text NOT NULL,
                checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())""")
            applied = {row[0]: row[1:] for row in conn.execute(
                "SELECT version, name, checksum FROM schema_migrations")}
            local = {v for v, *_ in migrations}
            if set(applied) - local:
                raise ValueError("Applied migration missing locally")
            high = max(applied, default=-1)
            for version, name, checksum, sql in migrations:
                if version in applied:
                    if tuple(applied[version]) != (name, checksum):
                        raise ValueError("Applied migration changed")
                    continue
                if version < high:
                    raise ValueError("Out-of-order migration")
                with conn.transaction():
                    # Migration files are trusted developer code, never user input.
                    if any(line.strip() and not line.lstrip().startswith("--") for line in sql.splitlines()):
                        conn.execute(sql, prepare=False)
                    conn.execute("INSERT INTO schema_migrations(version,name,checksum) VALUES (%s,%s,%s)",
                                 (version, name, checksum))
                print("Applied", name)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))

if __name__ == "__main__":
    try:
        migrate()
    except Exception:
        print("Migration failed: check DB availability, credentials and migration integrity", file=sys.stderr)
        sys.exit(1)
