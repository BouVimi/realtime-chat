"""DB tests create and remove an isolated random schema. Explicit opt-in required."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import psycopg
from psycopg import sql
spec = importlib.util.spec_from_file_location("migrate", Path(__file__).resolve().parents[2] / "scripts/migrate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

@unittest.skipUnless(os.getenv("RUN_DB_TESTS") == "1", "Set RUN_DB_TESTS=1 on a test DB")
class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self):
        self.schema = "test_" + uuid.uuid4().hex
        self.conn = psycopg.connect(host=os.getenv("DB_HOST", "127.0.0.1"),
            port=os.getenv("DB_PORT", "5432"), dbname=os.environ["POSTGRES_DB"],
            user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"], autocommit=True)
        self.conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.old_options = os.environ.get("PGOPTIONS")
        os.environ["PGOPTIONS"] = "-c search_path=" + self.schema
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "0001_initial.sql").write_text("-- Empty baseline\n")

    def tearDown(self):
        if self.old_options is None: os.environ.pop("PGOPTIONS", None)
        else: os.environ["PGOPTIONS"] = self.old_options
        self.conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
        self.conn.close()
        self.tmp.cleanup()

    def count(self):
        return self.conn.execute(sql.SQL("SELECT count(*) FROM {}.schema_migrations").format(
            sql.Identifier(self.schema))).fetchone()[0]

    def test_idempotency_and_tamper(self):
        m.migrate(self.root)
        m.migrate(self.root)
        self.assertEqual(self.count(), 1)
        (self.root / "0001_initial.sql").write_text("SELECT 2;")
        with self.assertRaises(ValueError): m.migrate(self.root)
        self.assertEqual(self.count(), 1)

    def test_rollback(self):
        m.migrate(self.root)
        (self.root / "0002_failure.sql").write_text("CREATE TABLE must_rollback(id integer); SELECT 1/0;")
        with self.assertRaises(psycopg.Error): m.migrate(self.root)
        self.assertEqual(self.count(), 1)
        name = self.schema + ".must_rollback"
        self.assertIsNone(self.conn.execute("SELECT to_regclass(%s)", (name,)).fetchone()[0])

    def test_missing_applied_file(self):
        m.migrate(self.root)
        (self.root / "0001_initial.sql").unlink()
        (self.root / "0002_next.sql").write_text("SELECT 2;")
        with self.assertRaises(ValueError): m.migrate(self.root)

if __name__ == "__main__": unittest.main()
