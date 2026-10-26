import importlib.util
from pathlib import Path
import tempfile
import unittest
spec = importlib.util.spec_from_file_location("migrate", Path(__file__).resolve().parents[2] / "scripts/migrate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class MigrationTests(unittest.TestCase):
    def test_checksum_and_order(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "0002_next.sql").write_text("SELECT 2;")
            (p / "0001_initial.sql").write_text("SELECT 1;")
            rows = m.discover(p)
            self.assertEqual([r[0] for r in rows], [1, 2])
            old = rows[0][2]
            (p / "0001_initial.sql").write_text("SELECT 3;")
            self.assertNotEqual(old, m.discover(p)[0][2])
    def test_duplicate(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "0001_a.sql").write_text("")
            (p / "0001_b.sql").write_text("")
            with self.assertRaises(ValueError): m.discover(p)
    def test_bad_name(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "wrong.sql").write_text("")
            with self.assertRaises(ValueError): m.discover(p)
if __name__ == "__main__": unittest.main()
