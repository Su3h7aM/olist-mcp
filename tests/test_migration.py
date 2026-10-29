import pathlib
import sqlite3
import unittest


class MigrationTest(unittest.TestCase):
    def test_account_isolation_and_constraints(self):
        db = sqlite3.connect(':memory:')
        db.executescript((pathlib.Path(__file__).parent.parent / 'migrations/001_mirror.sql').read_text())
        db.executemany('INSERT INTO accounts(id, display_name) VALUES (?, ?)', [('a', 'A'), ('b', 'B')])
        for account in ('a', 'b'):
            db.execute('INSERT INTO records(account_id, resource, remote_id, payload, observed_at) VALUES (?, ?, ?, ?, ?)', (account, 'produtos', '1', '{}', '2026-01-01'))
        self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0], 2)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT INTO records VALUES ('a', 'produtos', '2', 'invalid', 'now', NULL)")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT INTO identity_candidates VALUES ('a', 'produtos', 'missing', 'sku', '123')")


if __name__ == '__main__':
    unittest.main()
