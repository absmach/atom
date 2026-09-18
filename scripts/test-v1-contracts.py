"""Exercise the contract gate against disposable copies, without Cargo or a DB."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path("api/v1/contracts-v1.0.0.sha384")
MIGRATIONS = Path("api/v1/migrations-v1.0.0.sha384")


class ContractGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="atom-contract-gate-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        paths = {CONTRACTS, Path("scripts/check-v1-contracts.sh")}
        for manifest in (CONTRACTS, MIGRATIONS):
            paths.update(Path(line.split()[1]) for line in (ROOT / manifest).read_text().splitlines())
        paths.update(path.relative_to(ROOT) for path in (ROOT / "migrations").glob("*.sql"))
        for path in paths:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)

    def refresh(self, manifest, paths=None):
        file = self.root / manifest
        if paths is None:
            paths = [Path(line.split()[1]) for line in file.read_text().splitlines()]
        file.write_text("".join(
            f"{hashlib.sha384((self.root / path).read_bytes()).hexdigest()}  {path}\n"
            for path in paths
        ))

    def register_migrations(self):
        self.refresh(MIGRATIONS, sorted(path.relative_to(self.root)
                                       for path in (self.root / "migrations").glob("*.sql")))
        self.refresh(CONTRACTS)

    def check(self, expected_error=None):
        result = subprocess.run(
            ["bash", "scripts/check-v1-contracts.sh"], cwd=self.root,
            capture_output=True, text=True,
        )
        output = result.stdout + result.stderr
        if expected_error is None:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(expected_error, output)

    def test_current_contracts_and_forward_migration_pass(self):
        self.check()

    def test_launch_baseline_alone_passes(self):
        for path in (self.root / "migrations").glob("*.sql"):
            if path.name != "001_initial.sql":
                path.unlink()
        self.check()

    def test_forward_migration_needs_no_manifest_update(self):
        (self.root / "migrations/004_next.sql").write_text("SELECT 1;\n")
        self.check()

    def test_missing_launch_baseline_fails(self):
        (self.root / "migrations/001_initial.sql").unlink()
        self.check("migrations/001_initial.sql: FAILED")

    def test_missing_launch_baseline_fails_even_if_manifest_refreshed(self):
        (self.root / "migrations/001_initial.sql").unlink()
        self.register_migrations()
        self.check("must contain the launch baseline exactly once")

    def test_duplicate_version_fails(self):
        (self.root / "migrations/002_duplicate.sql").write_text("SELECT 1;\n")
        self.check("Duplicate migration version 2")

    def test_pre_baseline_version_fails(self):
        (self.root / "migrations/000_before.sql").write_text("SELECT 1;\n")
        self.check("must follow the 001 launch baseline")

    def test_invalid_migration_name_fails(self):
        (self.root / "migrations/next.sql").write_text("SELECT 1;\n")
        self.check("must use the NNN_name.sql form")

    def test_migration_checksum_drift_fails(self):
        for name in ("001_initial.sql",):
            with self.subTest(migration=name):
                path = self.root / "migrations" / name
                original = path.read_text()
                path.write_text(original + "\n-- unexpected edit\n")
                self.check(f"migrations/{name}: FAILED")
                path.write_text(original)

    def test_contract_checksum_drift_fails(self):
        path = self.root / "apidocs/graphql-schema.graphql"
        path.write_text(path.read_text() + "\n# unexpected edit\n")
        self.check("apidocs/graphql-schema.graphql: FAILED")

    def test_duplicate_manifest_entry_fails(self):
        path = self.root / MIGRATIONS
        text = path.read_text()
        path.write_text(text + text.splitlines(keepends=True)[0])
        self.refresh(CONTRACTS)
        self.check("must contain the launch baseline exactly once")

    def test_migration_manifest_checksum_drift_fails(self):
        path = self.root / MIGRATIONS
        path.write_text(path.read_text() + "\n")
        self.check(f"{MIGRATIONS}: FAILED")


if __name__ == "__main__":
    unittest.main()
