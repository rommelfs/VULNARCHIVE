from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fd_sightings.workers import ImportWorkerManager


class ImportWorkerManagerTests(unittest.TestCase):
    def test_validates_period_and_builds_non_publishing_archive_command(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "archive.sqlite"
            manager = ImportWorkerManager(database)
            captured = []

            class Result:
                returncode = 0

            def run(command, **kwargs):
                captured.append(command)
                return Result()

            with patch("fd_sightings.workers.subprocess.run", side_effect=run):
                job = manager.submit("2024-01", "2024-03", limit=25, semantic=False, refresh=True)
                manager.executor.shutdown(wait=True)

            stored = json.loads((database.parent / "workers" / f'{job["id"]}.json').read_text())
            self.assertEqual(stored["status"], "completed")
            command = captured[0]
            self.assertIn("--no-semantic", command)
            self.assertIn("--refresh", command)
            self.assertEqual(command[-7:], [
                "archive", "--from-period", "2024-01", "--to-period", "2024-03", "--limit", "25",
            ])
            self.assertNotIn("sync", command)
            self.assertNotIn("publish-auto", command)

    def test_rejects_invalid_or_excessive_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ImportWorkerManager(Path(directory) / "archive.sqlite")
            for start, end in (("2024-03", "2024-01"), ("2001-01", "2001-02"), ("2020-01", "2030-01")):
                with self.assertRaises(ValueError):
                    manager.submit(start, end)
            with self.assertRaises(ValueError):
                manager.submit("2024-01", "2024-02", limit=10001)
            now = datetime.now(timezone.utc)
            future = f"{now.year + 1:04d}-01"
            with self.assertRaises(ValueError):
                manager.submit("2024-01", future)
            manager.executor.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
