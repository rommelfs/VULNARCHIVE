from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .sources import SOURCES, configured_source_ids


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _month_number(period: str) -> int:
    year, month = (int(part) for part in period.split("-", 1))
    if year < 1993 or not 1 <= month <= 12:
        raise ValueError("period must be between 1993-01 and the supported calendar range")
    return year * 12 + month


class ImportWorkerManager:
    """Run bounded historical imports outside the review HTTP request thread."""

    def __init__(self, database: Path, *, max_workers: int = 1) -> None:
        self.database = database.resolve()
        self.directory = self.database.parent / "workers"
        self.directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="archive-import")
        self.lock = threading.Lock()
        self._mark_abandoned_jobs()

    def _job_path(self, job_id: str) -> Path:
        return self.directory / f"{job_id}.json"

    def _write(self, job: dict[str, Any]) -> None:
        target = self._job_path(str(job["id"]))
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(job, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o640)
        temporary.replace(target)

    def _mark_abandoned_jobs(self) -> None:
        for path in self.directory.glob("*.json"):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
                if job.get("status") in {"queued", "running"}:
                    job["status"] = "interrupted"
                    job["finished_at"] = _now()
                    job["error"] = "review service stopped while the import was active"
                    self._write(job)
            except (OSError, ValueError, TypeError):
                continue

    def submit(
        self, start: str, end: str, *, limit: int = 0,
        semantic: bool = False, refresh: bool = False, sources: list[str] | None = None,
    ) -> dict[str, Any]:
        first = _month_number(start)
        last = _month_number(end)
        now = datetime.now(timezone.utc)
        if last > now.year * 12 + now.month:
            raise ValueError("to period must not be in the future")
        if last < first:
            raise ValueError("to period must not be earlier than from period")
        if last - first + 1 > 120:
            raise ValueError("one worker may import at most 120 months")
        if limit < 0 or limit > 10_000:
            raise ValueError("per-month limit must be between 0 and 10000")
        source_ids = list(dict.fromkeys(sources if sources is not None else configured_source_ids()))
        if not source_ids:
            raise ValueError("select at least one source")
        if any(source_id not in SOURCES for source_id in source_ids):
            raise ValueError("unsupported source selection")
        job_id = uuid.uuid4().hex
        job: dict[str, Any] = {
            "id": job_id,
            "status": "queued",
            "from_period": start,
            "to_period": end,
            "limit": limit,
            "semantic": semantic,
            "refresh": refresh,
            "sources": source_ids,
            "created_at": _now(),
            "started_at": "",
            "finished_at": "",
            "return_code": None,
            "error": "",
            "log": str(self.directory / f"{job_id}.log"),
        }
        with self.lock:
            self._write(job)
        self.executor.submit(self._run, job_id)
        return job

    def _run(self, job_id: str) -> None:
        with self.lock:
            job = self.get(job_id)
            if not job:
                return
            job["status"] = "running"
            job["started_at"] = _now()
            self._write(job)
        command = [
            sys.executable, "-m", "fd_sightings.cli", "--db", str(self.database),
        ]
        if not job["semantic"]:
            command.append("--no-semantic")
        if job.get("refresh"):
            command.append("--refresh")
        command.extend(["archive", "--from-period", job["from_period"], "--to-period", job["to_period"]])
        for source_id in job.get("sources") or ["full-disclosure"]:
            command.extend(["--source", source_id])
        if job["limit"]:
            command.extend(["--limit", str(job["limit"])])
        environment = os.environ.copy()
        environment.pop("VA_REVIEW_PASSWORD", None)
        environment["PYTHONUNBUFFERED"] = "1"
        try:
            with Path(job["log"]).open("w", encoding="utf-8") as output:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=environment, check=False)
            job["return_code"] = result.returncode
            job["status"] = "completed" if result.returncode == 0 else "failed"
            if result.returncode:
                job["error"] = f"archive command exited with status {result.returncode}"
        except Exception as exc:
            job["status"] = "failed"
            job["error"] = str(exc)
        finally:
            job["finished_at"] = _now()
            with self.lock:
                self._write(job)

    def get(self, job_id: str) -> dict[str, Any] | None:
        if not job_id.isalnum():
            return None
        path = self._job_path(job_id)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, TypeError):
            return None

    def jobs(self) -> list[dict[str, Any]]:
        result = [job for path in self.directory.glob("*.json") if (job := self.get(path.stem))]
        return sorted(result, key=lambda job: str(job.get("created_at", "")), reverse=True)

    def log_tail(self, job: dict[str, Any], maximum: int = 20_000) -> str:
        try:
            with Path(job["log"]).open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - maximum))
                return stream.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return ""
