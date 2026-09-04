from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class HTTPError(RuntimeError):
    def __init__(self, status: int, message: str, body: str = "") -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


class Client:
    def __init__(self, user_agent: str, timeout: float = 30, min_interval: float = 0.0) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.min_interval = min_interval
        self._last_request = 0.0

    def _wait(self) -> None:
        remaining = self.min_interval - (time.monotonic() - self._last_request)
        if remaining > 0:
            time.sleep(remaining)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        retries: int = 3,
    ) -> tuple[int, str, dict[str, str]]:
        request_headers = {"User-Agent": self.user_agent, "Accept": "application/json, text/html, application/rss+xml"}
        request_headers.update(headers or {})
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        for attempt in range(retries + 1):
            self._wait()
            req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    self._last_request = time.monotonic()
                    return response.status, response.read().decode("utf-8", "replace"), dict(response.headers.items())
            except urllib.error.HTTPError as exc:
                self._last_request = time.monotonic()
                body = exc.read().decode("utf-8", "replace")
                if exc.code == 429 or 500 <= exc.code < 600:
                    if attempt < retries:
                        retry_after = exc.headers.get("Retry-After")
                        delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
                        time.sleep(min(delay, 30))
                        continue
                raise HTTPError(exc.code, exc.reason, body) from exc
            except urllib.error.URLError as exc:
                self._last_request = time.monotonic()
                if attempt < retries:
                    time.sleep(min(2**attempt, 30))
                    continue
                raise RuntimeError(f"Request failed for {url}: {exc.reason}") from exc
        raise AssertionError("unreachable")

    def get_text(self, url: str) -> str:
        return self.request(url)[1]

    def get_json(self, url: str, params: dict[str, str] | None = None) -> Any:
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return json.loads(self.request(url)[1])
