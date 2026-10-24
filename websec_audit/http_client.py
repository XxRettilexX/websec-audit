"""Rate-limited HTTP client used by all checks.

Centralizing requests here means every check automatically respects the
global rate limit and timeout, which keeps the tool from ever behaving like
a flooder/DoS tool even by accident.
"""
from __future__ import annotations

import time
from typing import Optional

import requests

DEFAULT_USER_AGENT = "websec-audit/0.1 (+authorized-self-test; https://github.com/)"


class RateLimitedClient:
    def __init__(self, requests_per_second: float = 3.0, timeout: float = 8.0,
                 user_agent: str = DEFAULT_USER_AGENT, verify_tls: bool = True):
        self.min_interval = 1.0 / max(requests_per_second, 0.1)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.verify_tls = verify_tls
        self._last_request_ts = 0.0
        self.request_count = 0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_ts
        wait = self.min_interval - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_ts = time.monotonic()

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("verify", self.verify_tls)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            return resp
        except requests.RequestException:
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("OPTIONS", url, **kwargs)
