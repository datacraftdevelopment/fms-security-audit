"""An HTTP session that can only read.

The FileMaker Admin API has no read-only account, so the audit enforces read-only
behaviour in code: GET requests only, plus the login and logout calls.
"""

import re

import requests

ALLOWED_WRITES = [
    ("POST", re.compile(r"/fmi/admin/api/v2/user/auth/?$")),
    ("DELETE", re.compile(r"/fmi/admin/api/v2/user/auth/[^/]+/?$")),
]


class WriteBlocked(RuntimeError):
    pass


class ReadOnlySession(requests.Session):
    def request(self, method, url, *args, **kwargs):
        method = method.upper()
        if method not in ("GET", "HEAD"):
            path = requests.utils.urlparse(url).path
            if not any(method == m and rx.search(path) for m, rx in ALLOWED_WRITES):
                raise WriteBlocked(f"Blocked {method} {path}: the audit only reads.")
        kwargs.setdefault("timeout", 20)
        return super().request(method, url, *args, **kwargs)
