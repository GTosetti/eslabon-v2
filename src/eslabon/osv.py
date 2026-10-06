"""ESL-006 known-malicious: ask OSV whether a package name is a reported MAL-*.

Package-level, run once per scan in the parent process (cli), after the worker
returned, on the same name(s) ESL-005 checks. Only non-withdrawn records whose id
starts with ``MAL-`` count (OSV's malicious-packages feed); CVE/GHSA/PYSEC
records, which the same endpoint returns mixed in, are ignored.

Fail closed: any network, HTTP, size, redirect or JSON problem makes the lookup
``unavailable`` (scan status ``osv_unavailable``, exit 2), never "clean". The
response is attacker-influenced (advisory summaries are free text), so it is
never printed or logged; only clean_text'ed summaries reach the finding snippet.

Limits of the rule (local archives): ESL-006 trusts the name and version the
archive DECLARES (metadata, else its file name). A known-bad artifact that is
renamed or re-versioned is not matched here; content rules ESL-001..004 cover
edited artifacts. A MAL record that lists specific versions can be dodged by
declaring another version; most MAL records cover every version of the name.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from eslabon import __version__
from eslabon.model import Finding
from eslabon.sanitize import clean_text, to_hex

RULE_ID = "ESL-006"
API_URL = "https://api.osv.dev/v1/query"
API_HOST = "api.osv.dev"
TIMEOUT_S = 15.0  # per request
TOTAL_DEADLINE_S = 30.0  # across every page of every name in one check/query
MAX_RESPONSE = 8 * 2**20  # bytes per response, counted while reading
MAX_PAGES = 10  # a longer next_page_token chain fails closed
_CHUNK = 64 * 2**10
_SNIPPET_CAP = 1024
# Our ecosystem names (and OSV's own spelling) -> OSV ecosystem.
_ECOSYSTEMS = {"pypi": "PyPI", "PyPI": "PyPI", "npm": "npm"}

# opener(url, body, timeout) -> (final url after redirects, response body)
Opener = Callable[[str, bytes, float], tuple[str, bytes]]


class OsvError(Exception):
    """The lookup could not be completed; the message is safe to report."""


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != API_HOST:
        raise OsvError("osv url not https://api.osv.dev")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if it stays on https://api.osv.dev."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_capped(resp, cap: int, deadline: float | None = None) -> bytes:
    """Read ``resp`` to the end, refusing more than ``cap`` bytes or going on
    past ``deadline`` (a ``_clock`` value; a server dribbling bytes just under
    the socket timeout would otherwise hold the read open indefinitely)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline is not None and _clock() >= deadline:
            raise OsvError("osv deadline exceeded")
        chunk = resp.read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise OsvError("osv response too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _request(url: str, data: bytes) -> urllib.request.Request:
    _check_url(url)
    # https://api.osv.dev only: _check_url above, _SafeRedirect on redirects
    return urllib.request.Request(  # noqa: S310
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"eslabon/{__version__}",
        },
    )


def urllib_opener(url: str, data: bytes, timeout: float) -> tuple[str, bytes]:
    """The real opener: HTTPS POST with a timeout, a size cap and safe redirects."""
    req = _request(url, data)
    # ``timeout`` is already capped at what is left of the overall deadline
    deadline = _clock() + timeout
    opener = urllib.request.build_opener(_SafeRedirect())
    with opener.open(req, timeout=timeout) as resp:
        final = resp.geturl()
        body = _read_capped(resp, MAX_RESPONSE, deadline)
    return final, body


# Tests replace this (conftest makes it raise); query_malicious looks it up at
# call time, so the replacement applies everywhere, the cli included.
DEFAULT_OPENER: Opener = urllib_opener
_clock = time.monotonic  # tests replace it to exercise the overall deadline


def _remaining(deadline: float, timeout_s: float) -> float:
    left = deadline - _clock()
    if left <= 0:
        raise OsvError("osv deadline exceeded")
    return min(timeout_s, left)


def _page(opener: Opener, body: dict, timeout_s: float, deadline: float) -> dict:
    data = json.dumps(body, ensure_ascii=True).encode("ascii")
    final, raw = opener(API_URL, data, _remaining(deadline, timeout_s))
    _remaining(deadline, timeout_s)  # a reply after the deadline does not count
    _check_url(final)
    if len(raw) > MAX_RESPONSE:
        raise OsvError("osv response too large")
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise OsvError("osv response is not JSON") from exc
    if not isinstance(doc, dict):
        raise OsvError("osv response is not an object")
    return doc


def _records(
    name: str,
    version: str | None,
    ecosystem: str,
    opener: Opener,
    timeout_s: float,
    deadline: float,
) -> list[tuple[str, str]]:
    """(id, summary) of every non-withdrawn MAL-* record for name/version.

    Raises OsvError on any failure. Follows next_page_token up to MAX_PAGES.
    """
    eco = _ECOSYSTEMS.get(ecosystem)
    if eco is None:
        raise OsvError("osv unknown ecosystem")
    query: dict = {"package": {"name": name, "ecosystem": eco}}
    if version:
        query["version"] = version
    found: list[tuple[str, str]] = []
    for _ in range(MAX_PAGES):
        doc = _page(opener, query, timeout_s, deadline)
        vulns = doc.get("vulns", [])
        if not isinstance(vulns, list):
            raise OsvError("osv vulns is not a list")
        for rec in vulns:
            if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
                raise OsvError("osv record without an id")
            rid = rec["id"]
            if not rid.startswith("MAL-") or "withdrawn" in rec:
                continue
            summary = rec.get("summary")
            entry = (rid, summary if isinstance(summary, str) else "")
            if entry[0] not in (e[0] for e in found):
                found.append(entry)
        token = doc.get("next_page_token")
        if token is None or token == "":
            return found
        if not isinstance(token, str):
            raise OsvError("osv bad next_page_token")
        query = dict(query, page_token=token)
    raise OsvError("osv pagination cap")


def _error_text(exc: Exception) -> str:
    if isinstance(exc, OsvError):
        return str(exc)
    return f"osv unavailable: {type(exc).__name__}"


def _lookup(
    name: str,
    version: str | None,
    ecosystem: str,
    opener: Opener | None,
    timeout_s: float,
    deadline: float,
) -> tuple[list[tuple[str, str]] | None, str | None]:
    try:
        records = _records(
            name, version, ecosystem, opener or DEFAULT_OPENER, timeout_s, deadline
        )
        return records, None
    except Exception as exc:  # fail closed on anything at all
        return None, _error_text(exc)


def query_malicious(
    name: str,
    version: str | None,
    ecosystem: str,
    opener: Opener | None = None,
    timeout_s: float = TIMEOUT_S,
) -> tuple[str, list[str]]:
    """("ok", [MAL ids]) or ("unavailable", []).

    ``ecosystem`` is "PyPI" or "npm" (our lowercase "pypi" is accepted too).
    Without a version OSV returns every advisory for the package.
    """
    deadline = _clock() + TOTAL_DEADLINE_S
    records, _ = _lookup(name, version, ecosystem, opener, timeout_s, deadline)
    if records is None:
        return "unavailable", []
    return "ok", [rid for rid, _ in records]


@dataclass
class OsvResult:
    status: str  # "ok" | "unavailable"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def _finding(name: str, records: list[tuple[str, str]]) -> Finding:
    parts = [f"{rid}: {summary}" if summary else rid for rid, summary in records]
    return Finding(
        rule_id=RULE_ID,
        file="<osv>",
        member_index=-1,
        line=0,
        snippet=clean_text("; ".join(parts), _SNIPPET_CAP),
        match_count=len(records),
        name_hex=to_hex(name),
    )


def check(
    queries: Iterable[tuple[str, str | None]],
    ecosystem: str,
    opener: Opener | None = None,
    timeout_s: float = TIMEOUT_S,
) -> OsvResult:
    """Query every (name, version); one ESL-006 finding per name with a MAL id.

    If any lookup fails the whole result is "unavailable" with no findings from
    the failed name (findings for names that did answer are kept).
    """
    result = OsvResult("ok")
    deadline = _clock() + TOTAL_DEADLINE_S
    for name, version in queries:
        records, error = _lookup(name, version, ecosystem, opener, timeout_s, deadline)
        if records is None:
            result.status = "unavailable"
            if result.error is None:
                result.error = error
            continue
        if records:
            result.findings.append(_finding(name, records))
    return result
