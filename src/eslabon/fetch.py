"""Fetch a ``name==version`` artifact from PyPI or npm by direct HTTPS.

Nothing is installed, built or executed: the registry API names one archive
(``resolve``) and ``download`` streams it to a file in a caller-made temporary
directory, counting bytes and hashing as they arrive. The cli then scans that
file exactly like a local archive and deletes the directory.

Safety rules (design.md section 4):
- https only, to ALLOWED_HOSTS, checked on the initial URL, on every redirect
  (``_SafeRedirect``) and on the final URL;
- socket timeout TIMEOUT_S per operation and an overall deadline;
- sizes counted while reading, never trusting Content-Length: the archive is
  capped at ``Limits.max_download`` (LimitsExceeded), registry JSON at
  MAX_JSON; ``Accept-Encoding: identity`` is sent and any other
  Content-Encoding is refused, so nothing is decompressed on the HTTP layer;
- the archive must match the registry hash (PyPI ``digests.sha256``; npm
  ``dist.integrity`` sha512, else the sha1 ``dist.shasum`` with the anomaly
  ``weak_hash_sha1``), compared with hmac.compare_digest.

Every failure is a FetchError (status fetch_error) with a fixed, safe message,
except LimitsExceeded and HashMismatch.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.client
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from eslabon import __version__
from eslabon.model import Anomaly, FetchError, HashMismatch, Limits, LimitsExceeded
from eslabon.names import registry_key

ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"})
TIMEOUT_S = 30.0  # socket timeout, per connect/read
TOTAL_DEADLINE_S = 600.0  # registry lookup + download, end to end
MAX_JSON = 16 * 2**20  # registry API response cap, counted while reading
MAX_FILENAME = 120
_CHUNK = 64 * 2**10

PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"

_PYPI_NAME = re.compile(r"[A-Za-z0-9._-]+")
_NPM_NAME = re.compile(r"(@[a-z0-9._-]+/)?[A-Za-z0-9._-]+")
_VERSION = re.compile(r"[A-Za-z0-9.+!_-]+")
_HEX = {"sha256": 64, "sha512": 128, "sha1": 40}
_SUFFIXES = (".tar.gz", ".tar.bz2", ".tgz", ".whl", ".zip")
_UNSAFE_CHAR = re.compile(r"[^A-Za-z0-9._+-]")
_WIN_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
)
WEAK_SHA1 = "weak_hash_sha1"

# opener(request, timeout) -> an open response (context manager with read(n),
# geturl() and headers.get()). Tests replace DEFAULT_OPENER (conftest blocks it).
Opener = Callable[[urllib.request.Request, float], Any]


@dataclass(frozen=True)
class Artifact:
    url: str
    filename: str  # as the registry names it; download() sanitises it
    hash_alg: str  # "sha256" | "sha512" | "sha1"
    hash_value: str  # lowercase hex


_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


def _check_url(url: str) -> None:
    # Before urlsplit, which silently strips tab/CR/LF ("https://pyp<LF>i.org").
    if not isinstance(url, str) or _CONTROL_OR_SPACE.search(url):
        raise FetchError("fetch: url with control characters or spaces refused")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port  # a malformed port raises ValueError
    except ValueError as exc:
        raise FetchError("fetch: malformed url") from exc
    if parts.scheme != "https" or host not in ALLOWED_HOSTS:
        raise FetchError("fetch: url not https to an allowed registry host")
    if port not in (None, 443):
        raise FetchError("fetch: url not on the https port")
    if parts.username is not None or parts.password is not None:
        raise FetchError("fetch: url with credentials refused")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if it stays https and on ALLOWED_HOSTS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(
    *handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    """urllib opener with the safe redirect handler (tests add fake handlers)."""
    return urllib.request.build_opener(_SafeRedirect(), *handlers)


def urllib_opener(req: urllib.request.Request, timeout: float):
    """The real opener: urllib with _SafeRedirect and a socket timeout."""
    return build_opener().open(req, timeout=timeout)


DEFAULT_OPENER: Opener = urllib_opener
_clock = time.monotonic  # tests replace it to exercise the deadline


def new_deadline() -> float:
    return _clock() + TOTAL_DEADLINE_S


def _remaining(deadline: float) -> float:
    left = deadline - _clock()
    if left <= 0:
        raise FetchError("fetch: deadline exceeded")
    return min(TIMEOUT_S, left)


def _open(url: str, accept: str, opener: Opener | None, deadline: float):
    _check_url(url)
    # https to ALLOWED_HOSTS only: _check_url above, _SafeRedirect on redirects
    req = urllib.request.Request(  # noqa: S310
        url,
        method="GET",
        headers={
            "Accept": accept,
            "Accept-Encoding": "identity",
            "User-Agent": f"eslabon/{__version__}",
        },
    )
    try:
        resp = (opener or DEFAULT_OPENER)(req, _remaining(deadline))
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise FetchError(f"fetch: http {int(exc.code)}") from exc
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise FetchError(f"fetch: {type(exc).__name__}") from exc
    try:
        _check_url(resp.geturl())
        encoding = (resp.headers.get("Content-Encoding") or "identity").strip().lower()
        if encoding != "identity":
            raise FetchError("fetch: unexpected Content-Encoding")
    except BaseException:
        resp.close()
        raise
    return resp


def _chunks(resp, cap: int, deadline: float, too_big: Callable[[], Exception]):
    """Yield the body in chunks, refusing more than ``cap`` bytes in total."""
    total = 0
    while True:
        _remaining(deadline)
        try:
            chunk = resp.read(_CHUNK)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise FetchError(f"fetch: {type(exc).__name__}") from exc
        if not chunk:
            return
        total += len(chunk)
        if total > cap:
            raise too_big()
        yield chunk


def get_json(url: str, opener: Opener | None, deadline: float) -> dict:
    with _open(url, "application/json", opener, deadline) as resp:
        too_big = lambda: FetchError("fetch: registry response too large")  # noqa: E731
        raw = b"".join(_chunks(resp, MAX_JSON, deadline, too_big))
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise FetchError("fetch: registry response is not JSON") from exc
    if not isinstance(doc, dict):
        raise FetchError("fetch: registry response is not an object")
    return doc


# ------------------------------------------------------------ resolve ----


def has_alnum(text: str) -> bool:
    return any(c.isalnum() for c in text)


def _check_spec(name: str, version: str, ecosystem: str) -> None:
    pattern = _NPM_NAME if ecosystem == "npm" else _PYPI_NAME
    if ecosystem not in ("pypi", "npm"):
        raise FetchError("fetch: unknown ecosystem")
    bare = name.rsplit("/", 1)[-1]
    if not (pattern.fullmatch(name) and _VERSION.fullmatch(version)):
        raise FetchError("fetch: bad package name or version")
    if not (has_alnum(bare) and has_alnum(version)):
        raise FetchError("fetch: bad package name or version")


def _hex_digest(value: object, alg: str) -> str:
    if not isinstance(value, str):
        raise FetchError(f"fetch: registry {alg} missing")
    value = value.strip().lower()
    if len(value) != _HEX[alg] or any(c not in "0123456789abcdef" for c in value):
        raise FetchError(f"fetch: registry {alg} malformed")
    return value


def _wheel_tags(filename: str) -> tuple[set[str], set[str], set[str]] | None:
    if not filename.lower().endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) < 5:
        return None
    py, abi, plat = (set(p.lower().split(".")) for p in parts[-3:])
    return py, abi, plat


def _py3_none_any(tags) -> bool:
    py, abi, plat = tags
    return "py3" in py and "none" in abi and "any" in plat


def _cp313_manylinux_x86_64(tags) -> bool:
    py, _, plat = tags
    return "cp313" in py and any(
        p.startswith("manylinux") and p.endswith("_x86_64") for p in plat
    )


def pick_pypi_file(entries: list[dict]) -> dict | None:
    """sdist first (setup.py lives there); else the py3-none-any wheel; else the
    first cp313 manylinux x86_64 wheel; else the first wheel listed."""
    files = [e for e in entries if isinstance(e, dict)]
    for e in files:
        if e.get("packagetype") == "sdist":
            return e
    wheels = [
        (e, tags)
        for e in files
        if e.get("packagetype") == "bdist_wheel"
        and isinstance(e.get("filename"), str)
        and (tags := _wheel_tags(e["filename"])) is not None
    ]
    for wanted in (_py3_none_any, _cp313_manylinux_x86_64):
        for e, tags in wheels:
            if wanted(tags):
                return e
    return wheels[0][0] if wheels else None


def pypi_url(name: str, version: str) -> str:
    norm = registry_key(name, "pypi")
    return f"{PYPI_API}/{quote(norm, safe='')}/{quote(version, safe='')}/json"


def npm_url(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, bare = name.split("/", 1)
        path = quote(scope, safe="@") + "%2f" + quote(bare, safe="")
    else:
        path = quote(name, safe="")
    return f"{NPM_API}/{path}/{quote(version, safe='')}"


def _resolve_pypi(name: str, version: str, opener, deadline) -> Artifact:
    doc = get_json(pypi_url(name, version), opener, deadline)
    urls = doc.get("urls")
    if not isinstance(urls, list):
        raise FetchError("fetch: registry urls is not a list")
    entry = pick_pypi_file(urls)
    if entry is None:
        raise FetchError("fetch: no sdist or wheel for this version")
    url, filename = entry.get("url"), entry.get("filename")
    if not isinstance(url, str) or not isinstance(filename, str):
        raise FetchError("fetch: registry file entry malformed")
    digests = entry.get("digests")
    published = digests.get("sha256") if isinstance(digests, dict) else None
    sha = _hex_digest(published, "sha256")
    _check_url(url)
    return Artifact(url, filename, "sha256", sha)


def parse_integrity(integrity: str) -> str | None:
    """Hex sha512 from an SRI string (several space-separated entries allowed).

    None if there is no sha512 entry. A sha512 entry that does not decode to
    64 bytes is an error, not a reason to fall back to a weaker hash.
    """
    for token in integrity.split():
        alg, sep, rest = token.partition("-")
        if not sep or alg.lower() != "sha512":
            continue
        b64 = rest.split("?", 1)[0]
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FetchError("fetch: registry integrity malformed") from exc
        if len(raw) != 64:
            raise FetchError("fetch: registry integrity malformed")
        return raw.hex()
    return None


def _resolve_npm(name: str, version: str, opener, deadline) -> Artifact:
    doc = get_json(npm_url(name, version), opener, deadline)
    dist = doc.get("dist")
    if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
        raise FetchError("fetch: registry dist.tarball missing")
    url = dist["tarball"]
    _check_url(url)
    filename = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    integrity = dist.get("integrity")
    sha512 = parse_integrity(integrity) if isinstance(integrity, str) else None
    if sha512 is not None:
        return Artifact(url, filename, "sha512", sha512)
    return Artifact(url, filename, "sha1", _hex_digest(dist.get("shasum"), "sha1"))


def resolve(
    name: str,
    version: str,
    ecosystem: str,
    opener: Opener | None = None,
    deadline: float | None = None,
) -> Artifact:
    """The one archive Eslabon scans for ``name==version`` (design.md section 4)."""
    _check_spec(name, version, ecosystem)
    deadline = new_deadline() if deadline is None else deadline
    if ecosystem == "npm":
        return _resolve_npm(name, version, opener, deadline)
    return _resolve_pypi(name, version, opener, deadline)


# ----------------------------------------------------------- download ----


def safe_filename(raw: str) -> str:
    """A local file name for a registry-supplied one: the last path component
    only, ASCII letters/digits/``._+-`` (anything else becomes ``_``), no
    leading dots, no Windows device name, at most MAX_FILENAME characters, and
    the archive suffix (.tar.gz/.tgz/.whl/.zip/.tar.bz2) kept so it still
    decides the archive kind."""
    base = re.split(r"[/\\]", raw)[-1]
    clean = _UNSAFE_CHAR.sub("_", base)
    cut = next((len(s) for s in _SUFFIXES if clean.lower().endswith(s)), 0)
    stem, suffix = clean[: len(clean) - cut].strip("."), clean[len(clean) - cut :]
    stem = stem[: MAX_FILENAME - len(suffix)]
    if not stem:
        stem = "artifact"
    elif stem.split(".", 1)[0].upper() in _WIN_RESERVED:
        stem = "_" + stem[: MAX_FILENAME - len(suffix) - 1]
    return stem + suffix


def hash_anomalies(a: Artifact) -> list[Anomaly]:
    if a.hash_alg == "sha1":
        detail = "registry publishes only a sha1 shasum for this version"
        return [Anomaly(WEAK_SHA1, "", detail)]
    return []


def download(
    a: Artifact,
    dest: Path,
    limits: Limits,
    opener: Opener | None = None,
    deadline: float | None = None,
) -> tuple[Path, list[Anomaly]]:
    """Stream ``a`` into the directory ``dest`` and verify its hash.

    Writes exactly one new file, ``dest / safe_filename(a.filename)`` (opened
    with "xb": never an existing file); it is removed again on any failure.
    Raises LimitsExceeded above ``limits.max_download`` bytes (counted as they
    arrive), HashMismatch (with the received SHA-256), or FetchError.
    """
    if a.hash_alg not in _HEX:
        raise FetchError("fetch: unknown hash algorithm")
    expected = _hex_digest(a.hash_value, a.hash_alg)
    deadline = new_deadline() if deadline is None else deadline
    path = dest / safe_filename(a.filename)
    if path.parent != dest:  # cannot happen after safe_filename; belt and braces
        raise FetchError("fetch: bad artifact file name")
    sha256 = hashlib.sha256()
    verify = sha256 if a.hash_alg == "sha256" else hashlib.new(a.hash_alg)

    def too_big() -> Exception:
        return LimitsExceeded(f"download larger than {limits.max_download}")

    created = False
    try:
        with _open(a.url, "application/octet-stream", opener, deadline) as resp:
            try:
                fh = open(path, "xb")  # noqa: SIM115
            except OSError as exc:
                raise FetchError(f"fetch: cannot write: {type(exc).__name__}") from exc
            created = True
            with fh:
                for chunk in _chunks(resp, limits.max_download, deadline, too_big):
                    sha256.update(chunk)
                    if verify is not sha256:
                        verify.update(chunk)
                    try:
                        fh.write(chunk)
                    except OSError as exc:
                        msg = f"fetch: cannot write: {type(exc).__name__}"
                        raise FetchError(msg) from exc
        if not hmac.compare_digest(verify.hexdigest(), expected):
            raise HashMismatch(
                f"downloaded {a.hash_alg} does not match the registry",
                sha256.hexdigest(),
            )
    except BaseException:
        if created:  # never touch a file this call did not create
            path.unlink(missing_ok=True)
        raise
    return path, hash_anomalies(a)
