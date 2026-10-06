"""Shared fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def workdir(tmp_path, monkeypatch, request):
    """cwd = tmp_path; afterwards only the module's ARCHIVE file may exist there."""
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    assert sorted(os.listdir(tmp_path)) == [request.module.ARCHIVE]


@pytest.fixture(autouse=True)
def _empty_top_lists(monkeypatch):
    """ESL-005 sees empty top lists unless a test installs its own.

    No test depends on the bundled data by accident; tests that want it call
    typosquat.load_top_list() explicitly.
    """
    from eslabon import typosquat

    monkeypatch.setattr(
        typosquat,
        "_OVERRIDE",
        {e: typosquat.TopList.from_names([], e) for e in ("pypi", "npm")},
    )


@pytest.fixture(autouse=True)
def _no_osv_network(monkeypatch):
    """The real OSV opener is replaced by one that raises: no test reaches the
    network by accident (a scan then reports osv_unavailable, exit 2). Tests that
    want OSV answers install a recorded opener; the ``network`` test passes the
    real one explicitly."""
    from eslabon import osv

    def _blocked(url, data, timeout):
        raise AssertionError("network access to OSV is disabled in tests")

    monkeypatch.setattr(osv, "DEFAULT_OPENER", _blocked)


@pytest.fixture(autouse=True)
def _no_registry_network(monkeypatch):
    """The same for the registry fetch (name==version): the real opener is
    replaced by one that raises; tests install fake registries, and the
    ``network`` tests pass the real opener explicitly."""
    from eslabon import fetch

    def _blocked(req, timeout):
        raise AssertionError("network access to the registries is disabled in tests")

    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _blocked)


@pytest.fixture
def osv_clean(monkeypatch):
    """OSV answers every query with no advisories (a recorded empty ``{}``).

    For end-to-end CLI tests about other rules: the OSV path still runs, offline,
    and reports osv_status "ok". Returns the list of request URLs it served.
    """
    from eslabon import osv

    calls: list[str] = []

    def _empty(url, data, timeout):
        calls.append(url)
        return osv.API_URL, b"{}"

    monkeypatch.setattr(osv, "DEFAULT_OPENER", _empty)
    return calls
