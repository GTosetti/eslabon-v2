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
