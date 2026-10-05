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
