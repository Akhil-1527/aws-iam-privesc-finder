"""Pytest configuration: make ``src`` importable as a top-level package.

Tests import via ``from src.analyzer import ...`` so the project root needs
to be on sys.path. We also expose helpers for loading mock policy JSON.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


MOCK_DIR = Path(__file__).resolve().parent / "mock_policies"


def load_mock_policy(name: str) -> dict:
    """Load a mock policy JSON by filename (with or without ``.json``)."""
    filename = name if name.endswith(".json") else f"{name}.json"
    return json.loads((MOCK_DIR / filename).read_text(encoding="utf-8"))


@pytest.fixture
def mock_policy():
    """Pytest fixture exposing ``load_mock_policy``."""
    return load_mock_policy


@pytest.fixture
def make_policy_set():
    """Build a PrincipalPolicySet from one or more raw policy documents."""
    from src.enumerator import build_policy_set_from_documents

    def _factory(*docs: dict, principal_arn: str = "arn:aws:iam::123456789012:user/test"):
        return build_policy_set_from_documents(
            principal_arn=principal_arn,
            principal_type="user",
            documents=list(docs),
        )

    return _factory
