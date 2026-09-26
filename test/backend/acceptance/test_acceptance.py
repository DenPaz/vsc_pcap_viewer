"""Collect every scenario in ``features/`` (step definitions live in conftest.py)."""

from pytest_bdd import scenarios

scenarios(".")
