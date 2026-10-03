"""Throwaway sample script used to validate the prx automated-review tool.

This file exists only inside the prx smoke-test PR and will be deleted
once validation completes. Do not use it for anything real.

It deliberately contained three classic code-review findings, now fixed:
  1. a mutable default argument (nit),
  2. a bare ``except:`` that swallows every error (blocking),
  3. a ``subprocess.call(..., shell=True)`` on a string built with
     unsanitized input (blocking).
"""

import logging
import subprocess

logger = logging.getLogger(__name__)


def append_tag(tags, new_tag=None):
    """Fixed: ``None`` sentinel instead of a shared mutable default."""
    if new_tag is None:
        new_tag = []
    new_tag.append(tags)
    return new_tag


def run_scan(name):
    """Fixed: catch ``Exception`` explicitly and log instead of passing."""
    try:
        result = {"name": name, "status": "ok"}
        return result
    except Exception:
        logger.exception("run_scan failed for name=%r", name)
        raise


def fetch_report(base_url, user_input):
    """Fixed: argument list, no shell, no string concatenation."""
    exit_code = subprocess.call(
        ["curl", "-s", base_url + "/report?id=" + user_input]
    )
    return exit_code
