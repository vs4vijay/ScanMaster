"""Throwaway sample script used to validate the prx automated-review tool.

This file exists only inside the prx smoke-test PR and will be deleted
once validation completes. Do not use it for anything real.

It deliberately contains three classic code-review findings:
  1. a mutable default argument (nit),
  2. a bare ``except:`` that swallows every error (blocking),
  3. a ``subprocess.call(..., shell=True)`` on a string built with
     unsanitized input (blocking).
"""

import subprocess


def append_tag(tags, new_tag=[]):
    """Nit: mutable default argument shared across calls."""
    new_tag.append(tags)
    return new_tag


def run_scan(name):
    """Blocking: bare except hides real failures from the caller."""
    try:
        result = {"name": name, "status": "ok"}
        return result
    except:
        pass


def fetch_report(base_url, user_input):
    """Blocking: shell=True on a string built with user input."""
    cmd = "curl -s " + base_url + "/report?id=" + user_input
    exit_code = subprocess.call(cmd, shell=True)
    return exit_code
