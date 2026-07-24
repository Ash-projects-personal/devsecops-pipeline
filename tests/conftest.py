"""
Fixture builder for secrets tests.

GitHub push protection (rightly) rejects committed files that look like
real access tokens, so the ``leaked_secrets.env`` fixture is assembled at
test-collection time from concatenated non-secret pieces instead of being
checked in. The scanner still sees a fully-formed pattern to match.
"""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _assemble_leaked_env():
    # Split-and-concat to keep the literal strings out of any grep, secret
    # scanner, or git-history search of this repo.
    aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"           # AWS official example key
    gh = "gh" + "p_" + "a" * 20 + "b" * 16           # matches ghp_ + 36 chars
    stripe = "sk_" + "live_" + "0" * 24              # matches sk_live_ + 24+ chars
    return (
        "# do not commit\n"
        f"AWS_ACCESS_KEY_ID={aws}\n"
        f"GITHUB_TOKEN={gh}\n"
        f"STRIPE_KEY={stripe}\n"
        "NOT_A_SECRET=hello-world\n"
    )


@pytest.fixture(scope="session")
def leaked_secrets_file(tmp_path_factory):
    """Return a Path to a temp file containing planted secret patterns."""
    p = tmp_path_factory.mktemp("secrets") / "leaked_secrets.env"
    p.write_text(_assemble_leaked_env())
    return p
