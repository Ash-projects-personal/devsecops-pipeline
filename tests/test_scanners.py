"""
Golden-file tests for the SAST/SCA/secrets scanners.

We feed each scanner a known-vulnerable fixture and assert the exact
rule IDs it must catch, plus a companion clean fixture that must produce
zero findings. Any rule regression here is a test failure.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanners import (
    BLOCKING_SEVERITIES,
    evaluate_gate,
    scan_sast,
    scan_sca,
    scan_secrets,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# SAST
# ---------------------------------------------------------------------------

def test_sast_catches_every_planted_rule():
    findings = scan_sast(FIXTURES / "vuln_app.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {"B105", "B201", "B301", "B501", "B602", "B608", "B307"}
    missing = expected - rule_ids
    assert not missing, f"SAST missed rules: {sorted(missing)}"


def test_sast_reports_line_numbers():
    findings = scan_sast(FIXTURES / "vuln_app.py")
    for f in findings:
        assert f.line > 0
        assert f.file.endswith("vuln_app.py")


def test_sast_flags_high_severity_rules_as_high():
    findings = scan_sast(FIXTURES / "vuln_app.py")
    by_id = {f.rule_id: f for f in findings}
    for rid in ("B201", "B501", "B602", "B307"):
        assert by_id[rid].severity == "HIGH", f"{rid} should be HIGH"


def test_sast_clean_file_has_no_findings():
    findings = scan_sast(FIXTURES / "clean_app.py")
    assert findings == []


def test_sast_walks_directory_tree(tmp_path):
    (tmp_path / "a.py").write_text('password = "leakme-123"\n')
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("requests.get(u, verify=False)\n")
    findings = scan_sast(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "B105" in rule_ids
    assert "B501" in rule_ids


# ---------------------------------------------------------------------------
# SCA
# ---------------------------------------------------------------------------

def test_sca_flags_known_vulnerable_pins():
    findings = scan_sca(FIXTURES / "vuln_requirements.txt")
    rule_ids = {f.rule_id for f in findings}
    # All five vulnerable pins in the fixture must be caught.
    for expected_cve in (
        "CVE-2023-32681",   # requests
        "CVE-2023-44271",   # pillow
        "CVE-2023-49083",   # cryptography
        "CVE-2023-45803",   # urllib3
        "CVE-2023-46695",   # django
    ):
        assert expected_cve in rule_ids, f"missed {expected_cve}"


def test_sca_clean_requirements_has_no_findings():
    findings = scan_sca(FIXTURES / "clean_requirements.txt")
    assert findings == []


def test_sca_ignores_comments_and_blanks(tmp_path):
    req = tmp_path / "r.txt"
    req.write_text(
        "\n# a comment\n\nrequests==2.31.0\n# another\nurllib3==1.26.18\n"
    )
    assert scan_sca(req) == []


def test_sca_message_includes_fix_version():
    findings = scan_sca(FIXTURES / "vuln_requirements.txt")
    requests_finding = next(f for f in findings if f.rule_id == "CVE-2023-32681")
    assert "2.31.0" in requests_finding.message


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def test_secrets_scan_catches_all_planted_kinds(leaked_secrets_file):
    findings = scan_secrets(leaked_secrets_file)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids >= {"aws-access-key", "github-token-classic", "stripe-live-key"}


def test_secrets_scan_redacts_snippet(leaked_secrets_file):
    findings = scan_secrets(leaked_secrets_file)
    assert findings, "expected secrets to be flagged"
    for f in findings:
        assert f.snippet == "<redacted>"


def test_secrets_scan_no_findings_for_clean_file(tmp_path):
    f = tmp_path / "clean.env"
    f.write_text("FOO=bar\nHELLO=world\n")
    assert scan_secrets(f) == []


def test_secrets_scan_finds_slack_webhook(tmp_path):
    f = tmp_path / "notify.py"
    f.write_text(
        'WEBHOOK = "https://hooks.slack.com/services/T01234567/B01234567/abcdefghij1234567890"\n'
    )
    findings = scan_secrets(f)
    assert any(x.rule_id == "slack-webhook" for x in findings)


def test_secrets_scan_finds_pem_block(tmp_path):
    f = tmp_path / "leaked.pem"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n")
    findings = scan_secrets(f)
    assert any(x.rule_id == "private-key-block" for x in findings)


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def test_gate_blocks_when_high_sast_present():
    sast = scan_sast(FIXTURES / "vuln_app.py")
    passed, reasons = evaluate_gate(sast, [], [])
    assert passed is False
    assert any("SAST" in r for r in reasons)


def test_gate_blocks_when_high_sca_present():
    sca = scan_sca(FIXTURES / "vuln_requirements.txt")
    passed, reasons = evaluate_gate([], sca, [])
    assert passed is False
    assert any("SCA" in r for r in reasons)


def test_gate_blocks_on_any_secret(leaked_secrets_file):
    secrets = scan_secrets(leaked_secrets_file)
    passed, reasons = evaluate_gate([], [], secrets)
    assert passed is False
    assert any("secret" in r for r in reasons)


def test_gate_passes_on_all_clean_inputs():
    sast = scan_sast(FIXTURES / "clean_app.py")
    sca = scan_sca(FIXTURES / "clean_requirements.txt")
    passed, reasons = evaluate_gate(sast, sca, [])
    assert passed is True
    assert reasons == []


def test_blocking_severities_matches_docs():
    # Contract check — the README claims HIGH/CRITICAL block the pipeline.
    assert BLOCKING_SEVERITIES == {"HIGH", "CRITICAL"}
