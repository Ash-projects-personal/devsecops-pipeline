"""
Deterministic pattern-based security scanners for the DevSecOps pipeline.

The ``security_scanner.py`` demo is randomised for the README run. This module
is the real, deterministic surface that CI actually uses — small enough to
reproduce Bandit/Trivy/Gitleaks behaviour on golden-file fixtures without
requiring those binaries to be installed. Every scanner reads a file (or
directory of files) and returns a list of dict findings.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    file: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# SAST (Bandit-shaped)
# ---------------------------------------------------------------------------

SAST_RULES = [
    # rule_id, severity, regex, message
    ("B105", "MEDIUM", re.compile(r"""(password|passwd|pwd|secret)\s*=\s*["'][^"']{4,}["']""", re.IGNORECASE),
     "Hardcoded password/secret string"),
    ("B201", "HIGH", re.compile(r"""\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE),
     "Flask app running with debug=True (RCE risk)"),
    ("B301", "MEDIUM", re.compile(r"""\bpickle\.loads?\s*\("""),
     "Deserialization of untrusted data via pickle"),
    ("B501", "HIGH", re.compile(r"""verify\s*=\s*False"""),
     "TLS certificate verification disabled"),
    ("B602", "HIGH", re.compile(r"""subprocess\.(Popen|call|run|check_output)\([^)]*shell\s*=\s*True"""),
     "subprocess with shell=True (command injection risk)"),
    ("B608", "MEDIUM", re.compile(r"""(execute|executemany)\s*\(\s*f?["'][^"']*%s|(execute|executemany)\s*\(\s*["'][^"']*["']\s*\+"""),
     "SQL query built via string interpolation"),
    ("B307", "HIGH", re.compile(r"""\beval\s*\("""),
     "Use of eval() — arbitrary code execution risk"),
]


def scan_sast(path):
    """Walk ``path`` and yield SAST Findings from every ``.py`` file."""
    findings = []
    root = Path(path)
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, sev, pattern, msg in SAST_RULES:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=sev,
                            file=str(file),
                            line=lineno,
                            message=msg,
                            snippet=line.strip()[:120],
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# SCA (Trivy-shaped)
# ---------------------------------------------------------------------------

# Minimal in-repo KEV/CVE table. In prod this is refreshed from the NVD API;
# here it's static so the tests are reproducible.
KNOWN_VULN_PACKAGES = {
    # package: [(vulnerable_max_version, cve, severity, fixed_version)]
    "requests": [("2.30.0", "CVE-2023-32681", "HIGH", "2.31.0")],
    "pillow": [("10.0.1", "CVE-2023-44271", "HIGH", "10.0.2")],
    "cryptography": [("41.0.6", "CVE-2023-49083", "MEDIUM", "41.0.7")],
    "urllib3": [("1.26.17", "CVE-2023-45803", "MEDIUM", "1.26.18")],
    "setuptools": [("65.5.0", "CVE-2022-40897", "HIGH", "65.5.1")],
    "django": [("4.2.6", "CVE-2023-46695", "HIGH", "4.2.7")],
}


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9_.\-]*)")


def _semver_tuple(v):
    parts = []
    for chunk in v.split("."):
        try:
            parts.append(int(re.sub(r"[^0-9].*", "", chunk) or "0"))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def scan_sca(requirements_file):
    """Parse a requirements.txt and flag pinned packages with known CVEs."""
    findings = []
    text = Path(requirements_file).read_text(encoding="utf-8", errors="ignore")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        pkg, ver = m.group(1).lower(), m.group(2)
        entries = KNOWN_VULN_PACKAGES.get(pkg, [])
        for max_vuln, cve, sev, fixed in entries:
            if _semver_tuple(ver) <= _semver_tuple(max_vuln):
                findings.append(
                    Finding(
                        rule_id=cve,
                        severity=sev,
                        file=str(requirements_file),
                        line=lineno,
                        message=f"{pkg} {ver} is vulnerable to {cve}; upgrade to {fixed}",
                        snippet=line.strip(),
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Secrets (Gitleaks-shaped)
# ---------------------------------------------------------------------------

SECRET_RULES = [
    ("aws-access-key",   "HIGH",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token-classic", "HIGH", re.compile(r"gh[pousr]_[0-9A-Za-z]{36}")),
    ("stripe-live-key",  "CRITICAL", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("slack-webhook",    "MEDIUM",   re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{20,}")),
    ("private-key-block","HIGH",     re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
]


def scan_secrets(path):
    """Scan a file (or directory tree) for known secret formats."""
    findings = []
    root = Path(path)
    files = [root] if root.is_file() else [
        p for p in root.rglob("*")
        if p.is_file() and p.suffix not in {".pyc", ".png", ".jpg", ".gif"}
    ]
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, sev, pattern in SECRET_RULES:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=sev,
                            file=str(file),
                            line=lineno,
                            message=f"Potential {rule_id} committed",
                            snippet="<redacted>",
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# Pipeline gate
# ---------------------------------------------------------------------------

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def evaluate_gate(sast, sca, secrets):
    """Return (passed, blocking_reasons)."""
    reasons = []
    if any(f.severity in BLOCKING_SEVERITIES for f in sast):
        reasons.append(f"{sum(1 for f in sast if f.severity in BLOCKING_SEVERITIES)} HIGH/CRITICAL SAST findings")
    if any(f.severity in BLOCKING_SEVERITIES for f in sca):
        reasons.append(f"{sum(1 for f in sca if f.severity in BLOCKING_SEVERITIES)} HIGH/CRITICAL SCA findings")
    if secrets:  # any leaked secret is blocking
        reasons.append(f"{len(secrets)} secret(s) detected")
    return (not reasons), reasons
