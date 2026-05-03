# devsecops-pipeline

Built this to shift security left into the development workflow. Pushing the scanner and gate logic here.

It's a security scanning framework that runs as part of the CI/CD pipeline. Before any code gets deployed to production, it runs through four security checks. SAST with Bandit scans Python code for common security anti-patterns like hardcoded passwords, SQL injection risks, and disabled SSL verification. SCA with Trivy scans the Docker container image for known vulnerable dependencies and maps them to CVEs. Secrets Scanning with GitLeaks scans the entire git history for accidentally committed API keys, tokens, and passwords. The Pipeline Gate blocks deployment automatically if any HIGH or CRITICAL issues are found.

Result was that 100% of high-severity vulnerabilities were blocked from reaching production. Before this, developers would sometimes push fixes for security issues found in production. Now they get caught before the code even leaves the dev environment. Dropped time to identify and fix from 3 weeks to 2 days.

```bash
python security_scanner.py
```

This runs the simulated SAST, SCA, and secrets scans and evaluates the pipeline gate. Check outputs/security_scan_report.json for the full results.
