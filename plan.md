# ScanMaster v2 Modernization

## Summary

Rebuild ScanMaster as a modern Python 3.14 CLI and CI security orchestrator. It will run explicitly selected ZAP and Greenbone scanners, support Rapid7 InsightVM as an optional adapter, normalize their findings, and produce terminal, JSON, and SARIF reports.

Current research supports:

- `uv` with `pyproject.toml` and a committed cross-platform lockfile for reproducible environments. [uv project documentation](https://docs.astral.sh/uv/guides/projects/)
- ZAP 2.17 and its actively maintained `zaproxy` Python client, replacing the inactive `python-owasp-zap-v2.4` package. [ZAP automation guidance](https://www.zaproxy.org/docs/automate/), [`zaproxy` 0.6.0](https://pypi.org/project/zaproxy/)
- `python-gvm` 27.5.0, replacing the repository's 1.0 beta integration. [python-gvm releases](https://pypi.org/project/python-gvm/)
- Rapid7's supported REST API v3/OpenAPI specification instead of the obsolete generated client. [Rapid7 VM API v3](https://help.rapid7.com/insightvm/en-us/api/index.html)

## Implementation Changes

### Project foundation

- Create an installable `src/scanmaster` package with a `scanmaster` console command.
- Use Python 3.14 and `uv` exclusively:
  - Initialize project metadata through `uv init`.
  - Add every runtime dependency with `uv add <name>`.
  - Add testing and quality tools with `uv add --dev <name>`.
  - Never hand-edit dependency declarations in `pyproject.toml`.
  - Commit `uv.lock`; replace `requirements.txt` and `setup.sh`.
- Use current stable releases resolved by `uv`, including Typer, Rich, Pydantic/Pydantic Settings, `python-dotenv`, SQLAlchemy/Alembic, `zaproxy`, `python-gvm`, and HTTPX.
- Add Ruff for linting/formatting, pytest with coverage, and static type checking. Current baselines include Typer 0.27, Ruff 0.15, and pytest 9.1.
- Remove obsolete direct dependencies that were only transitive dependencies in the old frozen requirements.

### Configuration and secrets

- Load `.env` automatically with `python-dotenv`, using `override=False` so real process/CI environment variables take precedence.
- Keep `.env` gitignored and provide a complete `.env.example` containing descriptions, safe example values, defaults, and allowed values for:
  - ScanMaster database path, artifact directory, log level, polling interval, and timeouts.
  - ZAP endpoint and API key.
  - Greenbone Unix-socket or TLS connection mode, endpoint, credentials, certificate verification, and CA path.
  - Rapid7 base URL, credentials, certificate verification, and CA path.
- Validate configuration at startup with Pydantic Settings, reject invalid combinations, and redact credentials from logs and exceptions.
- Enable TLS verification by default; disabling it requires an explicit environment setting and emits a warning.

### Core architecture and CLI

- Define a typed asynchronous scanner protocol: `healthcheck`, `submit`, `status`, `findings`, and `cancel`.
- Run selected scanners concurrently while isolating failures so one unavailable backend does not corrupt results from another.
- Replace TinyDB with SQLite through SQLAlchemy and Alembic, storing runs, per-scanner jobs, normalized findings, source occurrences, and artifact metadata.
- Support these commands:
  - `scanmaster scanners` and `scanmaster doctor`
  - `scanmaster scan TARGET --scanner NAME...`
  - `scanmaster status RUN_ID`
  - `scanmaster report RUN_ID --format terminal|json|sarif`
  - `scanmaster cancel RUN_ID`
- Require at least one `--scanner`; never start every configured backend implicitly.
- Default `scan` to waiting with live Rich progress. `--detach` submits jobs, persists external job IDs, and exits without requiring a resident ScanMaster worker.
- Require both `--active` and `--confirm-authorized` for active ZAP, Greenbone, or Rapid7 scans. Without them, only ZAP passive/baseline behavior is allowed.
- Add `--fail-on low|medium|high|critical|never`; use exit code `1` for threshold violations, `2` for configuration/execution failures, and `0` otherwise.
- Treat the old CLI and `scans.json` format as unsupported v1 state; no compatibility aliases or importer.

### Scanner integrations

- ZAP:
  - Run a pinned ZAP stable container through Compose.
  - Use the maintained `zaproxy` client for submission, progress, results, and cancellation.
  - Correctly track spider and active-scan IDs separately.
  - Support passive baseline mode by default and active scanning only after explicit authorization.
- Greenbone:
  - Use current `python-gvm` APIs and context-managed Unix-socket/TLS connections.
  - Query task status directly rather than inferring completion from the presence of findings.
  - Discover or configure current scanner, scan-config, and report-format IDs instead of embedding legacy UUID assumptions.
  - Provide an optional Compose profile based on current Greenbone Community containers; document that Greenbone describes these containers as evaluation/familiarization-oriented rather than a production deployment. [Greenbone container documentation](https://greenbone.github.io/docs/latest/22.4/container/)
- Rapid7:
  - Implement an optional adapter against API v3 using HTTPX and typed request/response models.
  - Remove `rapid7-vm-console`, manual Basic-auth construction, and disabled TLS verification.
  - Health-check credentials and API compatibility before creating sites or scans.
- Store raw scanner responses as artifacts while keeping the normalized model independent of vendor schemas.

### Findings and reporting

- Normalize findings into a versioned JSON schema containing run/target, title, severity, CVSS score/vector when supplied, CVE/CWE identifiers, affected locations, description, remediation, evidence, scanner sources, and timestamps.
- Deduplicate using a stable fingerprint derived from target/location, vulnerability identifiers, and normalized title—not title alone—and merge all contributing scanners and locations.
- Preserve unknown severities and missing fields rather than inventing scores.
- Produce:
  - Rich terminal tables and summaries.
  - Deterministic JSON suitable for downstream automation.
  - SARIF 2.1.0 with stable rule IDs and fingerprints for CI consumers.
- Include a GitHub Actions example that uploads SARIF when GitHub Code Security is available. [GitHub SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github)

### Containers, automation, and documentation

- Add a multi-stage, non-root application image and Compose profiles for ScanMaster, ZAP, and optional Greenbone integration, with persistent volumes for SQLite and artifacts.
- Pin container images and GitHub Actions immutably; update them through Dependabot. GitHub recommends full commit SHAs for immutable Actions references. [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- Replace the stale Renovate/Sweep configuration with Dependabot covering Python, Docker, and GitHub Actions.
- Add CI for `uv sync --locked`, lint, formatting check, type checking, tests, package build, dependency audit, image scan, and SBOM generation.
- Rewrite the README around authorized-use warnings, quick start, Compose profiles, environment setup, command examples, report formats, and scanner-specific prerequisites.

## Test Plan

- Unit-test target validation, configuration precedence/redaction, state transitions, severity mapping, fingerprints, deduplication, report serialization, and exit codes.
- Add adapter contract tests using recorded/sanitized ZAP, Greenbone, and Rapid7 responses, including authentication failures, timeouts, malformed payloads, empty successful scans, cancellation, and partial backend failure.
- Run ZAP integration tests against a local disposable HTTP fixture; never scan public targets from CI.
- Keep Greenbone and Rapid7 CI tests mocked; provide opt-in integration markers for environments with those services.
- Validate detached submission followed by status/report retrieval from a fresh CLI process.
- Validate JSON against its schema and SARIF against SARIF 2.1.0/GitHub limits.
- Test Compose startup, health checks, non-root execution, persistent state, graceful shutdown, and a complete passive ZAP smoke scan.
- Use useful fixtures from the unmerged unit-test branches as references, but do not merge those branches wholesale.

## Assumptions

- v2 prioritizes a CLI and GitHub Actions workflow, not a web dashboard or hosted SaaS.
- Docker Compose is the supported local/server deployment path.
- ZAP and Greenbone form the open-source core; Rapid7 requires an existing licensed InsightVM/Nexpose deployment.
- Active scanning is never performed without explicit scanner selection and authorization acknowledgement.
- Existing `scans.json` data and exact v1 command compatibility are intentionally discarded.
