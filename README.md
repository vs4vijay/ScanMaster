# ScanMaster

ScanMaster is a Python 3.14 orchestrator for authorized vulnerability scanning with OWASP ZAP, Nuclei, Greenbone, and optional Rapid7 InsightVM. It persists runs in SQLite, keeps redacted raw artifacts on disk, tracks finding lifecycle, and emits terminal, normalized JSON, and SARIF 2.1.0 reports.

> Use ScanMaster only on systems you own or have explicit written permission to test. Active, intrusive, authenticated, and infrastructure scans can disrupt services. ScanMaster requires both an opt-in mode and `--confirm-authorized` before those workflows begin.

## Install and verify

Install `uv`, then let the lockfile provision Python and every dependency:

```console
uv sync --locked
uv run scanmaster --version
uv run scanmaster scanners
uv run scanmaster doctor
```

Never use `pip` or a hand-built requirements file for this project. Development gates are:

```console
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest -q
uv build
```

## Configuration

Copy `.env.example` to `.env` and enable only the scanners you intend to use. Process and CI environment variables override `.env`. Secrets belong in the environment or your secret manager, never in `scanmaster.yaml`, generated ZAP plans, or source control. TLS verification defaults to enabled; `doctor` prominently warns about an explicit scanner override.

Deployment settings use `SCANMASTER_*` variables. Operational policy belongs in optional `scanmaster.yaml`:

```yaml
include_targets: ["https://staging.example.test/*"]
exclude_targets: ["https://staging.example.test/logout"]
scanner_profiles: {nuclei: safe}
rate_limits: {nuclei: 25}
timeouts: {nuclei: 10}
fail_on: high
suppressions:
  - fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    reason: Accepted until vendor upgrade
    owner: security@example.test
    expires: 2026-12-31T00:00:00Z
```

## Scanner workflows

Start the pinned local scanner service required by your workflow:

```console
docker compose --profile zap up -d zap
docker compose --profile nuclei run --rm nuclei
docker compose --profile greenbone up -d greenbone
```

The Greenbone profile is for evaluation and familiarization, not a production Greenbone deployment. Rapid7 requires an existing licensed InsightVM console.

Passive scans always require explicit scanner selection:

```console
uv run scanmaster scan https://app.example.test --scanner zap
uv run scanmaster scan https://app.example.test --scanner zap --scanner nuclei
```

Active/API/authenticated ZAP examples:

```console
uv run scanmaster scan https://app.example.test --scanner zap --active --confirm-authorized --spider both
uv run scanmaster scan https://api.example.test --scanner zap --active --confirm-authorized --api-spec ./openapi.json
uv run scanmaster scan https://app.example.test --scanner zap --active --confirm-authorized --authentication json --authentication-secret-env ZAP_AUTH_SECRET
```

Infrastructure scanners accept a hostname, IP, or CIDR explicitly; a URL is never silently converted:

```console
uv run scanmaster scan 192.0.2.0/24 --scanner greenbone --active --confirm-authorized --detach
uv run scanmaster status RUN_ID
uv run scanmaster cancel RUN_ID
```

## Reports and recurring scans

```console
uv run scanmaster report RUN_ID --format terminal
uv run scanmaster report RUN_ID --format json --fail-on high
uv run scanmaster report RUN_ID --format sarif
uv run scanmaster report RUN_ID --baseline PREVIOUS_RUN_ID --new-only --fail-on-new
```

Exit code `0` means success, `1` means a finding policy threshold was violated, and `2` means configuration or execution failed. Cached CISA KEV JSON and FIRST EPSS CSV can be supplied with `--kev-cache` and `--epss-cache`; missing or stale enrichment never fails a scan.

## Container deployment

The application image is multi-stage, digest-pinned, read-only, and runs as UID/GID 10001 with persistent `/data` storage:

```console
docker compose --profile scanmaster build scanmaster
docker compose --profile scanmaster run --rm scanmaster --version
docker compose --profile scanmaster run --rm scanmaster report RUN_ID --format json
```

Compose profiles isolate ZAP, Nuclei, and evaluation Greenbone dependencies. SQLite and artifacts persist in `scanmaster-data`; ZAP plans use the configured bind mount.

## Troubleshooting

- Run `scanmaster doctor` first. Exit `2` identifies invalid settings or unavailable prerequisites.
- Confirm scanner URLs, credentials, socket mounts, and container health with `docker compose ps`.
- Keep the ZAP host and container plan directories aligned.
- A detached request is rejected unless every selected adapter exposes a durable external job identifier.
- Authentication loss, scanner timeouts, malformed vendor payloads, and partial backend failures are persisted as failed runs without erasing successful sibling results.
- Do not disable TLS verification except for a controlled local fixture; the warning is intentional.
