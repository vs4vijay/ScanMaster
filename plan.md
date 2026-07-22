# ScanMaster v2 Modernization

## Summary

Rebuild ScanMaster as a Python 3.14 security-scanning orchestrator for authorized live targets. The first release will provide a CLI and CI workflow for explicitly selected ZAP, Nuclei, Greenbone, and optional Rapid7 InsightVM scanners, normalize their findings, track changes between runs, and produce terminal, JSON, and SARIF reports.

Implementation is divided into vertical slices. Every phase must leave the application runnable and tested through a real user workflow rather than delivering an isolated architectural layer.

## Non-negotiable engineering rules

- Use `uv` exclusively for Python environments, commands, builds, and dependency management:
  - Initialize metadata with `uv init` and commit the cross-platform `uv.lock`.
  - Add runtime dependencies only with `uv add <name>` and development dependencies only with `uv add --dev <name>`.
  - Never manually add, remove, or change dependency declarations in `pyproject.toml`.
  - Replace `requirements.txt`, `setup.sh`, and direct `python`/`pip` instructions with their `uv` equivalents.
- Load `.env` with `python-dotenv` and `override=False`, so process and CI variables take precedence. Keep `.env` gitignored.
- Provide a complete `.env.example` that documents every supported environment variable, whether it is required, its default, safe example values, and its allowed values or format. Never include real credentials.
- Create one immutable, typed application settings object using Pydantic Settings. It must load environment values once at the composition root, validate cross-field requirements, fail fast with actionable errors, and use secret types/redaction so credentials cannot appear in logs or exceptions.
- Keep TLS verification enabled by default. An explicit per-adapter opt-out may be supported but must produce a prominent warning.
- Pin container images and GitHub Actions immutably; update them through Dependabot.

## Modular architecture

- Use an installable `src/scanmaster` package with dependency flow pointing inward:
  - **Domain:** scanner-independent entities and value objects for targets, runs, jobs, findings, occurrences, artifacts, severities, lifecycle states, and fingerprints. This layer imports no CLI, UI, database, HTTP, or vendor packages.
  - **Application:** UI-independent use cases such as list scanners, diagnose, start scan, get status, cancel run, compare runs, and render/export report data. Use cases accept typed request objects and return typed result objects; they never print, prompt, call Typer/Rich, or read environment variables.
  - **Ports:** protocols for scanner adapters, run/finding repositories, artifact storage, clock/ID generation, event/progress sinks, and report serializers.
  - **Adapters:** ZAP, Nuclei, Greenbone, Rapid7, SQLite, filesystem artifacts, terminal/JSON/SARIF presenters, and configuration loaders.
  - **Entrypoints:** a thin Typer CLI composition root that creates settings and adapters, invokes application use cases, and maps results to presentation and exit codes.
- Use constructor injection and explicit factories/registries; do not use global settings, database sessions, scanner clients, or Rich consoles.
- Publish progress as typed events through an application port. The CLI converts them to Rich output; a future TUI, web API, WebSocket/SSE stream, or background worker can subscribe without changing scanner or use-case code.
- Keep presenters separate from use cases. Future TUI and web entrypoints must be able to reuse the same application requests/results and serializers without importing CLI modules.
- Keep database transactions and vendor payloads at adapter boundaries. Domain/application types must not expose SQLAlchemy models, HTTPX responses, XML elements, Typer objects, or vendor SDK objects.
- Define `ScannerCapabilities` for supported target kinds, scan modes, authentication, cancellation, durable detach, and prerequisites. Validate the complete request before any scanner is submitted.

## Vertical delivery phases

### Phase 1 — Runnable foundation and diagnostics ✅ COMPLETE

Deliver an installable `scanmaster` command with validated configuration and a complete diagnostic path.

- Initialize the Python 3.14 project with `uv`; add Typer, Rich, Pydantic/Pydantic Settings, `python-dotenv`, Ruff, pytest/coverage, and the chosen static type checker using `uv add` commands only.
- Implement the architecture boundaries, settings composition root, structured redacted logging, and typed application errors.
- Add `scanmaster --version`, `scanmaster scanners`, and `scanmaster doctor` using a registry with initially stubbed health adapters.
- Add `.env.example` entries for database/artifact paths, log level, polling and execution timeouts, retention, and TLS defaults, plus namespaced ZAP, Nuclei, Greenbone, and Rapid7 settings.
- Exit `0` on success and `2` for invalid configuration or failed diagnostics. Test process-environment-over-dotenv precedence, missing/invalid values, cross-field validation, and secret redaction.

Completion record (2026-07-23): initialized the Python 3.14 `uv` package and lockfile; added domain/application/ports/adapters/entrypoint boundaries, immutable validated settings, redacted logging, typed errors/events/capabilities, scanner registry health stubs, and the version/scanners/doctor CLI workflow. Replaced legacy dependency/bootstrap instructions with locked `uv` commands. Verification passed with Ruff formatting/lint, strict mypy, package build, and 14 unit/process-level E2E tests at 99% measured coverage. Phase 2 has not been started.

### Phase 2 — End-to-end passive ZAP scan

Deliver the first complete workflow: submit a safe web scan, persist it, and view its result from another process.

- Add SQLite persistence with SQLAlchemy/Alembic for runs, scanner jobs, normalized findings, source occurrences, and artifact metadata; store raw payloads in a filesystem artifact store.
- Implement typed targets and canonical scope for URL, hostname, IP address, CIDR, and API specification. ZAP initially accepts URL targets only.
- Run a pinned ZAP stable container and drive it through the ZAP Automation Framework plan API, retaining the maintained `zaproxy` client only where needed for supported API calls. Track the plan and component job identifiers required for progress and cancellation.
- Implement `scanmaster scan TARGET --scanner zap`, `status RUN_ID`, `cancel RUN_ID`, and `report RUN_ID --format terminal|json`.
- Default ZAP to passive/baseline scanning. Persist state transitions and raw redacted scanner responses, recover status from a fresh CLI process, and isolate adapter failures from stored run data.
- Integration-test against a disposable local HTTP fixture; never scan public targets in CI.

### Phase 3 — Nuclei and capability-aware orchestration

Deliver concurrent multi-scanner scans with a lightweight, reproducible template scanner.

- Add Nuclei as a pinned container adapter. Parse JSONL, retain redacted raw JSONL, and normalize template IDs, references, evidence, CVE/CWE, CVSS, severity, and matched locations.
- Pin the Nuclei engine and template release/digest and disable implicit template updates during scans. Accept signed official templates by default; unsigned/custom, code, fuzzing, intrusive, and denial-of-service templates require explicit policy.
- Provide `safe`, `standard`, and `intrusive` Nuclei profiles with configurable rate limit, concurrency, timeout, and identification headers. The intrusive profile requires authorization confirmation.
- Validate scanner capabilities and target compatibility before submission, then run compatible selected scanners concurrently while preserving partial results if another adapter fails.
- Require at least one `--scanner`; never select every configured backend implicitly. Reject `--detach` if any selected adapter cannot continue durably without the CLI, rather than starting a fragile background subprocess.
- Test mixed success/failure, malformed JSONL, timeouts, cancellation, template-policy rejection, rate settings, and no-partial-submission preflight behavior.

### Phase 4 — Active, authenticated, and API web scanning

Deliver opt-in active scans for modern authenticated web applications and APIs.

- Require both `--active` and `--confirm-authorized` before any active or intrusive scan. Validate authorization before contacting a scanner.
- Add policy-driven ZAP traditional spider, AJAX/client spider, OpenAPI, GraphQL, passive, and active jobs through Automation Framework plans.
- Support ZAP manual/header, HTTP/NTLM, form, JSON, auto-detect, browser, client-script, and scripted authentication without writing secrets into generated plans or artifacts.
- Add `--api-spec PATH_OR_URL`; enforce canonical include/exclude scope when importing API servers, following redirects, crawling, or discovering links.
- Verify authenticated state using ZAP authentication statistics and fail clearly if a requested authenticated scan becomes anonymous.
- Test active-authorization gates, authentication success/loss, AJAX crawling, OpenAPI server overrides, redirects, DNS changes, and out-of-scope discovery against local fixtures.

### Phase 5 — Infrastructure scanners

Deliver infrastructure vulnerability scanning through open-source Greenbone and optional licensed Rapid7.

- Add Greenbone with current `python-gvm` APIs and context-managed Unix-socket/TLS connections. Discover or configure current scanner, scan-config, and report-format IDs; query task state directly and support cancellation.
- Add an optional Greenbone Compose profile using current Community containers and document that it is intended for evaluation/familiarization rather than production deployment.
- Add an optional Rapid7 InsightVM adapter against REST API v3 using HTTPX and typed boundary models. Health-check credentials and API compatibility before creating or selecting sites and starting scans; never disable TLS or construct authorization headers manually.
- Map hostname, IP, and CIDR targets explicitly. Do not silently convert an incompatible URL into infrastructure scope.
- Support durable `--detach` only for adapters that return externally recoverable job identifiers; status, cancellation, and reporting must work from a new CLI process.
- Add sanitized adapter contract fixtures for authentication failures, timeouts, malformed payloads, empty successful scans, cancellation, and partial backend failure. Keep live Greenbone/Rapid7 tests opt-in.

### Phase 6 — Normalization, deduplication, and reports

Deliver deterministic consolidated reports suitable for humans and CI.

- Publish a versioned normalized JSON schema containing run/target, title, scanner-native ID, severity, CVSS score/vector when supplied, CVE/CWE identifiers, affected locations, description, remediation, redacted evidence, scanner sources, confidence, and timestamps.
- Preserve unknown severity and missing fields rather than inventing values. Deduplicate with a versioned fingerprint based on canonical target/location, vulnerability identifiers, and normalized title; merge scanner sources and occurrences without discarding their native data.
- Add deterministic terminal, JSON, and SARIF 2.1.0 presenters. Emit separate SARIF runs/categories per scanner with stable rule IDs and fingerprints, and validate GitHub limits before upload.
- Add `--fail-on low|medium|high|critical|never`; exit `1` only for a finding threshold violation, `2` for configuration/execution failure, and `0` otherwise.
- Add a GitHub Actions example using `uv sync --locked`, a passive/local test target, artifact upload, and optional SARIF upload where GitHub Code Security is available.

### Phase 7 — Finding lifecycle and prioritization

Deliver useful recurring-scan behavior instead of repeatedly presenting the same undifferentiated findings.

- Compare compatible runs and classify findings as `new`, `recurring`, or `resolved`; add `--baseline RUN_ID`, `--new-only`, and `--fail-on-new`.
- Add `scanmaster.yaml` policy-as-code for target scopes, scanner profiles, exclusions, rate limits, timeouts, report thresholds, and suppressions. Environment variables remain reserved for deployment configuration and secrets.
- Support suppression by stable fingerprint with required reason, owner, and expiry. Preserve suppression metadata in JSON/SARIF and make expired suppressions visible.
- Optionally enrich CVE findings from locally cached CISA KEV and FIRST EPSS data. Keep original scanner severity immutable and store enrichment source/version/time separately; unavailable enrichment must not fail a scan.
- Redact credentials, tokens, cookies, and authorization headers before persistence. Enforce configured artifact retention, file-count/size limits, and safe deletion boundaries.
- Test baselines, incompatible comparisons, resolved findings, expiring suppressions, `--fail-on-new`, offline/stale enrichment, deterministic re-runs, and sensitive-data redaction.

### Phase 8 — Packaging, hardening, and extension proof

Deliver a reproducible release and prove that the core is not coupled to the CLI.

- Add a multi-stage non-root application image and Compose profiles for ScanMaster, ZAP, Nuclei, and optional Greenbone, with persistent volumes for SQLite and artifacts.
- Add CI for `uv sync --locked`, lint, formatting check, static typing, unit/contract/integration tests, package build, dependency audit, image scan, and SBOM generation.
- Replace stale Renovate/Sweep configuration with Dependabot for Python, Docker, and GitHub Actions.
- Add a minimal non-CLI test adapter that invokes application use cases and consumes progress events without importing Typer or Rich. This is the acceptance proof for future TUI/web integration; it is not a shipped UI.
- Rewrite the README around authorized-use warnings, `uv` workflows, Compose profiles, `.env` and policy configuration, scanner prerequisites, command examples, report formats, and troubleshooting.
- Test Compose health checks, non-root execution, persistent state, graceful shutdown, locked/offline reproducibility, and a complete passive ZAP plus Nuclei smoke scan.

## Deferred scope

- Defer Trivy until ScanMaster intentionally supports repositories, filesystems, container images, SBOMs, secrets, and infrastructure-as-code. Those targets require a broader domain model than live-target findings.
- Defer Nmap as a scanner adapter. If added, model discovered assets, ports, services, and NSE observations separately rather than treating every observation as a vulnerability.
- Defer Tenable/Nessus until a later commercial-adapter milestone because it substantially overlaps Rapid7 and introduces another licensed API lifecycle.
- Do not add Nikto, Semgrep, or Burp in v2: Nikto overlaps ZAP/Nuclei, Semgrep changes the scope to source analysis, and Burp introduces another commercial DAST integration.
- Do not build a TUI, web dashboard, hosted service, internal scheduler, or background-worker fleet in v2. The ports, typed use cases, progress events, and composition roots must make those additions possible without rewriting the core.

## Acceptance and compatibility assumptions

- Docker Compose is the supported local/server deployment path; GitHub Actions is the primary CI example.
- ZAP and Nuclei are the initial open-source web core, Greenbone adds infrastructure coverage, and Rapid7 requires an existing licensed deployment.
- Existing `scans.json` data and exact v1 CLI behavior are intentionally unsupported; no importer or compatibility aliases are required.
- Active scanning never occurs without explicit scanner selection, an active/intrusive profile, and authorization acknowledgement.
- A phase is complete only when its documented command path works end to end, persists/reloads correctly where applicable, and passes its unit, contract, and integration acceptance tests.

## Research references

- [`uv` project documentation](https://docs.astral.sh/uv/guides/projects/)
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [ZAP authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/)
- [Nuclei execution, formats, templates, and rate controls](https://docs.projectdiscovery.io/opensource/nuclei/running)
- [Nuclei safety guidance](https://docs.projectdiscovery.io/opensource/nuclei/faq)
- [`python-gvm` releases](https://pypi.org/project/python-gvm/)
- [Greenbone Community containers](https://greenbone.github.io/docs/latest/22.4/container/)
- [Rapid7 InsightVM API v3](https://help.rapid7.com/insightvm/en-us/api/index.html)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS API](https://api.first.org/epss/)
- [GitHub SARIF upload guidance](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github)
- [GitHub SARIF limits](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/results-exceed-limit)
- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
