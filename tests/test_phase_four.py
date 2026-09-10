import json
from pathlib import Path

import httpx
import pytest

from scanmaster.adapters.zap import ZapAdapter, ZapAuthentication, ZapScanPolicy, ZapSpider
from scanmaster.application.scans import StartScans, StartScansRequest
from scanmaster.domain.targets import Target


def test_active_authorization_is_rejected_before_submission() -> None:
    use_case = StartScans(None, None, {}, 0.01, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="active scans require"):
        use_case.execute(StartScansRequest("https://example.test", ("zap",), active=True))


def test_zap_active_authenticated_api_plan_contains_reference_not_secret(tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = str(request.url.params["filePath"])
        return httpx.Response(200, json={"planId": "plan-4"})

    policy = ZapScanPolicy(
        active=True,
        authorized=True,
        spider=ZapSpider.BOTH,
        api_spec="/zap/wrk/openapi.json",
        graphql_endpoint="https://example.test/graphql",
        authentication=ZapAuthentication.JSON,
        authentication_secret_env="ZAP_AUTH_SECRET",
        include_paths=(r"https://example\.test/.*",),
        exclude_paths=(r"https://example\.test/logout",),
    )
    adapter = ZapAdapter("https://zap.test", None, True, 1, tmp_path, Path("/zap/wrk"), policy)
    adapter._client = httpx.Client(  # type: ignore[attr-defined]
        base_url="https://zap.test", transport=httpx.MockTransport(handler)
    )
    submission = adapter.submit(Target.parse("https://example.test"))

    plan_file = tmp_path / Path(captured["path"]).name
    raw = plan_file.read_text(encoding="utf-8")
    plan = json.loads(raw)
    assert "ZAP_AUTH_SECRET" in raw
    assert "super-secret" not in raw
    assert [job["type"] for job in plan["jobs"]] == [
        "openapi",
        "graphql",
        "spider",
        "spiderAjax",
        "passiveScan-wait",
        "activeScan",
    ]
    assert submission.external_id == "plan-4"


def test_zap_authentication_requires_secret_reference() -> None:
    with pytest.raises(ValueError, match="secret environment"):
        ZapScanPolicy(authentication=ZapAuthentication.FORM).validate()
