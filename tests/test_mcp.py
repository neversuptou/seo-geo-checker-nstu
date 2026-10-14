import importlib

import pytest
from fastapi.testclient import TestClient

from app.mcp_server import compact_result, resolve_check_ids

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _fake_result():
    return {
        "url": "https://example.com",
        "overall_score": 60,
        "summary": {"critical": 1, "warning": 1, "ok": 1, "skipped": 1},
        "plan": {"findings": [{"hours": 3}], "total_hours": 3},
        "checks": [
            {"id": "w", "title": "W", "category": "C", "status": "warning",
             "findings": [{"level": "warning", "text": "warn", "fix": "fix w", "hours": 1}]},
            {"id": "c", "title": "C", "category": "C", "status": "critical",
             "findings": [{"level": "critical", "text": "crit", "fix": "fix c", "hours": 2},
                          {"level": "info", "text": "tip", "fix": "", "hours": 0}]},
            {"id": "o", "title": "O", "category": "C", "status": "ok",
             "findings": [{"level": "ok", "text": "fine", "fix": "", "hours": 0}]},
            {"id": "s", "title": "S", "category": "C", "status": "skipped",
             "findings": [{"level": "info", "text": "no key", "fix": "", "hours": 0}]},
        ],
    }


def test_compact_result_sorts_by_priority_and_hides_hours():
    out = compact_result(_fake_result(), 7, base="https://x.test")
    assert [p["priority"] for p in out["problems"]] == ["critical", "warning", "info"]
    assert out["passed"] == ["O"]
    assert out["skipped"] == [{"check": "S", "reason": "no key"}]
    assert out["links"]["pdf"] == "https://x.test/api/audits/7/report.pdf"
    assert "hours" not in repr(out) and "plan" not in out


def test_resolve_check_ids_by_category():
    ids = resolve_check_ids(["http_status"], ["geo / ai"])
    assert ids[0] == "http_status"
    assert "llms_txt" in ids
    assert len(ids) == len(set(ids))
    assert resolve_check_ids(None, None) == []


@pytest.fixture(scope="module")
def mcp_client():
    # Менеджер сессий MCP запускается один раз на процесс — один клиент на модуль
    mp = pytest.MonkeyPatch()
    mp.setenv("MCP_TOKEN", "secret-token")
    import app.main as main

    main = importlib.reload(main)
    with TestClient(main.app) as client:
        yield client
    mp.undo()
    importlib.reload(main)


def _rpc(client, path, method, params=None, id_=1):
    body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
    return client.post(path, json=body, headers=MCP_HEADERS)


def test_mcp_lists_tools(mcp_client):
    init = _rpc(mcp_client, "/mcp/secret-token/", "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    })
    assert init.status_code == 200, init.text
    tools = _rpc(mcp_client, "/mcp/secret-token/", "tools/list", id_=2)
    assert tools.status_code == 200, tools.text
    names = {t["name"] for t in tools.json()["result"]["tools"]}
    assert {"run_audit", "get_report", "list_checks", "get_audit", "list_audits", "compare_sites"} <= names


def test_mcp_wrong_token_is_404(mcp_client):
    resp = _rpc(mcp_client, "/mcp/wrong/", "tools/list")
    assert resp.status_code == 404
