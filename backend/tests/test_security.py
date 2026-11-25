"""Security regression tests: no user input may reach Nmap as an option."""
import subprocess

import pytest
from fastapi.testclient import TestClient

import main
import scanner_core

FRONTEND = {"Origin": "http://localhost:5173"}


@pytest.fixture
def nmap_calls(monkeypatch):
    """Replace subprocess.run so no real scan is launched, and record the commands."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="Nmap done: 1 IP address (1 host up)", stderr="")

    monkeypatch.setattr(scanner_core.subprocess, "run", fake_run)
    return calls


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.mark.parametrize("target", [
    "--script=http-shellshock",
    "-iL /etc/passwd",
    "-oN/tmp/out",
    "127.0.0.1 -oN /tmp/out",
    "127.0.0.1;id",
    "$(id)",
    "",
    "10.0.0.0/8",
])
@pytest.mark.parametrize("endpoint", ["/scan", "/targeted-scan", "/aggressive-scan"])
def test_malicious_targets_are_rejected(client, nmap_calls, endpoint, target):
    if endpoint == "/aggressive-scan" and target == "":
        pytest.skip("an empty target means 'scan my own subnet' on this endpoint")
    response = client.get(endpoint, params={"target": target}, headers=FRONTEND)
    assert response.status_code == 422
    assert nmap_calls == []


@pytest.mark.parametrize("ports", ["--script=vuln", "22 -oN x", "0", "70000", "80-22", "all"])
@pytest.mark.parametrize("endpoint", ["/scan", "/targeted-scan"])
def test_malicious_ports_are_rejected(client, nmap_calls, endpoint, ports):
    response = client.get(endpoint, params={"target": "192.168.1.10", "ports": ports}, headers=FRONTEND)
    assert response.status_code == 422
    assert nmap_calls == []


@pytest.mark.parametrize("target, expected", [
    ("192.168.1.10", "192.168.1.10"),
    ("192.168.1.0/24", "192.168.1.0/24"),
    ("192.168.1.77/24", "192.168.1.0/24"),
    ("scanme.nmap.org", "scanme.nmap.org"),
    ("fe80::1", "fe80::1"),
])
def test_valid_targets_reach_nmap_as_last_argument(client, nmap_calls, target, expected):
    response = client.get("/targeted-scan", params={"target": target, "ports": "22,80,8000-8100"}, headers=FRONTEND)
    assert response.status_code == 200
    assert nmap_calls[-1][-1] == expected
    assert "22,80,8000-8100" in nmap_calls[-1]


def test_unknown_origin_is_blocked(client, nmap_calls):
    response = client.get("/scan", params={"target": "192.168.1.10"}, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert nmap_calls == []


def test_cross_site_request_without_origin_is_blocked(client, nmap_calls):
    # What a browser sends for <img src="http://127.0.0.1:8000/scan?..."> on another site.
    response = client.get("/scan", params={"target": "192.168.1.10"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert nmap_calls == []


def test_frontend_origin_and_cli_clients_are_allowed(client, nmap_calls):
    assert client.get("/scan", params={"target": "192.168.1.10"}, headers=FRONTEND).status_code == 200
    assert client.get("/scan", params={"target": "192.168.1.10"}).status_code == 200
