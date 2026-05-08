from __future__ import annotations

from fastapi.testclient import TestClient

from takt.interface_adapters.api.main import create_app


def test_integration_ingest_endpoints_work_for_syslog_snmp_netflow_ipfix() -> None:
    client = TestClient(create_app())
    payloads = {
        "/integrations/ingest/syslog/rfc5424": {
            "observed_at": "2026-05-07T12:00:00+00:00",
            "asset_id": "edge-sw-01",
            "payload_size": 256,
            "collector": "edge-gw-1",
            "integration_ref": "collector/a",
            "message": "<34>1 2026-05-07T12:00:00Z edge-sw-01 sshd 101 ID47 login failed",
            "hostname": "edge-sw-01",
        },
        "/integrations/ingest/snmp/trap": {
            "observed_at": "2026-05-07T12:00:00+00:00",
            "asset_id": "switch-snmp-01",
            "payload_size": 200,
            "collector": "edge-gw-1",
            "integration_ref": "collector/b",
            "trap_oid": "1.3.6.1.6.3.1.1.5.3",
            "version": "v2c",
            "community": "public",
            "agent_addr": "10.10.10.5",
            "varbinds": {"ifIndex.7": 7, "ifAdminStatus.7": "down"},
        },
        "/integrations/ingest/netflow": {
            "observed_at": "2026-05-07T12:00:00+00:00",
            "asset_id": "router-netflow-01",
            "payload_size": 320,
            "collector": "edge-gw-1",
            "integration_ref": "collector/c",
            "exporter_ip": "10.10.0.1",
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.20",
            "src_port": 502,
            "dst_port": 443,
            "bytes": 4096,
            "packets": 18,
            "protocol_number": 6,
        },
        "/integrations/ingest/ipfix": {
            "observed_at": "2026-05-07T12:00:00+00:00",
            "asset_id": "router-ipfix-01",
            "payload_size": 344,
            "collector": "edge-gw-1",
            "integration_ref": "collector/d",
            "exporter_ip": "10.10.0.2",
            "src_ip": "10.0.0.30",
            "dst_ip": "10.0.0.40",
            "src_port": 2000,
            "dst_port": 161,
            "bytes": 8192,
            "packets": 29,
            "protocol_number": 17,
            "template_id": 256,
            "observation_domain_id": 42,
        },
    }
    for path, payload in payloads.items():
        r = client.post(path, json=payload)
        assert r.status_code == 200
        body = r.json()
        assert body["case_id"]
        assert body["risk_class"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_health_reports_sprint1_and_sprint4_capability_flags(monkeypatch) -> None:
    monkeypatch.setenv("TAKT_INGEST_SYSLOG_RFC5424", "1")
    monkeypatch.setenv("TAKT_INGEST_SNMP", "1")
    monkeypatch.setenv("TAKT_INGEST_NETFLOW", "1")
    monkeypatch.setenv("TAKT_INGEST_IPFIX", "1")
    monkeypatch.setenv("TAKT_LDAP_URL", "ldap://dc.local")
    monkeypatch.setenv("TAKT_AD_DOMAIN", "corp.local")
    monkeypatch.setenv("TAKT_TIMESERIES_BACKEND", "timescaledb")
    monkeypatch.setenv("TAKT_TIMESERIES_DSN", "postgres://user:pwd@db/takt")
    monkeypatch.setenv("TAKT_OBJECT_STORAGE_BACKEND", "minio")
    monkeypatch.setenv("TAKT_OBJECT_STORAGE_BUCKET", "takt-evidence")
    monkeypatch.setenv("TAKT_GOSSOPKA_PROFILE", "official")

    h = TestClient(create_app()).get("/health").json()
    assert h["ingest_syslog_rfc5424_enabled"] is True
    assert h["ingest_snmp_enabled"] is True
    assert h["ingest_netflow_enabled"] is True
    assert h["ingest_ipfix_enabled"] is True
    assert h["ldap_integration_configured"] is True
    assert h["ad_integration_configured"] is True
    assert h["timeseries_backend"] == "timescaledb"
    assert h["timeseries_configured"] is True
    assert h["object_storage_backend"] == "minio"
    assert h["object_storage_configured"] is True
    assert h["gossopka_profile"] == "official"
    assert h["gossopka_official_exchange_enabled"] is True
