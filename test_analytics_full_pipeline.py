"""
Comprehensive Real-Data Pipeline Integration Tests for ATLAS Analytics Engine
=============================================================================
Verifies end-to-end evidence normalization, strict anti-fabrication rules,
private IP classification, 10-stage attack story construction, multi-lane timeline,
metric-selectable time bucketing, and raw payload forensic drawer retrieval.
"""

import json
import pytest
import time
from datetime import datetime, timezone

import database
from analytics_engine import AnalyticsEngine, normalize_event_record, is_private_ip
from campaign_engine import CampaignEngine
from playbook_engine import DefenceResponseEngine


@pytest.fixture(scope="module")
def analytics_engine():
    database.init_db()
    camp_engine = CampaignEngine()
    def_engine = DefenceResponseEngine()
    return AnalyticsEngine(campaign_engine=camp_engine, defense_engine=def_engine)


def test_1_private_ip_classification():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("::1") is True
    assert is_private_ip("localhost") is True
    assert is_private_ip("10.0.0.55") is True
    assert is_private_ip("192.168.1.10") is True
    assert is_private_ip("172.16.0.5") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("185.220.101.5") is False
    assert is_private_ip("45.120.21.32") is False


def test_2_event_record_normalization():
    raw_flat = {
        "event_id": "test-flat-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process_name": "powershell.exe",
        "command": "powershell.exe -enc AAAA==",
        "src_ip": "10.0.0.55",
        "dst_ip": "185.220.101.5",
        "severity": "HIGH",
        "action": "EXECUTE"
    }
    norm = normalize_event_record(raw_flat)
    assert norm["event_id"] == "test-flat-1"
    assert norm["process_name"] == "powershell.exe"
    assert norm["dst_ip"] == "185.220.101.5"
    assert norm["severity"] == "HIGH"

    raw_nested = {
        "event_id": "test-nested-2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process": {"name": "cmd.exe", "command_line": "cmd.exe /c whoami", "pid": 4820},
        "network": {"src_ip": "192.168.1.10", "dst_ip": "192.168.1.1", "dst_port": 53},
        "severity": "info"
    }
    norm_n = normalize_event_record(raw_nested)
    assert norm_n["event_id"] == "test-nested-2"
    assert norm_n["process_name"] == "cmd.exe"
    assert norm_n["pid"] == 4820
    assert norm_n["dst_ip"] == "192.168.1.1"


def test_3_executive_overview_and_data_freshness(analytics_engine):
    ov = analytics_engine.get_security_overview(source_mode="LIVE", time_range="24h")
    assert "data_freshness" in ov
    assert "metrics" in ov
    assert "events_analyzed" in ov["data_freshness"]
    assert "earliest_event" in ov["data_freshness"]
    assert "last_event" in ov["data_freshness"]


def test_4_threats_over_time_metric_types(analytics_engine):
    for m_type in ["events", "threats", "high_risk", "network", "process", "powershell", "auth", "file"]:
        res = analytics_engine.get_threats_over_time(source_mode="LIVE", time_range="24h", metric_type=m_type)
        assert res["metric_type"] == m_type
        assert "buckets" in res
        assert len(res["buckets"]) == 6
        for b in res["buckets"]:
            assert "time" in b
            assert "total" in b
            assert "evidence_ids" in b


def test_5_threat_class_distribution_with_evidence(analytics_engine):
    res_live = analytics_engine.get_threat_class_distribution(source_mode="LIVE", time_range="24h")
    assert "distribution" in res_live
    assert res_live["status"] in ["CALCULATED", "NO_CLASSIFIED_THREATS"]

    res_scen = analytics_engine.get_threat_class_distribution(source_mode="SCENARIO", time_range="24h")
    assert len(res_scen["distribution"]) > 0
    for d in res_scen["distribution"]:
        assert "class_name" in d
        assert "count" in d
        assert "evidence_ids" in d


def test_6_10_stage_attack_story_reconstruction(analytics_engine):
    story = analytics_engine.reconstruct_attack_story(source_mode="SCENARIO")
    assert story["stages_count"] == 10
    stages = story["stages"]
    assert len(stages) == 10
    assert stages[0]["stage_name"] == "Initial Event"
    assert stages[1]["stage_name"] == "Process Execution"
    assert stages[2]["stage_name"] == "Network Activity"
    assert stages[9]["stage_name"] == "Current Posture"
    for s in stages:
        assert "status" in s
        assert s["status"] in ["OBSERVED", "NOT_OBSERVED"]
        assert "evidence_ids" in s


def test_7_temporal_attack_timeline_multi_lane(analytics_engine):
    tl = analytics_engine.get_attack_timeline(source_mode="SCENARIO", time_range="24h")
    assert "timeline" in tl
    for item in tl["timeline"]:
        assert "lane" in item
        assert item["lane"] in ["Processes", "Network", "Files", "Telemetry", "Campaigns", "Responses"]
        assert "raw_event" in item


def test_8_mitre_analysis_categorization(analytics_engine):
    mitre = analytics_engine.get_mitre_analysis(source_mode="SCENARIO")
    assert "techniques" in mitre
    for t in mitre["techniques"]:
        assert t["status"] in ["OBSERVED", "INFERRED", "NOT OBSERVED", "NOT_OBSERVED"]
        assert "evidence_count" in t


def test_9_process_behavior_and_parent_child_tree(analytics_engine):
    proc = analytics_engine.get_process_behavior_analytics(source_mode="SCENARIO")
    assert "top_processes" in proc
    assert "process_tree" in proc
    for t in proc["top_processes"]:
        assert "deviation_pct" in t
        assert "is_anomalous" in t


def test_10_network_behavior_and_private_filtering(analytics_engine):
    net = analytics_engine.get_network_behavior_analytics(source_mode="SCENARIO")
    assert "top_destinations" in net
    for d in net["top_destinations"]:
        if d["ip"].startswith("192.168.") or d["ip"].startswith("10."):
            assert "PRIVATE / LOCAL NETWORK" in d["type"]


def test_11_public_ip_geolocation_map(analytics_engine):
    geo = analytics_engine.get_ip_geolocation_threat_map(source_mode="SCENARIO")
    assert "markers" in geo
    for m in geo["markers"]:
        assert not is_private_ip(m["ip"])


def test_12_telemetry_quality_coverage(analytics_engine):
    dq = analytics_engine.get_data_quality_metrics(source_mode="LIVE")
    assert "telemetry_completeness" in dq
    assert "collectors" in dq
    assert "coverage_stats" in dq
    assert "timestamp_coverage" in dq["coverage_stats"]


def test_13_performance_and_latencies(analytics_engine):
    perf = analytics_engine.calculate_detection_and_response_performance(source_mode="LIVE", time_range="24h")
    assert "mttd" in perf
    assert "mttr" in perf
    assert perf["mttd"]["status"] in ["CALCULATED", "INSUFFICIENT_DATA"]


def test_14_risk_trend_and_decision_explainer(analytics_engine):
    trend = analytics_engine.get_risk_trend_and_explainer(source_mode="SCENARIO")
    assert "current_risk" in trend
    assert "residual_risk" in trend
    assert "why_atlas_decided" in trend
    assert len(trend["why_atlas_decided"]["evidence_factors"]) > 0


def test_15_single_evidence_retrieval(analytics_engine):
    test_ev = {
        "event_id": "test-evidence-retrieve-99",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": "WK-902",
        "source": "windows",
        "source_mode": "LIVE",
        "event_type": "process",
        "category": "process",
        "severity": "high",
        "process_name": "mimikatz.exe",
        "src_ip": "10.0.0.55",
        "dst_ip": "192.168.1.10",
        "correlation_id": "corr-99",
        "event_json": json.dumps({"event_id": "test-evidence-retrieve-99", "process_name": "mimikatz.exe"})
    }
    database.save_telemetry_event(test_ev)
    retrieved = analytics_engine.get_evidence_by_id("test-evidence-retrieve-99")
    assert retrieved is not None
    assert retrieved["event_id"] == "test-evidence-retrieve-99"
