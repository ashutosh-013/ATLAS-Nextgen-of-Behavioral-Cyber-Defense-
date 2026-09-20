"""
ATLAS Phase 5 Supervisor Test Suite — Advanced Analytics, AI Investigator & Threat Story Engine.

Validates:
1. Zero-Fabrication Invariant on Empty Streams (empty query modes return INSUFFICIENT_DATA and zero counts).
2. Executive Security Overview metrics derived from empirical DB events.
3. Temporal threat bucketing without fabricated curve heights.
4. Empirical threat class distribution (Execution, Credential Access, C2, etc.).
5. 10-Stage causal attack story reconstruction linking processes, network, campaigns, playbooks, and verification.
6. Multi-lane chronological forensic timeline generation (Processes, Network, Files, Campaigns, Responses).
7. RFC1918 Private IP classification and strict local network isolation (no false foreign geolocations).
8. AI Investigator ensemble threat classification and classical model fallback.
9. AI Evidence synthesis with MITRE ATT&CK mappings, critical paths, and natural language summaries.
10. Platform performance and resource telemetry (memory RSS, CPU, threads, query latency).
"""

import os
import sys
import time
import uuid
import pytest
from datetime import datetime, timezone

import database
from analytics_engine import AnalyticsEngine, is_private_ip
from intelligence.investigator import AIInvestigator, MITREMapper
from data_models import (
    BADNAEmbedding,
    BehaviorGraph,
    BehaviorNode,
    BehaviorEdge,
    ThreatClassification,
    IntentPrediction
)


@pytest.fixture(autouse=True)
def init_test_env():
    """Initialize database before each test."""
    database.init_db()


@pytest.fixture
def analytics():
    return AnalyticsEngine()


@pytest.fixture
def investigator():
    return AIInvestigator()


# ---------------------------------------------------------------------------
# Test 1: Zero-Fabrication on Empty Stream
# ---------------------------------------------------------------------------
def test_zero_fabrication_on_empty_stream(analytics):
    """Empty source modes must honestly report INSUFFICIENT_DATA and zero evidence counts."""
    empty_mode = f"SYNTHETIC_EMPTY_{uuid.uuid4().hex[:8]}"

    # Overview
    overview = analytics.get_security_overview(source_mode=empty_mode)
    assert overview["status"] == "INSUFFICIENT_DATA"
    assert overview["evidence_count"] == 0
    assert overview["metrics"]["total_events"] == 0

    # Threats over time
    tot = analytics.get_threats_over_time(source_mode=empty_mode)
    assert tot["status"] == "INSUFFICIENT_DATA"
    assert tot["evidence_count"] == 0
    for b in tot["buckets"]:
        assert b["total"] == 0
        assert b["threat_count"] == 0

    # Threat classes
    classes = analytics.get_threat_class_distribution(source_mode=empty_mode)
    assert classes["status"] == "NO_CLASSIFIED_THREATS"
    assert classes["total_threat_events"] == 0
    assert classes["distribution"] == []


# ---------------------------------------------------------------------------
# Test 2: Executive Security Overview Realism
# ---------------------------------------------------------------------------
def test_security_overview_metrics(analytics):
    """Security overview metrics must accurately reflect empirical telemetry records."""
    test_mode = f"TEST_MODE_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()

    ev1 = {
        "event_id": f"ev-ov-1-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "process",
        "process_name": "cmd.exe",
        "pid": 5001,
        "severity": "LOW"
    }
    ev2 = {
        "event_id": f"ev-ov-2-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "network",
        "dst_ip": "10.0.0.99",
        "dst_port": 443,
        "severity": "HIGH"
    }

    database.save_telemetry_event(ev1)
    database.save_telemetry_event(ev2)

    overview = analytics.get_security_overview(source_mode=test_mode)
    assert overview["status"] == "PROVEN_LIVE"
    assert overview["evidence_count"] == 2
    assert overview["metrics"]["total_events"] == 2
    assert overview["metrics"]["unique_processes"] == 1
    assert overview["metrics"]["network_connections"] == 1
    assert overview["metrics"]["threat_events"] == 1  # HIGH severity event


# ---------------------------------------------------------------------------
# Test 3: Temporal Threat Bucketing Without Fabrication
# ---------------------------------------------------------------------------
def test_threats_over_time_temporal_bucketing(analytics):
    """Time-series aggregation groups actual events into discrete time windows."""
    test_mode = f"TEST_MODE_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()

    for i in range(5):
        database.save_telemetry_event({
            "event_id": f"ev-tot-{i}-{uuid.uuid4().hex[:6]}",
            "timestamp": now_str,
            "source_mode": test_mode,
            "event_type": "powershell",
            "command": "powershell.exe -enc dGVzdA==",
            "severity": "HIGH"
        })

    tot = analytics.get_threats_over_time(source_mode=test_mode, time_range="24h")
    assert tot["status"] == "PROVEN_LIVE"
    assert tot["evidence_count"] == 5
    assert len(tot["buckets"]) > 0

    total_sum = sum(b["total"] for b in tot["buckets"])
    assert total_sum == 5

    # Most recent bucket should contain the injected events
    recent_bucket = tot["buckets"][-1]
    assert recent_bucket["total"] == 5
    assert recent_bucket["threat_count"] == 5


# ---------------------------------------------------------------------------
# Test 4: Empirical Threat Class Distribution
# ---------------------------------------------------------------------------
def test_threat_class_distribution_empirical(analytics):
    """Events are categorized empirically into Execution, Credential Access, etc."""
    test_mode = f"TEST_MODE_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()

    # 1. Execution
    database.save_telemetry_event({
        "event_id": f"ev-cls-1-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "powershell",
        "command": "powershell.exe -enc payload"
    })
    # 2. Credential Access
    database.save_telemetry_event({
        "event_id": f"ev-cls-2-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "process",
        "command": "mimikatz.exe sekurlsa::logonpasswords"
    })

    classes = analytics.get_threat_class_distribution(source_mode=test_mode)
    assert classes["status"] == "CALCULATED"
    assert classes["total_threat_events"] == 2

    class_names = [c["class_name"] for c in classes["distribution"]]
    assert "Execution" in class_names
    assert "Credential Access" in class_names


# ---------------------------------------------------------------------------
# Test 5: 10-Stage Attack Story Reconstruction
# ---------------------------------------------------------------------------
def test_attack_story_10_stage_reconstruction(analytics):
    """Attack story reconstructs 10 chronological stages with evidence links."""
    story = analytics.reconstruct_attack_story(source_mode="SCENARIO")
    assert story["stages_count"] == 10
    assert len(story["stages"]) == 10

    stage_names = [s["stage_name"] for s in story["stages"]]
    assert "Initial Event" in stage_names
    assert "Process Execution" in stage_names
    assert "Network Activity" in stage_names
    assert "Suspicious Behavior" in stage_names
    assert "IOC / Threat Correlation" in stage_names
    assert "Campaign Correlation" in stage_names
    assert "Threat Detection" in stage_names
    assert "Playbook Response" in stage_names
    assert "Post-Action Verification" in stage_names
    assert "Current Posture" in stage_names

    # Nodes and links for graph visualization
    assert len(story["nodes"]) >= 3
    assert len(story["links"]) >= 2


# ---------------------------------------------------------------------------
# Test 6: Multi-Lane Temporal Attack Timeline
# ---------------------------------------------------------------------------
def test_temporal_attack_timeline_lanes(analytics):
    """Forensic timeline assigns events to multi-lane visual streams."""
    test_mode = f"TEST_MODE_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()

    database.save_telemetry_event({
        "event_id": f"ev-lane-1-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "process",
        "process_name": "proc.exe",
        "command": "proc.exe /run"
    })
    database.save_telemetry_event({
        "event_id": f"ev-lane-2-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "network",
        "dst_ip": "198.51.100.1"
    })

    timeline = analytics.get_attack_timeline(source_mode=test_mode)
    assert timeline["total_items"] >= 2

    lanes = set(item["lane"] for item in timeline["timeline"])
    assert "Processes" in lanes
    assert "Network" in lanes


# ---------------------------------------------------------------------------
# Test 7: RFC1918 Private IP Classification & Isolation
# ---------------------------------------------------------------------------
def test_rfc1918_private_ip_isolation(analytics):
    """RFC1918 private IPs must be classified as LOCAL NETWORK and never geolocated."""
    # Test private IP classifier
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("::1") is True
    assert is_private_ip("10.1.2.3") is True
    assert is_private_ip("172.16.5.10") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("Local Host") is True

    # Public IPs should not be classified as private
    assert is_private_ip("185.220.101.5") is False
    assert is_private_ip("8.8.8.8") is False

    # Geolocation threat map must NOT geolocate private IPs to overseas countries
    test_mode = f"TEST_MODE_{uuid.uuid4().hex[:8]}"
    now_str = datetime.now(timezone.utc).isoformat()

    database.save_telemetry_event({
        "event_id": f"ev-geo-1-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "network",
        "dst_ip": "192.168.1.50"
    })
    database.save_telemetry_event({
        "event_id": f"ev-geo-2-{uuid.uuid4().hex[:6]}",
        "timestamp": now_str,
        "source_mode": test_mode,
        "event_type": "network",
        "dst_ip": "185.220.101.5"
    })

    geomap = analytics.get_ip_geolocation_threat_map(source_mode=test_mode)
    nodes = geomap.get("nodes", [])

    # Ensure private IP is labeled LOCAL NETWORK
    private_node = next((n for n in nodes if n["ip"] == "192.168.1.50"), None)
    if private_node:
        assert private_node["country"] == "LOCAL NETWORK"
        assert private_node["lat"] == 0.0
        assert private_node["lon"] == 0.0


import numpy as np


# ---------------------------------------------------------------------------
# Test 8: AI Investigator Ensemble Classification and Fallback
# ---------------------------------------------------------------------------
def test_ai_investigator_ensemble_and_fallback(investigator):
    """AI Investigator classifies threats across classes and supports classical fallback."""
    # Test valid 128-D embedding classification
    dummy_vec = np.array([0.05] * 128)
    dummy_vec[0] = 0.85
    dummy_vec[1] = 0.90
    embedding = dummy_vec / np.linalg.norm(dummy_vec)

    classification = investigator.classify_threat(embedding)
    assert classification.profile_id is not None
    assert classification.threat_class in ['APT', 'Ransomware', 'Insider_Threat', 'Malware', 'Phishing', 'Benign']
    assert 0.0 <= classification.confidence <= 1.0
    assert len(classification.probability_distribution) > 0
    assert classification.classification_method in ["ensemble_learning", "Ensemble (RF+SVM+NN)", "GNN+Ensemble", "GNN+Ensemble (Enriched)"]

    # Invalid dimension must trigger fallback with uncertainty flag
    invalid_emb = np.array([0.1] * 64)
    fallback_res = investigator.classify_threat(invalid_emb)
    assert fallback_res.threat_class in ['APT', 'Ransomware', 'Insider_Threat', 'Malware', 'Phishing', 'Benign']
    assert fallback_res.uncertainty_flag is True


# ---------------------------------------------------------------------------
# Test 9: AI Evidence Generation Completeness
# ---------------------------------------------------------------------------
def test_ai_evidence_generation_completeness(investigator):
    """Evidence generation includes MITRE mappings, top features, and natural language summary."""
    now = datetime.now()
    graph = BehaviorGraph(
        graph_id="g-test-ev-01",
        nodes=[
            BehaviorNode(node_id="n1", action_type="execution", event_refs=["e1"], timestamp=now),
            BehaviorNode(node_id="n2", action_type="credential_access", event_refs=["e2"], timestamp=now)
        ],
        edges=[
            BehaviorEdge(source_node="n1", target_node="n2", transition_type="precedes", weight=1.0, temporal_gap=0.5)
        ]
    )
    vec = np.zeros(128)
    vec[2] = 0.75
    vec[3] = 0.80
    vec = vec / np.linalg.norm(vec)

    classification = investigator.classify_threat(vec)
    intent = investigator.predict_intent(vec, graph)

    evidence = investigator.generate_evidence(
        graph=graph,
        embedding=vec,
        classification=classification,
        intent=intent,
        novelty_score=0.15
    )

    assert evidence.profile_id == classification.profile_id
    assert len(evidence.top_features) > 0
    assert len(evidence.critical_path) > 0
    assert len(evidence.mitre_mappings) > 0
    assert "structured_json" in evidence.__dict__
    assert len(evidence.natural_language) > 20


# ---------------------------------------------------------------------------
# Test 10: Platform Performance & Resource Telemetry
# ---------------------------------------------------------------------------
def test_platform_resource_and_performance_metrics(analytics):
    """Platform metrics expose memory consumption, CPU, threads, and MTTD/MTTR without hardcoding."""
    perf = analytics.calculate_detection_and_response_performance(source_mode="LIVE")

    assert "mttd" in perf
    assert "mttr" in perf
    assert "platform_metrics" in perf

    pm = perf["platform_metrics"]
    assert pm["memory_usage_mb"] > 0.0
    assert pm["cpu_percent"] >= 0.0
    assert pm["thread_count"] >= 1
    assert pm["processing_time_ms"] >= 0.0
    assert pm["status"] == "HEALTHY"
