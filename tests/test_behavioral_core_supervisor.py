"""
Test Behavioral Core Supervisor - Batch 2 Verification Suite
Verifies ATLAS Rules #1, #2, and #4:
1. Rule #1: ATLAS is Behavior-First (d-BEF, BSF, NSF, CCF are the core research contribution)
2. Rule #2: Never Let Any Module Bypass BADNA (Every telemetry event must pass through the behavioral pipeline)
3. Rule #4: Use CCF for Confidence (Continuous evidential scaling without arbitrary hardcoded boosts)
"""

import pytest
import numpy as np
from datetime import datetime
import sys
import os

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_models import (
    BehaviorGraph, BehaviorNode, BehaviorEdge, BADNAEmbedding,
    FeatureVector, create_security_event, create_behavior_node
)
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.dbef import DBEFEngine, FeatureEngineer, compute_badna_embedding
from similarity.bsf import BSFEngine
from novelty.nsf import NSFEngine, MockKnowledgeBase
from confidence.ccf import CCFEngine, RiskScorer
from main import BADNAOrchestrator


@pytest.fixture
def sample_behavior_graph():
    """Build a realistic multi-stage behavior graph."""
    nodes = [
        BehaviorNode(
            node_id="n1",
            action_type="process_create",
            event_refs=["evt-1"],
            timestamp=datetime(2026, 9, 1, 10, 0, 0),
            attributes={"process_name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"}
        ),
        BehaviorNode(
            node_id="n2",
            action_type="network_connect",
            event_refs=["evt-2"],
            timestamp=datetime(2026, 9, 1, 10, 0, 5),
            attributes={"ip": "198.51.100.22", "port": 443}
        ),
        BehaviorNode(
            node_id="n3",
            action_type="file_write",
            event_refs=["evt-3"],
            timestamp=datetime(2026, 9, 1, 10, 0, 10),
            attributes={"path": "C:\\Windows\\Temp\\payload.dll", "bytes": 4096}
        )
    ]
    edges = [
        BehaviorEdge(source_node="n1", target_node="n2", transition_type="spawns_network", weight=1.0, temporal_gap=5.0),
        BehaviorEdge(source_node="n2", target_node="n3", transition_type="triggers_file", weight=1.0, temporal_gap=5.0)
    ]
    return BehaviorGraph(graph_id="graph-test-01", nodes=nodes, edges=edges)


def test_dbef_unit_length_normalization(sample_behavior_graph):
    """
    Test 1: d-BEF generates a 128-D embedding strictly normalized to unit length.
    Requirement: ||embedding||_2 = 1.0 +- 1e-5.
    """
    engine = DBEFEngine()
    embedding = engine.generate_embedding(sample_behavior_graph)
    
    assert embedding.dimensions == 128
    assert embedding.vector.shape == (128,)
    norm = np.linalg.norm(embedding.vector)
    assert abs(norm - 1.0) < 1e-5, f"Expected unit norm 1.0, got {norm}"


def test_dbef_determinism(sample_behavior_graph):
    """
    Test 2: d-BEF embedding generation is strictly deterministic.
    Identical graphs must yield numerically identical vectors.
    """
    engine = DBEFEngine()
    emb1 = engine.generate_embedding(sample_behavior_graph)
    emb2 = engine.generate_embedding(sample_behavior_graph)
    
    np.testing.assert_allclose(emb1.vector, emb2.vector, rtol=1e-6, atol=1e-6)


def test_dbef_degenerate_graph_resilience():
    """
    Test 3: d-BEF resilience against degenerate and disconnected graphs.
    Single-node and zero-edge graphs must not produce NaNs, Infs, or crash.
    """
    engine = DBEFEngine()
    
    # 1-node graph with 0 edges
    single_node_graph = BehaviorGraph(
        graph_id="single-node",
        nodes=[
            BehaviorNode(
                node_id="n_solo",
                action_type="process_create",
                event_refs=["evt-solo"],
                timestamp=datetime(2026, 9, 1, 10, 0, 0),
                attributes={"process_name": "cmd.exe"}
            )
        ],
        edges=[]
    )
    
    emb_solo = engine.generate_embedding(single_node_graph)
    assert emb_solo.vector.shape == (128,)
    assert not np.isnan(emb_solo.vector).any()
    assert not np.isinf(emb_solo.vector).any()
    norm_solo = np.linalg.norm(emb_solo.vector)
    assert abs(norm_solo - 1.0) < 1e-5
    
    # Empty graph
    empty_graph = BehaviorGraph(graph_id="empty", nodes=[], edges=[])
    emb_empty = engine.generate_embedding(empty_graph)
    assert emb_empty.vector.shape == (128,)
    assert not np.isnan(emb_empty.vector).any()
    assert abs(np.linalg.norm(emb_empty.vector) - 1.0) < 1e-5


def test_bsf_weight_conservation():
    """
    Test 4: BSF component weights sum exactly to 1.0, and outputs are strictly bounded in [0.0, 1.0].
    """
    bsf = BSFEngine()
    total_weight = sum(bsf.component_weights.values())
    assert total_weight == pytest.approx(1.0, abs=1e-7)
    
    # Test bounding with randomized unit vectors
    np.random.seed(42)
    for _ in range(50):
        v1 = np.random.randn(128)
        v2 = np.random.randn(128)
        v1 /= np.linalg.norm(v1)
        v2 /= np.linalg.norm(v2)
        
        sim = bsf.calculate_similarity(v1, v2)
        assert 0.0 <= sim <= 1.0, f"BSF similarity {sim} out of [0.0, 1.0] bounds"
    
    # Identity similarity must be 1.0
    v_unit = np.ones(128) / np.sqrt(128)
    assert bsf.calculate_similarity(v_unit, v_unit) == pytest.approx(1.0, abs=1e-5)


def test_nsf_low_kb_fallback():
    """
    Test 5: NSF gracefully handles knowledge bases with fewer than 5 patterns without LOF fitting crashes.
    """
    nsf = NSFEngine()
    query_vec = np.ones(128) / np.sqrt(128)
    
    # Case A: Empty KB
    kb_empty = MockKnowledgeBase(patterns=[])
    res_empty = nsf.compute_novelty(query_vec, kb_empty)
    assert res_empty.novelty_score == 1.0
    assert res_empty.novelty_category == "highly_novel"
    
    # Case B: Small KB (< 5 patterns, where standard LOF fails)
    from data_models import BehaviorPattern
    patterns = [
        BehaviorPattern(
            pattern_id=f"pat-{i}",
            threat_class="Malware",
            embedding=np.random.randn(128) / np.sqrt(128),
            confidence_score=0.85
        )
        for i in range(3)
    ]
    kb_small = MockKnowledgeBase(patterns=patterns)
    res_small = nsf.compute_novelty(query_vec, kb_small)
    assert 0.0 <= res_small.novelty_score <= 1.0
    assert res_small.novelty_category in ["highly_novel", "moderately_novel", "known"]


def test_ccf_no_hardcoded_boosts():
    """
    Test 6: Verify CCF RiskScorer uses continuous evidential scaling (Rule #4) rather than uncalibrated static jumps.
    """
    scorer = RiskScorer()
    
    # Scenario with high confidence vs low confidence for identical behavioral intent
    high_conf_result = scorer.compute_risk(
        similarity_score=0.7,
        novelty_score=0.4,
        confidence_score=0.9,
        threat_class="Malware",
        lateral_movement=True,
        exfiltration=True
    )
    
    low_conf_result = scorer.compute_risk(
        similarity_score=0.7,
        novelty_score=0.4,
        confidence_score=0.2,
        threat_class="Malware",
        lateral_movement=True,
        exfiltration=True
    )
    
    # High confidence evidence must yield higher or equal intent bonus than uncalibrated/low confidence evidence
    high_bonus = high_conf_result['contributing_factors']['intent_bonus']
    low_bonus = low_conf_result['contributing_factors']['intent_bonus']
    assert high_bonus > low_bonus, "Intent bonus should be scaled by calibrated confidence"
    
    # All scores must remain strictly bounded in [0.0, 1.0]
    assert 0.0 <= high_conf_result['score'] <= 1.0
    assert 0.0 <= low_conf_result['score'] <= 1.0


def test_zero_bypass_invariant():
    """
    Test 7: Rule #2 - Never Let Any Module Bypass BADNA.
    Even if an event matches an IOC or signature, the event MUST pass through the complete
    behavioral pipeline (d-BEF, BSF, NSF, CCF) to produce behavioral profile artifacts.
    """
    orchestrator = BADNAOrchestrator()
    
    # Create sample telemetry events
    raw_events = [
        {
            "event_id": "evt-ioc-01",
            "event_type": "process",
            "timestamp": "2026-09-01T12:00:00",
            "source_system": "Endpoint-Sensor-Alpha",
            "event_data": {
                "name": "mimikatz.exe",
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "action": "create"
            }
        },
        {
            "event_id": "evt-ioc-02",
            "event_type": "network",
            "timestamp": "2026-09-01T12:00:05",
            "source_system": "Firewall",
            "event_data": {
                "domain": "known-bad-c2.example.com",
                "ip": "203.0.113.55",
                "action": "connect"
            }
        }
    ]
    
    profile = orchestrator.process_events(raw_events)
    
    # Verify the profile is fully populated by the behavioral pipeline
    assert profile is not None, "Profile must be generated"
    assert profile.embedding is not None, "d-BEF embedding must be computed (Rule #2)"
    assert len(profile.embedding.vector) == 128, "d-BEF must produce 128D embedding"
    assert abs(np.linalg.norm(profile.embedding.vector) - 1.0) < 1e-5, "Embedding must be unit-length"
    
    # Novelty, similarity, and risk must be populated
    assert profile.novelty_result is not None, "NSF novelty must be calculated"
    assert profile.risk_score is not None, "CCF calibrated risk score must be computed"
    assert profile.risk_score is not None, "CCF calibrated risk score must be computed"
    assert 0.0 <= profile.risk_score.score <= 1.0, "Risk score must be in [0.0, 1.0]"
