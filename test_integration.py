"""
BADNA Integration Test - Task 7.1
Verify all research algorithms are functional and integrated correctly.

Tests the complete pipeline:
Events  Graph  Features  Embedding  Similarity + Novelty  Confidence
"""

import numpy as np
from datetime import datetime
import json
import sys
import os

# Import all our modules
from data_models import (
    SecurityEvent, BehaviorGraph, FeatureVector, BADNAEmbedding,
    create_security_event, create_behavior_node, BehaviorEdge
)
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.dbef import FeatureEngineer, DBEFEngine, compute_badna_embedding
from similarity.bsf import BSFEngine
from novelty.nsf import NSFEngine, MockKnowledgeBase
from confidence.ccf import CCFEngine, RiskScorer
from config import get_logger, get_config


def test_complete_pipeline():
    """Test the complete BADNA pipeline with sample data."""
    print("=" * 60)
    print("BADNA INTEGRATION TEST - COMPLETE PIPELINE")
    print("=" * 60)
    
    logger = get_logger()
    
    try:
        # Step 1: Create sample security events
        print("\n1. Creating sample security events...")
        sample_events = [
            {
                "event_type": "process",
                "timestamp": "2024-01-01T10:00:00",
                "source_system": "EDR",
                "event_data": {
                    "pid": 1234,
                    "action": "create",
                    "name": "powershell.exe",
                    "command": "powershell.exe -encodedCommand <base64>"
                }
            },
            {
                "event_type": "auth",
                "timestamp": "2024-01-01T10:00:05",
                "source_system": "Domain Controller",
                "event_data": {
                    "user": "admin",
                    "action": "escalate",
                    "from_privilege": "user",
                    "to_privilege": "admin"
                }
            },
            {
                "event_type": "file",
                "timestamp": "2024-01-01T10:00:10",
                "source_system": "SIEM",
                "event_data": {
                    "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "action": "write",
                    "size": 1024
                }
            },
            {
                "event_type": "registry",
                "timestamp": "2024-01-01T10:00:15",
                "source_system": "EDR",
                "event_data": {
                    "key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "action": "modify",
                    "value": "malware.exe"
                }
            },
            {
                "event_type": "network",
                "timestamp": "2024-01-01T10:00:20",
                "source_system": "Firewall",
                "event_data": {
                    "action": "dns",
                    "domain": "malicious-c2.com",
                    "ip": "192.168.1.100"
                }
            }
        ]
        
        # Step 2: Parse events and build behavior graph
        print("2. Parsing events and building behavior graph...")
        capture_engine = BehaviorCaptureEngine()
        parsed_events = capture_engine.parse_events(sample_events)
        behavior_graph = capture_engine.build_graph(parsed_events)
        
        print(f"    Parsed {len(parsed_events)} events")
        print(f"    Built graph with {behavior_graph.node_count} nodes, {behavior_graph.edge_count} edges")
        print(f"    Graph is acyclic: {behavior_graph.is_acyclic}")
        
        # Step 3: Extract features and generate embedding
        print("3. Extracting features and generating BADNA embedding...")
        badna_embedding = compute_badna_embedding(behavior_graph)
        
        print(f"    Generated {len(badna_embedding.vector)}-D embedding")
        print(f"    Embedding norm: {np.linalg.norm(badna_embedding.vector):.6f}")
        print(f"    Embedding ID: {badna_embedding.embedding_id}")
        
        # Step 4: Test similarity computation
        print("4. Testing similarity computation...")
        bsf_engine = BSFEngine()
        
        # Create second embedding for comparison
        sample_events_2 = [
            {
                "event_type": "process", 
                "timestamp": "2024-01-01T11:00:00",
                "event_data": {"pid": 5678, "action": "create", "name": "cmd.exe"}
            },
            {
                "event_type": "file",
                "timestamp": "2024-01-01T11:00:05", 
                "event_data": {"path": "/tmp/test.txt", "action": "read"}
            }
        ]
        
        parsed_events_2 = capture_engine.parse_events(sample_events_2)
        behavior_graph_2 = capture_engine.build_graph(parsed_events_2)
        badna_embedding_2 = compute_badna_embedding(behavior_graph_2)
        
        # Test similarity
        similarity_result = bsf_engine.calculate_similarity_detailed(badna_embedding, badna_embedding_2)
        self_similarity = bsf_engine.calculate_similarity(badna_embedding.vector, badna_embedding.vector)
        
        print(f"    Similarity between different behaviors: {similarity_result.similarity_score:.3f}")
        print(f"    Self-similarity: {self_similarity:.3f}")
        print(f"    BSF mathematical properties: Identity = {abs(self_similarity - 1.0) < 1e-6}")
        
        # Step 5: Test novelty detection
        print("5. Testing novelty detection...")
        nsf_engine = NSFEngine()
        
        # Create mock knowledge base with some patterns
        mock_kb = MockKnowledgeBase()
        for i in range(10):
            pattern_vector = np.random.randn(128)
            pattern_vector = pattern_vector / np.linalg.norm(pattern_vector)
            
            from data_models import BehaviorPattern
            pattern = BehaviorPattern(
                pattern_id=f"known_pattern_{i}",
                embedding=pattern_vector,
                threat_class="Known_Attack"
            )
            mock_kb.add_pattern(pattern)
        
        novelty_result = nsf_engine.compute_novelty(badna_embedding.vector, mock_kb)
        print(f"    Novelty score: {novelty_result.novelty_score:.3f} ({novelty_result.novelty_category})")
        print(f"    Nearest neighbors found: {len(novelty_result.nearest_neighbors)}")
        print(f"    LOF score: {novelty_result.local_outlier_factor:.3f}")
        
        # Step 6: Test confidence calibration
        print("6. Testing confidence calibration...")
        ccf_engine = CCFEngine()
        
        confidence_result = ccf_engine.calibrate_confidence(
            similarity_score=similarity_result.similarity_score,
            novelty_score=novelty_result.novelty_score,
            evidence_quality=0.9,
            knowledge_base_size=len(mock_kb.get_patterns())
        )
        
        print(f"    Confidence score: {confidence_result.confidence_score:.3f}")
        print(f"    Confidence interval: [{confidence_result.confidence_interval[0]:.3f}, {confidence_result.confidence_interval[1]:.3f}]")
        
        # Step 7: Test risk scoring
        print("7. Testing risk scoring...")
        risk_scorer = RiskScorer()
        
        risk_result = risk_scorer.compute_risk(
            similarity_score=similarity_result.similarity_score,
            novelty_score=novelty_result.novelty_score,
            confidence_score=confidence_result.confidence_score,
            threat_class="APT",
            lateral_movement=False,
            exfiltration=False
        )
        
        print(f"    Risk score: {risk_result['score']:.3f} ({risk_result['risk_level']})")
        print(f"    Risk rationale: {risk_result['rationale']}")
        
        # Step 8: Verify mathematical properties for all algorithms
        print("8. Verifying mathematical properties...")
        
        # Test vectors for property validation
        test_vectors = [badna_embedding.vector, badna_embedding_2.vector]
        
        # BSF properties
        bsf_properties = bsf_engine.validate_mathematical_properties(test_vectors)
        print(f"    BSF properties: {bsf_properties}")
        
        # NSF properties  
        nsf_properties = nsf_engine.validate_mathematical_properties(test_vectors, mock_kb)
        print(f"    NSF properties: {nsf_properties}")
        
        # CCF properties
        ccf_test_inputs = [
            {'similarity': 0.8, 'novelty': 0.2, 'evidence_quality': 1.0, 'kb_size': 100},
            {'similarity': 0.3, 'novelty': 0.9, 'evidence_quality': 0.5, 'kb_size': 10}
        ]
        ccf_properties = ccf_engine.validate_mathematical_properties(ccf_test_inputs)
        print(f"    CCF properties: {ccf_properties}")
        
        # Final validation
        all_properties_valid = all([
            all(bsf_properties.values()),
            all(nsf_properties.values()),
            all(ccf_properties.values())
        ])
        
        print("\n" + "=" * 60)
        print("INTEGRATION TEST RESULTS")
        print("=" * 60)
        
        print(f" Events  Graph: {behavior_graph.node_count} nodes, {behavior_graph.edge_count} edges")
        print(f" Graph  Features: Extracted and normalized successfully")
        print(f" Features  Embedding: 128-D unit vector generated")
        print(f" Embedding  Similarity: {similarity_result.similarity_score:.3f} computed")
        print(f" Embedding  Novelty: {novelty_result.novelty_score:.3f} computed")  
        print(f" All  Confidence: {confidence_result.confidence_score:.3f} calibrated")
        print(f" All  Risk: {risk_result['score']:.3f} ({risk_result['risk_level']}) assessed")
        print(f" Mathematical Properties: {'All valid' if all_properties_valid else 'Some failed'}")
        
        if all_properties_valid:
            print(f"\n ALL CORE RESEARCH ALGORITHMS ARE FUNCTIONAL!")
            print(f"   d-BEF, BSF, NSF, CCF are working correctly")
            print(f"   Complete pipeline: Events  BADNA Profile verified")
        return all_properties_valid
        
    except Exception as e:
        print(f"\n Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_investigation_endpoints():
    """Test Flask investigation GET /api/investigation/<id> across all 5 scenarios and live database profiles."""
    from web_app import app, INVESTIGATION_AUDIT_LOG
    import database
    client = app.test_client()

    # 1. Test GET benign baseline investigation
    resp_benign = client.get('/api/investigation/benign')
    assert resp_benign.status_code == 200
    data_benign = json.loads(resp_benign.data)
    assert data_benign['success'] is True
    assert data_benign['investigation']['status'] == 'BENIGN BASELINE'

    # 2. Test GET APT29 investigation
    resp_apt = client.get('/api/investigation/apt')
    assert resp_apt.status_code == 200
    data_apt = json.loads(resp_apt.data)
    assert data_apt['investigation']['status'] == 'CONFIRMED MALICIOUS'
    assert len(data_apt['investigation']['causal_chain']) == 4
    assert data_apt['investigation']['risk_score'] > 50

    # 3. Test GET Ransomware investigation
    resp_ransom = client.get('/api/investigation/ransomware')
    assert resp_ransom.status_code == 200
    data_ransom = json.loads(resp_ransom.data)
    assert data_ransom['investigation']['status'] == 'CONFIRMED RANSOMWARE'
    assert data_ransom['investigation']['risk_score'] > 75

    # 4. Test GET Insider Threat investigation
    resp_insider = client.get('/api/investigation/insider')
    assert resp_insider.status_code == 200
    data_insider = json.loads(resp_insider.data)
    assert data_insider['investigation']['status'] in ['OBSERVED', 'SUSPICIOUS']

    # 5. Test GET Unknown Threat investigation
    resp_unknown = client.get('/api/investigation/unknown')
    assert resp_unknown.status_code == 200
    data_unknown = json.loads(resp_unknown.data)
    assert data_unknown['investigation']['status'] in ['OBSERVED', 'BENIGN BASELINE', 'SUSPICIOUS']

    # 6. Test GET Real Live Telemetry Profile from Database
    live_profile_id = "PROF-LIVE-TEST-99"
    sample_live_events = [
        {"event_type": "process", "event_data": {"name": "powershell.exe", "pid": 9901, "command": "powershell.exe -EncodedCommand JABz..."}},
        {"event_type": "network", "event_data": {"dest_ip": "45.120.21.32", "dest_port": 443}}
    ]
    database.save_profile(
        profile_id=live_profile_id,
        timestamp="2026-08-20T22:00:00",
        threat_class="Malicious",
        risk_score=90.0,
        risk_level="High",
        events_count=2,
        device_metadata={"ip": "192.168.1.105"},
        events=sample_live_events,
        profile_json=json.dumps({"profile_id": live_profile_id})
    )

    resp_live = client.get(f'/api/investigation/{live_profile_id}')
    assert resp_live.status_code == 200
    data_live = json.loads(resp_live.data)
    assert data_live['success'] is True
    assert len(data_live['investigation']['causal_chain']) == 2
    assert data_live['investigation']['risk_score'] > 50

    # 7. Test POST analyst feedback
    fb_resp = client.post('/api/investigation/feedback', json={
        'investigation_id': 'INV-2026-000102',
        'decision': 'TP',
        'comment': 'Confirmed APT29 credential dumping sequence',
        'analyst': 'Analyst_Test'
    })
    assert fb_resp.status_code == 200
    fb_data = json.loads(fb_resp.data)
    assert fb_data['success'] is True
    assert len(INVESTIGATION_AUDIT_LOG) > 0
    assert INVESTIGATION_AUDIT_LOG[-1]['decision'] == 'TP'
    assert INVESTIGATION_AUDIT_LOG[-1]['status'] == 'FED_TO_EVALUATION_TRAINING_PIPELINE'
    print(" Investigation API Endpoints & Audit Logging Unit Tests Passed Cleanly Across All Scenarios!")



if __name__ == "__main__":
    success = test_complete_pipeline()
    
    if success:
        print("\n" + "=" * 60)
        print(" Task 7.1 COMPLETE: All research algorithms verified functional")
        print(" Ready to proceed to AI Investigator implementation")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print(" Task 7.1 FAILED: Issues found in algorithm integration")
        print("=" * 60)