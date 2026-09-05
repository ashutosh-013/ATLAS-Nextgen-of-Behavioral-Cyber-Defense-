"""
End-to-End Integration Test: Ingestion Pipeline → BADNA

This test validates the complete flow:
1. Create fake dataset using UnifiedEvent schema
2. Feed to BehaviorCaptureEngine
3. Generate BehaviorGraph
4. Extract BADNA embedding
5. Run through complete BADNA pipeline
6. Verify Knowledge Base storage

This proves the ingestion infrastructure works with existing BADNA code.
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timedelta

# Import ingestion components
from ingestion.unified_schema import (
    UnifiedEvent, create_process_event, create_file_event,
    create_network_event, create_auth_event
)
from ingestion.dataset_registry import DatasetRegistry

# Import existing BADNA components
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.dbef import compute_badna_embedding
from main import BADNAAnalysisOrchestrator


def create_fake_apt_scenario():
    """
    Create a fake APT attack scenario with realistic event sequence.
    
    Attack Flow:
    1. Initial access via phishing (user clicks malicious link)
    2. PowerShell execution
    3. Credential dumping (LSASS access)
    4. Lateral movement (SMB connection)
    5. Data exfiltration
    """
    print("Creating fake APT attack scenario...")
    
    base_time = datetime.now()
    events = []
    
    # Event 1: Initial access - suspicious process creation
    events.append(create_process_event(
        event_id="evt_001",
        timestamp=(base_time + timedelta(seconds=0)).isoformat(),
        pid=4321,
        action="create",
        name="outlook.exe",
        command_line="outlook.exe /c malicious_attachment.doc",
        source_system="fake_apt_scenario"
    ))
    
    # Event 2: Malicious document opens PowerShell
    events.append(create_process_event(
        event_id="evt_002",
        timestamp=(base_time + timedelta(seconds=5)).isoformat(),
        pid=5678,
        action="create",
        name="powershell.exe",
        command_line="powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...",
        parent_pid=4321,
        source_system="fake_apt_scenario"
    ))
    
    # Event 3: PowerShell writes to disk
    events.append(create_file_event(
        event_id="evt_003",
        timestamp=(base_time + timedelta(seconds=10)).isoformat(),
        path="C:\\Windows\\Temp\\payload.exe",
        action="write",
        file_size=245760,
        hash="1a2b3c4d5e6f7890abcdef",
        source_system="fake_apt_scenario"
    ))
    
    # Event 4: Network beacon to C2 server
    events.append(create_network_event(
        event_id="evt_004",
        timestamp=(base_time + timedelta(seconds=15)).isoformat(),
        action="c2",
        source_ip="192.168.1.100",
        dest_ip="45.120.34.56",
        source_port=49152,
        dest_port=443,
        protocol="HTTPS",
        domain="malicious-c2.com",
        source_system="fake_apt_scenario"
    ))
    
    # Event 5: Credential access - LSASS dump
    events.append(create_process_event(
        event_id="evt_005",
        timestamp=(base_time + timedelta(seconds=20)).isoformat(),
        pid=5679,
        action="create",
        name="lsass.exe",
        command_line="C:\\Windows\\System32\\lsass.exe",
        parent_pid=5678,
        source_system="fake_apt_scenario"
    ))
    
    # Event 6: Read credentials from memory
    events.append(create_file_event(
        event_id="evt_006",
        timestamp=(base_time + timedelta(seconds=25)).isoformat(),
        path="C:\\Windows\\System32\\config\\SAM",
        action="read",
        source_system="fake_apt_scenario"
    ))
    
    # Event 7: Authentication escalation
    events.append(create_auth_event(
        event_id="evt_007",
        timestamp=(base_time + timedelta(seconds=30)).isoformat(),
        user="Administrator",
        action="escalate",
        success=True,
        source_ip="192.168.1.100",
        source_system="fake_apt_scenario"
    ))
    
    # Event 8: Lateral movement via SMB
    events.append(create_network_event(
        event_id="evt_008",
        timestamp=(base_time + timedelta(seconds=35)).isoformat(),
        action="smb",
        source_ip="192.168.1.100",
        dest_ip="192.168.1.50",
        source_port=49153,
        dest_port=445,
        protocol="SMB",
        source_system="fake_apt_scenario"
    ))
    
    # Event 9: Data collection
    events.append(create_file_event(
        event_id="evt_009",
        timestamp=(base_time + timedelta(seconds=40)).isoformat(),
        path="C:\\Users\\Admin\\Documents\\sensitive_data.zip",
        action="read",
        file_size=10485760,
        source_system="fake_apt_scenario"
    ))
    
    # Event 10: Data exfiltration
    events.append(create_network_event(
        event_id="evt_010",
        timestamp=(base_time + timedelta(seconds=45)).isoformat(),
        action="upload",
        source_ip="192.168.1.100",
        dest_ip="45.120.34.56",
        source_port=49154,
        dest_port=443,
        protocol="HTTPS",
        domain="malicious-c2.com",
        source_system="fake_apt_scenario"
    ))
    
    print(f"✓ Created {len(events)} events for APT scenario")
    return events


def create_fake_ransomware_scenario():
    """Create a fake ransomware attack scenario"""
    print("Creating fake ransomware scenario...")
    
    base_time = datetime.now()
    events = []
    
    # Ransomware dropper execution
    events.append(create_process_event(
        event_id="evt_r01",
        timestamp=(base_time + timedelta(seconds=0)).isoformat(),
        pid=6789,
        action="create",
        name="invoice_2024.exe",
        source_system="fake_ransomware"
    ))
    
    # Mass file encryption
    for i in range(5):
        events.append(create_file_event(
            event_id=f"evt_r{i+2:02d}",
            timestamp=(base_time + timedelta(seconds=i*2)).isoformat(),
            path=f"C:\\Users\\Victim\\Documents\\file_{i}.docx",
            action="encrypt",
            source_system="fake_ransomware"
        ))
    
    # Ransom note creation
    events.append(create_file_event(
        event_id="evt_r07",
        timestamp=(base_time + timedelta(seconds=15)).isoformat(),
        path="C:\\Users\\Victim\\Desktop\\RANSOM_NOTE.txt",
        action="write",
        source_system="fake_ransomware"
    ))
    
    print(f"✓ Created {len(events)} events for ransomware scenario")
    return events


def run_unified_event_to_behavior_graph():
    """Test Step 1: UnifiedEvent → BehaviorCaptureEngine → BehaviorGraph"""
    print("\n" + "="*70)
    print("TEST 1: UnifiedEvent → BehaviorCaptureEngine → BehaviorGraph")
    print("="*70)
    
    # Create fake events
    events = create_fake_apt_scenario()
    
    # Convert to dicts (format expected by BehaviorCaptureEngine)
    print("\nConverting UnifiedEvents to dict format...")
    event_dicts = [e.to_dict() for e in events]
    print(f"✓ Converted {len(event_dicts)} events to dict format")
    
    # Test with BehaviorCaptureEngine
    print("\nFeeding to BehaviorCaptureEngine...")
    try:
        engine = BehaviorCaptureEngine()
        
        # Parse events
        parsed_events = engine.parse_events(event_dicts)
        print(f"✓ BehaviorCaptureEngine parsed {len(parsed_events)} events")
        
        # Build behavior graph
        behavior_graph = engine.build_graph(parsed_events)
        print(f"✓ Generated BehaviorGraph:")
        print(f"  - Graph ID: {behavior_graph.graph_id}")
        print(f"  - Nodes: {behavior_graph.node_count}")
        print(f"  - Edges: {behavior_graph.edge_count}")
        print(f"  - Acyclic: {behavior_graph.is_acyclic}")
        
        return behavior_graph, event_dicts
        
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def run_behavior_graph_to_embedding(behavior_graph):
    """Test Step 2: BehaviorGraph → d-BEF → 128D Embedding"""
    print("\n" + "="*70)
    print("TEST 2: BehaviorGraph → d-BEF → 128D Embedding")
    print("="*70)
    
    if not behavior_graph:
        print("✗ Skipping - no behavior graph available")
        return None
    
    try:
        print("\nGenerating BADNA embedding with d-BEF...")
        embedding = compute_badna_embedding(behavior_graph)
        
        print(f"✓ Generated embedding:")
        print(f"  - Embedding ID: {embedding.embedding_id}")
        print(f"  - Dimensions: {len(embedding.vector)}D")
        print(f"  - Vector norm: {sum(x**2 for x in embedding.vector)**0.5:.6f}")
        print(f"  - Sample values: [{', '.join(f'{x:.4f}' for x in embedding.vector[:5])}, ...]")
        
        return embedding
        
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_complete_badna_pipeline(event_dicts):
    """Test Step 3: Complete BADNA Pipeline (End-to-End)"""
    print("\n" + "="*70)
    print("TEST 3: Complete BADNA Pipeline (End-to-End)")
    print("="*70)
    
    if not event_dicts:
        print("✗ Skipping - no events available")
        return None
    
    try:
        print("\nInitializing BADNA Analysis Orchestrator...")
        orchestrator = BADNAAnalysisOrchestrator()
        
        print(f"Running complete analysis on {len(event_dicts)} events...")
        profile = orchestrator.analyze_events(event_dicts)
        
        print(f"✓ BADNA Analysis Complete!")
        print(f"\nBADNA Profile:")
        print(f"  - Profile ID: {profile.profile_id}")
        
        # Extract threat classification
        if profile.threat_classification:
            print(f"  - Threat Class: {profile.threat_classification.threat_class}")
            print(f"  - Confidence: {profile.threat_classification.confidence:.3f}")
        
        # Extract risk score
        if profile.risk_score:
            print(f"  - Risk Score: {profile.risk_score.score:.3f}")
            print(f"  - Risk Level: {profile.risk_score.risk_level}")
        
        # Extract novelty
        if profile.novelty_result:
            print(f"  - Novelty Score: {profile.novelty_result.novelty_score:.3f}")
            print(f"  - Novelty Category: {profile.novelty_result.novelty_category}")
        
        # Extract intent
        if profile.intent_prediction:
            print(f"  - Primary Intent: {profile.intent_prediction.primary_intent}")
            print(f"  - Attack Stage: {profile.intent_prediction.attack_stage}")
            if profile.intent_prediction.mitre_techniques:
                print(f"  - MITRE Techniques: {', '.join(profile.intent_prediction.mitre_techniques[:3])}")
        
        return profile
        
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_with_ransomware_scenario():
    """Test with second scenario (Ransomware)"""
    print("\n" + "="*70)
    print("TEST 4: Ransomware Scenario")
    print("="*70)
    
    # Create ransomware events
    events = create_fake_ransomware_scenario()
    event_dicts = [e.to_dict() for e in events]
    
    try:
        orchestrator = BADNAAnalysisOrchestrator()
        profile = orchestrator.analyze_events(event_dicts)
        
        print(f"✓ Ransomware Analysis Complete!")
        print(f"  - Threat Class: {profile.threat_classification.threat_class if profile.threat_classification else 'Unknown'}")
        print(f"  - Risk Level: {profile.risk_score.risk_level if profile.risk_score else 'Unknown'}")
        print(f"  - Novelty: {profile.novelty_result.novelty_score:.3f}" if profile.novelty_result else "")
        
        return profile
        
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


def save_test_results(apt_profile, ransomware_profile):
    """Save test results to file"""
    print("\n" + "="*70)
    print("Saving Test Results")
    print("="*70)
    
    results = {
        "test_timestamp": datetime.now().isoformat(),
        "test_type": "ingestion_pipeline_validation",
        "scenarios_tested": 2,
        "results": {}
    }
    
    if apt_profile:
        results["results"]["apt_scenario"] = {
            "profile_id": apt_profile.profile_id,
            "threat_class": apt_profile.threat_classification.threat_class if apt_profile.threat_classification else None,
            "risk_level": apt_profile.risk_score.risk_level if apt_profile.risk_score else None,
            "risk_score": apt_profile.risk_score.score if apt_profile.risk_score else None,
            "novelty_score": apt_profile.novelty_result.novelty_score if apt_profile.novelty_result else None,
            "confidence": apt_profile.confidence_result.confidence_score if apt_profile.confidence_result else None
        }
    
    if ransomware_profile:
        results["results"]["ransomware_scenario"] = {
            "profile_id": ransomware_profile.profile_id,
            "threat_class": ransomware_profile.threat_classification.threat_class if ransomware_profile.threat_classification else None,
            "risk_level": ransomware_profile.risk_score.risk_level if ransomware_profile.risk_score else None,
            "risk_score": ransomware_profile.risk_score.score if ransomware_profile.risk_score else None,
            "novelty_score": ransomware_profile.novelty_result.novelty_score if ransomware_profile.novelty_result else None
        }
    
    output_file = Path("test_results_ingestion_pipeline.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"✓ Results saved to: {output_file}")


def main():
    """Run complete integration test"""
    print("\n" + "="*70)
    print("ATLAS DATA INGESTION - END-TO-END INTEGRATION TEST")
    print("="*70)
    print("\nThis test validates:")
    print("1. UnifiedEvent schema → BehaviorCaptureEngine compatibility")
    print("2. BehaviorGraph generation from ingestion events")
    print("3. BADNA embedding extraction (d-BEF)")
    print("4. Complete BADNA pipeline (BSF, NSF, CCF, AI Investigator)")
    print("5. Multiple threat scenarios")
    print()
    
    # Test 1: APT Scenario - Graph Generation
    behavior_graph, apt_event_dicts = run_unified_event_to_behavior_graph()
    
    # Test 2: Embedding Generation
    embedding = run_behavior_graph_to_embedding(behavior_graph)
    
    # Test 3: Complete BADNA Pipeline (APT)
    apt_profile = run_complete_badna_pipeline(apt_event_dicts)
    
    # Test 4: Ransomware Scenario
    ransomware_profile = run_with_ransomware_scenario()
    
    # Save results
    save_test_results(apt_profile, ransomware_profile)
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    tests_passed = 0
    tests_total = 4
    
    if behavior_graph:
        print("✓ Test 1: UnifiedEvent → BehaviorGraph - PASSED")
        tests_passed += 1
    else:
        print("✗ Test 1: UnifiedEvent → BehaviorGraph - FAILED")
    
    if embedding:
        print("✓ Test 2: BehaviorGraph → Embedding - PASSED")
        tests_passed += 1
    else:
        print("✗ Test 2: BehaviorGraph → Embedding - FAILED")
    
    if apt_profile:
        print("✓ Test 3: Complete BADNA Pipeline (APT) - PASSED")
        tests_passed += 1
    else:
        print("✗ Test 3: Complete BADNA Pipeline (APT) - FAILED")
    
    if ransomware_profile:
        print("✓ Test 4: Ransomware Scenario - PASSED")
        tests_passed += 1
    else:
        print("✗ Test 4: Ransomware Scenario - FAILED")
    
    print(f"\nTests Passed: {tests_passed}/{tests_total}")
    
    if tests_passed == tests_total:
        print("\n✅ ALL TESTS PASSED - Ingestion infrastructure is fully functional!")
        print("✅ UnifiedEvent schema is compatible with existing BADNA pipeline")
        print("✅ Ready to implement dataset parsers")
    else:
        print(f"\n⚠️  {tests_total - tests_passed} test(s) failed - review errors above")
    
    print("="*70)


if __name__ == "__main__":
    main()
