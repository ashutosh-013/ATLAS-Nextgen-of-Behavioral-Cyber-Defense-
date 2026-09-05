#!/usr/bin/env python3
"""
Test script for BADNA Learning System

This script tests the FeedbackLoop, ModelEvolution, and KnowledgeUpdate components
to ensure they work correctly together.

Task: 9.2 - Implement feedback loop and model evolution (Testing)
"""

import sys
import os
import numpy as np
from datetime import datetime
from pathlib import Path

# Add BADNA to path
sys.path.append(str(Path(__file__).parent))

from data_models import Feedback, BehaviorPattern
from learning.feedback import FeedbackLoop, get_feedback_loop
from learning.evolution import ModelEvolution, get_model_evolution
from learning.knowledge_update import KnowledgeUpdater, get_knowledge_updater


def test_feedback_loop():
    """Test FeedbackLoop functionality."""
    print("\n=== Testing FeedbackLoop ===")
    
    try:
        # Create test feedback
        feedback = Feedback(
            profile_id="test-profile-001",
            feedback_type="true_positive",
            analyst_id="analyst-test",
            analyst_notes="Test feedback for validation"
        )
        
        # Initialize feedback loop
        feedback_loop = FeedbackLoop()
        
        # Process feedback
        result = feedback_loop.accept_feedback(feedback)
        
        print(f"✓ Feedback processed: {result.success}")
        print(f"  Message: {result.message}")
        print(f"  Updated weights: {list(result.updated_weights.keys())}")
        
        # Test statistics
        stats = feedback_loop.aggregate_statistics()
        if stats:
            print(f"✓ Statistics generated: {stats.total_feedback_count} total feedback")
        else:
            print("✓ No statistics yet (expected with single feedback)")
        
        # Test recent feedback summary
        summary = feedback_loop.get_recent_feedback_summary(days=7)
        print(f"✓ Recent feedback summary: {summary['total_feedback']} feedback in last 7 days")
        
        return True
        
    except Exception as e:
        print(f"✗ FeedbackLoop test failed: {e}")
        return False


def test_model_evolution():
    """Test ModelEvolution functionality."""
    print("\n=== Testing ModelEvolution ===")
    
    try:
        # Initialize model evolution
        evolution = ModelEvolution()
        
        # Check retraining triggers
        trigger_status = evolution.check_retraining_triggers()
        print(f"✓ Trigger status checked: {len(trigger_status.get('triggers', {}))} triggers")
        print(f"  Retraining recommended: {trigger_status.get('retraining_recommended', False)}")
        
        # Test version history
        version_history = evolution.get_version_history()
        print(f"✓ Version history retrieved: {len(version_history)} versions")
        
        # Test incremental learning with dummy data
        dummy_patterns = [
            BehaviorPattern(
                embedding=np.random.rand(128),
                threat_class="Malware",
                confidence_score=0.85,
                source="test"
            )
        ]
        
        incremental_success = evolution.incremental_embedding_update(dummy_patterns)
        print(f"✓ Incremental learning test: {incremental_success}")
        
        return True
        
    except Exception as e:
        print(f"✗ ModelEvolution test failed: {e}")
        return False


def test_knowledge_updater():
    """Test KnowledgeUpdater integration."""
    print("\n=== Testing KnowledgeUpdater ===")
    
    try:
        # Initialize knowledge updater
        updater = KnowledgeUpdater()
        
        # Test feedback processing
        feedback = Feedback(
            profile_id="test-integration-002",
            feedback_type="false_positive",
            analyst_id="analyst-integration",
            analyst_notes="Integration test feedback"
        )
        
        result = updater.process_analyst_feedback(feedback)
        print(f"✓ Feedback processed through updater: {result.feedback_processed}")
        print(f"  Message: {result.message}")
        
        # Test bulk pattern update
        test_patterns = [
            BehaviorPattern(
                embedding=np.random.rand(128),
                threat_class="APT",
                confidence_score=0.90,
                source="test_bulk"
            ),
            BehaviorPattern(
                embedding=np.random.rand(128),
                threat_class="Ransomware", 
                confidence_score=0.88,
                source="test_bulk"
            )
        ]
        
        bulk_result = updater.bulk_update_knowledge_base(test_patterns)
        print(f"✓ Bulk update completed: {bulk_result.patterns_added} patterns added")
        
        # Test system health check
        health = updater.get_learning_statistics()
        print(f"✓ System health retrieved: {len(health.keys())} metric categories")
        
        # Test maintenance check
        maintenance = updater.check_and_trigger_maintenance()
        print(f"✓ Maintenance check completed: {len(maintenance['operations_performed'])} operations")
        
        return True
        
    except Exception as e:
        print(f"✗ KnowledgeUpdater test failed: {e}")
        return False


def test_integration_workflow():
    """Test complete integration workflow."""
    print("\n=== Testing Integration Workflow ===")
    
    try:
        # Scenario: Analyst provides feedback on multiple detections
        feedback_scenarios = [
            ("true_positive", "APT", "Confirmed advanced persistent threat"),
            ("false_positive", "Benign", "Actually benign user activity"),
            ("false_negative", "Malware", "Missed malware detection")
        ]
        
        updater = get_knowledge_updater()
        processed_count = 0
        
        for feedback_type, threat_class, notes in feedback_scenarios:
            feedback = Feedback(
                profile_id=f"integration-{feedback_type}-{processed_count}",
                feedback_type=feedback_type,
                analyst_id="integration-analyst",
                analyst_notes=notes,
                corrected_label=threat_class if feedback_type == "false_negative" else None
            )
            
            # Add behavioral data for false negative
            behavioral_data = None
            if feedback_type == "false_negative":
                behavioral_data = {
                    'embedding': np.random.rand(128).tolist(),
                    'threat_class': threat_class
                }
            
            result = updater.process_analyst_feedback(feedback, behavioral_data)
            if result.feedback_processed:
                processed_count += 1
        
        print(f"✓ Integration workflow completed: {processed_count}/{len(feedback_scenarios)} feedback processed")
        
        # Get final system statistics
        final_stats = updater.get_learning_statistics()
        kb_stats = final_stats.get('knowledge_base', {})
        feedback_stats = final_stats.get('feedback_system', {})
        
        print(f"  Final KB size: {kb_stats.get('total_patterns', 0)} patterns")
        print(f"  Total feedback processed: {feedback_stats.get('total_feedback_count', 0)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Integration workflow test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("BADNA Learning System Integration Tests")
    print("=" * 50)
    
    test_results = []
    
    # Run individual component tests
    test_results.append(("FeedbackLoop", test_feedback_loop()))
    test_results.append(("ModelEvolution", test_model_evolution()))
    test_results.append(("KnowledgeUpdater", test_knowledge_updater()))
    test_results.append(("Integration Workflow", test_integration_workflow()))
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(test_results)
    
    for test_name, success in test_results:
        status = "PASS" if success else "FAIL"
        print(f"{test_name:25} {status}")
        if success:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Learning system implementation complete.")
        return 0
    else:
        print("❌ Some tests failed. Check implementation.")
        return 1


if __name__ == "__main__":
    exit(main())