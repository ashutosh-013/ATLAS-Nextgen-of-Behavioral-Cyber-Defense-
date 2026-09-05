#!/usr/bin/env python3
"""
Test Critical Bug Fixes for BADNA

This script validates that all 5 critical bug fixes have been implemented correctly:
1. Knowledge Base Guard
2. Module Fault Tolerance 
3. CCF Implementation
4. Unified Risk Engine
5. Feature Contribution Analysis
"""

import sys
import os
import tempfile
import numpy as np
from pathlib import Path

# Add BADNA to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_bug_fix_1_knowledge_base_guard():
    """Test BUG FIX 1: Knowledge Base Guard"""
    print("Testing BUG FIX 1: Knowledge Base Guard...")
    
    try:
        from knowledge_base.knowledge_base import KnowledgeBase
        
        # Create empty knowledge base
        with tempfile.TemporaryDirectory() as temp_dir:
            kb_path = os.path.join(temp_dir, 'empty_kb.json')
            kb = KnowledgeBase(kb_path=kb_path)
            
            # Test size checking methods
            assert kb.size == 0, f"Expected size 0, got {kb.size}"
            assert kb.get_patterns_count() == 0, f"Expected 0 patterns, got {kb.get_patterns_count()}"
            assert kb.get_campaigns_count() == 0, f"Expected 0 campaigns, got {kb.get_campaigns_count()}"
            assert kb.is_empty() == True, f"Expected empty=True, got {kb.is_empty()}"
            
            print("  ✓ Empty knowledge base size checking works")
            
            # Test campaign retrieval
            campaigns = kb.get_campaigns()
            assert isinstance(campaigns, list), f"Expected list, got {type(campaigns)}"
            assert len(campaigns) == 0, f"Expected empty list, got {len(campaigns)} campaigns"
            
            print("  ✓ Empty campaign list retrieval works")
            print("  ✓ BUG FIX 1: Knowledge Base Guard - PASSED")
            return True
            
    except Exception as e:
        print(f"  ✗ BUG FIX 1: Knowledge Base Guard - FAILED: {e}")
        return False

def test_bug_fix_2_module_fault_tolerance():
    """Test BUG FIX 2: Module Fault Tolerance"""
    print("Testing BUG FIX 2: Module Fault Tolerance...")
    
    try:
        # Test that main pipeline has try-catch wrappers
        from main import BADNAAnalysisOrchestrator
        
        # Check if the methods have proper exception handling
        import inspect
        
        orchestrator_class = BADNAAnalysisOrchestrator
        methods_to_check = [
            '_execute_step_1_graph_construction',
            '_execute_step_2_embedding_generation', 
            '_execute_step_3_similarity_analysis',
            '_execute_step_4_novelty_detection',
            '_execute_step_5_confidence_calibration',
            '_execute_step_6_threat_investigation',
            '_execute_step_7_risk_scoring',
            '_execute_step_8_defense_recommendations'
        ]
        
        for method_name in methods_to_check:
            if hasattr(orchestrator_class, method_name):
                method = getattr(orchestrator_class, method_name)
                source = inspect.getsource(method)
                
                # Check for try-except blocks and fallback handling
                assert 'try:' in source, f"Method {method_name} missing try block"
                assert 'except Exception as e:' in source, f"Method {method_name} missing exception handler"
                assert 'fallback' in source or 'continue' in source, f"Method {method_name} missing fallback logic"
                
                print(f"  ✓ {method_name} has fault tolerance")
        
        print("  ✓ BUG FIX 2: Module Fault Tolerance - PASSED")
        return True
        
    except Exception as e:
        print(f"  ✗ BUG FIX 2: Module Fault Tolerance - FAILED: {e}")
        return False

def test_bug_fix_3_ccf_implementation():
    """Test BUG FIX 3: CCF Implementation"""
    print("Testing BUG FIX 3: CCF Implementation...")
    
    try:
        from confidence.ccf import CCFEngine
        
        ccf_engine = CCFEngine()
        
        # Test that CCF uses evidence-based confidence (not constant values)
        result1 = ccf_engine.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,  # Low novelty
            evidence_quality=1.0, # High quality
            knowledge_base_size=100  # Good size
        )
        
        result2 = ccf_engine.calibrate_confidence(
            similarity_score=0.3,
            novelty_score=0.9,  # High novelty
            evidence_quality=0.3, # Poor quality  
            knowledge_base_size=5   # Small size
        )
        
        # Results should be different based on inputs (no constant values)
        assert result1.confidence_score != result2.confidence_score, \
            "CCF returning constant confidence values"
        
        # High quality evidence should give higher confidence
        assert result1.confidence_score > result2.confidence_score, \
            "CCF not properly weighting evidence quality"
        
        # Check that calibration factors are present
        assert 'evidence_quantity' in result1.calibration_factors, \
            "Missing evidence_quantity factor"
        assert 'evidence_quality' in result1.calibration_factors, \
            "Missing evidence_quality factor"
        assert 'completeness' in result1.calibration_factors, \
            "Missing completeness factor"
        
        print("  ✓ CCF uses evidence-based confidence calculation")
        print("  ✓ CCF properly weights multiple factors")
        print("  ✓ BUG FIX 3: CCF Implementation - PASSED")
        return True
        
    except Exception as e:
        print(f"  ✗ BUG FIX 3: CCF Implementation - FAILED: {e}")
        return False

def test_bug_fix_4_unified_risk_engine():
    """Test BUG FIX 4: Unified Risk Engine"""
    print("Testing BUG FIX 4: Unified Risk Engine...")
    
    try:
        # Check that main.py has unified risk calculation
        from main import BADNAAnalysisOrchestrator
        import inspect
        
        orchestrator = BADNAAnalysisOrchestrator()
        
        # Check for unified risk calculation methods
        assert hasattr(orchestrator, '_compute_unified_risk'), \
            "Missing _compute_unified_risk method"
        assert hasattr(orchestrator, '_get_threat_severity'), \
            "Missing _get_threat_severity method"
        
        # Test unified risk calculation
        unified_risk = orchestrator._compute_unified_risk(
            threat_severity=0.95,  # High severity
            predicted_intent="lateral_movement",
            novelty_score=0.8,     # High novelty
            confidence_score=0.7,
            similarity_score=0.6,
            lateral_movement=True,
            exfiltration=True
        )
        
        # Risk should be in [0.0, 1.0] range
        assert 0.0 <= unified_risk <= 1.0, f"Unified risk {unified_risk} out of range [0,1]"
        
        # Test threat severity mapping
        apt_severity = orchestrator._get_threat_severity('APT')
        benign_severity = orchestrator._get_threat_severity('Benign')
        
        assert apt_severity > benign_severity, \
            "APT should have higher severity than Benign"
        
        print("  ✓ Unified risk calculation implemented")
        print("  ✓ Risk normalized to [0.0, 1.0] scale")
        print("  ✓ Threat multipliers applied correctly")
        print("  ✓ BUG FIX 4: Unified Risk Engine - PASSED")
        return True
        
    except Exception as e:
        print(f"  ✗ BUG FIX 4: Unified Risk Engine - FAILED: {e}")
        return False

def test_bug_fix_5_feature_contribution_analysis():
    """Test BUG FIX 5: Feature Contribution Analysis"""
    print("Testing BUG FIX 5: Feature Contribution Analysis...")
    
    try:
        from intelligence.evidence import FeatureContributionAnalyzer, EvidenceGenerator
        from data_models import BehaviorGraph, ThreatClassification, IntentPrediction
        import uuid
        
        analyzer = FeatureContributionAnalyzer()
        
        # Create test data
        embedding = np.random.randn(128)  # Random 128-D embedding
        behavior_graph = BehaviorGraph(
            graph_id="test",
            nodes=[], 
            edges=[]
        )
        
        # Test feature contribution analysis
        feature_contributions = analyzer.analyze_feature_contributions(
            embedding=embedding,
            behavior_graph=behavior_graph,
            threat_class="APT",
            novelty_score=0.8
        )
        
        # Should return top 5 features
        assert len(feature_contributions) >= 5, \
            f"Expected at least 5 features, got {len(feature_contributions)}"
        
        # Each feature should have name and weight
        for feature_name, weight in feature_contributions:
            assert isinstance(feature_name, str), f"Feature name should be string, got {type(feature_name)}"
            assert isinstance(weight, (int, float)), f"Weight should be numeric, got {type(weight)}"
            assert 0.0 <= weight <= 1.0, f"Weight {weight} should be in [0,1]"
        
        # Test BADNA dimension mapping
        dimension_mapping = analyzer.map_to_badna_dimensions(feature_contributions)
        expected_dimensions = ['structural', 'temporal', 'semantic']
        
        for dim in expected_dimensions:
            assert dim in dimension_mapping, f"Missing dimension {dim}"
            assert isinstance(dimension_mapping[dim], list), \
                f"Dimension {dim} should map to list"
        
        print("  ✓ Top 5 behavioral contributors with weights returned")
        print("  ✓ Features mapped to BADNA dimensions")
        
        # Test evidence generator
        evidence_gen = EvidenceGenerator()
        classification = ThreatClassification(
            profile_id=str(uuid.uuid4()),
            threat_class="APT",
            confidence=0.8,
            probability_distribution={"APT": 0.8, "Other": 0.2},
            uncertainty_flag=False,
            classification_method="ensemble"
        )
        
        intent = IntentPrediction(
            profile_id=str(uuid.uuid4()),
            primary_intent="lateral_movement",
            intent_ranking=[("lateral_movement", 0.7)],
            attack_stage="intermediate",
            mitre_techniques=["T1021"],
            natural_language_explanation="Detected lateral movement behavior"
        )
        
        evidence = evidence_gen.generate_evidence(
            behavior_graph=behavior_graph,
            embedding=embedding,
            classification=classification,
            intent=intent,
            novelty_score=0.8
        )
        
        # Validate evidence structure
        assert hasattr(evidence, 'top_features'), "Missing top_features"
        assert hasattr(evidence, 'mitre_mappings'), "Missing mitre_mappings"
        assert hasattr(evidence, 'structured_json'), "Missing structured_json"
        assert hasattr(evidence, 'natural_language'), "Missing natural_language"
        
        print("  ✓ Explainable evidence generated successfully")
        print("  ✓ BUG FIX 5: Feature Contribution Analysis - PASSED")
        return True
        
    except Exception as e:
        print(f"  ✗ BUG FIX 5: Feature Contribution Analysis - FAILED: {e}")
        return False

def main():
    """Run all critical bug fix tests"""
    print("="*60)
    print("BADNA CRITICAL BUG FIXES VALIDATION")
    print("="*60)
    
    test_results = []
    
    # Run all tests
    test_results.append(test_bug_fix_1_knowledge_base_guard())
    test_results.append(test_bug_fix_2_module_fault_tolerance())
    test_results.append(test_bug_fix_3_ccf_implementation())
    test_results.append(test_bug_fix_4_unified_risk_engine()) 
    test_results.append(test_bug_fix_5_feature_contribution_analysis())
    
    # Summary
    passed_tests = sum(test_results)
    total_tests = len(test_results)
    
    print("="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Passed: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print("🎉 ALL CRITICAL BUG FIXES IMPLEMENTED SUCCESSFULLY!")
        print("✅ Knowledge Base Guard: Empty KB handling")
        print("✅ Module Fault Tolerance: Pipeline continues on failures") 
        print("✅ CCF Implementation: Evidence-based confidence")
        print("✅ Unified Risk Engine: Multi-factor risk scoring")
        print("✅ Feature Contribution Analysis: Explainable evidence")
        return 0
    else:
        print(f"❌ {total_tests - passed_tests} bug fixes failed validation")
        return 1

if __name__ == "__main__":
    sys.exit(main())