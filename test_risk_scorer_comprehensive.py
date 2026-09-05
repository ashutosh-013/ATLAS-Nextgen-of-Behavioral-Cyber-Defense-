"""
Comprehensive test for RiskScorer with realistic threat scenarios
Task 6.2: Unified Risk Scoring
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from confidence.ccf import RiskScorer
import json


def test_comprehensive_threat_scenarios():
    """Test RiskScorer with comprehensive realistic threat scenarios"""
    
    print("=" * 80)
    print("COMPREHENSIVE THREAT SCENARIO TESTING")
    print("Task 6.2: Unified Risk Scoring - RiskScorer Class Verification")
    print("=" * 80)
    
    risk_scorer = RiskScorer()
    
    scenarios = [
        {
            "name": "APT29 (Cozy Bear) - Known Campaign",
            "description": "Advanced Persistent Threat with high similarity to known campaign",
            "params": {
                "similarity_score": 0.92,  # High similarity to known APT campaign
                "novelty_score": 0.15,     # Known behavior patterns
                "confidence_score": 0.88,  # High confidence
                "threat_class": "APT",
                "lateral_movement": True,
                "exfiltration": True
            },
            "expected_risk_level": "Critical"
        },
        {
            "name": "WannaCry-Style Ransomware",
            "description": "Ransomware with known propagation patterns",
            "params": {
                "similarity_score": 0.85,
                "novelty_score": 0.25,
                "confidence_score": 0.90,
                "threat_class": "Ransomware",
                "lateral_movement": True,
                "exfiltration": False
            },
            "expected_risk_level": "Critical"
        },
        {
            "name": "Zero-Day Ransomware Attack",
            "description": "Never-before-seen ransomware variant",
            "params": {
                "similarity_score": 0.25,  # Low similarity to known threats
                "novelty_score": 0.95,     # Highly novel behavior
                "confidence_score": 0.55,  # Moderate confidence due to novelty
                "threat_class": "Ransomware",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Critical"
        },
        {
            "name": "Insider Threat - Data Exfiltration",
            "description": "Insider attempting to steal sensitive data",
            "params": {
                "similarity_score": 0.70,
                "novelty_score": 0.40,
                "confidence_score": 0.80,
                "threat_class": "Insider_Threat",
                "lateral_movement": False,
                "exfiltration": True
            },
            "expected_risk_level": "High"
        },
        {
            "name": "Insider Threat - Low Confidence",
            "description": "Potential insider threat with uncertain indicators",
            "params": {
                "similarity_score": 0.50,
                "novelty_score": 0.35,
                "confidence_score": 0.40,  # Low confidence
                "threat_class": "Insider_Threat",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Medium"
        },
        {
            "name": "Commodity Malware - Known Trojan",
            "description": "Common malware with well-known signatures",
            "params": {
                "similarity_score": 0.88,
                "novelty_score": 0.10,
                "confidence_score": 0.92,
                "threat_class": "Malware",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "High"
        },
        {
            "name": "Polymorphic Malware Variant",
            "description": "Malware with behavior variations",
            "params": {
                "similarity_score": 0.60,
                "novelty_score": 0.65,  # Moderately novel
                "confidence_score": 0.70,
                "threat_class": "Malware",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "High"
        },
        {
            "name": "Spear Phishing Campaign",
            "description": "Targeted phishing with credential harvesting",
            "params": {
                "similarity_score": 0.75,
                "novelty_score": 0.30,
                "confidence_score": 0.85,
                "threat_class": "Phishing",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Medium"
        },
        {
            "name": "Generic Phishing Attempt",
            "description": "Mass phishing campaign",
            "params": {
                "similarity_score": 0.82,
                "novelty_score": 0.15,
                "confidence_score": 0.88,
                "threat_class": "Phishing",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Medium"
        },
        {
            "name": "Benign Software Update",
            "description": "Legitimate software update activity",
            "params": {
                "similarity_score": 0.45,
                "novelty_score": 0.20,
                "confidence_score": 0.95,
                "threat_class": "Benign",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Minimal"
        },
        {
            "name": "Benign Admin Activity",
            "description": "Legitimate system administration",
            "params": {
                "similarity_score": 0.35,
                "novelty_score": 0.10,
                "confidence_score": 0.90,
                "threat_class": "Benign",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Minimal"
        },
        {
            "name": "Unknown Activity - Missing Data",
            "description": "Insufficient data for analysis",
            "params": {
                "similarity_score": 0.0,
                "novelty_score": 0.0,
                "confidence_score": 0.0,
                "threat_class": "Malware",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "Medium"  # Conservative estimate
        },
        {
            "name": "APT with Lateral Movement",
            "description": "APT actively moving laterally in network",
            "params": {
                "similarity_score": 0.78,
                "novelty_score": 0.45,
                "confidence_score": 0.82,
                "threat_class": "APT",
                "lateral_movement": True,
                "exfiltration": False
            },
            "expected_risk_level": "Critical"
        },
        {
            "name": "Data Breach in Progress",
            "description": "Active data exfiltration detected",
            "params": {
                "similarity_score": 0.68,
                "novelty_score": 0.55,
                "confidence_score": 0.75,
                "threat_class": "APT",
                "lateral_movement": True,
                "exfiltration": True
            },
            "expected_risk_level": "Critical"
        },
        {
            "name": "Novel Attack Vector",
            "description": "Completely unknown attack technique",
            "params": {
                "similarity_score": 0.10,
                "novelty_score": 0.98,
                "confidence_score": 0.45,
                "threat_class": "Malware",
                "lateral_movement": False,
                "exfiltration": False
            },
            "expected_risk_level": "High"
        }
    ]
    
    print("\nTesting {} threat scenarios...\n".format(len(scenarios)))
    
    results = []
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'─' * 80}")
        print(f"Scenario {i}: {scenario['name']}")
        print(f"{'─' * 80}")
        print(f"Description: {scenario['description']}")
        
        params = scenario['params']
        print(f"\nInput Parameters:")
        print(f"  • Similarity Score: {params['similarity_score']:.2f}")
        print(f"  • Novelty Score: {params['novelty_score']:.2f}")
        print(f"  • Confidence Score: {params['confidence_score']:.2f}")
        print(f"  • Threat Class: {params['threat_class']}")
        print(f"  • Lateral Movement: {params['lateral_movement']}")
        print(f"  • Exfiltration: {params['exfiltration']}")
        
        result = risk_scorer.compute_risk(**params)
        
        print(f"\nRisk Assessment:")
        print(f"  • Risk Score: {result['score']:.3f}")
        print(f"  • Risk Level: {result['risk_level']}")
        print(f"  • Expected Level: {scenario['expected_risk_level']}")
        
        # Check if risk level matches expected
        level_match = result['risk_level'] == scenario['expected_risk_level']
        print(f"  • Level Match: {'✓ YES' if level_match else '✗ NO'}")
        
        print(f"\nContributing Factors:")
        for factor, value in result['contributing_factors'].items():
            if value != 0:  # Only show non-zero factors
                print(f"  • {factor.replace('_', ' ').title()}: {value:.3f}")
        
        print(f"\nRationale:")
        print(f"  {result['rationale']}")
        
        results.append({
            'scenario': scenario['name'],
            'score': result['score'],
            'level': result['risk_level'],
            'expected_level': scenario['expected_risk_level'],
            'match': level_match
        })
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    matches = sum(1 for r in results if r['match'])
    total = len(results)
    
    print(f"\nTotal Scenarios: {total}")
    print(f"Risk Level Matches: {matches}/{total} ({matches/total*100:.1f}%)")
    
    # Group by risk level
    by_level = {}
    for r in results:
        level = r['level']
        if level not in by_level:
            by_level[level] = []
        by_level[level].append(r['scenario'])
    
    print("\nThreat Distribution by Risk Level:")
    for level in ['Critical', 'High', 'Medium', 'Low', 'Minimal']:
        if level in by_level:
            count = len(by_level[level])
            print(f"  • {level}: {count} scenarios")
            for scenario in by_level[level]:
                print(f"    - {scenario}")
    
    # Verify all requirements are satisfied
    print("\n" + "=" * 80)
    print("REQUIREMENTS VERIFICATION")
    print("=" * 80)
    
    all_requirements_pass = True
    
    # Check 10.1: All scores in [0, 1]
    req_10_1 = all(0.0 <= r['score'] <= 1.0 for r in results)
    print(f"\n10.1 Risk scores in [0.0, 1.0]: {'✓ PASS' if req_10_1 else '✗ FAIL'}")
    all_requirements_pass = all_requirements_pass and req_10_1
    
    # Check 10.3: APT/Ransomware have higher risk
    apt_scores = [r['score'] for r in results if 'APT' in r['scenario'] or 'Ransomware' in r['scenario']]
    benign_scores = [r['score'] for r in results if 'Benign' in r['scenario']]
    req_10_3 = all(apt > max(benign_scores) for apt in apt_scores if apt_scores and benign_scores)
    print(f"10.3 APT/Ransomware higher than Benign: {'✓ PASS' if req_10_3 else '✗ FAIL'}")
    all_requirements_pass = all_requirements_pass and req_10_3
    
    # Check 10.10: Conservative estimation for missing data
    missing_data_result = [r for r in results if 'Missing Data' in r['scenario']]
    req_10_10 = all(r['score'] >= 0.3 for r in missing_data_result)  # Should be at least Medium risk
    print(f"10.10 Conservative estimation for missing data: {'✓ PASS' if req_10_10 else '✗ FAIL'}")
    all_requirements_pass = all_requirements_pass and req_10_10
    
    print("\n" + "=" * 80)
    print(f"{'✓ ALL REQUIREMENTS SATISFIED' if all_requirements_pass else '✗ SOME REQUIREMENTS FAILED'}")
    print("=" * 80)
    
    return results


if __name__ == "__main__":
    results = test_comprehensive_threat_scenarios()
    print("\n✓ Comprehensive threat scenario testing completed!")
