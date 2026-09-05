#!/usr/bin/env python3
"""
BADNA End-to-End Demonstration

This demo shows the complete BADNA analysis pipeline working with realistic
threat scenarios. It demonstrates:

1. Behavioral capture and graph construction
2. Feature engineering and d-BEF embedding
3. Similarity computation (BSF) and novelty detection (NSF) 
4. Confidence calibration (CCF) and risk scoring
5. AI threat classification and intent prediction
6. Knowledge base learning and campaign clustering
7. Feedback processing and model evolution

Usage: python demo_end_to_end.py
"""

import json
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import time

# Import BADNA components
from data_models import *
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.dbef import compute_badna_embedding
from similarity.bsf import BSFEngine
from novelty.nsf import NSFEngine, MockKnowledgeBase
from confidence.ccf import CCFEngine, RiskScorer
from intelligence.investigator import AIInvestigator
from knowledge_base.knowledge_base import KnowledgeBase
from learning.knowledge_update import KnowledgeUpdater
from config import get_logger, get_config


class BADNADemo:
    """Complete BADNA system demonstration."""
    
    def __init__(self):
        """Initialize demo components."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Initialize all BADNA components
        self.capture_engine = BehaviorCaptureEngine()
        self.bsf_engine = BSFEngine()
        self.nsf_engine = NSFEngine()
        self.ccf_engine = CCFEngine()
        self.risk_scorer = RiskScorer()
        self.ai_investigator = AIInvestigator()
        
        # Initialize knowledge management
        self.knowledge_base = KnowledgeBase()
        self.knowledge_updater = KnowledgeUpdater()
        
        print(" BADNA End-to-End Demonstration System Initialized")
        print("=" * 80)
    
    def create_realistic_threat_scenarios(self):
        """Create realistic threat scenario data."""
        scenarios = {
            'apt_attack': {
                'name': 'APT Lateral Movement Attack',
                'threat_class': 'APT',
                'events': [
                    {
                        "event_type": "auth",
                        "timestamp": "2024-07-04T09:30:00",
                        "source_system": "Domain Controller",
                        "event_data": {
                            "user": "service_account",
                            "action": "login",
                            "source_ip": "192.168.1.50",
                            "status": "success"
                        }
                    },
                    {
                        "event_type": "process",
                        "timestamp": "2024-07-04T09:30:15",
                        "source_system": "EDR",
                        "event_data": {
                            "pid": 2547,
                            "action": "create",
                            "name": "powershell.exe",
                            "command": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden"
                        }
                    },
                    {
                        "event_type": "network",
                        "timestamp": "2024-07-04T09:30:30",
                        "source_system": "Firewall",
                        "event_data": {
                            "action": "dns",
                            "domain": "temp-files.azureedge.net",
                            "ip": "192.168.1.50",
                            "protocol": "DNS"
                        }
                    },
                    {
                        "event_type": "auth",
                        "timestamp": "2024-07-04T09:31:00",
                        "source_system": "Domain Controller",
                        "event_data": {
                            "user": "service_account",
                            "action": "escalate",
                            "from_privilege": "user",
                            "to_privilege": "admin"
                        }
                    },
                    {
                        "event_type": "process",
                        "timestamp": "2024-07-04T09:31:30",
                        "source_system": "EDR",
                        "event_data": {
                            "pid": 2548,
                            "action": "create",
                            "name": "mimikatz.exe",
                            "command": "mimikatz.exe sekurlsa::logonpasswords"
                        }
                    },
                    {
                        "event_type": "network",
                        "timestamp": "2024-07-04T09:32:00",
                        "source_system": "Network Monitor",
                        "event_data": {
                            "action": "http",
                            "url": "http://192.168.1.100/admin/config",
                            "method": "POST",
                            "source_ip": "192.168.1.50"
                        }
                    }
                ]
            },
            
            'ransomware_attack': {
                'name': 'Ransomware File Encryption Attack',
                'threat_class': 'Ransomware',
                'events': [
                    {
                        "event_type": "process",
                        "timestamp": "2024-07-04T14:15:00",
                        "source_system": "EDR",
                        "event_data": {
                            "pid": 1337,
                            "action": "create",
                            "name": "encrypt.exe",
                            "command": "encrypt.exe --recursive --target C:\\Users"
                        }
                    },
                    {
                        "event_type": "file",
                        "timestamp": "2024-07-04T14:15:30",
                        "source_system": "File Monitor",
                        "event_data": {
                            "path": "C:\\Users\\Documents\\important.docx",
                            "action": "encrypt",
                            "original_size": 2048,
                            "encrypted_size": 2560
                        }
                    },
                    {
                        "event_type": "file",
                        "timestamp": "2024-07-04T14:16:00",
                        "source_system": "File Monitor",
                        "event_data": {
                            "path": "C:\\Users\\Desktop\\README_RANSOM.txt",
                            "action": "write",
                            "content": "Your files are encrypted. Pay Bitcoin to recover."
                        }
                    },
                    {
                        "event_type": "registry",
                        "timestamp": "2024-07-04T14:16:15",
                        "source_system": "EDR",
                        "event_data": {
                            "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "action": "modify",
                            "value": "ransom_note.exe"
                        }
                    },
                    {
                        "event_type": "network",
                        "timestamp": "2024-07-04T14:17:00",
                        "source_system": "Firewall",
                        "event_data": {
                            "action": "http",
                            "url": "http://darkweb-payment.onion/payment",
                            "method": "POST",
                            "protocol": "TOR"
                        }
                    }
                ]
            },
            
            'benign_activity': {
                'name': 'Normal Administrative Activity',
                'threat_class': 'Benign',
                'events': [
                    {
                        "event_type": "auth",
                        "timestamp": "2024-07-04T11:00:00",
                        "source_system": "Domain Controller",
                        "event_data": {
                            "user": "admin_user",
                            "action": "login",
                            "source_ip": "192.168.1.25",
                            "status": "success"
                        }
                    },
                    {
                        "event_type": "process",
                        "timestamp": "2024-07-04T11:00:30",
                        "source_system": "EDR",
                        "event_data": {
                            "pid": 1024,
                            "action": "create",
                            "name": "cmd.exe",
                            "command": "cmd.exe /c dir C:\\Windows\\System32"
                        }
                    },
                    {
                        "event_type": "file",
                        "timestamp": "2024-07-04T11:01:00",
                        "source_system": "File Monitor",
                        "event_data": {
                            "path": "C:\\Admin\\logs\\maintenance.log",
                            "action": "write",
                            "size": 512
                        }
                    }
                ]
            },
            
            'insider_threat': {
                'name': 'Insider Data Exfiltration',
                'threat_class': 'Insider_Threat',
                'events': [
                    {
                        "event_type": "auth",
                        "timestamp": "2024-07-04T18:45:00",
                        "source_system": "VPN Gateway",
                        "event_data": {
                            "user": "employee_john",
                            "action": "login",
                            "source_ip": "203.0.113.50",
                            "location": "unusual_location"
                        }
                    },
                    {
                        "event_type": "file",
                        "timestamp": "2024-07-04T18:46:00",
                        "source_system": "DLP Agent",
                        "event_data": {
                            "path": "C:\\Confidential\\customer_database.xlsx",
                            "action": "read",
                            "user": "employee_john",
                            "size": 50000000
                        }
                    },
                    {
                        "event_type": "file",
                        "timestamp": "2024-07-04T18:47:30",
                        "source_system": "DLP Agent",
                        "event_data": {
                            "path": "C:\\Users\\john\\Downloads\\data_copy.zip",
                            "action": "write",
                            "size": 48000000,
                            "compression": "high"
                        }
                    },
                    {
                        "event_type": "network",
                        "timestamp": "2024-07-04T18:48:00",
                        "source_system": "Network Monitor",
                        "event_data": {
                            "action": "upload",
                            "destination": "personal-cloud-drive.com",
                            "size": 48000000,
                            "protocol": "HTTPS"
                        }
                    },
                    {
                        "event_type": "user",
                        "timestamp": "2024-07-04T18:50:00",
                        "source_system": "Endpoint Monitor",
                        "event_data": {
                            "action": "usb",
                            "device": "external_drive",
                            "operation": "connect"
                        }
                    }
                ]
            }
        }
        
        return scenarios
    
    def analyze_threat_scenario(self, scenario_name, scenario_data):
        """Analyze a complete threat scenario through the BADNA pipeline."""
        print(f"\n ANALYZING: {scenario_data['name']}")
        print(f"Expected Threat Class: {scenario_data['threat_class']}")
        print("-" * 60)
        
        start_time = time.time()
        
        try:
            # Step 1: Parse events and build behavior graph
            print("1. Behavioral Capture & Graph Construction...")
            parsed_events = self.capture_engine.parse_events(scenario_data['events'])
            behavior_graph = self.capture_engine.build_graph(parsed_events)
            
            print(f"    Events: {len(parsed_events)} parsed")
            print(f"    Graph: {behavior_graph.node_count} nodes, {behavior_graph.edge_count} edges")
            
            # Step 2: Generate BADNA embedding
            print("2. d-BEF Embedding Generation...")
            badna_embedding = compute_badna_embedding(behavior_graph)
            print(f"    Embedding: {len(badna_embedding.vector)}-D vector (norm: {np.linalg.norm(badna_embedding.vector):.6f})")
            
            # Step 3: Similarity analysis
            print("3. BSF Similarity Analysis...")
            # Compare against known patterns in knowledge base
            kb_patterns = list(self.knowledge_base.patterns.values())
            if kb_patterns:
                similar_patterns = self.knowledge_base.query_by_similarity(
                    badna_embedding.vector, threshold=0.7
                )
                if similar_patterns:
                    best_match = similar_patterns[0]
                    print(f"    Similar pattern found: {best_match[1]:.3f} similarity ({best_match[0].threat_class})")
                    similarity_score = best_match[1]
                    matched_campaign = best_match[0].pattern_id
                else:
                    print("    No similar patterns found (similarity < 0.7)")
                    similarity_score = 0.0
                    matched_campaign = None
            else:
                print("    No existing patterns in knowledge base")
                similarity_score = 0.0
                matched_campaign = None
            
            # Step 4: Novelty detection
            print("4. NSF Novelty Detection...")
            # Use existing patterns as knowledge base
            mock_kb = MockKnowledgeBase()
            for pattern in kb_patterns[:10]:  # Use first 10 patterns
                mock_kb.add_pattern(pattern)
            
            novelty_result = self.nsf_engine.compute_novelty(badna_embedding.vector, mock_kb)
            print(f"    Novelty: {novelty_result.novelty_score:.3f} ({novelty_result.novelty_category})")
            
            # Step 5: Confidence calibration
            print("5. CCF Confidence Calibration...")
            confidence_result = self.ccf_engine.calibrate_confidence(
                similarity_score=similarity_score,
                novelty_score=novelty_result.novelty_score,
                evidence_quality=0.9,
                knowledge_base_size=len(kb_patterns)
            )
            print(f"    Confidence: {confidence_result.confidence_score:.3f}")
            
            # Step 6: AI threat classification and intent prediction
            print("6. AI Investigator Analysis...")
            classification = self.ai_investigator.classify_threat(
                badna_embedding.vector, 
                similarity_score=similarity_score,
                matched_campaign=matched_campaign
            )
            
            intent = self.ai_investigator.predict_intent(badna_embedding.vector, behavior_graph)
            
            evidence = self.ai_investigator.generate_evidence(
                behavior_graph, badna_embedding.vector, classification, intent,
                novelty_score=novelty_result.novelty_score
            )
            
            print(f"    Classification: {classification.threat_class} (confidence: {classification.confidence:.3f})")
            print(f"    Intent: {intent.primary_intent} ({intent.attack_stage} stage)")
            print(f"    Evidence: {len(evidence.top_features)} key features identified")
            
            # Step 7: Risk scoring
            print("7. Risk Assessment...")
            risk_result = self.risk_scorer.compute_risk(
                similarity_score=similarity_score,
                novelty_score=novelty_result.novelty_score,
                confidence_score=confidence_result.confidence_score,
                threat_class=classification.threat_class,
                lateral_movement='lateral_movement' in intent.primary_intent,
                exfiltration='exfiltration' in intent.primary_intent
            )
            
            print(f"    Risk Score: {risk_result['score']:.3f} ({risk_result['risk_level']})")
            
            # Step 8: Generate complete BADNA profile
            print("8. BADNA Profile Generation...")
            profile = create_badna_profile()
            
            # Populate profile fields
            profile.embedding = badna_embedding
            profile.similarity_result = SimilarityResult(
                query_embedding_id=badna_embedding.embedding_id,
                target_embedding_id=matched_campaign or "none",
                similarity_score=similarity_score,
                similarity_category="dissimilar" if similarity_score < 0.6 else 
                                 "moderately_similar" if similarity_score < 0.85 else "highly_similar",
                component_scores={
                    "structural": similarity_score * 0.3,
                    "temporal": similarity_score * 0.2, 
                    "semantic": similarity_score * 0.5
                }
            )
            profile.novelty_result = novelty_result
            profile.confidence_result = confidence_result
            profile.threat_classification = classification
            profile.intent_prediction = intent
            profile.evidence = evidence
            profile.risk_score = RiskScore(
                profile_id=profile.profile_id,
                score=risk_result['score'],
                risk_level=risk_result['risk_level'],
                contributing_factors=risk_result.get('factors', {}),
                rationale=risk_result.get('rationale', f"Risk assessed as {risk_result['risk_level']}")
            )
            profile.matched_campaign_id = matched_campaign
            
            print(f"    Profile ID: {profile.profile_id}")
            
            # Step 9: Update knowledge base with new pattern
            print("9. Knowledge Base Learning...")
            new_pattern = BehaviorPattern(
                embedding=badna_embedding.vector,
                threat_class=scenario_data['threat_class'],  # Ground truth for demo
                confidence_score=confidence_result.confidence_score,
                source=f"demo_{scenario_name}",
                metadata={
                    'scenario': scenario_name,
                    'event_count': len(parsed_events),
                    'risk_level': risk_result['risk_level']
                }
            )
            
            pattern_id = self.knowledge_base.store_pattern(new_pattern)
            print(f"    Pattern stored: {pattern_id}")
            
            analysis_time = time.time() - start_time
            
            # Results summary
            print(f"\n ANALYSIS RESULTS ({analysis_time:.2f}s)")
            print(f"   Expected Class: {scenario_data['threat_class']}")
            print(f"   Detected Class: {classification.threat_class}")
            print(f"   Accuracy: {'' if classification.threat_class == scenario_data['threat_class'] else ''}")
            print(f"   Risk Level: {risk_result['risk_level']}")
            print(f"   Intent: {intent.primary_intent}")
            print(f"   Novelty: {novelty_result.novelty_category}")
            
            return {
                'profile': profile,
                'accuracy': classification.threat_class == scenario_data['threat_class'],
                'analysis_time': analysis_time,
                'risk_level': risk_result['risk_level'],
                'confidence': classification.confidence
            }
            
        except Exception as e:
            print(f"    Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def test_learning_system(self):
        """Test the feedback and learning system."""
        print(f"\n TESTING LEARNING SYSTEM")
        print("-" * 60)
        
        # Simulate analyst feedback
        feedback_scenarios = [
            {
                'profile_id': 'demo-apt-001',
                'feedback_type': 'true_positive',
                'analyst_notes': 'Confirmed APT attack with lateral movement'
            },
            {
                'profile_id': 'demo-ransomware-001', 
                'feedback_type': 'true_positive',
                'analyst_notes': 'Confirmed ransomware with file encryption'
            },
            {
                'profile_id': 'demo-benign-001',
                'feedback_type': 'false_positive',
                'analyst_notes': 'Normal admin activity, not malicious'
            }
        ]
        
        print("Processing analyst feedback...")
        for i, scenario in enumerate(feedback_scenarios, 1):
            feedback = Feedback(
                profile_id=scenario['profile_id'],
                feedback_type=scenario['feedback_type'],
                analyst_id='demo_analyst',
                analyst_notes=scenario['analyst_notes']
            )
            
            result = self.knowledge_updater.process_analyst_feedback(feedback)
            print(f"   {i}. {scenario['feedback_type']}: {'' if result.feedback_processed else ''}")
        
        # Check retraining triggers
        print("\nChecking model evolution triggers...")
        from learning.evolution import get_model_evolution
        evolution = get_model_evolution()
        trigger_status = evolution.check_retraining_triggers()
        
        print(f"   KB Growth: {trigger_status.get('kb_growth_since_last_training', 0)} patterns")
        print(f"   Retraining Recommended: {trigger_status.get('retraining_recommended', False)}")
        
        # Get learning statistics
        learning_stats = self.knowledge_updater.get_learning_statistics()
        kb_stats = learning_stats.get('knowledge_base', {})
        print(f"   Total Patterns: {kb_stats.get('total_patterns', 0)}")
        print(f"   Total Campaigns: {kb_stats.get('total_campaigns', 0)}")
    
    def run_complete_demo(self):
        """Run the complete end-to-end demonstration."""
        print(" BADNA END-TO-END DEMONSTRATION")
        print("Analyzing Multiple Threat Scenarios")
        print("=" * 80)
        
        # Get threat scenarios
        scenarios = self.create_realistic_threat_scenarios()
        
        results = []
        correct_classifications = 0
        total_scenarios = len(scenarios)
        
        # Analyze each scenario
        for scenario_name, scenario_data in scenarios.items():
            result = self.analyze_threat_scenario(scenario_name, scenario_data)
            if result:
                results.append(result)
                if result['accuracy']:
                    correct_classifications += 1
        
        # Test learning system
        self.test_learning_system()
        
        # Overall results
        accuracy = correct_classifications / total_scenarios if total_scenarios > 0 else 0
        avg_analysis_time = sum(r['analysis_time'] for r in results) / len(results) if results else 0
        
        print(f"\n OVERALL DEMONSTRATION RESULTS")
        print("=" * 80)
        print(f"   Total Scenarios: {total_scenarios}")
        print(f"   Correct Classifications: {correct_classifications}")
        print(f"   Overall Accuracy: {accuracy:.1%}")
        print(f"   Average Analysis Time: {avg_analysis_time:.2f}s")
        print(f"   Knowledge Base Size: {len(self.knowledge_base.patterns)} patterns")
        
        # Risk distribution
        risk_levels = [r['risk_level'] for r in results]
        risk_distribution = {level: risk_levels.count(level) for level in set(risk_levels)}
        print(f"   Risk Distribution: {risk_distribution}")
        
        # Performance assessment
        performance_score = (accuracy * 0.6 + 
                           (1.0 if avg_analysis_time < 5.0 else 0.5) * 0.2 +
                           (1.0 if len(self.knowledge_base.patterns) > 0 else 0.0) * 0.2)
        
        print(f"\n   Performance Score: {performance_score:.1%}")
        
        if performance_score > 0.8:
            print("   Status:  EXCELLENT - BADNA system fully functional!")
        elif performance_score > 0.6:
            print("   Status:  GOOD - BADNA system working well")
        else:
            print("   Status:  NEEDS IMPROVEMENT - Some issues detected")
        
        return {
            'accuracy': accuracy,
            'analysis_time': avg_analysis_time,
            'performance_score': performance_score,
            'scenarios_analyzed': total_scenarios,
            'risk_distribution': risk_distribution
        }


def main():
    """Main demonstration entry point."""
    try:
        # Initialize and run demo
        demo = BADNADemo()
        results = demo.run_complete_demo()
        
        print(f"\n Demo completed successfully!")
        print(f"Results summary: {results}")
        
        return 0
        
    except Exception as e:
        print(f" Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())