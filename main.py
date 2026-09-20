"""
BADNA Main Analysis Orchestrator

This is the main entry point for the BADNA (Behavioral Attack DNA Analysis) framework.
It orchestrates the complete end-to-end analysis pipeline following the FROZEN architecture:

Events → Graph → Features → Embedding → Similarity/Novelty → Classification → Risk Scoring → Recommendations

Pipeline Components:
1. BehaviorCaptureEngine: Events → Behavior Graph  
2. d-BEF: Graph → 128D Embedding
3. BSF: Embedding → Similarity Score + Campaign Match
4. NSF: Embedding → Novelty Score  
5. CCF: Similarity/Novelty → Confidence Score
6. AIInvestigator: Embedding → Threat Classification + Intent + Evidence
7. RiskScorer: All Results → Unified Risk Score
8. BADNAProfile: Complete Analysis Output

Requirements: 11.1-11.11, 18.1, 12.10
Task: 10.1 - Implement end-to-end analysis orchestration
"""

import json
import sys
import time
import uuid
import argparse
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Core BADNA components
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.dbef import compute_badna_embedding
from similarity.bsf import BSFEngine
from novelty.nsf import NSFEngine
from confidence.ccf import CCFEngine, RiskScorer
from intelligence.investigator import AIInvestigator
from intelligence.adaptive_defense import AdaptiveDefenseIntelligence
from knowledge_base.knowledge_base import initialize_knowledge_base
from intelligence.ioc_monitor import IOCMonitorEngine

# Enterprise NGAV Upgrades
from ingestion.pre_filter import StaticPreFilterEngine
from intelligence.authenticode import AuthenticodeEngine
from behavior.canary_engine import CanaryTrapEngine
from intelligence.amsi_scanner import AMSIScanner
from intelligence.rollback import VSSRollbackManager
from intelligence.self_defense import SelfDefenseEngine

# Data models and configuration
from data_models import (
    BADNAProfile, SecurityEvent, BehaviorGraph, BADNAEmbedding,
    ThreatClassification, IntentPrediction, Evidence, 
    create_badna_profile
)
from config import (
    initialize_config, get_config, get_logger, get_degradation,
    BADNAError, ValidationError, ProcessingError, ResourceError
)


class BADNAAnalysisOrchestrator:
    """
    Main BADNA Analysis Orchestrator implementing the FROZEN pipeline.
    
    This class coordinates all BADNA components to provide complete end-to-end
    behavioral attack analysis from raw security events to actionable intelligence.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the BADNA Analysis Orchestrator.
        
        Args:
            config_path: Optional path to configuration file
        """
        # Initialize configuration and logging
        self.config = initialize_config(config_path)
        self.logger = get_logger()
        self.degradation = get_degradation()
        
        # Initialize knowledge base
        self.knowledge_base = initialize_knowledge_base(
            kb_path=Path(self.config.knowledge_base_path) / "behavior_memory.json",
            campaigns_path=Path(self.config.knowledge_base_path) / "campaigns.json"
        )
        
        # Initialize core engines
        self._initialize_engines()
        
        self.logger.log_operation(
            "INFO", 
            "BADNA Analysis Orchestrator initialized successfully",
            component="BADNAOrchestrator"
        )
    
    def _initialize_engines(self):
        """Initialize all BADNA analysis engines."""
        try:
            # Core analysis engines following FROZEN pipeline
            self.capture_engine = BehaviorCaptureEngine()
            self.bsf_engine = BSFEngine()
            self.nsf_engine = NSFEngine()
            self.ccf_engine = CCFEngine()
            self.risk_scorer = RiskScorer()
            self.ai_investigator = AIInvestigator()
            self.adaptive_defense = AdaptiveDefenseIntelligence()
            self.ioc_monitor = IOCMonitorEngine(self.knowledge_base)
            self.ioc_monitor.start_scheduler()
            # Enterprise NGAV Upgrade Engines
            self.pre_filter = StaticPreFilterEngine()
            self.authenticode_engine = AuthenticodeEngine()
            self.canary_engine = CanaryTrapEngine()
            self.amsi_scanner = AMSIScanner()
            self.vss_manager = VSSRollbackManager()
            self.self_defense = SelfDefenseEngine()
            self.self_defense.start_watchdog()
            
            self.logger.log_operation(
                "INFO",
                "All BADNA engines initialized successfully",
                component="BADNAOrchestrator",
                operation="initialize_engines"
            )
            
        except Exception as e:
            raise ProcessingError(f"Failed to initialize BADNA engines: {e}")
            
    def __del__(self):
        """Clean up orchestrator by stopping background scheduler"""
        if hasattr(self, 'ioc_monitor'):
            try:
                self.ioc_monitor.stop_scheduler()
            except:
                pass
    
    def analyze_events(self, raw_events: List[Dict[str, Any]], 
                      profile_id: Optional[str] = None) -> BADNAProfile:
        """
        Complete end-to-end analysis of security events following FROZEN pipeline.
        
        Args:
            raw_events: List of raw security event dictionaries
            profile_id: Optional custom profile ID
            
        Returns:
            BADNAProfile with complete analysis results
            
        Pipeline:
            1. Events → Graph (BehaviorCaptureEngine)
            2. Graph → Features → Embedding (d-BEF) 
            3. Embedding → Similarity + Campaign Match (BSF)
            4. Embedding → Novelty Score (NSF)
            5. Similarity/Novelty → Confidence (CCF)
            6. Embedding → Classification + Intent + Evidence (AIInvestigator)
            7. All Results → Risk Score (RiskScorer)
            8. Complete BADNAProfile Assembly
        """
        start_time = time.time()
        
        # Create BADNA profile
        profile = create_badna_profile() if not profile_id else BADNAProfile(profile_id=profile_id)
        
        try:
            # Validate input
            if not raw_events:
                raise ValidationError("No events provided for analysis")
            
            self.logger.log_operation(
                "INFO",
                f"Starting BADNA analysis of {len(raw_events)} events",
                component="BADNAOrchestrator",
                operation="analyze_events",
                profile_id=profile.profile_id
            )
            
            # Continuous IOC & Signature Monitoring (Runs in parallel with behavior capture)
            ioc_matches = []
            for event in raw_events:
                match = self.ioc_monitor.check_event(event)
                if match:
                    ioc_matches.append(match)
            if ioc_matches:
                profile.metadata["ioc_matches"] = ioc_matches
            
            # STEP 1: Events → Behavior Graph (Behavioral Capture Engine)
            behavior_graph = self._execute_step_1_graph_construction(raw_events)
            
            # STEP 2: Graph → 128D Embedding (d-BEF)  
            embedding = self._execute_step_2_embedding_generation(behavior_graph)
            profile.embedding = embedding
            
            # STEP 3: Embedding → Similarity + Campaign Match (BSF)
            similarity_result, campaign_match = self._execute_step_3_similarity_analysis(embedding)
            profile.similarity_result = similarity_result
            if campaign_match:
                profile.matched_campaign_id = campaign_match.get('campaign_id')
            
            # STEP 4: Embedding → Novelty Score (NSF)
            novelty_result = self._execute_step_4_novelty_detection(embedding)
            profile.novelty_result = novelty_result
            
            # STEP 5: Similarity/Novelty → Confidence (CCF)
            confidence_result = self._execute_step_5_confidence_calibration(
                similarity_result, novelty_result, campaign_match
            )
            profile.confidence_result = confidence_result
            
            # STEP 6: Embedding → Classification + Intent + Evidence (AI Investigator)
            first_ioc_match = ioc_matches[0] if ioc_matches else None
            classification, intent, evidence = self._execute_step_6_threat_investigation(
                embedding, behavior_graph, similarity_result, novelty_result, first_ioc_match
            )
            profile.threat_classification = classification
            profile.intent_prediction = intent
            profile.evidence = evidence
            
            # STEP 7: All Results → Risk Score (Risk Scorer)
            risk_score = self._execute_step_7_risk_scoring(
                similarity_result, novelty_result, confidence_result, 
                classification, intent
            )
            profile.risk_score = risk_score
            
            # STEP 8: Generate Defense Recommendations (Adaptive Defense Intelligence)
            defense_recommendations = self._execute_step_8_defense_recommendations(profile)
            
            # STEP 9: Finalize profile with metadata
            profile.config = self.config.to_dict()
            profile.timestamp = datetime.now()
            
            # Add defense recommendations to profile metadata if not already included
            if not hasattr(profile, 'defense_recommendations'):
                if not hasattr(profile, 'metadata'):
                    profile.metadata = {}
                # Store defense recommendations safely to prevent circular reference
                if defense_recommendations:
                    try:
                        # Create a safe copy without potential circular references
                        safe_defense_dict = {
                            'profile_id': defense_recommendations.profile_id,
                            'threat_class': defense_recommendations.threat_class,
                            'risk_level': defense_recommendations.risk_level,
                            'recommendations_count': len(defense_recommendations.recommendations),
                            'immediate_actions_count': len(defense_recommendations.immediate_actions),
                            'generated_at': defense_recommendations.generated_at.isoformat() if defense_recommendations.generated_at else None
                        }
                        profile.metadata['defense_recommendations'] = safe_defense_dict
                    except Exception as e:
                        # Fallback if even the safe copy fails
                        profile.metadata['defense_recommendations'] = {'error': f'Failed to serialize defense recommendations: {str(e)}'}
                else:
                    profile.metadata['defense_recommendations'] = None
            
            # Log completion
            duration_ms = (time.time() - start_time) * 1000
            self.logger.log_analysis_operation(
                "end_to_end_analysis",
                duration_ms,
                events_processed=len(raw_events),
                status="success",
                profile_id=profile.profile_id,
                risk_score=risk_score.score if risk_score else None,
                threat_class=classification.threat_class if classification else None
            )
            
            self.logger.log_operation(
                "INFO",
                f"BADNA analysis completed successfully in {duration_ms:.1f}ms",
                component="BADNAOrchestrator",
                operation="analyze_events",
                duration_ms=duration_ms,
                profile_id=profile.profile_id
            )
            
            return profile
            
        except Exception as e:
            # Log error and apply graceful degradation
            duration_ms = (time.time() - start_time) * 1000
            self.logger.log_analysis_operation(
                "end_to_end_analysis", 
                duration_ms,
                events_processed=len(raw_events),
                status="error",
                error_message=str(e)
            )
            
            # Apply graceful degradation for non-critical failures
            if not isinstance(e, (ValidationError, ResourceError)):
                return self._apply_graceful_degradation(profile, raw_events, e)
            else:
                raise e
    
    # Backwards compatibility alias
    process_events = analyze_events
    
    def _execute_step_1_graph_construction(self, raw_events: List[Dict[str, Any]]) -> BehaviorGraph:
        """Execute Step 1: Events → Behavior Graph."""
        try:
            self.logger.log_operation("INFO", "Executing Step 1: Graph Construction",
                                     component="BADNAOrchestrator", operation="step_1")
            
            # Parse events
            parsed_events = self.capture_engine.parse_events(raw_events)
            
            # Build behavior graph
            behavior_graph = self.capture_engine.build_graph(parsed_events)
            
            self.logger.log_operation("INFO", f"Graph constructed: {behavior_graph.node_count} nodes, {behavior_graph.edge_count} edges",
                                     component="BADNAOrchestrator", operation="step_1")
            
            return behavior_graph
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - Capture Engine fails → continue with empty graph
            self.logger.log_operation("ERROR", f"Behavior Capture Engine failed: {e}, using fallback empty graph",
                                     component="BADNAOrchestrator", operation="step_1")
            from data_models import BehaviorGraph
            fallback_graph = BehaviorGraph(nodes=[], edges=[], graph_id="fallback_empty")
            return fallback_graph
    
    def _execute_step_2_embedding_generation(self, behavior_graph: BehaviorGraph) -> BADNAEmbedding:
        """Execute Step 2: Graph → 128D Embedding."""
        try:
            self.logger.log_operation("INFO", "Executing Step 2: Embedding Generation",
                                     component="BADNAOrchestrator", operation="step_2")
            
            # Generate embedding using d-BEF
            embedding = compute_badna_embedding(behavior_graph)
            
            self.logger.log_operation("INFO", f"Embedding generated: {len(embedding.vector)}D vector",
                                     component="BADNAOrchestrator", operation="step_2")
            
            return embedding
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - d-BEF fails → continue with zero embedding
            self.logger.log_operation("ERROR", f"d-BEF module failed: {e}, using zero embedding fallback",
                                     component="BADNAOrchestrator", operation="step_2")
            from data_models import BADNAEmbedding
            import uuid
            zero_embedding = BADNAEmbedding(
                embedding_id=str(uuid.uuid4()),
                vector=np.zeros(128),  # Zero vector fallback
                source_graph_id="fallback_zero"
            )
            return zero_embedding
    
    def _execute_step_3_similarity_analysis(self, embedding: BADNAEmbedding) -> tuple:
        """Execute Step 3: Embedding → Similarity + Campaign Match."""
        try:
            self.logger.log_operation("INFO", "Executing Step 3: Similarity Analysis",
                                     component="BADNAOrchestrator", operation="step_3")
            
            # BUG FIX 1: Knowledge Base Guard - Check if knowledge_base.size == 0
            if not hasattr(self.knowledge_base, 'patterns') or len(self.knowledge_base.patterns) == 0:
                self.logger.log_operation("WARNING", "Knowledge base is empty, skipping BSF execution and campaign matching",
                                         component="BADNAOrchestrator", operation="step_3")
                # Return default values for empty knowledge base
                fallback_result = (
                    None,  # similarity_result
                    {
                        'campaign_id': None,
                        'similarity_score': 0.0,
                        'campaign_metadata': {},
                        'tracking_status': "UNKNOWN"
                    }
                )
                return fallback_result
            
            # Find campaign match
            campaign_match = self.bsf_engine.match_campaign(embedding.vector, self.knowledge_base)
            
            # Create similarity result
            similarity_result = None
            if campaign_match['campaign_id']:
                # Get campaign embedding for detailed similarity
                campaigns = self.knowledge_base.campaigns
                if campaign_match['campaign_id'] in campaigns:
                    campaign = campaigns[campaign_match['campaign_id']]
                    if campaign.signature_embedding is not None:
                        from data_models import BADNAEmbedding
                        campaign_embedding = BADNAEmbedding(
                            embedding_id=f"campaign_{campaign.campaign_id}",
                            vector=campaign.signature_embedding,
                            source_graph_id="campaign_signature"
                        )
                        similarity_result = self.bsf_engine.calculate_similarity_detailed(
                            embedding, campaign_embedding
                        )
            
            self.logger.log_operation("INFO", f"Similarity analysis: campaign_match={bool(campaign_match['campaign_id'])}",
                                     component="BADNAOrchestrator", operation="step_3")
            
            return similarity_result, campaign_match
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - BSF fails → continue pipeline with fallback
            self.logger.log_operation("ERROR", f"BSF module failed: {e}, continuing with fallback values",
                                     component="BADNAOrchestrator", operation="step_3")
            fallback = (None, {'campaign_id': None, 'similarity_score': 0.0, 'campaign_metadata': {}, 'tracking_status': "BSF_FAILURE"})
            return fallback
    
    def _execute_step_4_novelty_detection(self, embedding: BADNAEmbedding):
        """Execute Step 4: Embedding → Novelty Score."""
        try:
            self.logger.log_operation("INFO", "Executing Step 4: Novelty Detection",
                                     component="BADNAOrchestrator", operation="step_4")
            
            # Compute novelty score
            novelty_result = self.nsf_engine.compute_novelty(embedding.vector, self.knowledge_base)
            
            self.logger.log_operation("INFO", f"Novelty detected: {novelty_result.novelty_score:.3f} ({novelty_result.novelty_category})",
                                     component="BADNAOrchestrator", operation="step_4")
            
            return novelty_result
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - NSF fails → continue with high novelty fallback
            self.logger.log_operation("ERROR", f"NSF module failed: {e}, using high novelty fallback",
                                     component="BADNAOrchestrator", operation="step_4")
            from data_models import NoveltyResult
            fallback_novelty = NoveltyResult(
                query_embedding_id=embedding.embedding_id,
                novelty_score=0.95,  # Conservative high novelty when NSF fails
                novelty_category="highly_novel",
                nearest_neighbors=[],
                novelty_explanation={"error": f"NSF failure: {str(e)}"}
            )
            return fallback_novelty
    
    def _execute_step_5_confidence_calibration(self, similarity_result, novelty_result, campaign_match):
        """Execute Step 5: Similarity/Novelty → Confidence."""
        try:
            self.logger.log_operation("INFO", "Executing Step 5: Confidence Calibration",
                                     component="BADNAOrchestrator", operation="step_5")
            
            # Extract scores
            similarity_score = similarity_result.similarity_score if similarity_result else 0.0
            novelty_score = novelty_result.novelty_score if novelty_result else 1.0
            evidence_quality = 1.0  # Assume full quality for now
            kb_size = len(self.knowledge_base.patterns) if self.knowledge_base else 0
            has_campaign_match = bool(campaign_match.get('campaign_id'))
            
            # Calibrate confidence
            confidence_result = self.ccf_engine.calibrate_confidence(
                similarity_score=similarity_score,
                novelty_score=novelty_score,
                evidence_quality=evidence_quality,
                knowledge_base_size=kb_size,
                campaign_match=has_campaign_match
            )
            
            self.logger.log_operation("INFO", f"Confidence calibrated: {confidence_result.confidence_score:.3f}",
                                     component="BADNAOrchestrator", operation="step_5")
            
            return confidence_result
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - CCF fails → continue with conservative confidence
            self.logger.log_operation("ERROR", f"CCF module failed: {e}, using conservative confidence fallback",
                                     component="BADNAOrchestrator", operation="step_5")
            from data_models import ConfidenceResult
            fallback_confidence = ConfidenceResult(
                profile_id="fallback_confidence",
                confidence_score=0.5,  # Conservative fallback
                confidence_interval=(0.3, 0.7),
                calibration_factors={"error": f"CCF failure: {str(e)}"},
                raw_prediction_score=0.5
            )
            return fallback_confidence
    
    def _execute_step_6_threat_investigation(self, embedding: BADNAEmbedding, 
                                            behavior_graph: BehaviorGraph,
                                            similarity_result, novelty_result,
                                            ioc_match: Optional[Dict[str, Any]] = None):
        """Execute Step 6: Embedding → Classification + Intent + Evidence."""
        try:
            self.logger.log_operation("INFO", "Executing Step 6: Threat Investigation",
                                     component="BADNAOrchestrator", operation="step_6")
            
            # Threat classification
            similarity_score = similarity_result.similarity_score if similarity_result else None
            matched_campaign = None  # Could extract from similarity_result if needed
            
            classification = self.ai_investigator.classify_threat(
                embedding.vector, similarity_score, matched_campaign, ioc_match, behavior_graph
            )
            
            # Intent prediction
            intent = self.ai_investigator.predict_intent(embedding.vector, behavior_graph)
            
            # Evidence generation
            novelty_score = novelty_result.novelty_score if novelty_result else None
            evidence = self.ai_investigator.generate_evidence(
                behavior_graph, embedding.vector, classification, intent, novelty_score
            )
            
            self.logger.log_operation("INFO", f"Threat investigation: {classification.threat_class} confidence={classification.confidence:.3f}",
                                     component="BADNAOrchestrator", operation="step_6")
            
            return classification, intent, evidence
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - AI Investigator fails → continue with fallback classifications
            self.logger.log_operation("ERROR", f"AI Investigator failed: {e}, using fallback classifications",
                                     component="BADNAOrchestrator", operation="step_6")
            from data_models import ThreatClassification, IntentPrediction, Evidence
            import uuid
            
            fallback_classification = ThreatClassification(
                profile_id=str(uuid.uuid4()),
                threat_class="Unknown",
                confidence=0.5,
                probability_distribution={"Unknown": 1.0},
                uncertainty_flag=True
            )
            
            fallback_intent = IntentPrediction(
                profile_id=str(uuid.uuid4()),
                primary_intent="unknown",
                intent_ranking=[("unknown", 0.5)],
                attack_stage="unknown",
                mitre_techniques=[],
                natural_language_explanation="AI Investigator module failed"
            )
            
            fallback_evidence = Evidence(
                profile_id=str(uuid.uuid4()),
                top_features=[],
                critical_path=[],
                mitre_mappings={},
                campaign_reference=None,
                novelty_explanation={},
                structured_json={"error": f"Evidence generation failed: {str(e)}"},
                natural_language="Evidence generation unavailable due to module failure"
            )
            
            return fallback_classification, fallback_intent, fallback_evidence
    
    def _execute_step_7_risk_scoring(self, similarity_result, novelty_result, 
                                    confidence_result, classification, intent):
        """Execute Step 7: All Results → Risk Score."""
        try:
            self.logger.log_operation("INFO", "Executing Step 7: Risk Scoring",
                                     component="BADNAOrchestrator", operation="step_7")
            
            # BUG FIX 4: Unified Risk Engine - Combine all factors with proper normalization
            # Extract scores
            similarity_score = similarity_result.similarity_score if similarity_result else 0.0
            novelty_score = novelty_result.novelty_score if novelty_result else 1.0
            confidence_score = confidence_result.confidence_score if confidence_result else 0.5
            threat_class = classification.threat_class if classification else "Unknown"
            
            # Detect behavioral patterns from intent
            lateral_movement = False
            exfiltration = False
            if intent and intent.intent_ranking:
                intents = [intent_name for intent_name, _ in intent.intent_ranking]
                lateral_movement = 'lateral_movement' in intents or 'Lateral Movement' in intents
                exfiltration = 'exfiltration' in intents or 'Exfiltration' in intents
            
            # Extract threat severity for unified calculation
            predicted_intent = intent.primary_intent if intent else "unknown"
            
            # Task 6.2: Use RiskScorer class for unified risk calculation
            # Implements Requirements 10.1-10.10
            risk_result = self.risk_scorer.compute_risk(
                similarity_score=similarity_score,
                novelty_score=novelty_score,
                confidence_score=confidence_score,
                threat_class=threat_class,
                lateral_movement=lateral_movement,
                exfiltration=exfiltration
            )
            
            normalized_risk = risk_result['score']
            risk_level = risk_result['risk_level']
            risk_rationale = risk_result['rationale']
            
            # Use contributing factors from RiskScorer
            contributing_factors = risk_result['contributing_factors']
            
            # Add additional context for transparency
            contributing_factors['predicted_intent'] = predicted_intent
            contributing_factors['threat_class'] = threat_class
            
            # Create risk score object
            from data_models import RiskScore
            risk_score = RiskScore(
                profile_id=classification.profile_id if classification else str(uuid.uuid4()),
                score=float(normalized_risk),
                risk_level=risk_level,
                contributing_factors=contributing_factors,
                rationale=risk_rationale
            )
            
            self.logger.log_operation("INFO", f"Risk scored: {risk_score.score:.3f} ({risk_score.risk_level})",
                                     component="BADNAOrchestrator", operation="step_7")
            
            return risk_score
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - Risk Scorer fails → continue with medium risk fallback
            self.logger.log_operation("ERROR", f"Risk Scorer failed: {e}, using medium risk fallback",
                                     component="BADNAOrchestrator", operation="step_7")
            from data_models import RiskScore
            fallback_risk = RiskScore(
                profile_id=str(uuid.uuid4()),
                score=0.6,  # Medium risk fallback
                risk_level="Medium",
                contributing_factors={"error": f"Risk scoring failed: {str(e)}"},
                rationale="Risk assessment unavailable due to module failure, defaulting to medium risk"
            )
            return fallback_risk
    
    def _get_threat_severity(self, threat_class: str) -> float:
        """Get normalized threat severity score for threat class."""
        severity_map = {
            'APT': 0.95,
            'Ransomware': 0.95, 
            'Insider_Threat': 0.80,
            'Malware': 0.70,
            'Phishing': 0.60,
            'Benign': 0.10,
            'Unknown': 0.50
        }
        return severity_map.get(threat_class, 0.50)
    
    def _compute_unified_risk(self, threat_severity: float, predicted_intent: str, 
                             novelty_score: float, confidence_score: float,
                             similarity_score: float, lateral_movement: bool, exfiltration: bool) -> float:
        """Compute unified risk score combining all factors using calibrated CCF RiskScorer (Rule #4)."""
        threat_class = "Unknown"
        for tc, sev in [('APT', 0.95), ('Ransomware', 0.95), ('Insider_Threat', 0.80), ('Malware', 0.70), ('Phishing', 0.60), ('Benign', 0.10)]:
            if abs(threat_severity - sev) < 0.05:
                threat_class = tc
                break
        
        risk_result = self.risk_scorer.compute_risk(
            similarity_score=similarity_score,
            novelty_score=novelty_score,
            confidence_score=confidence_score,
            threat_class=threat_class,
            lateral_movement=lateral_movement,
            exfiltration=exfiltration
        )
        return float(risk_result['score'])
    
    def _categorize_risk_level(self, risk_score: float) -> str:
        """Categorize risk score into levels."""
        if risk_score >= 0.85:
            return 'Critical'
        elif risk_score >= 0.70:
            return 'High'
        elif risk_score >= 0.50:
            return 'Medium'
        elif risk_score >= 0.30:
            return 'Low'
        else:
            return 'Minimal'
    
    def _generate_risk_rationale(self, risk_score: float, threat_class: str,
                               novelty_score: float, lateral_movement: bool,
                               exfiltration: bool, confidence_score: float) -> str:
        """Generate human-readable risk rationale."""
        factors = []
        
        # Threat class factor
        if threat_class in ['APT', 'Ransomware']:
            factors.append(f"High-severity threat class ({threat_class})")
        elif threat_class == 'Unknown':
            factors.append("Unknown threat classification increases uncertainty")
        
        # Novelty factor
        if novelty_score > 0.8:
            factors.append("Potential zero-day attack (highly novel behavior)")
        elif novelty_score > 0.5:
            factors.append("Variant attack behavior (moderately novel)")
        
        # Intent factors
        if lateral_movement:
            factors.append("Lateral movement detected")
        if exfiltration:
            factors.append("Data exfiltration detected")
        
        # Confidence factor
        if confidence_score < 0.5:
            factors.append(f"Low confidence ({confidence_score:.2f}) increases risk assessment uncertainty")
        
        # Combine factors
        if factors:
            rationale = f"Risk assessment based on: {'; '.join(factors)}"
        else:
            rationale = f"Standard risk assessment for {threat_class} threat"
        
        return rationale
    
    def _execute_step_8_defense_recommendations(self, profile: BADNAProfile):
        """Execute Step 8: Generate Defense Recommendations."""
        try:
            self.logger.log_operation("INFO", "Executing Step 8: Defense Recommendations",
                                     component="BADNAOrchestrator", operation="step_8")
            
            # Generate defense recommendations
            defense_recommendations = self.adaptive_defense.recommend_actions(profile)
            
            self.logger.log_operation("INFO", f"Defense recommendations: {len(defense_recommendations.recommendations)} generated",
                                     component="BADNAOrchestrator", operation="step_8")
            
            return defense_recommendations
            
        except Exception as e:
            # BUG FIX 2: Module Fault Tolerance - Defense recommendations fail → continue without recommendations
            self.logger.log_operation("ERROR", f"Adaptive Defense Intelligence failed: {e}, continuing without recommendations",
                                     component="BADNAOrchestrator", operation="step_8")
            return None
    
    def _apply_graceful_degradation(self, profile: BADNAProfile, 
                                  raw_events: List[Dict[str, Any]], 
                                  error: Exception) -> BADNAProfile:
        """Apply graceful degradation for non-critical failures."""
        self.logger.log_operation("WARNING", f"Applying graceful degradation due to: {error}",
                                 component="BADNAOrchestrator", operation="graceful_degradation")
        
        # Fill profile with conservative estimates
        profile.config = self.config.to_dict()
        profile.timestamp = datetime.now()
        
        # Add degradation notice to profile metadata
        if not hasattr(profile, 'metadata'):
            profile.metadata = {}
        
        profile.metadata['degraded'] = True
        profile.metadata['degradation_reason'] = str(error)
        profile.metadata['degraded_components'] = list(self.degradation.get_degraded_components())
        
        return profile
    
    def analyze_event_file(self, file_path: str) -> BADNAProfile:
        """
        Analyze events from a JSON file.
        
        Args:
            file_path: Path to JSON file containing events
            
        Returns:
            BADNAProfile with analysis results
        """
        try:
            # Load events from file
            events_file = Path(file_path)
            if not events_file.exists():
                raise ResourceError(f"Event file not found: {file_path}")
            
            with open(events_file, 'r', encoding='utf-8') as f:
                raw_events = json.load(f)
            
            # Validate events format
            if not isinstance(raw_events, list):
                raise ValidationError("Events file must contain a JSON array")
            
            self.logger.log_operation("INFO", f"Loaded {len(raw_events)} events from {file_path}",
                                     component="BADNAOrchestrator", operation="analyze_event_file")
            
            # Analyze events
            return self.analyze_events(raw_events)
            
        except Exception as e:
            self.logger.log_operation("ERROR", f"Failed to analyze event file {file_path}: {e}",
                                     component="BADNAOrchestrator", operation="analyze_event_file")
            raise
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status and statistics."""
        kb_stats = self.knowledge_base.get_statistics()
        
        return {
            'system': {
                'badna_version': '1.0.0',
                'config_loaded': True,
                'engines_initialized': True,
                'degraded_components': list(self.degradation.get_degraded_components())
            },
            'knowledge_base': kb_stats,
            'configuration': {
                'embedding_dimensions': self.config.embedding_dimensions,
                'similarity_threshold': self.config.similarity_threshold,
                'novelty_threshold': self.config.novelty_threshold,
                'confidence_threshold': self.config.confidence_threshold,
                'max_graph_size': self.config.max_graph_size
            }
        }


# =============================================================================
# CLI Interface
# =============================================================================

def setup_cli() -> argparse.ArgumentParser:
    """Set up command-line interface."""
    parser = argparse.ArgumentParser(
        description="BADNA - Behavioral Attack DNA Analysis Framework",
        epilog="Example: python main.py analyze --file tests/apt.json --output output/analysis.json"
    )
    
    # Global options
    parser.add_argument('--config', '-c', 
                       help="Path to configuration file")
    parser.add_argument('--verbose', '-v', action='store_true',
                       help="Enable verbose logging")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze security events')
    analyze_parser.add_argument('--file', '-f', required=True,
                               help="Path to JSON file containing security events")
    analyze_parser.add_argument('--output', '-o',
                               help="Path to save analysis results (JSON format)")
    analyze_parser.add_argument('--pretty', action='store_true',
                               help="Pretty-print JSON output")
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run system tests')
    test_parser.add_argument('--components', nargs='*',
                            choices=['capture', 'dbef', 'bsf', 'nsf', 'ccf', 'investigator'],
                            help="Test specific components (default: all)")
    
    return parser


# Backwards compatibility alias
BADNAOrchestrator = BADNAAnalysisOrchestrator


def main():
    """Main CLI entry point."""
    parser = setup_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Initialize BADNA orchestrator
        orchestrator = BADNAAnalysisOrchestrator(config_path=args.config)
        
        if args.verbose:
            print(f"BADNA v1.0.0 - Behavioral Attack DNA Analysis Framework")
            print(f"Configuration loaded from: {args.config or 'default'}")
        
        # Execute command
        if args.command == 'analyze':
            # Analyze events from file
            if args.verbose:
                print(f"Analyzing events from: {args.file}")
            
            profile = orchestrator.analyze_event_file(args.file)
            
            # Generate output
            if args.output:
                # Save to file
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    if args.pretty:
                        f.write(profile.to_json())
                    else:
                        json.dump(json.loads(profile.to_json()), f)
                
                print(f"Analysis results saved to: {args.output}")
            else:
                # Print to stdout
                if args.pretty:
                    print(profile.to_json())
                else:
                    print(json.loads(profile.to_json()))
            
            # Print summary
            print(f"\n=== ANALYSIS SUMMARY ===")
            print(f"Profile ID: {profile.profile_id}")
            print(f"Timestamp: {profile.timestamp}")
            if profile.threat_classification:
                print(f"Threat Class: {profile.threat_classification.threat_class}")
                print(f"Confidence: {profile.threat_classification.confidence:.3f}")
            if profile.risk_score:
                print(f"Risk Score: {profile.risk_score.score:.3f} ({profile.risk_score.risk_level})")
            if profile.novelty_result:
                print(f"Novelty: {profile.novelty_result.novelty_score:.3f} ({profile.novelty_result.novelty_category})")
            
        elif args.command == 'status':
            # Show system status
            status = orchestrator.get_system_status()
            print(json.dumps(status, indent=2, default=str))
        
        elif args.command == 'test':
            # Run system tests
            print("Running BADNA system tests...")
            
            # Load test events
            test_files = [
                'tests/apt.json',
                'tests/ransomware.json', 
                'tests/benign.json'
            ]
            
            for test_file in test_files:
                if Path(test_file).exists():
                    try:
                        print(f"Testing with {test_file}...")
                        profile = orchestrator.analyze_event_file(test_file)
                        print(f"  [OK] Success - Risk: {profile.risk_score.score:.3f} ({profile.risk_score.risk_level})")
                    except Exception as e:
                        print(f"  [FAIL] Failed: {e}")
                else:
                    print(f"  - Skipping {test_file} (not found)")
            
            print("System tests completed.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()