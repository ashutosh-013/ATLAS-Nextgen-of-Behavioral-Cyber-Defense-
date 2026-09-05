"""
Evidence Generation with Feature Contribution Analysis

This module implements explainable evidence generation for BADNA threat detections.
BUG FIX 5: Feature Contribution Analysis - Return top 5 behavioral contributors with weights.

Requirements: 9.1-9.10  
Task: 8.2 - Implement explainable evidence generation
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json

# Import our models
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_models import Evidence, BehaviorGraph, ThreatClassification, IntentPrediction
from config import get_logger, get_config


class FeatureContributionAnalyzer:
    """
    BUG FIX 5: Feature Contribution Analysis
    
    Implements explainable evidence with top 5 behavioral contributors and weights.
    Maps behavioral features to BADNA dimensions affected.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        
        # BADNA dimension mappings for explainability
        self.badna_dimensions = {
            'structural': list(range(0, 43)),      # Dimensions 0-42 (graph structure)
            'temporal': list(range(43, 68)),       # Dimensions 43-67 (timing patterns)
            'semantic': list(range(68, 128))       # Dimensions 68-127 (behavioral semantics)
        }
        
        # Behavioral feature mapping to BADNA aspects
        self.feature_mappings = {
            'privilege_escalation': {'dimension': 'semantic', 'weight_base': 0.35},
            'network_beacon': {'dimension': 'temporal', 'weight_base': 0.28},
            'lateral_movement': {'dimension': 'structural', 'weight_base': 0.25},
            'data_exfiltration': {'dimension': 'semantic', 'weight_base': 0.32},
            'persistence_mechanism': {'dimension': 'semantic', 'weight_base': 0.30},
            'credential_access': {'dimension': 'semantic', 'weight_base': 0.27},
            'defense_evasion': {'dimension': 'structural', 'weight_base': 0.24},
            'reconnaissance': {'dimension': 'temporal', 'weight_base': 0.20},
            'initial_access': {'dimension': 'structural', 'weight_base': 0.26},
            'execution_anomaly': {'dimension': 'temporal', 'weight_base': 0.23},
            'file_encryption': {'dimension': 'semantic', 'weight_base': 0.38},
            'process_injection': {'dimension': 'structural', 'weight_base': 0.29},
            'network_discovery': {'dimension': 'temporal', 'weight_base': 0.21},
            'command_control': {'dimension': 'temporal', 'weight_base': 0.31},
            'impact_behavior': {'dimension': 'semantic', 'weight_base': 0.36}
        }
    
    def analyze_feature_contributions(self, 
                                    embedding: np.ndarray,
                                    behavior_graph: BehaviorGraph,
                                    threat_class: str,
                                    novelty_score: float) -> List[Tuple[str, float]]:
        """
        BUG FIX 5: Return top 5 behavioral contributors with weights.
        
        Args:
            embedding: 128-D BADNA embedding
            behavior_graph: Original behavior graph
            threat_class: Predicted threat classification
            novelty_score: Novelty score from NSF
            
        Returns:
            List of (feature_name, weight) tuples for top 5 contributors
            Format: "Privilege Escalation: Weight 0.35, Network Beacon: Weight 0.22" etc.
        """
        try:
            # Extract behavioral features from graph and embedding
            detected_features = self._extract_behavioral_features(behavior_graph, embedding)
            
            # Calculate feature weights based on embedding activations
            feature_weights = self._calculate_feature_weights(embedding, detected_features, threat_class, novelty_score)
            
            # Sort by weight and return top 5
            sorted_features = sorted(feature_weights.items(), key=lambda x: x[1], reverse=True)
            top_5_features = sorted_features[:5]
            
            self.logger.log_operation("INFO", f"Feature contribution analysis identified {len(top_5_features)} top contributors",
                                     component="FeatureContributionAnalyzer", 
                                     operation="analyze_feature_contributions")
            
            return top_5_features
            
        except Exception as e:
            self.logger.log_operation("ERROR", f"Feature contribution analysis failed: {e}",
                                     component="FeatureContributionAnalyzer")
            # Return fallback features
            return [
                ("Behavioral_Analysis_Failed", 0.20),
                ("Unknown_Pattern", 0.15),
                ("Generic_Threat_Indicator", 0.12),
                ("Anomalous_Activity", 0.10),
                ("System_Interaction", 0.08)
            ]
    
    def map_to_badna_dimensions(self, feature_contributions: List[Tuple[str, float]]) -> Dict[str, List[str]]:
        """
        BUG FIX 5: Map to BADNA dimensions affected.
        
        Args:
            feature_contributions: List of (feature_name, weight) tuples
            
        Returns:
            Dict mapping BADNA dimensions to affected features
        """
        dimension_mapping = {
            'structural': [],
            'temporal': [], 
            'semantic': []
        }
        
        for feature_name, weight in feature_contributions:
            # Normalize feature name for lookup
            normalized_name = feature_name.lower().replace(' ', '_').replace(':', '')
            
            # Find dimension mapping
            if normalized_name in self.feature_mappings:
                dimension = self.feature_mappings[normalized_name]['dimension']
                dimension_mapping[dimension].append(f"{feature_name} (Weight: {weight:.2f})")
            else:
                # Default to semantic for unknown features
                dimension_mapping['semantic'].append(f"{feature_name} (Weight: {weight:.2f})")
        
        return dimension_mapping
    
    def _extract_behavioral_features(self, behavior_graph: BehaviorGraph, embedding: np.ndarray) -> Dict[str, float]:
        """Extract behavioral features from graph structure and embedding activations."""
        features = {}
        
        # Analyze graph structure for behavioral patterns
        if behavior_graph and hasattr(behavior_graph, 'nodes') and behavior_graph.nodes:
            # Process-based features
            process_activities = [node for node in behavior_graph.nodes if hasattr(node, 'node_type') and 'process' in str(node.node_type).lower()]
            if len(process_activities) > 5:
                features['privilege_escalation'] = min(1.0, len(process_activities) / 20.0)
            
            # Network-based features  
            network_activities = [node for node in behavior_graph.nodes if hasattr(node, 'node_type') and 'network' in str(node.node_type).lower()]
            if len(network_activities) > 3:
                features['network_beacon'] = min(1.0, len(network_activities) / 15.0)
                features['command_control'] = min(1.0, len(network_activities) / 12.0)
            
            # File-based features
            file_activities = [node for node in behavior_graph.nodes if hasattr(node, 'node_type') and 'file' in str(node.node_type).lower()]
            if len(file_activities) > 8:
                features['data_exfiltration'] = min(1.0, len(file_activities) / 25.0)
                features['file_encryption'] = min(1.0, len(file_activities) / 20.0)
            
            # High node count suggests complex behavior
            if behavior_graph.node_count > 50:
                features['lateral_movement'] = min(1.0, behavior_graph.node_count / 100.0)
        
        # Analyze embedding activations for semantic features
        if embedding is not None and len(embedding) == 128:
            # Semantic dimension analysis (68-127)
            semantic_activations = embedding[68:]
            semantic_mean = np.mean(np.abs(semantic_activations))
            
            if semantic_mean > 0.6:
                features['persistence_mechanism'] = min(1.0, semantic_mean)
                features['credential_access'] = min(1.0, semantic_mean * 0.8)
            
            # Structural dimension analysis (0-42)
            structural_activations = embedding[:43]
            structural_variance = np.var(structural_activations)
            
            if structural_variance > 0.1:
                features['defense_evasion'] = min(1.0, structural_variance * 2.0)
                features['process_injection'] = min(1.0, structural_variance * 1.5)
            
            # Temporal dimension analysis (43-67)
            temporal_activations = embedding[43:68]
            temporal_max = np.max(np.abs(temporal_activations))
            
            if temporal_max > 0.7:
                features['reconnaissance'] = min(1.0, temporal_max * 0.9)
                features['execution_anomaly'] = min(1.0, temporal_max * 0.7)
        
        return features
    
    def _calculate_feature_weights(self, embedding: np.ndarray, detected_features: Dict[str, float], 
                                 threat_class: str, novelty_score: float) -> Dict[str, float]:
        """Calculate normalized feature weights based on multiple factors."""
        feature_weights = {}
        
        for feature_name, activation_score in detected_features.items():
            # Base weight from feature mapping
            base_weight = self.feature_mappings.get(feature_name, {}).get('weight_base', 0.15)
            
            # Adjust weight based on activation strength
            activation_weight = base_weight * activation_score
            
            # Threat class adjustment
            threat_multiplier = self._get_threat_class_multiplier(threat_class, feature_name)
            threat_adjusted_weight = activation_weight * threat_multiplier
            
            # Novelty adjustment (novel behaviors get higher weights for explanation)
            novelty_multiplier = 1.0 + (novelty_score * 0.3) if novelty_score > 0.7 else 1.0
            final_weight = threat_adjusted_weight * novelty_multiplier
            
            # Normalize to reasonable range
            feature_weights[feature_name.replace('_', ' ').title()] = min(1.0, max(0.05, final_weight))
        
        # Ensure we have at least 5 features, add generic ones if needed
        if len(feature_weights) < 5:
            generic_features = {
                'Anomalous Behavior': 0.15,
                'System Interaction': 0.12,
                'Process Activity': 0.10,
                'Network Communication': 0.08,
                'File Operations': 0.06
            }
            
            for feature, weight in generic_features.items():
                if feature not in feature_weights and len(feature_weights) < 5:
                    feature_weights[feature] = weight
        
        return feature_weights
    
    def _get_threat_class_multiplier(self, threat_class: str, feature_name: str) -> float:
        """Get threat class-specific multiplier for feature weights."""
        threat_feature_affinity = {
            'APT': {
                'lateral_movement': 1.5,
                'persistence_mechanism': 1.4,
                'credential_access': 1.3,
                'reconnaissance': 1.2
            },
            'Ransomware': {
                'file_encryption': 1.8,
                'privilege_escalation': 1.4,
                'defense_evasion': 1.3,
                'impact_behavior': 1.6
            },
            'Insider_Threat': {
                'data_exfiltration': 1.6,
                'credential_access': 1.4,
                'privilege_escalation': 1.3
            },
            'Malware': {
                'process_injection': 1.4,
                'persistence_mechanism': 1.3,
                'defense_evasion': 1.2
            }
        }
        
        if threat_class in threat_feature_affinity:
            return threat_feature_affinity[threat_class].get(feature_name, 1.0)
        else:
            return 1.0


class EvidenceGenerator:
    """
    Main evidence generator that uses feature contribution analysis.
    
    Requirements: 9.1-9.10
    Task: 8.2 - Implement explainable evidence generation
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.feature_analyzer = FeatureContributionAnalyzer()
    
    def generate_evidence(self, 
                         behavior_graph: BehaviorGraph,
                         embedding: np.ndarray,
                         classification: ThreatClassification,
                         intent: IntentPrediction,
                         novelty_score: Optional[float] = None) -> Evidence:
        """
        Generate explainable evidence for threat detection.
        
        Args:
            behavior_graph: Original behavior graph
            embedding: 128-D BADNA embedding vector
            classification: Threat classification result
            intent: Intent prediction result  
            novelty_score: Novelty score from NSF
            
        Returns:
            Evidence with feature contributions, critical path, MITRE mappings, etc.
        """
        try:
            profile_id = classification.profile_id if classification else f"evidence_{int(datetime.now().timestamp())}"
            
            # BUG FIX 5: Feature Contribution Analysis
            feature_contributions = self.feature_analyzer.analyze_feature_contributions(
                embedding, behavior_graph, 
                classification.threat_class if classification else "Unknown",
                novelty_score or 0.5
            )
            
            # Map to BADNA dimensions
            badna_dimension_mapping = self.feature_analyzer.map_to_badna_dimensions(feature_contributions)
            
            # Extract critical behavioral path
            critical_path = self._extract_critical_path(behavior_graph)
            
            # Generate MITRE ATT&CK mappings
            mitre_mappings = self._generate_mitre_mappings(classification, intent, feature_contributions)
            
            # Campaign reference (if available)
            campaign_reference = self._extract_campaign_reference(classification)
            
            # Novelty explanation
            novelty_explanation = self._generate_novelty_explanation(novelty_score, feature_contributions)
            
            # Generate structured JSON for SIEM integration
            structured_json = self._generate_structured_json(
                profile_id, feature_contributions, badna_dimension_mapping,
                classification, intent, novelty_score
            )
            
            # Generate natural language summary
            natural_language = self._generate_natural_language_summary(
                classification, intent, feature_contributions, novelty_score
            )
            
            evidence = Evidence(
                profile_id=profile_id,
                top_features=feature_contributions,
                critical_path=critical_path,
                mitre_mappings=mitre_mappings,
                campaign_reference=campaign_reference,
                novelty_explanation=novelty_explanation,
                structured_json=structured_json,
                natural_language=natural_language
            )
            
            self.logger.log_operation("INFO", f"Evidence generated with {len(feature_contributions)} feature contributions",
                                     component="EvidenceGenerator", 
                                     operation="generate_evidence",
                                     profile_id=profile_id)
            
            return evidence
            
        except Exception as e:
            self.logger.log_operation("ERROR", f"Evidence generation failed: {e}",
                                     component="EvidenceGenerator")
            
            # Return fallback evidence
            return Evidence(
                profile_id="fallback_evidence",
                top_features=[("Evidence Generation Failed", 0.20)],
                critical_path=[],
                mitre_mappings={},
                campaign_reference=None,
                novelty_explanation={"error": f"Evidence generation failed: {str(e)}"},
                structured_json={"error": "Evidence generation unavailable"},
                natural_language="Evidence generation failed due to system error"
            )
    
    def _extract_critical_path(self, behavior_graph: BehaviorGraph) -> List[Dict[str, Any]]:
        """Extract critical behavioral sequence from graph."""
        critical_path = []
        
        if behavior_graph and hasattr(behavior_graph, 'nodes') and behavior_graph.nodes:
            # Sort nodes by importance (simplified heuristic)
            sorted_nodes = sorted(behavior_graph.nodes, 
                                key=lambda x: getattr(x, 'weight', 1.0) if hasattr(x, 'weight') else 1.0, 
                                reverse=True)
            
            # Take top 5 most important nodes
            for node in sorted_nodes[:5]:
                critical_path.append({
                    'node_id': getattr(node, 'node_id', 'unknown'),
                    'node_type': str(getattr(node, 'node_type', 'unknown')),
                    'weight': getattr(node, 'weight', 1.0),
                    'timestamp': str(getattr(node, 'timestamp', datetime.now()))
                })
        
        return critical_path
    
    def _generate_mitre_mappings(self, classification: ThreatClassification, 
                               intent: IntentPrediction, 
                               feature_contributions: List[Tuple[str, float]]) -> Dict[str, str]:
        """Generate MITRE ATT&CK technique mappings."""
        mitre_mappings = {}
        
        # From intent prediction
        if intent and hasattr(intent, 'mitre_techniques'):
            for technique_id in intent.mitre_techniques:
                mitre_mappings[technique_id] = f"Detected through intent analysis: {intent.primary_intent}"
        
        # From feature contributions
        feature_mitre_map = {
            'privilege escalation': 'T1068',
            'lateral movement': 'T1021',
            'data exfiltration': 'T1041',
            'persistence mechanism': 'T1053',
            'credential access': 'T1003',
            'defense evasion': 'T1055',
            'reconnaissance': 'T1083',
            'file encryption': 'T1486',
            'process injection': 'T1055',
            'command control': 'T1071'
        }
        
        for feature_name, weight in feature_contributions:
            normalized_name = feature_name.lower()
            for key_pattern, technique_id in feature_mitre_map.items():
                if key_pattern in normalized_name:
                    mitre_mappings[technique_id] = f"Behavioral evidence: {feature_name} (Weight: {weight:.2f})"
                    break
        
        return mitre_mappings
    
    def _extract_campaign_reference(self, classification: ThreatClassification) -> Optional[Dict[str, Any]]:
        """Extract campaign reference information if available."""
        # This would be populated if campaign matching was successful
        # For now, return None as campaign matching is handled elsewhere
        return None
    
    def _generate_novelty_explanation(self, novelty_score: Optional[float], 
                                    feature_contributions: List[Tuple[str, float]]) -> Dict[str, Any]:
        """Generate explanation for novel behaviors."""
        novelty_explanation = {}
        
        if novelty_score is not None:
            if novelty_score > 0.8:
                novelty_explanation['category'] = 'highly_novel'
                novelty_explanation['description'] = 'Behavior significantly deviates from known patterns'
                novelty_explanation['deviating_features'] = [name for name, weight in feature_contributions if weight > 0.25]
            elif novelty_score > 0.5:
                novelty_explanation['category'] = 'moderately_novel'
                novelty_explanation['description'] = 'Behavior shows some deviation from known patterns'
                novelty_explanation['deviating_features'] = [name for name, weight in feature_contributions if weight > 0.20]
            else:
                novelty_explanation['category'] = 'known'
                novelty_explanation['description'] = 'Behavior matches known patterns'
                novelty_explanation['deviating_features'] = []
            
            novelty_explanation['novelty_score'] = novelty_score
        
        return novelty_explanation
    
    def _generate_structured_json(self, profile_id: str, feature_contributions: List[Tuple[str, float]],
                                badna_dimension_mapping: Dict[str, List[str]],
                                classification: ThreatClassification, intent: IntentPrediction,
                                novelty_score: Optional[float]) -> Dict[str, Any]:
        """Generate structured JSON format for SIEM integration."""
        return {
            'profile_id': profile_id,
            'timestamp': datetime.now().isoformat(),
            'threat_classification': {
                'class': classification.threat_class if classification else 'Unknown',
                'confidence': classification.confidence if classification else 0.0
            },
            'behavioral_features': {
                'top_contributors': [{'feature': name, 'weight': weight} for name, weight in feature_contributions],
                'badna_dimensions': badna_dimension_mapping
            },
            'intent_analysis': {
                'primary_intent': intent.primary_intent if intent else 'unknown',
                'attack_stage': intent.attack_stage if intent else 'unknown'
            },
            'novelty_assessment': {
                'score': novelty_score,
                'category': 'highly_novel' if novelty_score and novelty_score > 0.8 else 'known'
            }
        }
    
    def _generate_natural_language_summary(self, classification: ThreatClassification,
                                         intent: IntentPrediction,
                                         feature_contributions: List[Tuple[str, float]],
                                         novelty_score: Optional[float]) -> str:
        """Generate natural language summary for analysts."""
        threat_class = classification.threat_class if classification else "Unknown"
        confidence = classification.confidence if classification else 0.0
        
        # Start with threat classification
        summary = f"Behavioral analysis indicates {threat_class} threat activity with {confidence:.1%} confidence. "
        
        # Add top behavioral contributors
        if feature_contributions:
            top_feature = feature_contributions[0]
            summary += f"Primary behavioral indicator: {top_feature[0]} (Weight: {top_feature[1]:.2f}). "
            
            if len(feature_contributions) > 1:
                other_features = [name for name, _ in feature_contributions[1:3]]
                summary += f"Additional indicators include: {', '.join(other_features)}. "
        
        # Add intent information
        if intent and intent.primary_intent != 'unknown':
            summary += f"Detected intent: {intent.primary_intent.replace('_', ' ').title()}. "
        
        # Add novelty information
        if novelty_score is not None:
            if novelty_score > 0.8:
                summary += "This behavior is highly novel and may represent a zero-day attack. "
            elif novelty_score > 0.5:
                summary += "This behavior shows moderate novelty compared to known patterns. "
        
        return summary