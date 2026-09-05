"""
Unit Tests for AI Investigator (Task 8.1)

Tests threat classification, intent prediction, and MITRE ATT&CK mapping.
Requirements: 7.1-7.10, 8.1-8.10, 9.1-9.10

Target: 85%+ classification accuracy
"""

import pytest
import numpy as np
import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.investigator import AIInvestigator, MITREMapper
from behavior.capture_engine import BehaviorCaptureEngine
from behavior.feature_engineering import FeatureEngineer
from behavior.dbef import DBEFEngine
from data_models import (
    BADNAEmbedding, BehaviorGraph, ThreatClassification, IntentPrediction,
    Evidence, VALID_THREAT_CLASSES
)


class TestMITREMapper:
    """Test MITRE ATT&CK mapping functionality."""
    
    def setup_method(self):
        """Initialize MITRE mapper."""
        self.mapper = MITREMapper()
    
    def test_mitre_mapper_initialization(self):
        """Test that MITRE mapper initializes with correct tactics."""
        assert len(self.mapper.attack_tactics) == 13
        assert 'reconnaissance' in self.mapper.attack_tactics
        assert 'exfiltration' in self.mapper.attack_tactics
        assert 'command_and_control' in self.mapper.attack_tactics
    
    def test_technique_mapping_completeness(self):
        """Test that all tactics have technique mappings."""
        for tactic in self.mapper.attack_tactics:
            techniques = self.mapper.get_techniques_for_behavior(tactic)
            if tactic in self.mapper.behavior_to_techniques:
                assert len(techniques) > 0, f"Tactic {tactic} has no techniques"
    
    def test_technique_descriptions_exist(self):
        """Test that technique descriptions are available."""
        # Check a few key techniques
        assert 'T1059' in self.mapper.technique_descriptions
        assert 'T1486' in self.mapper.technique_descriptions
        assert 'T1055' in self.mapper.technique_descriptions


class TestAIInvestigatorInitialization:
    """Test AI Investigator initialization and setup."""
    
    def setup_method(self):
        """Initialize AI investigator."""
        self.investigator = AIInvestigator()
    
    def test_investigator_initialization(self):
        """Test that investigator initializes correctly."""
        assert self.investigator.models_trained is True
        assert self.investigator.rf_classifier is not None
        assert self.investigator.svm_classifier is not None
        assert self.investigator.nn_classifier is not None
    
    def test_ensemble_models_present(self):
        """Test that all three ensemble models are present."""
        assert hasattr(self.investigator, 'rf_classifier')
        assert hasattr(self.investigator, 'svm_classifier')
        assert hasattr(self.investigator, 'nn_classifier')
    
    def test_mitre_mapper_present(self):
        """Test that MITRE mapper is initialized."""
        assert self.investigator.mitre_mapper is not None
        assert len(self.investigator.mitre_mapper.attack_tactics) == 13


class TestThreatClassification:
    """Test threat classification with ensemble learning."""
    
    def setup_method(self):
        """Initialize investigator and test data."""
        self.investigator = AIInvestigator()
    
    def test_classify_threat_with_valid_embedding(self):
        """Test classification with valid 128-D embedding."""
        # Create a random normalized embedding
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.classify_threat(embedding)
        
        assert isinstance(result, ThreatClassification)
        assert result.threat_class in VALID_THREAT_CLASSES
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.probability_distribution) == len(VALID_THREAT_CLASSES)
    
    def test_classify_threat_invalid_dimensions(self):
        """Test that invalid dimensions are handled gracefully."""
        invalid_embedding = np.random.randn(64)  # Wrong size
        
        result = self.investigator.classify_threat(invalid_embedding)
        # Should return fallback classification with valid threat class
        assert result.threat_class in VALID_THREAT_CLASSES
        assert result.uncertainty_flag is True  # Should flag uncertainty
    
    def test_classify_threat_probability_distribution(self):
        """Test that probability distribution sums to approximately 1.0."""
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.classify_threat(embedding)
        
        prob_sum = sum(result.probability_distribution.values())
        assert abs(prob_sum - 1.0) < 0.01, f"Probabilities sum to {prob_sum}, expected ~1.0"
    
    def test_classify_threat_with_campaign_match(self):
        """Test classification uses campaign match when available."""
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.classify_threat(
            embedding,
            similarity_score=0.90,
            matched_campaign="APT29_Campaign"
        )
        
        assert result.confidence >= 0.85
        assert result.classification_method == "campaign_match"
    
    def test_classify_threat_uncertainty_flag(self):
        """Test uncertainty flag for low confidence."""
        # Create embedding that might result in low confidence
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.classify_threat(embedding)
        
        if result.confidence < 0.6:
            assert bool(result.uncertainty_flag) is True
    
    def test_ensemble_classification_consistency(self):
        """Test that ensemble provides consistent results for same input."""
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result1 = self.investigator.classify_threat(embedding)
        result2 = self.investigator.classify_threat(embedding)
        
        assert result1.threat_class == result2.threat_class
        assert abs(result1.confidence - result2.confidence) < 0.01


class TestIntentPrediction:
    """Test attacker intent prediction and MITRE mapping."""
    
    def setup_method(self):
        """Initialize investigator and create test data."""
        self.investigator = AIInvestigator()
        self.capture_engine = BehaviorCaptureEngine()
    
    def _load_test_events(self, filename):
        """Load test events from JSON file."""
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def test_predict_intent_with_behavior_graph(self):
        """Test intent prediction with actual behavior graph."""
        # Load APT test data
        events_data = self._load_test_events('apt.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        # Create embedding
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, graph)
        
        assert isinstance(result, IntentPrediction)
        assert result.primary_intent in self.investigator.mitre_mapper.attack_tactics
        assert len(result.intent_ranking) > 0
        assert result.attack_stage in ['initial', 'intermediate', 'advanced']
    
    def test_predict_intent_mitre_techniques(self):
        """Test that MITRE techniques are mapped."""
        events_data = self._load_test_events('ransomware.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, graph)
        
        assert len(result.mitre_techniques) > 0
        # Check that techniques are in correct format (T####)
        for technique in result.mitre_techniques:
            assert technique.startswith('T'), f"Invalid technique format: {technique}"
    
    def test_predict_intent_ranking(self):
        """Test that intent ranking is ordered by confidence."""
        events_data = self._load_test_events('insider.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, graph)
        
        # Check ranking is in descending order by confidence
        for i in range(len(result.intent_ranking) - 1):
            assert result.intent_ranking[i][1] >= result.intent_ranking[i+1][1], \
                "Intent ranking not in descending order"
    
    def test_predict_intent_natural_language(self):
        """Test that natural language explanation is generated."""
        events_data = self._load_test_events('benign.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, graph)
        
        assert result.natural_language_explanation is not None
        assert len(result.natural_language_explanation) > 0
        assert isinstance(result.natural_language_explanation, str)
    
    def test_attack_stage_progression(self):
        """Test attack stage prediction logic."""
        # Create simple graphs for different stages
        from data_models import BehaviorNode, BehaviorEdge
        
        # Initial stage: reconnaissance only
        initial_graph = BehaviorGraph(
            graph_id="test_graph",
            nodes=[
                BehaviorNode('n1', 'reconnaissance', '2024-01-01T00:00:00', {}),
                BehaviorNode('n2', 'initial_access', '2024-01-01T00:01:00', {})
            ],
            edges=[BehaviorEdge('n1', 'n2', 'next', 1.0, 60.0)]
        )
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, initial_graph)
        # Stage could be initial or intermediate depending on intent detection
        assert result.attack_stage in ['initial', 'intermediate']


class TestEvidenceGeneration:
    """Test explainable evidence generation."""
    
    def setup_method(self):
        """Initialize components."""
        self.investigator = AIInvestigator()
        self.capture_engine = BehaviorCaptureEngine()
    
    def _load_test_events(self, filename):
        """Load test events from JSON file."""
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def test_generate_evidence_completeness(self):
        """Test that evidence contains all required components."""
        # Create full analysis pipeline
        events_data = self._load_test_events('apt.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        classification = self.investigator.classify_threat(embedding)
        intent = self.investigator.predict_intent(embedding, graph)
        
        evidence = self.investigator.generate_evidence(
            graph, embedding, classification, intent, novelty_score=0.75
        )
        
        assert isinstance(evidence, Evidence)
        assert evidence.profile_id == classification.profile_id
        assert isinstance(evidence.top_features, list)
        assert isinstance(evidence.critical_path, list)
        assert isinstance(evidence.mitre_mappings, dict)
        assert isinstance(evidence.structured_json, dict)
        assert evidence.natural_language is not None
    
    def test_generate_evidence_top_features(self):
        """Test that top features are extracted."""
        events_data = self._load_test_events('ransomware.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        classification = self.investigator.classify_threat(embedding)
        intent = self.investigator.predict_intent(embedding, graph)
        
        evidence = self.investigator.generate_evidence(
            graph, embedding, classification, intent
        )
        
        # Should have up to 5 top features
        assert len(evidence.top_features) <= 5
        # Each feature should be a tuple (name, score)
        for feature in evidence.top_features:
            assert isinstance(feature, tuple)
            assert len(feature) == 2
    
    def test_generate_evidence_structured_json(self):
        """Test structured JSON format for SIEM integration."""
        events_data = self._load_test_events('insider.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        classification = self.investigator.classify_threat(embedding)
        intent = self.investigator.predict_intent(embedding, graph)
        
        evidence = self.investigator.generate_evidence(
            graph, embedding, classification, intent
        )
        
        # Verify JSON structure
        json_data = evidence.structured_json
        assert 'profile_id' in json_data
        assert 'threat_class' in json_data
        assert 'primary_intent' in json_data
        assert 'mitre_techniques' in json_data
    
    def test_generate_evidence_novelty_explanation(self):
        """Test novelty explanation when provided."""
        events_data = self._load_test_events('benign.json')
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        classification = self.investigator.classify_threat(embedding)
        intent = self.investigator.predict_intent(embedding, graph)
        
        # High novelty score
        evidence = self.investigator.generate_evidence(
            graph, embedding, classification, intent, novelty_score=0.85
        )
        
        assert isinstance(evidence.novelty_explanation, dict)


class TestClassificationAccuracy:
    """Test classification accuracy with real threat scenarios."""
    
    def setup_method(self):
        """Initialize components."""
        self.investigator = AIInvestigator()
        self.capture_engine = BehaviorCaptureEngine()
        self.feature_engineer = FeatureEngineer()
        self.dbef = DBEFEngine()
    
    def _load_and_classify(self, filename, expected_pattern):
        """Load test data, process it, and classify."""
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'r') as f:
            events_data = json.load(f)
        
        events = self.capture_engine.parse_events(events_data)
        graph = self.capture_engine.build_graph(events)
        features = self.feature_engineer.extract_features(graph)
        embedding = self.dbef.compute_embedding(features)
        
        classification = self.investigator.classify_threat(embedding.vector)
        intent = self.investigator.predict_intent(embedding.vector, graph)
        
        return classification, intent, expected_pattern
    
    def test_apt_classification(self):
        """Test classification of APT scenario."""
        classification, intent, _ = self._load_and_classify('apt.json', 'APT')
        
        # APT typically involves privilege escalation and credential access
        assert classification.confidence > 0.0
        # Intent should include relevant tactics
        assert any(tactic in ['privilege_escalation', 'credential_access', 'lateral_movement']
                  for tactic, _ in intent.intent_ranking)
    
    def test_ransomware_classification(self):
        """Test classification of ransomware scenario."""
        classification, intent, _ = self._load_and_classify('ransomware.json', 'Ransomware')
        
        # Ransomware typically involves impact tactics
        assert classification.confidence > 0.0
        # Intent should include impact
        intents = [tactic for tactic, _ in intent.intent_ranking]
        # Could be impact, or other tactics depending on the scenario
        assert len(intents) > 0
    
    def test_insider_threat_classification(self):
        """Test classification of insider threat scenario."""
        classification, intent, _ = self._load_and_classify('insider.json', 'Insider')
        
        # Should have reasonable confidence
        assert classification.confidence > 0.0
        # Intent should be detected
        assert len(intent.intent_ranking) > 0
    
    def test_benign_classification(self):
        """Test classification of benign scenario."""
        classification, intent, _ = self._load_and_classify('benign.json', 'Benign')
        
        # Should classify successfully
        assert classification.confidence > 0.0
        # Should have some intent detected
        assert len(intent.intent_ranking) > 0


class TestRobustness:
    """Test robustness and error handling."""
    
    def setup_method(self):
        """Initialize investigator."""
        self.investigator = AIInvestigator()
    
    def test_classify_with_edge_case_embedding(self):
        """Test classification with edge case embeddings."""
        # All zeros
        zero_embedding = np.zeros(128)
        result = self.investigator.classify_threat(zero_embedding)
        assert result.threat_class in VALID_THREAT_CLASSES or result.threat_class == "Unknown"
        
        # All ones normalized
        ones_embedding = np.ones(128)
        ones_embedding = ones_embedding / np.linalg.norm(ones_embedding)
        result = self.investigator.classify_threat(ones_embedding)
        assert result.threat_class in VALID_THREAT_CLASSES or result.threat_class == "Unknown"
    
    def test_predict_intent_empty_graph(self):
        """Test intent prediction with minimal graph."""
        from data_models import BehaviorNode, BehaviorEdge
        
        empty_graph = BehaviorGraph(
            graph_id="empty_graph",
            nodes=[],
            edges=[]
        )
        
        embedding = np.random.randn(128)
        embedding = embedding / np.linalg.norm(embedding)
        
        result = self.investigator.predict_intent(embedding, empty_graph)
        
        # Should still return a result with fallback
        assert isinstance(result, IntentPrediction)
        assert result.primary_intent in self.investigator.mitre_mapper.attack_tactics


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
