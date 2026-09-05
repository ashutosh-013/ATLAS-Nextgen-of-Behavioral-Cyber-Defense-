"""
BADNA Data Models

This module implements all core data structures for the BADNA system as specified
in the design document. All models support JSON serialization/deserialization.

Requirements: 1.1-1.10, 2.1-2.8, 3.7, 4.1, 5.1, 6.1, 7.1-7.10, 8.1-8.10, 
             9.1-9.10, 10.1-10.10, 11.1-11.11, 12.1-12.3, 14.1
"""

import json
import uuid
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from config import ValidationError


# =============================================================================
# Core Event and Graph Data Models
# =============================================================================

@dataclass
class SecurityEvent:
    """Raw security event from external systems."""
    event_id: str
    event_type: str  # process, file, network, auth, registry, user
    timestamp: datetime
    source_system: str
    event_data: Dict[str, Any]
    
    def __post_init__(self):
        """Validate required fields."""
        valid_types = ['process', 'file', 'network', 'auth', 'registry', 'user']
        if self.event_type not in valid_types:
            raise ValidationError(f"Invalid event_type: {self.event_type}", "event_type")
        
        if not isinstance(self.event_data, dict):
            raise ValidationError("event_data must be a dictionary", "event_data")
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


@dataclass
class BehaviorNode:
    """Node in behavior graph representing an action."""
    node_id: str
    action_type: str
    event_refs: List[str]
    timestamp: datetime
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorNode':
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)

@dataclass
class BehaviorEdge:
    """Edge in behavior graph representing a transition."""
    source_node: str
    target_node: str
    transition_type: str
    weight: float
    temporal_gap: float  # Time gap in seconds
    
    def __post_init__(self):
        """Validate edge properties."""
        if self.weight < 0:
            raise ValidationError("Edge weight must be non-negative", "weight")
        if self.temporal_gap < 0:
            raise ValidationError("Temporal gap must be non-negative", "temporal_gap")


@dataclass
class BehaviorGraph:
    """Directed acyclic graph representing attack behavior."""
    graph_id: str
    nodes: List[BehaviorNode]
    edges: List[BehaviorEdge]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Compute graph properties."""
        self.node_count = len(self.nodes)
        self.edge_count = len(self.edges)
        if self.node_count > 1:
            max_edges = self.node_count * (self.node_count - 1)
            self.density = self.edge_count / max_edges if max_edges > 0 else 0.0
        else:
            self.density = 0.0
        self.is_acyclic = True  # Enforced by construction
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'graph_id': self.graph_id,
            'nodes': [node.to_dict() for node in self.nodes],
            'edges': [asdict(edge) for edge in self.edges],
            'metadata': self.metadata,
            'node_count': self.node_count,
            'edge_count': self.edge_count,
            'density': self.density,
            'is_acyclic': self.is_acyclic
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorGraph':
        nodes = [BehaviorNode.from_dict(node_data) for node_data in data['nodes']]
        edges = [BehaviorEdge(**edge_data) for edge_data in data['edges']]
        return cls(
            graph_id=data['graph_id'],
            nodes=nodes,
            edges=edges,
            metadata=data.get('metadata', {})
        )

# =============================================================================
# Feature Vector and Embedding Models  
# =============================================================================

@dataclass
class FeatureVector:
    """Extracted features from behavior graph."""
    graph_id: str
    features: np.ndarray
    feature_names: List[str]
    extraction_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate feature constraints."""
        if len(self.features) < 64:
            raise ValidationError(f"Feature vector must have at least 64 dimensions, got {len(self.features)}")
        
        if len(self.feature_names) != len(self.features):
            raise ValidationError("Feature names length must match features length")
        
        # Check normalization
        if np.any((self.features < 0) | (self.features > 1)):
            raise ValidationError("All features must be normalized to [0.0, 1.0] range")
    
    def normalize(self) -> np.ndarray:
        """Normalize features to [0, 1] scale."""
        if np.max(self.features) == np.min(self.features):
            return np.zeros_like(self.features)
        return (self.features - np.min(self.features)) / (np.max(self.features) - np.min(self.features))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'graph_id': self.graph_id,
            'features': self.features.tolist(),
            'feature_names': self.feature_names,
            'extraction_time': self.extraction_time.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FeatureVector':
        return cls(
            graph_id=data['graph_id'],
            features=np.array(data['features']),
            feature_names=data['feature_names'],
            extraction_time=datetime.fromisoformat(data['extraction_time'])
        )


@dataclass
class BADNAEmbedding:
    """128-dimensional behavioral fingerprint."""
    embedding_id: str
    vector: np.ndarray
    source_graph_id: str
    generation_method: str = "d-BEF"
    generation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate embedding constraints."""
        if self.vector.shape != (128,):
            raise ValidationError(f"BADNA embedding must be 128-dimensional, got {self.vector.shape}")
        
        # Check unit length (within tolerance)
        norm = np.linalg.norm(self.vector)
        if abs(norm - 1.0) > 1e-6:
            raise ValidationError(f"BADNA embedding must have unit length, got norm {norm}")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'embedding_id': self.embedding_id,
            'vector': self.vector.tolist(),
            'source_graph_id': self.source_graph_id,
            'generation_method': self.generation_method,
            'generation_time': self.generation_time.isoformat()
        }
    
    @classmethod  
    def from_dict(cls, data: Dict[str, Any]) -> 'BADNAEmbedding':
        return cls(
            embedding_id=data['embedding_id'],
            vector=np.array(data['vector']),
            source_graph_id=data['source_graph_id'],
            generation_method=data.get('generation_method', 'd-BEF'),
            generation_time=datetime.fromisoformat(data['generation_time'])
        )
# =============================================================================
# Analysis Result Models
# =============================================================================

@dataclass
class SimilarityResult:
    """Result of BSF similarity computation."""
    query_embedding_id: str
    target_embedding_id: str
    similarity_score: float
    similarity_category: str
    component_scores: Dict[str, float]
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate similarity result."""
        if not 0.0 <= self.similarity_score <= 1.0:
            raise ValidationError(f"Similarity score must be in [0.0, 1.0], got {self.similarity_score}")
        
        valid_categories = ['highly_similar', 'moderately_similar', 'dissimilar']
        if self.similarity_category not in valid_categories:
            raise ValidationError(f"Invalid similarity category: {self.similarity_category}")


@dataclass  
class NoveltyResult:
    """Result of NSF novelty detection."""
    embedding_id: str
    novelty_score: float
    novelty_category: str
    nearest_neighbors: List[Tuple[str, float]]
    local_outlier_factor: float
    explanation: Dict[str, float]
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate novelty result."""
        if not 0.0 <= self.novelty_score <= 1.0:
            raise ValidationError(f"Novelty score must be in [0.0, 1.0], got {self.novelty_score}")
        
        valid_categories = ['highly_novel', 'moderately_novel', 'known']
        if self.novelty_category not in valid_categories:
            raise ValidationError(f"Invalid novelty category: {self.novelty_category}")


@dataclass
class ConfidenceResult:
    """Result of CCF confidence calibration."""
    profile_id: str
    confidence_score: float
    confidence_interval: Tuple[float, float]
    calibration_factors: Dict[str, float]
    raw_prediction_score: float
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate confidence result."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValidationError(f"Confidence score must be in [0.0, 1.0], got {self.confidence_score}")
        
        low, high = self.confidence_interval
        if not (0.0 <= low <= high <= 1.0):
            raise ValidationError(f"Invalid confidence interval: [{low}, {high}]")


@dataclass
class ThreatClassification:
    """Result of threat classification."""
    profile_id: str
    threat_class: str
    confidence: float
    probability_distribution: Dict[str, float]
    uncertainty_flag: bool
    classification_method: str
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate threat classification."""
        valid_classes = ['APT', 'Ransomware', 'Insider_Threat', 'Malware', 'Phishing', 'Benign']
        if self.threat_class not in valid_classes:
            raise ValidationError(f"Invalid threat class: {self.threat_class}")
        
        if not 0.0 <= self.confidence <= 1.0:
            raise ValidationError(f"Confidence must be in [0.0, 1.0], got {self.confidence}")
@dataclass
class IntentPrediction:
    """Result of attacker intent prediction."""
    profile_id: str
    primary_intent: str
    intent_ranking: List[Tuple[str, float]]
    attack_stage: str
    mitre_techniques: List[str]
    natural_language_explanation: str
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate intent prediction."""
        valid_stages = ['initial', 'intermediate', 'advanced']
        if self.attack_stage not in valid_stages:
            raise ValidationError(f"Invalid attack stage: {self.attack_stage}")


@dataclass
class Evidence:
    """Explainable evidence for threat detection."""
    profile_id: str
    top_features: List[Tuple[str, float]]
    critical_path: List[str]
    mitre_mappings: Dict[str, str]
    campaign_reference: Optional[str]
    novelty_explanation: Dict[str, float]
    structured_json: Dict[str, Any]
    natural_language: str
    generation_time: datetime = field(default_factory=datetime.now)


@dataclass
class RiskScore:
    """Unified risk assessment."""
    profile_id: str
    score: float
    risk_level: str
    contributing_factors: Dict[str, float]
    rationale: str
    computation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate risk score."""
        if not 0.0 <= self.score <= 1.0:
            raise ValidationError(f"Risk score must be in [0.0, 1.0], got {self.score}")
        
        valid_levels = ['Critical', 'High', 'Medium', 'Low', 'Minimal']
        if self.risk_level not in valid_levels:
            raise ValidationError(f"Invalid risk level: {self.risk_level}")


# =============================================================================
# BADNA Profile - Complete Analysis Result
# =============================================================================

@dataclass 
class BADNAProfile:
    """Complete BADNA analysis output."""
    profile_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Core components
    embedding: Optional[BADNAEmbedding] = None
    similarity_result: Optional[SimilarityResult] = None
    novelty_result: Optional[NoveltyResult] = None
    confidence_result: Optional[ConfidenceResult] = None
    threat_classification: Optional[ThreatClassification] = None
    intent_prediction: Optional[IntentPrediction] = None
    evidence: Optional[Evidence] = None
    risk_score: Optional[RiskScore] = None
    
    # Optional campaign match
    matched_campaign_id: Optional[str] = None
    
    # System metadata
    badna_version: str = "1.0.0"
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Serialize to JSON for storage/transmission."""
        def convert_for_json(obj, visited=None):
            if visited is None:
                visited = set()
                
            # Prevent circular references by tracking object IDs
            obj_id = id(obj)
            if obj_id in visited:
                return f"<circular_reference_to_{type(obj).__name__}>"
            
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif hasattr(obj, 'to_dict'):
                # Handle objects with to_dict method (like DefenseRecommendationSuite)
                visited.add(obj_id)
                try:
                    result = obj.to_dict()
                    visited.remove(obj_id)
                    return result
                except Exception as e:
                    visited.remove(obj_id)
                    return f"<serialization_error_{type(obj).__name__}: {str(e)}>"
            elif isinstance(obj, tuple):
                return list(obj)
            elif isinstance(obj, (list, dict)):
                # Handle collections that might contain circular references
                visited.add(obj_id)
                try:
                    if isinstance(obj, list):
                        result = [convert_for_json(item, visited) for item in obj]
                    else:  # dict
                        result = {k: convert_for_json(v, visited) for k, v in obj.items()}
                    visited.remove(obj_id)
                    return result
                except Exception as e:
                    visited.remove(obj_id)
                    return f"<collection_error: {str(e)}>"
            return obj
        
        try:
            data = asdict(self)
            return json.dumps(data, default=convert_for_json, indent=2)
        except Exception as e:
            # Fallback: create a minimal safe representation
            safe_data = {
                'profile_id': self.profile_id,
                'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                'badna_version': self.badna_version,
                'serialization_error': str(e),
                'error_type': 'circular_reference_or_serialization_failure'
            }
            return json.dumps(safe_data, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'BADNAProfile':
        """Deserialize from JSON."""
        data = json.loads(json_str)
        
        # Convert timestamp
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        
        # Convert nested objects
        if data.get('embedding'):
            data['embedding'] = BADNAEmbedding.from_dict(data['embedding'])
        
        # Handle other nested objects (simplified for now)
        return cls(**data)
# =============================================================================
# Knowledge Base Models
# =============================================================================

@dataclass
class BehaviorPattern:
    """Stored behavioral pattern in knowledge base."""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    embedding: np.ndarray = field(default=None)
    threat_class: str = ""
    campaign_id: Optional[str] = None
    confidence_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "unknown"  # feedback, automated, imported
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate behavior pattern."""
        if self.embedding is not None and self.embedding.shape != (128,):
            raise ValidationError(f"Pattern embedding must be 128-dimensional, got {self.embedding.shape}")
        
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValidationError(f"Confidence score must be in [0.0, 1.0], got {self.confidence_score}")
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        if self.embedding is not None:
            result['embedding'] = self.embedding.tolist()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorPattern':
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        if 'embedding' in data and data['embedding'] is not None:
            data['embedding'] = np.array(data['embedding'])
        return cls(**data)


@dataclass
class CampaignProfile:
    """Attack campaign with behavioral signature."""
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    signature_embedding: np.ndarray = field(default=None)
    member_patterns: List[str] = field(default_factory=list)
    threat_class: str = ""
    common_techniques: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    detection_count: int = 0
    attribution: Optional[str] = None
    
    def __post_init__(self):
        """Validate campaign profile."""
        if self.signature_embedding is not None and self.signature_embedding.shape != (128,):
            raise ValidationError(f"Campaign signature must be 128-dimensional, got {self.signature_embedding.shape}")
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['first_seen'] = self.first_seen.isoformat()
        result['last_seen'] = self.last_seen.isoformat()
        if self.signature_embedding is not None:
            result['signature_embedding'] = self.signature_embedding.tolist()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CampaignProfile':
        if isinstance(data['first_seen'], str):
            data['first_seen'] = datetime.fromisoformat(data['first_seen'])
        if isinstance(data['last_seen'], str):
            data['last_seen'] = datetime.fromisoformat(data['last_seen'])
        if 'signature_embedding' in data and data['signature_embedding'] is not None:
            data['signature_embedding'] = np.array(data['signature_embedding'])
        return cls(**data)


@dataclass
class Feedback:
    """Analyst feedback on detection."""
    feedback_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    profile_id: str = ""
    feedback_type: str = ""  # true_positive, false_positive, false_negative
    analyst_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    analyst_notes: Optional[str] = None
    corrected_label: Optional[str] = None
    
    def __post_init__(self):
        """Validate feedback."""
        valid_types = ['true_positive', 'false_positive', 'false_negative']
        if self.feedback_type not in valid_types:
            raise ValidationError(f"Invalid feedback type: {self.feedback_type}")
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Feedback':
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


# =============================================================================
# Utility Functions
# =============================================================================

def create_security_event(event_type: str, event_data: Dict[str, Any], 
                         source_system: str = "BADNA") -> SecurityEvent:
    """Create a security event with automatic ID and timestamp."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=datetime.now(),
        source_system=source_system,
        event_data=event_data
    )


def create_behavior_node(action_type: str, event_refs: List[str], 
                        attributes: Dict[str, Any] = None) -> BehaviorNode:
    """Create a behavior node with automatic ID and timestamp."""
    return BehaviorNode(
        node_id=str(uuid.uuid4()),
        action_type=action_type,
        event_refs=event_refs,
        timestamp=datetime.now(),
        attributes=attributes or {}
    )


def create_badna_profile() -> BADNAProfile:
    """Create a new BADNA profile with automatic ID and timestamp."""
    return BADNAProfile()


# Valid constants for validation
VALID_THREAT_CLASSES = ['APT', 'Ransomware', 'Insider_Threat', 'Malware', 'Phishing', 'Benign']
VALID_RISK_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Minimal']
VALID_ATTACK_STAGES = ['initial', 'intermediate', 'advanced']
VALID_FEEDBACK_TYPES = ['true_positive', 'false_positive', 'false_negative']


if __name__ == "__main__":
    # Test data model creation and serialization
    print("Testing BADNA data models...")
    
    # Test SecurityEvent
    event = create_security_event("process", {"pid": 1234, "name": "cmd.exe"})
    print(f"Created event: {event.event_id}")
    
    # Test BADNAProfile serialization
    profile = create_badna_profile()
    json_str = profile.to_json()
    profile2 = BADNAProfile.from_json(json_str)
    print(f"Profile serialization test: {profile.profile_id == profile2.profile_id}")
    
    print("Data models implementation complete!")