"""
BSF: Behavioral Similarity Function

This module implements the BSF algorithm, one of the four core research
contributions of BADNA. Measures behavioral similarity between BADNA embeddings
using weighted cosine similarity with multiple component analysis.

Algorithm: Weighted cosine similarity with structural (0.3), temporal (0.2), 
          and semantic (0.5) components.

Requirements: 4.1-4.10
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json

# Import our models
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_models import BADNAEmbedding, SimilarityResult, BehaviorPattern, CampaignProfile
from config import ValidationError, ProcessingError, get_logger, get_config


class BSFEngine:
    """
    BSF: Behavioral Similarity Function
    
    Computes behavioral similarity between BADNA embeddings using weighted
    multi-component similarity analysis. One of the core research algorithms.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        
        # Component weights (as specified in design)
        self.component_weights = {
            'structural': 0.3,
            'temporal': 0.2, 
            'semantic': 0.5
        }
        
        # Similarity thresholds
        self.similarity_threshold = self.config.similarity_threshold  # 0.70
        self.similarity_categories = {
            'highly_similar': 0.85,
            'moderately_similar': 0.60,
            'dissimilar': 0.0
        }
    
    def calculate_similarity(self, vector_a: np.ndarray, vector_b: np.ndarray) -> float:
        """
        Compute behavioral similarity score between two embeddings.
        
        Args:
            vector_a: 128-D BADNA embedding
            vector_b: 128-D BADNA embedding
            
        Returns:
            Similarity score in [0.0, 1.0] where:
                >= 0.85: Highly similar
                0.60-0.85: Moderately similar
                < 0.60: Dissimilar
                
        Algorithm:
            1. Compute weighted cosine similarity
            2. Apply structural component weight (0.3)
            3. Apply temporal component weight (0.2)
            4. Apply semantic component weight (0.5)
            5. Normalize to [0, 1]
        """
        # Validate inputs
        if vector_a.shape != (128,) or vector_b.shape != (128,):
            raise ValidationError("BADNA embeddings must be 128-dimensional")
        
        # Clean inputs of any non-finite values
        vector_a = np.nan_to_num(vector_a, nan=0.0, posinf=0.0, neginf=0.0)
        vector_b = np.nan_to_num(vector_b, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Check for zero vectors
        norm_a = np.linalg.norm(vector_a)
        norm_b = np.linalg.norm(vector_b)
        
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0  # Zero similarity for zero vectors
        
        # Split vectors into components for weighted similarity
        structural_a, temporal_a, semantic_a = self._split_embedding_components(vector_a)
        structural_b, temporal_b, semantic_b = self._split_embedding_components(vector_b)
        
        # Compute component similarities
        structural_sim = self._cosine_similarity(structural_a, structural_b)
        temporal_sim = self._cosine_similarity(temporal_a, temporal_b) 
        semantic_sim = self._cosine_similarity(semantic_a, semantic_b)
        
        # Weighted combination
        weighted_similarity = (
            self.component_weights['structural'] * structural_sim +
            self.component_weights['temporal'] * temporal_sim +
            self.component_weights['semantic'] * semantic_sim
        )
        
        # Normalize to [0, 1] and ensure mathematical properties
        similarity_score = np.clip(weighted_similarity, 0.0, 1.0)
        
        # Log similarity computation
        self.logger.log_operation("DEBUG", f"BSF similarity computed: {similarity_score:.3f}",
                                 component="BSFEngine", 
                                 operation="calculate_similarity")
        
        return float(similarity_score)
    
    def calculate_similarity_detailed(self, embedding_a: BADNAEmbedding, 
                                    embedding_b: BADNAEmbedding) -> SimilarityResult:
        """
        Compute detailed similarity result with component breakdown.
        
        Args:
            embedding_a: First BADNA embedding
            embedding_b: Second BADNA embedding
            
        Returns:
            SimilarityResult with detailed component scores and categorization
        """
        # Compute overall similarity
        similarity_score = self.calculate_similarity(embedding_a.vector, embedding_b.vector)
        
        # Compute component similarities for detailed analysis
        structural_a, temporal_a, semantic_a = self._split_embedding_components(embedding_a.vector)
        structural_b, temporal_b, semantic_b = self._split_embedding_components(embedding_b.vector)
        
        component_scores = {
            'structural': float(self._cosine_similarity(structural_a, structural_b)),
            'temporal': float(self._cosine_similarity(temporal_a, temporal_b)),
            'semantic': float(self._cosine_similarity(semantic_a, semantic_b)),
            'overall_cosine': float(self._cosine_similarity(embedding_a.vector, embedding_b.vector))
        }
        
        # Categorize similarity
        similarity_category = self._categorize_similarity(similarity_score)
        
        return SimilarityResult(
            query_embedding_id=embedding_a.embedding_id,
            target_embedding_id=embedding_b.embedding_id,
            similarity_score=similarity_score,
            similarity_category=similarity_category,
            component_scores=component_scores
        )
    
    def match_campaign(self, vector: np.ndarray, knowledge_base: 'KnowledgeBase') -> Dict[str, Any]:
        """
        Find most similar campaign in knowledge base.
        
        Args:
            vector: Query BADNA embedding
            knowledge_base: Repository of known campaigns
            
        Returns:
            Dict with campaign_id, similarity_score, and campaign_metadata
        """
        # BUG FIX 1: Knowledge Base Guard - Check if knowledge_base is empty
        if not hasattr(knowledge_base, 'get_campaigns'):
            return {
                'campaign_id': None,
                'similarity_score': 0.0,
                'campaign_metadata': {},
                'tracking_status': "NO_KB_INTERFACE"
            }
        
        campaigns = knowledge_base.get_campaigns()
        
        # BUG FIX 1: Knowledge Base Guard - Handle empty campaigns
        if not campaigns:
            return {
                'campaign_id': None,
                'similarity_score': 0.0,
                'campaign_metadata': {},
                'tracking_status': "UNKNOWN"
            }
        
        best_match = None
        best_similarity = 0.0
        
        for campaign in campaigns:
            if campaign.signature_embedding is not None:
                similarity = self.calculate_similarity(vector, campaign.signature_embedding)
                
                if similarity > best_similarity and similarity > self.similarity_threshold:
                    best_similarity = similarity
                    best_match = campaign
        
        if best_match:
            return {
                'campaign_id': best_match.campaign_id,
                'similarity_score': best_similarity,
                'campaign_metadata': {
                    'campaign_name': best_match.campaign_name,
                    'threat_class': best_match.threat_class,
                    'detection_count': best_match.detection_count,
                    'attribution': best_match.attribution
                },
                'tracking_status': "MATCHED"
            }
        else:
            return {
                'campaign_id': None,
                'similarity_score': 0.0,
                'campaign_metadata': {},
                'tracking_status': "NO_MATCH"
            }
    
    def batch_similarity(self, query_vector: np.ndarray, 
                        target_vectors: List[np.ndarray]) -> List[float]:
        """
        Compute similarity between query vector and multiple targets efficiently.
        
        Args:
            query_vector: Query BADNA embedding
            target_vectors: List of target BADNA embeddings
            
        Returns:
            List of similarity scores in same order as targets
        """
        similarities = []
        
        for target_vector in target_vectors:
            similarity = self.calculate_similarity(query_vector, target_vector)
            similarities.append(similarity)
        
        return similarities
    
    def _split_embedding_components(self, embedding: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Split 128-D embedding into structural, temporal, and semantic components.
        
        Component allocation:
        - Structural: dimensions 0-42 (33%)
        - Temporal: dimensions 43-67 (20%) 
        - Semantic: dimensions 68-127 (47%)
        """
        structural = embedding[:43]  # First 43 dimensions
        temporal = embedding[43:68]  # Next 25 dimensions
        semantic = embedding[68:]    # Last 60 dimensions
        
        return structural, temporal, semantic
    
    def _cosine_similarity(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """
        Compute cosine similarity between two vectors.
        
        Returns similarity in [-1, 1], but we map to [0, 1] for behavioral similarity.
        """
        # Handle zero vectors
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        
        # Compute cosine similarity
        cosine_sim = np.dot(vec_a, vec_b) / (norm_a * norm_b)
        
        # Map from [-1, 1] to [0, 1] for behavioral similarity
        # We want similar behaviors to have high similarity
        behavioral_sim = (cosine_sim + 1.0) / 2.0
        
        return np.clip(behavioral_sim, 0.0, 1.0)
    
    def _categorize_similarity(self, similarity_score: float) -> str:
        """Categorize similarity score into predefined categories."""
        if similarity_score >= self.similarity_categories['highly_similar']:
            return 'highly_similar'
        elif similarity_score >= self.similarity_categories['moderately_similar']:
            return 'moderately_similar'
        else:
            return 'dissimilar'
    
    def validate_mathematical_properties(self, test_vectors: List[np.ndarray]) -> Dict[str, bool]:
        """
        Validate BSF mathematical properties for testing.
        
        Tests:
        - Range invariant: BSF(x, y) ∈ [0, 1]
        - Identity property: BSF(x, x) = 1.0
        - Symmetry property: BSF(x, y) = BSF(y, x)
        
        Args:
            test_vectors: List of test embedding vectors
            
        Returns:
            Dict with validation results for each property
        """
        results = {
            'range_invariant': True,
            'identity_property': True,
            'symmetry_property': True
        }
        
        # Test range invariant and identity
        for vector in test_vectors:
            # Test identity: BSF(x, x) should equal 1.0
            self_similarity = self.calculate_similarity(vector, vector)
            if abs(self_similarity - 1.0) > 1e-6:
                results['identity_property'] = False
                self.logger.log_operation("ERROR", f"Identity property violated: BSF(x,x) = {self_similarity}",
                                         component="BSFEngine")
            
            # Test range invariant for self-similarity
            if not (0.0 <= self_similarity <= 1.0):
                results['range_invariant'] = False
        
        # Test symmetry and range for pairs
        for i in range(len(test_vectors)):
            for j in range(i + 1, len(test_vectors)):
                vec_i, vec_j = test_vectors[i], test_vectors[j]
                
                # Test symmetry: BSF(x, y) should equal BSF(y, x)
                sim_ij = self.calculate_similarity(vec_i, vec_j)
                sim_ji = self.calculate_similarity(vec_j, vec_i)
                
                if abs(sim_ij - sim_ji) > 1e-6:
                    results['symmetry_property'] = False
                    self.logger.log_operation("ERROR", f"Symmetry property violated: BSF({i},{j}) = {sim_ij}, BSF({j},{i}) = {sim_ji}",
                                             component="BSFEngine")
                
                # Test range invariant
                if not (0.0 <= sim_ij <= 1.0) or not (0.0 <= sim_ji <= 1.0):
                    results['range_invariant'] = False
        
        return results


# =============================================================================
# Utility Functions
# =============================================================================

def compute_pairwise_similarities(embeddings: List[BADNAEmbedding]) -> np.ndarray:
    """
    Compute pairwise similarity matrix for list of embeddings.
    
    Args:
        embeddings: List of BADNA embeddings
        
    Returns:
        Square similarity matrix where entry (i,j) is similarity between embeddings i and j
    """
    n = len(embeddings)
    similarity_matrix = np.zeros((n, n))
    
    bsf_engine = BSFEngine()
    
    for i in range(n):
        for j in range(n):
            if i == j:
                similarity_matrix[i, j] = 1.0  # Self-similarity
            else:
                sim = bsf_engine.calculate_similarity(embeddings[i].vector, embeddings[j].vector)
                similarity_matrix[i, j] = sim
    
    return similarity_matrix


def find_most_similar_embeddings(query_embedding: BADNAEmbedding,
                                candidate_embeddings: List[BADNAEmbedding],
                                top_k: int = 5) -> List[Tuple[BADNAEmbedding, float]]:
    """
    Find top-k most similar embeddings to query.
    
    Args:
        query_embedding: Query embedding
        candidate_embeddings: List of candidate embeddings to search
        top_k: Number of top results to return
        
    Returns:
        List of (embedding, similarity_score) tuples, sorted by similarity descending
    """
    bsf_engine = BSFEngine()
    results = []
    
    for candidate in candidate_embeddings:
        similarity = bsf_engine.calculate_similarity(query_embedding.vector, candidate.vector)
        results.append((candidate, similarity))
    
    # Sort by similarity descending and return top-k
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:top_k]


if __name__ == "__main__":
    # Test BSF implementation
    print("Testing BSF Algorithm...")
    
    # Import required modules for testing
    from data_models import BADNAEmbedding
    import uuid
    
    try:
        # Create test embeddings
        np.random.seed(42)  # For reproducible tests
        
        # Create similar embeddings (should have high similarity)
        base_vector = np.random.randn(128)
        base_vector = base_vector / np.linalg.norm(base_vector)  # Normalize
        
        similar_vector = base_vector + 0.1 * np.random.randn(128)
        similar_vector = similar_vector / np.linalg.norm(similar_vector)
        
        # Create dissimilar embedding
        different_vector = np.random.randn(128)
        different_vector = different_vector / np.linalg.norm(different_vector)
        
        # Create embedding objects
        embedding1 = BADNAEmbedding(
            embedding_id=str(uuid.uuid4()),
            vector=base_vector,
            source_graph_id="test_graph_1"
        )
        
        embedding2 = BADNAEmbedding(
            embedding_id=str(uuid.uuid4()),
            vector=similar_vector,
            source_graph_id="test_graph_2"
        )
        
        embedding3 = BADNAEmbedding(
            embedding_id=str(uuid.uuid4()),
            vector=different_vector,
            source_graph_id="test_graph_3"
        )
        
        # Test BSF engine
        bsf_engine = BSFEngine()
        
        # Test basic similarity computation
        sim_12 = bsf_engine.calculate_similarity(embedding1.vector, embedding2.vector)
        sim_13 = bsf_engine.calculate_similarity(embedding1.vector, embedding3.vector)
        sim_11 = bsf_engine.calculate_similarity(embedding1.vector, embedding1.vector)
        
        print(f"Similarity 1-2 (similar): {sim_12:.3f}")
        print(f"Similarity 1-3 (different): {sim_13:.3f}")
        print(f"Self-similarity 1-1: {sim_11:.3f}")
        
        # Test detailed similarity
        detailed_result = bsf_engine.calculate_similarity_detailed(embedding1, embedding2)
        print(f"Detailed similarity: {detailed_result.similarity_score:.3f} ({detailed_result.similarity_category})")
        print(f"Component scores: {detailed_result.component_scores}")
        
        # Test mathematical properties
        test_vectors = [embedding1.vector, embedding2.vector, embedding3.vector]
        properties = bsf_engine.validate_mathematical_properties(test_vectors)
        print(f"Mathematical properties validation: {properties}")
        
        # Test pairwise similarities
        embeddings = [embedding1, embedding2, embedding3]
        similarity_matrix = compute_pairwise_similarities(embeddings)
        print(f"Pairwise similarity matrix:\n{similarity_matrix}")
        
        # Test top-k similarity search
        top_similar = find_most_similar_embeddings(embedding1, [embedding2, embedding3], top_k=2)
        print(f"Top similar to embedding1: {[(emb.embedding_id, sim) for emb, sim in top_similar]}")
        
        print("BSF Algorithm implementation complete!")
        
    except Exception as e:
        print(f"Error testing BSF: {e}")
        import traceback
        traceback.print_exc()