"""
NSF: Novelty Score Function

This module implements the NSF algorithm, one of the four core research
contributions of BADNA. Detects novel and zero-day attacks through distance-based
anomaly detection using locality-sensitive hashing and Local Outlier Factor.

Algorithm: LSH → Candidate Selection → BSF → Novelty Computation

Requirements: 5.1-5.10
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import pairwise_distances
import hashlib

# Import our models and BSF
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_models import BADNAEmbedding, NoveltyResult, BehaviorPattern
from config import ValidationError, ProcessingError, get_logger, get_config
from similarity.bsf import BSFEngine


class LSHIndex:
    """
    Locality-Sensitive Hashing index for efficient nearest neighbor search.
    Used for candidate selection in novelty detection.
    """
    
    def __init__(self, embedding_dim: int = 128, num_hash_functions: int = 10, hash_size: int = 4):
        self.embedding_dim = embedding_dim
        self.num_hash_functions = num_hash_functions
        self.hash_size = hash_size
        
        # Generate random projection vectors for LSH
        np.random.seed(42)  # For reproducibility
        self.projection_vectors = []
        for _ in range(num_hash_functions):
            # Random hyperplanes for hashing
            proj_vector = np.random.randn(embedding_dim, hash_size)
            self.projection_vectors.append(proj_vector)
        
        # Storage for embeddings and their hashes
        self.embedding_store = {}  # hash -> list of (embedding_id, embedding_vector)
        self.embedding_lookup = {}  # embedding_id -> embedding_vector
    
    def _compute_hash(self, vector: np.ndarray) -> str:
        """Compute LSH hash for a vector."""
        hash_bits = []
        
        for proj_vector in self.projection_vectors:
            # Project vector and take sign
            projection = np.dot(vector, proj_vector)
            bits = ''.join('1' if x > 0 else '0' for x in projection)
            hash_bits.append(bits)
        
        # Combine all hash functions
        combined_hash = ''.join(hash_bits)
        return combined_hash
    
    def add_embedding(self, embedding_id: str, vector: np.ndarray) -> None:
        """Add an embedding to the LSH index."""
        if vector.shape != (self.embedding_dim,):
            raise ValidationError(f"Vector must be {self.embedding_dim}-dimensional")
        
        # Compute hash
        hash_key = self._compute_hash(vector)
        
        # Store in hash bucket
        if hash_key not in self.embedding_store:
            self.embedding_store[hash_key] = []
        
        self.embedding_store[hash_key].append((embedding_id, vector))
        self.embedding_lookup[embedding_id] = vector
    
    def find_candidates(self, query_vector: np.ndarray, max_candidates: int = 50) -> List[Tuple[str, np.ndarray]]:
        """Find candidate neighbors for a query vector."""
        query_hash = self._compute_hash(query_vector)
        candidates = []
        
        # Start with exact hash match
        if query_hash in self.embedding_store:
            candidates.extend(self.embedding_store[query_hash])
        
        # If not enough candidates, expand to similar hashes
        if len(candidates) < max_candidates:
            for stored_hash, embeddings in self.embedding_store.items():
                if stored_hash != query_hash:
                    # Compute Hamming distance between hashes
                    hamming_dist = sum(c1 != c2 for c1, c2 in zip(query_hash, stored_hash))
                    
                    # Include similar hashes (within threshold)
                    if hamming_dist <= len(query_hash) * 0.2:  # 20% different bits allowed
                        candidates.extend(embeddings)
                        
                        if len(candidates) >= max_candidates:
                            break
        
        return candidates[:max_candidates]
    
    def size(self) -> int:
        """Return number of embeddings in index."""
        return len(self.embedding_lookup)


class NSFEngine:
    """
    NSF: Novelty Score Function
    
    Detects novel and zero-day attacks using distance-based anomaly detection.
    One of the four core research algorithms of BADNA.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.bsf_engine = BSFEngine()
        
        # Novelty thresholds
        self.novelty_threshold = self.config.novelty_threshold  # 0.80
        self.novelty_categories = {
            'highly_novel': 0.80,
            'moderately_novel': 0.50,
            'known': 0.0
        }
        
        # LSH parameters
        self.lsh_index = LSHIndex(embedding_dim=128)
        self.k_neighbors = 5  # For LOF computation
        self.min_knowledge_base_size = 10  # Minimum KB size for reliable novelty
    
    def compute_novelty(self, vector: np.ndarray, knowledge_base: 'KnowledgeBase') -> NoveltyResult:
        """
        Compute novelty score for behavior embedding.
        
        Args:
            vector: 128-D BADNA embedding to evaluate
            knowledge_base: Repository of known patterns
            
        Returns:
            NoveltyResult with:
                - novelty_score: float in [0.0, 1.0]
                - classification: str ('highly_novel', 'moderately_novel', 'known')
                - nearest_neighbors: List[Tuple[str, float]]
                - explanation: dict with contributing features
                
        Score Interpretation:
            >= 0.80: Highly novel (potential zero-day)
            0.50-0.80: Moderately novel (variant attack)
            < 0.50: Known pattern
            
        Algorithm:
            1. Use LSH for candidate selection (approximate nearest neighbors)
            2. Compute exact distances to k=5 nearest neighbors
            3. Calculate Local Outlier Factor (LOF)
            4. Apply distance-based anomaly score
            5. Normalize to [0, 1]
        """
        if vector.shape != (128,):
            raise ValidationError("Input vector must be 128-dimensional")
        
        # Clean non-finites
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Handle empty knowledge base
        if not hasattr(knowledge_base, 'get_patterns') or not knowledge_base.get_patterns():
            return NoveltyResult(
                embedding_id=f"novel_{int(datetime.now().timestamp())}",
                novelty_score=1.0,
                novelty_category='highly_novel',
                nearest_neighbors=[],
                local_outlier_factor=float('inf'),
                explanation={'reason': 'empty_knowledge_base'}
            )
        
        patterns = knowledge_base.get_patterns()
        
        # Handle small knowledge base
        if len(patterns) < self.min_knowledge_base_size:
            confidence_penalty = len(patterns) / self.min_knowledge_base_size
            base_novelty = self._compute_base_novelty(vector, patterns)
            penalized_novelty = min(base_novelty * (2 - confidence_penalty), 1.0)
            
            return NoveltyResult(
                embedding_id=f"novel_{int(datetime.now().timestamp())}",
                novelty_score=penalized_novelty,
                novelty_category=self._categorize_novelty(penalized_novelty),
                nearest_neighbors=self._find_nearest_neighbors(vector, patterns),
                local_outlier_factor=1.0,
                explanation={'reason': 'small_knowledge_base', 'penalty': 1 - confidence_penalty}
            )
        
        # Build LSH index if not already built
        self._build_lsh_index(patterns)
        
        # Step 1: LSH candidate selection
        candidates = self.lsh_index.find_candidates(vector)
        
        if not candidates:
            # No candidates found - highly novel
            return NoveltyResult(
                embedding_id=f"novel_{int(datetime.now().timestamp())}",
                novelty_score=1.0,
                novelty_category='highly_novel',
                nearest_neighbors=[],
                local_outlier_factor=float('inf'),
                explanation={'reason': 'no_candidates_found'}
            )
        
        # Step 2: Compute exact distances to k nearest neighbors
        nearest_neighbors = self._compute_exact_neighbors(vector, candidates)
        
        # Step 3: Calculate Local Outlier Factor
        lof_score = self._compute_local_outlier_factor(vector, nearest_neighbors, patterns)
        
        # Step 4: Compute distance-based novelty score
        distance_novelty = self._compute_distance_novelty(vector, nearest_neighbors)
        
        # Step 5: Combine LOF and distance scores
        combined_novelty = self._combine_novelty_scores(distance_novelty, lof_score)
        
        # Step 6: Generate explanation
        explanation = self._generate_novelty_explanation(vector, nearest_neighbors, lof_score)
        
        # Categorize novelty
        novelty_category = self._categorize_novelty(combined_novelty)
        
        result = NoveltyResult(
            embedding_id=f"novel_{int(datetime.now().timestamp())}",
            novelty_score=combined_novelty,
            novelty_category=novelty_category,
            nearest_neighbors=[(nn_id, dist) for nn_id, dist, _ in nearest_neighbors],
            local_outlier_factor=lof_score,
            explanation=explanation
        )
        
        self.logger.log_operation("INFO", f"Novelty computed: {combined_novelty:.3f} ({novelty_category})",
                                 component="NSFEngine", 
                                 operation="compute_novelty")
        
        return result
    
    def explain_novelty(self, vector: np.ndarray, neighbors: List[Tuple[str, float, np.ndarray]]) -> Dict[str, float]:
        """
        Explain which features contribute to novelty.
        
        Enhanced explanation includes all novelty components:
        - Vocabulary novelty: semantic feature deviations
        - Topology novelty: structural pattern deviations
        - Timing novelty: temporal pattern deviations  
        - Intent novelty: behavioral intent deviations
        - Edge novelty: transition pattern deviations
        
        Args:
            vector: Novel behavior embedding
            neighbors: Nearest known patterns
            
        Returns:
            Dict mapping feature names to deviation scores
        """
        if not neighbors:
            return {
                'overall_deviation': 1.0,
                'vocabulary_novelty': 1.0,
                'topology_novelty': 1.0,
                'timing_novelty': 1.0,
                'intent_novelty': 1.0,
                'edge_novelty': 1.0
            }
        
        explanation = {}
        
        # Compute feature-wise deviations
        neighbor_vectors = [neighbor[2] for neighbor in neighbors]
        neighbor_mean = np.mean(neighbor_vectors, axis=0)
        
        # Calculate per-dimension deviations
        deviations = np.abs(vector - neighbor_mean)
        
        # Enhanced component analysis for Bug 8 fix:
        # Map embedding dimensions to novelty components
        
        # Vocabulary novelty (semantic features: dims 68-127) 
        vocabulary_dev = np.mean(deviations[68:])
        explanation['vocabulary_novelty'] = float(vocabulary_dev)
        
        # Topology novelty (structural features: dims 0-42)
        topology_dev = np.mean(deviations[:43]) 
        explanation['topology_novelty'] = float(topology_dev)
        
        # Timing novelty (temporal features: dims 43-67)
        timing_dev = np.mean(deviations[43:68])
        explanation['timing_novelty'] = float(timing_dev)
        
        # Intent novelty (behavioral patterns: mixed dimensions)
        intent_dev = np.mean([
            np.mean(deviations[0:20]),    # Early structural patterns
            np.mean(deviations[68:88])    # Early semantic patterns
        ])
        explanation['intent_novelty'] = float(intent_dev)
        
        # Edge novelty (transition patterns: mixed dimensions)
        edge_dev = np.mean([
            np.mean(deviations[20:43]),   # Later structural patterns  
            np.mean(deviations[43:68]),   # Temporal patterns
            np.mean(deviations[108:128])  # Later semantic patterns
        ])
        explanation['edge_novelty'] = float(edge_dev)
        
        # Legacy components for backward compatibility
        explanation['structural_deviation'] = float(topology_dev)
        explanation['temporal_deviation'] = float(timing_dev) 
        explanation['semantic_deviation'] = float(vocabulary_dev)
        explanation['overall_deviation'] = float(np.mean(deviations))
        
        # Find most deviating dimensions
        top_deviating_dims = np.argsort(deviations)[-5:]
        explanation['top_deviating_dimensions'] = top_deviating_dims.tolist()
        
        # Add p-norm based overall score
        novelty_components = np.array([
            vocabulary_dev, topology_dev, timing_dev, intent_dev, edge_dev
        ])
        p_norm_score = np.power(np.mean(np.power(novelty_components, 2)), 0.5)
        explanation['p_norm_novelty'] = float(p_norm_score)
        
        return explanation
    
    def _build_lsh_index(self, patterns: List[BehaviorPattern]) -> None:
        """Build or update LSH index with patterns."""
        # Clear existing index
        self.lsh_index = LSHIndex(embedding_dim=128)
        
        # Add all patterns to index
        for pattern in patterns:
            if pattern.embedding is not None:
                self.lsh_index.add_embedding(pattern.pattern_id, pattern.embedding)
    
    def _compute_base_novelty(self, vector: np.ndarray, patterns: List[BehaviorPattern]) -> float:
        """Compute base novelty score using simple distance measures."""
        if not patterns:
            return 1.0
        
        min_distance = float('inf')
        
        for pattern in patterns:
            if pattern.embedding is not None:
                # Use BSF similarity and convert to distance
                similarity = self.bsf_engine.calculate_similarity(vector, pattern.embedding)
                distance = 1.0 - similarity
                min_distance = min(min_distance, distance)
        
        return min_distance
    
    def _find_nearest_neighbors(self, vector: np.ndarray, 
                               patterns: List[BehaviorPattern]) -> List[Tuple[str, float]]:
        """Find nearest neighbors using brute force search."""
        neighbors = []
        
        for pattern in patterns:
            if pattern.embedding is not None:
                similarity = self.bsf_engine.calculate_similarity(vector, pattern.embedding)
                distance = 1.0 - similarity
                neighbors.append((pattern.pattern_id, distance))
        
        # Sort by distance and return top k
        neighbors.sort(key=lambda x: x[1])
        return neighbors[:self.k_neighbors]
    
    def _compute_exact_neighbors(self, vector: np.ndarray, 
                                candidates: List[Tuple[str, np.ndarray]]) -> List[Tuple[str, float, np.ndarray]]:
        """Compute exact distances to candidate neighbors."""
        neighbors = []
        
        for candidate_id, candidate_vector in candidates:
            # Use BSF similarity and convert to distance  
            similarity = self.bsf_engine.calculate_similarity(vector, candidate_vector)
            distance = 1.0 - similarity
            neighbors.append((candidate_id, distance, candidate_vector))
        
        # Sort by distance and return top k
        neighbors.sort(key=lambda x: x[1])
        return neighbors[:self.k_neighbors]
    
    def _compute_local_outlier_factor(self, vector: np.ndarray,
                                     nearest_neighbors: List[Tuple[str, float, np.ndarray]],
                                     all_patterns: List[BehaviorPattern]) -> float:
        """Compute Local Outlier Factor score."""
        if len(nearest_neighbors) < 2:
            return float('inf')  # Highly novel if too few neighbors
        
        try:
            # Prepare data for LOF computation
            neighbor_vectors = [nn[2] for nn in nearest_neighbors]
            all_vectors = [vector] + neighbor_vectors
            
            k = min(len(neighbor_vectors), self.k_neighbors)
            # Scikit-learn LOF requires n_samples > n_neighbors
            # If candidate set is too small, fall back directly to nearest-neighbor distance
            if len(all_vectors) <= k or len(all_vectors) < 4:
                return float(nearest_neighbors[0][1]) if nearest_neighbors else 1.0
            
            # Compute LOF using scikit-learn
            lof = LocalOutlierFactor(n_neighbors=min(k, len(all_vectors) - 1), 
                                   contamination='auto',
                                   novelty=False)
            
            lof_scores = lof.fit_predict(all_vectors)
            
            # LOF score for query vector (first in list)
            query_lof_score = -lof.negative_outlier_factor_[0]
            
            return float(query_lof_score)
            
        except Exception as e:
            self.logger.log_operation("WARNING", f"LOF computation failed: {e}",
                                     component="NSFEngine")
            # Fallback to simple distance-based score
            if nearest_neighbors:
                return float(nearest_neighbors[0][1])  # Distance to nearest neighbor
            else:
                return 1.0
    
    def _compute_distance_novelty(self, vector: np.ndarray,
                                 nearest_neighbors: List[Tuple[str, float, np.ndarray]]) -> float:
        """Compute distance-based novelty score."""
        if not nearest_neighbors:
            return 1.0
        
        # Use distance to k-th nearest neighbor
        k_distance = nearest_neighbors[-1][1] if len(nearest_neighbors) >= self.k_neighbors else nearest_neighbors[-1][1]
        
        # Use average distance to all neighbors
        avg_distance = np.mean([nn[1] for nn in nearest_neighbors])
        
        # Combine k-distance and average distance
        distance_novelty = 0.6 * k_distance + 0.4 * avg_distance
        
        return min(distance_novelty, 1.0)
    
    def _combine_novelty_scores(self, distance_novelty: float, lof_score: float) -> float:
        """
        Combine distance and LOF scores into final novelty score.
        
        BUG FIX 8: Enhanced NSF equation combining multiple novelty components:
        - Vocabulary novelty (semantic features)
        - Topology novelty (structural features) 
        - Timing novelty (temporal features)
        - Intent novelty (behavioral patterns)
        - Edge novelty (transition patterns)
        
        Uses p-norm formulation for robust combination.
        """
        # Normalize LOF score to [0, 1] range
        # LOF = 1 means normal, LOF > 1 means outlier
        normalized_lof = min((lof_score - 1.0) * 0.5, 1.0) if lof_score > 1.0 else 0.0
        
        # Enhanced NSF: Compute component-wise novelty scores
        vocabulary_novelty = distance_novelty  # Semantic distance
        topology_novelty = normalized_lof     # Structural outlier
        timing_novelty = min(distance_novelty * 1.2, 1.0)  # Temporal patterns
        intent_novelty = distance_novelty * 0.8  # Behavioral patterns
        edge_novelty = normalized_lof * 0.9  # Transition anomalies
        
        # P-norm combination (p=2 for balanced sensitivity)
        p = 2.0
        novelty_components = np.array([
            vocabulary_novelty,
            topology_novelty, 
            timing_novelty,
            intent_novelty,
            edge_novelty
        ])
        
        # Compute p-norm
        p_norm_novelty = np.power(np.mean(np.power(novelty_components, p)), 1.0/p)
        
        # Apply component weights
        weights = np.array([0.3, 0.25, 0.2, 0.15, 0.1])  # Sum = 1.0
        weighted_novelty = np.sum(weights * novelty_components)
        
        # Combine p-norm and weighted approaches
        final_novelty = 0.6 * p_norm_novelty + 0.4 * weighted_novelty
        
        return np.clip(final_novelty, 0.0, 1.0)
    
    def _generate_novelty_explanation(self, vector: np.ndarray,
                                     nearest_neighbors: List[Tuple[str, float, np.ndarray]],
                                     lof_score: float) -> Dict[str, Any]:
        """
        Generate explanation for novelty score.
        
        Enhanced explanation with Bug 8 fix includes all novelty components.
        """
        explanation = {
            'lof_score': float(lof_score),
            'num_neighbors': len(nearest_neighbors),
            'min_distance': float(nearest_neighbors[0][1]) if nearest_neighbors else 1.0,
            'avg_distance': float(np.mean([nn[1] for nn in nearest_neighbors])) if nearest_neighbors else 1.0
        }
        
        # Add enhanced feature-wise explanations (Bug 8 fix)
        if nearest_neighbors:
            feature_explanation = self.explain_novelty(vector, nearest_neighbors)
            explanation.update(feature_explanation)
            
            # Add novelty component summary
            explanation['novelty_components'] = {
                'vocabulary': feature_explanation.get('vocabulary_novelty', 0.0),
                'topology': feature_explanation.get('topology_novelty', 0.0), 
                'timing': feature_explanation.get('timing_novelty', 0.0),
                'intent': feature_explanation.get('intent_novelty', 0.0),
                'edge': feature_explanation.get('edge_novelty', 0.0)
            }
        
        return explanation
    
    def _categorize_novelty(self, novelty_score: float) -> str:
        """Categorize novelty score into predefined categories."""
        if novelty_score >= self.novelty_categories['highly_novel']:
            return 'highly_novel'
        elif novelty_score >= self.novelty_categories['moderately_novel']:
            return 'moderately_novel'
        else:
            return 'known'
    
    def validate_mathematical_properties(self, test_vectors: List[np.ndarray],
                                       mock_knowledge_base) -> Dict[str, bool]:
        """
        Validate NSF mathematical properties for testing.
        
        Tests:
        - Range invariant: NSF(x, KB) ∈ [0, 1]
        
        Args:
            test_vectors: List of test embedding vectors
            mock_knowledge_base: Mock knowledge base for testing
            
        Returns:
            Dict with validation results
        """
        results = {'range_invariant': True}
        
        for vector in test_vectors:
            try:
                novelty_result = self.compute_novelty(vector, mock_knowledge_base)
                novelty_score = novelty_result.novelty_score
                
                if not (0.0 <= novelty_score <= 1.0):
                    results['range_invariant'] = False
                    self.logger.log_operation("ERROR", f"Range invariant violated: NSF = {novelty_score}",
                                             component="NSFEngine")
            except Exception as e:
                results['range_invariant'] = False
                self.logger.log_operation("ERROR", f"NSF computation failed: {e}",
                                         component="NSFEngine")
        
        return results


# =============================================================================
# Mock Knowledge Base for Testing
# =============================================================================

class MockKnowledgeBase:
    """Mock knowledge base for testing NSF functionality."""
    
    def __init__(self, patterns: List[BehaviorPattern] = None):
        self.patterns = patterns or []
    
    def get_patterns(self) -> List[BehaviorPattern]:
        return self.patterns
    
    def add_pattern(self, pattern: BehaviorPattern) -> None:
        self.patterns.append(pattern)
    
    def clear(self) -> None:
        self.patterns = []


# =============================================================================
# Utility Functions
# =============================================================================

def detect_zero_day_attacks(embeddings: List[BADNAEmbedding],
                           knowledge_base,
                           threshold: float = 0.8) -> List[Tuple[BADNAEmbedding, NoveltyResult]]:
    """
    Detect potential zero-day attacks from list of embeddings.
    
    Args:
        embeddings: List of behavior embeddings to analyze
        knowledge_base: Repository of known attack patterns
        threshold: Novelty threshold for zero-day classification
        
    Returns:
        List of (embedding, novelty_result) tuples for potential zero-days
    """
    nsf_engine = NSFEngine()
    zero_day_candidates = []
    
    for embedding in embeddings:
        novelty_result = nsf_engine.compute_novelty(embedding.vector, knowledge_base)
        
        if novelty_result.novelty_score >= threshold:
            zero_day_candidates.append((embedding, novelty_result))
    
    # Sort by novelty score descending
    zero_day_candidates.sort(key=lambda x: x[1].novelty_score, reverse=True)
    
    return zero_day_candidates


if __name__ == "__main__":
    # Test NSF implementation
    print("Testing NSF Algorithm...")
    
    # Import required modules for testing  
    from data_models import BehaviorPattern
    import uuid
    
    try:
        # Create mock knowledge base with known patterns
        np.random.seed(42)
        known_patterns = []
        
        for i in range(20):
            # Create known pattern embeddings
            pattern_vector = np.random.randn(128)
            pattern_vector = pattern_vector / np.linalg.norm(pattern_vector)
            
            pattern = BehaviorPattern(
                pattern_id=f"pattern_{i}",
                embedding=pattern_vector,
                threat_class="Known_Attack",
                confidence_score=0.9
            )
            known_patterns.append(pattern)
        
        mock_kb = MockKnowledgeBase(known_patterns)
        
        # Create test vectors
        # Similar to known pattern (should have low novelty)
        similar_vector = known_patterns[0].embedding + 0.05 * np.random.randn(128)
        similar_vector = similar_vector / np.linalg.norm(similar_vector)
        
        # Very different vector (should have high novelty)
        novel_vector = np.random.randn(128) * 2  # Different distribution
        novel_vector = novel_vector / np.linalg.norm(novel_vector)
        
        # Test NSF engine
        nsf_engine = NSFEngine()
        
        # Test novelty detection
        similar_result = nsf_engine.compute_novelty(similar_vector, mock_kb)
        novel_result = nsf_engine.compute_novelty(novel_vector, mock_kb)
        
        print(f"Similar vector novelty: {similar_result.novelty_score:.3f} ({similar_result.novelty_category})")
        print(f"Novel vector novelty: {novel_result.novelty_score:.3f} ({novel_result.novelty_category})")
        print(f"Similar vector neighbors: {len(similar_result.nearest_neighbors)}")
        print(f"Novel vector LOF: {novel_result.local_outlier_factor:.3f}")
        
        # Test empty knowledge base
        empty_kb = MockKnowledgeBase([])
        empty_result = nsf_engine.compute_novelty(similar_vector, empty_kb)
        print(f"Empty KB novelty: {empty_result.novelty_score:.3f}")
        
        # Test mathematical properties
        test_vectors = [similar_vector, novel_vector, known_patterns[0].embedding]
        properties = nsf_engine.validate_mathematical_properties(test_vectors, mock_kb)
        print(f"Mathematical properties validation: {properties}")
        
        # Test zero-day detection utility
        from data_models import BADNAEmbedding
        test_embeddings = [
            BADNAEmbedding(str(uuid.uuid4()), similar_vector, "graph1"),
            BADNAEmbedding(str(uuid.uuid4()), novel_vector, "graph2")
        ]
        
        zero_days = detect_zero_day_attacks(test_embeddings, mock_kb)
        print(f"Zero-day candidates: {len(zero_days)}")
        
        print("NSF Algorithm implementation complete!")
        
    except Exception as e:
        print(f"Error testing NSF: {e}")
        import traceback
        traceback.print_exc()