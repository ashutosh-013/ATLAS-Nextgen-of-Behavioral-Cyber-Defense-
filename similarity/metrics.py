"""
Distance Metrics Utilities

This module provides distance and similarity metric implementations used by BSF
and other BADNA components. Includes cosine similarity, euclidean distance,
and other mathematical metric functions.

Part of the BSF (Behavioral Similarity Function) research core.
"""

import numpy as np
from typing import Union, List, Tuple
import math

# Import our logging and error handling
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ValidationError, get_logger


def cosine_similarity(vector_a: np.ndarray, vector_b: np.ndarray) -> float:
    """
    Compute cosine similarity between two vectors.
    
    Args:
        vector_a: First vector
        vector_b: Second vector
        
    Returns:
        Cosine similarity in [-1, 1] range
        
    Formula:
        cosine_sim(A, B) = (A · B) / (||A|| × ||B||)
    """
    # Validate input shapes
    if vector_a.shape != vector_b.shape:
        raise ValidationError(f"Vector shapes must match: {vector_a.shape} vs {vector_b.shape}")
    
    # Handle zero vectors
    norm_a = np.linalg.norm(vector_a)
    norm_b = np.linalg.norm(vector_b)
    
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    
    # Compute cosine similarity
    dot_product = np.dot(vector_a, vector_b)
    cosine_sim = dot_product / (norm_a * norm_b)
    
    # Ensure result is in valid range due to floating point precision
    return np.clip(cosine_sim, -1.0, 1.0)


def cosine_distance(vector_a: np.ndarray, vector_b: np.ndarray) -> float:
    """
    Compute cosine distance between two vectors.
    
    Args:
        vector_a: First vector
        vector_b: Second vector
        
    Returns:
        Cosine distance in [0, 2] range
        
    Formula:
        cosine_distance(A, B) = 1 - cosine_similarity(A, B)
    """
    similarity = cosine_similarity(vector_a, vector_b)
    return 1.0 - similarity


def euclidean_distance(vector_a: np.ndarray, vector_b: np.ndarray) -> float:
    """
    Compute Euclidean distance between two vectors.
    
    Args:
        vector_a: First vector
        vector_b: Second vector
        
    Returns:
        Euclidean distance (non-negative)
        
    Formula:
        euclidean_distance(A, B) = sqrt(Σ(A_i - B_i)²)
    """
    if vector_a.shape != vector_b.shape:
        raise ValidationError(f"Vector shapes must match: {vector_a.shape} vs {vector_b.shape}")
    
    diff = vector_a - vector_b
    return np.sqrt(np.sum(diff ** 2))


def manhattan_distance(vector_a: np.ndarray, vector_b: np.ndarray) -> float:
    """
    Compute Manhattan (L1) distance between two vectors.
    
    Args:
        vector_a: First vector
        vector_b: Second vector
        
    Returns:
        Manhattan distance (non-negative)
        
    Formula:
        manhattan_distance(A, B) = Σ|A_i - B_i|
    """
    if vector_a.shape != vector_b.shape:
        raise ValidationError(f"Vector shapes must match: {vector_a.shape} vs {vector_b.shape}")
    
    return np.sum(np.abs(vector_a - vector_b))


def behavioral_similarity(vector_a: np.ndarray, vector_b: np.ndarray) -> float:
    """
    Compute behavioral similarity between two vectors.
    Maps cosine similarity from [-1, 1] to [0, 1] for behavioral analysis.
    
    Args:
        vector_a: First behavioral embedding
        vector_b: Second behavioral embedding
        
    Returns:
        Behavioral similarity in [0, 1] where:
        - 1.0 = identical behavior
        - 0.5 = orthogonal behavior  
        - 0.0 = opposite behavior
        
    Formula:
        behavioral_sim(A, B) = (cosine_similarity(A, B) + 1) / 2
    """
    cosine_sim = cosine_similarity(vector_a, vector_b)
    
    # Map from [-1, 1] to [0, 1] for behavioral similarity
    behavioral_sim = (cosine_sim + 1.0) / 2.0
    
    return np.clip(behavioral_sim, 0.0, 1.0)


def weighted_cosine_similarity(vector_a: np.ndarray, vector_b: np.ndarray, 
                              weights: np.ndarray) -> float:
    """
    Compute weighted cosine similarity between two vectors.
    
    Args:
        vector_a: First vector
        vector_b: Second vector  
        weights: Weight vector (same shape as input vectors)
        
    Returns:
        Weighted cosine similarity in [-1, 1]
        
    Formula:
        weighted_cosine_sim(A, B, W) = (W·A · W·B) / (||W·A|| × ||W·B||)
    """
    if vector_a.shape != vector_b.shape or vector_a.shape != weights.shape:
        raise ValidationError("All vectors must have the same shape")
    
    # Apply weights
    weighted_a = vector_a * weights
    weighted_b = vector_b * weights
    
    # Compute weighted cosine similarity
    return cosine_similarity(weighted_a, weighted_b)


def multi_component_similarity(vector_a: np.ndarray, vector_b: np.ndarray,
                              component_ranges: List[Tuple[int, int]],
                              component_weights: List[float]) -> float:
    """
    Compute multi-component weighted similarity.
    Used by BSF for structural, temporal, and semantic component analysis.
    
    Args:
        vector_a: First vector
        vector_b: Second vector
        component_ranges: List of (start, end) indices for each component
        component_weights: Weights for each component
        
    Returns:
        Weighted multi-component similarity in [0, 1]
    """
    if len(component_ranges) != len(component_weights):
        raise ValidationError("Number of component ranges must match number of weights")
    
    if abs(sum(component_weights) - 1.0) > 1e-6:
        raise ValidationError("Component weights must sum to 1.0")
    
    weighted_similarity = 0.0
    
    for (start, end), weight in zip(component_ranges, component_weights):
        # Extract component vectors
        component_a = vector_a[start:end]
        component_b = vector_b[start:end]
        
        # Compute component similarity using behavioral similarity mapping
        component_sim = behavioral_similarity(component_a, component_b)
        
        # Add weighted contribution
        weighted_similarity += weight * component_sim
    
    return np.clip(weighted_similarity, 0.0, 1.0)


def pairwise_distances(vectors: List[np.ndarray], metric: str = "euclidean") -> np.ndarray:
    """
    Compute pairwise distance matrix for a list of vectors.
    
    Args:
        vectors: List of vectors to compute distances between
        metric: Distance metric ("euclidean", "cosine", "manhattan")
        
    Returns:
        Symmetric distance matrix where entry (i,j) is distance between vectors i and j
    """
    n = len(vectors)
    distance_matrix = np.zeros((n, n))
    
    # Select distance function
    if metric == "euclidean":
        distance_func = euclidean_distance
    elif metric == "cosine":
        distance_func = cosine_distance
    elif metric == "manhattan":
        distance_func = manhattan_distance
    else:
        raise ValidationError(f"Unknown distance metric: {metric}")
    
    # Compute pairwise distances
    for i in range(n):
        for j in range(i + 1, n):  # Only compute upper triangle (symmetric matrix)
            distance = distance_func(vectors[i], vectors[j])
            distance_matrix[i, j] = distance
            distance_matrix[j, i] = distance  # Symmetry
    
    return distance_matrix


def k_nearest_neighbors(query_vector: np.ndarray, candidate_vectors: List[np.ndarray], 
                       k: int = 5, metric: str = "euclidean") -> List[Tuple[int, float]]:
    """
    Find k nearest neighbors to query vector.
    
    Args:
        query_vector: Query vector
        candidate_vectors: List of candidate vectors
        k: Number of neighbors to return
        metric: Distance metric to use
        
    Returns:
        List of (index, distance) tuples for k nearest neighbors, sorted by distance
    """
    if k > len(candidate_vectors):
        k = len(candidate_vectors)
    
    # Select distance function
    if metric == "euclidean":
        distance_func = euclidean_distance
    elif metric == "cosine":
        distance_func = cosine_distance
    elif metric == "manhattan":
        distance_func = manhattan_distance
    else:
        raise ValidationError(f"Unknown distance metric: {metric}")
    
    # Compute distances to all candidates
    distances = []
    for i, candidate in enumerate(candidate_vectors):
        distance = distance_func(query_vector, candidate)
        distances.append((i, distance))
    
    # Sort by distance and return top k
    distances.sort(key=lambda x: x[1])
    return distances[:k]


def normalize_vector(vector: np.ndarray, norm_type: str = "l2") -> np.ndarray:
    """
    Normalize vector to unit length.
    
    Args:
        vector: Input vector
        norm_type: Normalization type ("l2" for Euclidean, "l1" for Manhattan)
        
    Returns:
        Normalized vector
    """
    if norm_type == "l2":
        norm = np.linalg.norm(vector)
        if norm == 0.0:
            return vector  # Cannot normalize zero vector
        return vector / norm
    elif norm_type == "l1":
        norm = np.sum(np.abs(vector))
        if norm == 0.0:
            return vector
        return vector / norm
    else:
        raise ValidationError(f"Unknown normalization type: {norm_type}")


def similarity_to_distance(similarity: float, similarity_range: str = "cosine") -> float:
    """
    Convert similarity score to distance score.
    
    Args:
        similarity: Similarity score
        similarity_range: Range of similarity ("cosine" for [-1,1], "behavioral" for [0,1])
        
    Returns:
        Distance score
    """
    if similarity_range == "cosine":
        # Cosine similarity [-1, 1] → cosine distance [0, 2]
        return 1.0 - similarity
    elif similarity_range == "behavioral":
        # Behavioral similarity [0, 1] → behavioral distance [0, 1]
        return 1.0 - similarity
    else:
        raise ValidationError(f"Unknown similarity range: {similarity_range}")


def distance_to_similarity(distance: float, distance_range: str = "cosine") -> float:
    """
    Convert distance score to similarity score.
    
    Args:
        distance: Distance score
        distance_range: Range of distance ("cosine" for [0,2], "behavioral" for [0,1])
        
    Returns:
        Similarity score
    """
    if distance_range == "cosine":
        # Cosine distance [0, 2] → cosine similarity [-1, 1]
        return 1.0 - distance
    elif distance_range == "behavioral":
        # Behavioral distance [0, 1] → behavioral similarity [0, 1]
        return 1.0 - distance
    else:
        raise ValidationError(f"Unknown distance range: {distance_range}")


# =============================================================================
# Utility Functions for BSF Integration
# =============================================================================

def bsf_component_similarity(embedding_a: np.ndarray, embedding_b: np.ndarray) -> dict:
    """
    Compute BSF component similarities for 128-D BADNA embeddings.
    
    Args:
        embedding_a: First 128-D BADNA embedding
        embedding_b: Second 128-D BADNA embedding
        
    Returns:
        Dict with structural, temporal, semantic, and overall similarities
    """
    if embedding_a.shape != (128,) or embedding_b.shape != (128,):
        raise ValidationError("BSF embeddings must be 128-dimensional")
    
    # BSF component allocation
    component_ranges = [
        (0, 43),    # Structural: dimensions 0-42 (33%)
        (43, 68),   # Temporal: dimensions 43-67 (20%) 
        (68, 128)   # Semantic: dimensions 68-127 (47%)
    ]
    
    component_names = ['structural', 'temporal', 'semantic']
    component_similarities = {}
    
    # Compute individual component similarities
    for name, (start, end) in zip(component_names, component_ranges):
        component_a = embedding_a[start:end]
        component_b = embedding_b[start:end]
        component_similarities[name] = behavioral_similarity(component_a, component_b)
    
    # Overall similarity
    component_similarities['overall'] = behavioral_similarity(embedding_a, embedding_b)
    
    return component_similarities


def validate_distance_properties(vectors: List[np.ndarray], distance_func, 
                                tolerance: float = 1e-6) -> dict:
    """
    Validate mathematical properties of a distance function.
    
    Args:
        vectors: List of test vectors
        distance_func: Distance function to test
        tolerance: Numerical tolerance for floating point comparisons
        
    Returns:
        Dict with validation results for each property
    """
    results = {
        'non_negativity': True,
        'identity': True, 
        'symmetry': True,
        'triangle_inequality': True
    }
    
    n = len(vectors)
    
    # Test all pairs
    for i in range(n):
        for j in range(n):
            distance_ij = distance_func(vectors[i], vectors[j])
            
            # Non-negativity: d(x, y) >= 0
            if distance_ij < 0:
                results['non_negativity'] = False
            
            # Identity: d(x, x) = 0
            if i == j and abs(distance_ij) > tolerance:
                results['identity'] = False
            
            # Identity: d(x, y) > 0 if x != y (for distinct vectors)
            if i != j and distance_ij <= tolerance:
                # Check if vectors are actually different
                if not np.allclose(vectors[i], vectors[j], atol=tolerance):
                    results['identity'] = False
            
            # Symmetry: d(x, y) = d(y, x)
            distance_ji = distance_func(vectors[j], vectors[i])
            if abs(distance_ij - distance_ji) > tolerance:
                results['symmetry'] = False
            
            # Triangle inequality: d(x, z) <= d(x, y) + d(y, z)
            for k in range(n):
                if k != i and k != j:
                    distance_ik = distance_func(vectors[i], vectors[k])
                    distance_jk = distance_func(vectors[j], vectors[k])
                    
                    if distance_ik > distance_ij + distance_jk + tolerance:
                        results['triangle_inequality'] = False
    
    return results


if __name__ == "__main__":
    # Test distance metrics implementation
    print("Testing Distance Metrics...")
    
    try:
        # Create test vectors
        np.random.seed(42)
        vec1 = np.random.randn(128)
        vec1 = vec1 / np.linalg.norm(vec1)  # Normalize
        
        vec2 = np.random.randn(128)
        vec2 = vec2 / np.linalg.norm(vec2)
        
        vec3 = np.random.randn(128)
        vec3 = vec3 / np.linalg.norm(vec3)
        
        # Test basic metrics
        cosine_sim = cosine_similarity(vec1, vec2)
        cosine_dist = cosine_distance(vec1, vec2)
        euclidean_dist = euclidean_distance(vec1, vec2)
        manhattan_dist = manhattan_distance(vec1, vec2)
        behavioral_sim = behavioral_similarity(vec1, vec2)
        
        print(f"Cosine similarity: {cosine_sim:.3f}")
        print(f"Cosine distance: {cosine_dist:.3f}")
        print(f"Euclidean distance: {euclidean_dist:.3f}")
        print(f"Manhattan distance: {manhattan_dist:.3f}")
        print(f"Behavioral similarity: {behavioral_sim:.3f}")
        
        # Test BSF component similarities
        bsf_components = bsf_component_similarity(vec1, vec2)
        print(f"BSF component similarities: {bsf_components}")
        
        # Test multi-component similarity (BSF-style)
        component_ranges = [(0, 43), (43, 68), (68, 128)]
        component_weights = [0.3, 0.2, 0.5]
        multi_sim = multi_component_similarity(vec1, vec2, component_ranges, component_weights)
        print(f"Multi-component similarity: {multi_sim:.3f}")
        
        # Test k-nearest neighbors
        candidates = [vec2, vec3]
        neighbors = k_nearest_neighbors(vec1, candidates, k=2, metric="cosine")
        print(f"K-nearest neighbors: {neighbors}")
        
        # Test pairwise distances
        vectors = [vec1, vec2, vec3]
        dist_matrix = pairwise_distances(vectors, metric="cosine")
        print(f"Pairwise distance matrix:\n{dist_matrix}")
        
        # Test distance properties validation
        properties = validate_distance_properties(vectors, euclidean_distance)
        print(f"Euclidean distance properties: {properties}")
        
        print("Distance Metrics implementation complete!")
        
    except Exception as e:
        print(f"Error testing distance metrics: {e}")
        import traceback
        traceback.print_exc()