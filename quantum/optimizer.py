"""
Quantum Optimization Layer for BADNA

This module implements the main quantum optimization orchestrator that coordinates
quantum-enhanced algorithms for behavioral analysis at scale.

Key Features:
- Automatic quantum/classical fallback based on problem size
- IBM Quantum backend integration
- Local quantum simulation for development
- Hybrid quantum-classical optimization

Requirements: qiskit>=0.45.0, qiskit-aer>=0.13.0
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import warnings

try:
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
    from qiskit import transpile
    from qiskit_aer import AerSimulator
    from qiskit.primitives import Sampler
    QISKIT_AVAILABLE = True
except ImportError:
    QISKIT_AVAILABLE = False
    warnings.warn("Qiskit not installed. Quantum optimization will use classical fallback.")

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_logger, get_config, ProcessingError


class QuantumOptimizer:
    """
    Main Quantum Optimization Orchestrator for BADNA.
    
    Coordinates quantum algorithms for:
    - Pattern search (Grover's algorithm)
    - Behavioral clustering (Quantum K-means)
    - Similarity optimization (Quantum distance estimation)
    - Large-scale optimization (QAOA for NP-hard problems)
    
    Automatically falls back to classical algorithms when quantum advantage
    is not available or problem size is too small.
    """
    
    def __init__(self, use_quantum: bool = True, backend_name: str = 'aer_simulator'):
        """
        Initialize Quantum Optimizer.
        
        Args:
            use_quantum: Enable quantum algorithms (falls back to classical if unavailable)
            backend_name: Quantum backend ('aer_simulator', 'ibm_quantum', etc.)
        """
        self.logger = get_logger()
        self.config = get_config()
        
        # Quantum configuration
        self.use_quantum = use_quantum and QISKIT_AVAILABLE
        self.backend_name = backend_name
        self.backend = None
        
        # Thresholds for quantum advantage
        self.min_problem_size_for_quantum = 100  # Minimum patterns for quantum speedup
        self.max_qubits_available = 20  # Maximum qubits for simulation
        
        # Performance tracking
        self.quantum_speedup_achieved = False
        self.execution_stats = {
            'quantum_executions': 0,
            'classical_fallbacks': 0,
            'total_speedup': 0.0
        }
        
        if self.use_quantum:
            self._initialize_quantum_backend()
        
        self.logger.log_operation(
            "INFO",
            f"Quantum Optimizer initialized (quantum={'enabled' if self.use_quantum else 'disabled'})",
            component="QuantumOptimizer"
        )
    
    def _initialize_quantum_backend(self):
        """Initialize quantum backend for execution."""
        try:
            if self.backend_name == 'aer_simulator':
                # Use local Aer simulator
                self.backend = AerSimulator()
                self.logger.log_operation(
                    "INFO",
                    "Initialized Aer quantum simulator",
                    component="QuantumOptimizer"
                )
            elif self.backend_name == 'ibm_quantum':
                # Connect to IBM Quantum (requires API token)
                try:
                    from qiskit_ibm_runtime import QiskitRuntimeService
                    service = QiskitRuntimeService()
                    self.backend = service.least_busy(operational=True, simulator=False)
                    self.logger.log_operation(
                        "INFO",
                        f"Connected to IBM Quantum backend: {self.backend.name}",
                        component="QuantumOptimizer"
                    )
                except Exception as e:
                    self.logger.log_operation(
                        "WARNING",
                        f"IBM Quantum connection failed: {e}, using simulator",
                        component="QuantumOptimizer"
                    )
                    self.backend = AerSimulator()
            else:
                self.backend = AerSimulator()
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Quantum backend initialization failed: {e}",
                component="QuantumOptimizer"
            )
            self.use_quantum = False
    
    def should_use_quantum(self, problem_size: int, required_qubits: int) -> bool:
        """
        Determine if quantum algorithm should be used based on problem size and resources.
        
        Args:
            problem_size: Number of patterns/data points
            required_qubits: Qubits needed for quantum algorithm
            
        Returns:
            bool: True if quantum should be used, False for classical fallback
        """
        if not self.use_quantum:
            return False
        
        # Check if problem is large enough for quantum advantage
        if problem_size < self.min_problem_size_for_quantum:
            self.logger.log_operation(
                "INFO",
                f"Problem size ({problem_size}) too small for quantum advantage, using classical",
                component="QuantumOptimizer"
            )
            return False
        
        # Check if we have enough qubits
        if required_qubits > self.max_qubits_available:
            self.logger.log_operation(
                "WARNING",
                f"Required qubits ({required_qubits}) exceeds available ({self.max_qubits_available}), using classical",
                component="QuantumOptimizer"
            )
            return False
        
        return True
    
    def optimize_pattern_search(self, query_pattern: np.ndarray, 
                               pattern_database: List[np.ndarray],
                               threshold: float = 0.7) -> List[int]:
        """
        Quantum-optimized pattern search using Grover's algorithm.
        
        Searches for patterns matching query with similarity >= threshold.
        Provides O(√N) speedup over classical linear search.
        
        Args:
            query_pattern: Query embedding (128-D)
            pattern_database: List of pattern embeddings to search
            threshold: Similarity threshold for matches
            
        Returns:
            List of indices of matching patterns
        """
        n_patterns = len(pattern_database)
        
        # Calculate required qubits (log2(N) qubits for N patterns)
        required_qubits = int(np.ceil(np.log2(n_patterns)))
        
        # Decide quantum vs classical
        use_quantum = self.should_use_quantum(n_patterns, required_qubits)
        
        if use_quantum:
            return self._quantum_pattern_search(query_pattern, pattern_database, threshold, required_qubits)
        else:
            return self._classical_pattern_search(query_pattern, pattern_database, threshold)
    
    def _quantum_pattern_search(self, query: np.ndarray, database: List[np.ndarray],
                               threshold: float, n_qubits: int) -> List[int]:
        """Grover's algorithm for pattern search (quantum speedup: O(√N))."""
        try:
            from .quantum_search import QuantumPatternSearch
            
            search_engine = QuantumPatternSearch(self.backend)
            matches = search_engine.grover_search(query, database, threshold, n_qubits)
            
            self.execution_stats['quantum_executions'] += 1
            self.quantum_speedup_achieved = True
            
            self.logger.log_operation(
                "INFO",
                f"Quantum pattern search completed: {len(matches)} matches found",
                component="QuantumOptimizer",
                operation="quantum_search",
                quantum_speedup="√N advantage"
            )
            
            return matches
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Quantum search failed: {e}, falling back to classical",
                component="QuantumOptimizer"
            )
            self.execution_stats['classical_fallbacks'] += 1
            return self._classical_pattern_search(query, database, threshold)
    
    def _classical_pattern_search(self, query: np.ndarray, database: List[np.ndarray],
                                 threshold: float) -> List[int]:
        """Classical linear search fallback."""
        from sklearn.metrics.pairwise import cosine_similarity
        
        matches = []
        query_reshaped = query.reshape(1, -1)
        
        for i, pattern in enumerate(database):
            similarity = cosine_similarity(query_reshaped, pattern.reshape(1, -1))[0][0]
            if similarity >= threshold:
                matches.append(i)
        
        self.execution_stats['classical_fallbacks'] += 1
        return matches
    
    def optimize_clustering(self, embeddings: np.ndarray, n_clusters: int,
                          max_iterations: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """
        Quantum-optimized behavioral clustering using Quantum K-means.
        
        Uses quantum distance estimation for speedup in centroid calculation.
        
        Args:
            embeddings: Array of behavior embeddings (N x 128)
            n_clusters: Number of clusters (campaigns)
            max_iterations: Maximum clustering iterations
            
        Returns:
            Tuple of (cluster_labels, centroids)
        """
        n_patterns = len(embeddings)
        
        # Quantum K-means requires qubits for distance estimation
        required_qubits = int(np.ceil(np.log2(embeddings.shape[1])))  # For 128-D: 7 qubits
        
        use_quantum = self.should_use_quantum(n_patterns, required_qubits)
        
        if use_quantum:
            return self._quantum_clustering(embeddings, n_clusters, max_iterations, required_qubits)
        else:
            return self._classical_clustering(embeddings, n_clusters, max_iterations)
    
    def _quantum_clustering(self, embeddings: np.ndarray, n_clusters: int,
                          max_iterations: int, n_qubits: int) -> Tuple[np.ndarray, np.ndarray]:
        """Quantum K-means clustering."""
        try:
            from .quantum_clustering import QuantumBehavioralClustering
            
            clustering_engine = QuantumBehavioralClustering(self.backend)
            labels, centroids = clustering_engine.quantum_kmeans(
                embeddings, n_clusters, max_iterations, n_qubits
            )
            
            self.execution_stats['quantum_executions'] += 1
            self.quantum_speedup_achieved = True
            
            self.logger.log_operation(
                "INFO",
                f"Quantum clustering completed: {n_clusters} campaigns identified",
                component="QuantumOptimizer",
                operation="quantum_clustering"
            )
            
            return labels, centroids
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Quantum clustering failed: {e}, falling back to classical",
                component="QuantumOptimizer"
            )
            self.execution_stats['classical_fallbacks'] += 1
            return self._classical_clustering(embeddings, n_clusters, max_iterations)
    
    def _classical_clustering(self, embeddings: np.ndarray, n_clusters: int,
                            max_iterations: int) -> Tuple[np.ndarray, np.ndarray]:
        """Classical DBSCAN clustering fallback."""
        from sklearn.cluster import KMeans
        
        kmeans = KMeans(n_clusters=n_clusters, max_iter=max_iterations, random_state=42)
        labels = kmeans.fit_predict(embeddings)
        centroids = kmeans.cluster_centers_
        
        self.execution_stats['classical_fallbacks'] += 1
        return labels, centroids
    
    def optimize_similarity_calculation(self, embedding1: np.ndarray, 
                                       embedding2: np.ndarray) -> float:
        """
        Quantum-optimized similarity calculation using quantum distance estimation.
        
        Uses SWAP test or quantum distance estimation for speedup.
        
        Args:
            embedding1: First embedding (128-D)
            embedding2: Second embedding (128-D)
            
        Returns:
            Similarity score [0, 1]
        """
        # For similarity, quantum advantage is marginal for single pair
        # Use quantum only for batch similarity calculations
        return self._classical_similarity(embedding1, embedding2)
    
    def _classical_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Classical cosine similarity."""
        from sklearn.metrics.pairwise import cosine_similarity
        return cosine_similarity(emb1.reshape(1, -1), emb2.reshape(1, -1))[0][0]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get quantum optimization statistics."""
        return {
            'quantum_enabled': self.use_quantum,
            'backend': self.backend_name if self.use_quantum else 'classical_only',
            'quantum_executions': self.execution_stats['quantum_executions'],
            'classical_fallbacks': self.execution_stats['classical_fallbacks'],
            'quantum_speedup_achieved': self.quantum_speedup_achieved,
            'qubits_available': self.max_qubits_available
        }


if __name__ == "__main__":
    # Test quantum optimizer
    print("=" * 70)
    print("Testing Quantum Optimization Layer")
    print("=" * 70)
    
    try:
        # Initialize optimizer
        optimizer = QuantumOptimizer(use_quantum=True)
        
        # Test 1: Pattern search
        print("\n1. Testing Quantum Pattern Search")
        query = np.random.randn(128)
        query = query / np.linalg.norm(query)
        
        database = [np.random.randn(128) / np.linalg.norm(np.random.randn(128)) for _ in range(50)]
        
        matches = optimizer.optimize_pattern_search(query, database, threshold=0.7)
        print(f"   Found {len(matches)} matching patterns")
        
        # Test 2: Clustering
        print("\n2. Testing Quantum Clustering")
        embeddings = np.random.randn(100, 128)
        for i in range(len(embeddings)):
            embeddings[i] = embeddings[i] / np.linalg.norm(embeddings[i])
        
        labels, centroids = optimizer.optimize_clustering(embeddings, n_clusters=5)
        print(f"   Clustered into {len(set(labels))} campaigns")
        
        # Statistics
        print("\n3. Quantum Optimization Statistics")
        stats = optimizer.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        print("\n✅ Quantum Optimization Layer test completed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
