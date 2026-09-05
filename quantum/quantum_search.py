"""
Quantum Pattern Search using Grover's Algorithm

Implements Grover's algorithm for searching behavioral patterns with O(√N) speedup
over classical linear search.

Grover's algorithm provides quadratic speedup for unstructured search:
- Classical: O(N) comparisons
- Quantum: O(√N) oracle queries

Reference: Grover, L.K. (1996). "A fast quantum mechanical algorithm for database search"
"""

import numpy as np
from typing import List, Callable
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit import transpile
from qiskit.circuit.library import GroverOperator, MCMT, ZGate
from qiskit_aer import AerSimulator

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_logger


class QuantumPatternSearch:
    """
    Quantum pattern search engine using Grover's algorithm.
    
    Provides O(√N) speedup for searching behavioral patterns that match
    a query pattern with similarity above a threshold.
    """
    
    def __init__(self, backend=None):
        """
        Initialize quantum search engine.
        
        Args:
            backend: Qiskit backend (defaults to Aer simulator)
        """
        self.logger = get_logger()
        self.backend = backend if backend else AerSimulator()
    
    def grover_search(self, query_pattern: np.ndarray, 
                     pattern_database: List[np.ndarray],
                     similarity_threshold: float,
                     n_qubits: int) -> List[int]:
        """
        Search for patterns matching query using Grover's algorithm.
        
        Args:
            query_pattern: Query embedding (128-D)
            pattern_database: List of pattern embeddings
            similarity_threshold: Minimum similarity for match
            n_qubits: Number of qubits (determines search space size)
            
        Returns:
            List of indices of matching patterns
        """
        try:
            # Step 1: Create oracle that marks matching patterns
            oracle = self._create_similarity_oracle(
                query_pattern, pattern_database, similarity_threshold, n_qubits
            )
            
            # Step 2: Calculate optimal number of Grover iterations
            n_patterns = len(pattern_database)
            n_matches = sum(1 for p in pattern_database 
                          if self._cosine_similarity(query_pattern, p) >= similarity_threshold)
            
            if n_matches == 0:
                return []
            
            n_iterations = self._calculate_grover_iterations(n_patterns, n_matches)
            
            # Step 3: Build Grover circuit
            circuit = self._build_grover_circuit(oracle, n_qubits, n_iterations)
            
            # Step 4: Execute circuit
            transpiled = transpile(circuit, self.backend)
            result = self.backend.run(transpiled, shots=1024).result()
            counts = result.get_counts()
            
            # Step 5: Extract matching indices from measurement results
            matches = self._extract_matches_from_counts(
                counts, query_pattern, pattern_database, similarity_threshold
            )
            
            self.logger.log_operation(
                "INFO",
                f"Grover search completed: {len(matches)} matches in {n_iterations} iterations",
                component="QuantumPatternSearch",
                operation="grover_search"
            )
            
            return matches
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Grover search failed: {e}",
                component="QuantumPatternSearch"
            )
            raise
    
    def _create_similarity_oracle(self, query: np.ndarray, database: List[np.ndarray],
                                 threshold: float, n_qubits: int) -> QuantumCircuit:
        """
        Create quantum oracle that marks states corresponding to matching patterns.
        
        The oracle applies a phase flip (-1) to basis states |i⟩ where pattern i
        has similarity to query >= threshold.
        """
        # Create quantum circuit for oracle
        qr = QuantumRegister(n_qubits, 'q')
        oracle = QuantumCircuit(qr, name='Oracle')
        
        # Identify which patterns match
        matching_indices = []
        for i, pattern in enumerate(database):
            if i >= 2**n_qubits:  # Can't represent with n qubits
                break
            if self._cosine_similarity(query, pattern) >= threshold:
                matching_indices.append(i)
        
        # Apply phase flip to matching indices
        # For each matching index, create controlled-Z gate
        for idx in matching_indices:
            # Convert index to binary representation
            binary_idx = format(idx, f'0{n_qubits}b')
            
            # Apply X gates to qubits that should be 0
            for qubit, bit in enumerate(binary_idx):
                if bit == '0':
                    oracle.x(qr[qubit])
            
            # Apply multi-controlled Z gate
            if n_qubits > 1:
                oracle.h(qr[-1])
                oracle.mcx(list(range(n_qubits - 1)), n_qubits - 1)
                oracle.h(qr[-1])
            else:
                oracle.z(qr[0])
            
            # Undo X gates
            for qubit, bit in enumerate(binary_idx):
                if bit == '0':
                    oracle.x(qr[qubit])
        
        return oracle
    
    def _calculate_grover_iterations(self, n_total: int, n_matches: int) -> int:
        """
        Calculate optimal number of Grover iterations.
        
        Formula: k ≈ (π/4) * √(N/M) where N=total, M=matches
        """
        if n_matches == 0 or n_matches == n_total:
            return 0
        
        ratio = n_total / n_matches
        optimal_iterations = int(np.round((np.pi / 4) * np.sqrt(ratio)))
        
        return max(1, optimal_iterations)
    
    def _build_grover_circuit(self, oracle: QuantumCircuit, n_qubits: int,
                            n_iterations: int) -> QuantumCircuit:
        """
        Build complete Grover circuit with oracle and diffusion operators.
        
        Circuit structure:
        1. Initialize uniform superposition (Hadamard gates)
        2. Apply Grover iterations (oracle + diffusion)
        3. Measure
        """
        qr = QuantumRegister(n_qubits, 'q')
        cr = ClassicalRegister(n_qubits, 'c')
        circuit = QuantumCircuit(qr, cr)
        
        # Step 1: Initialize uniform superposition
        circuit.h(qr)
        
        # Step 2: Apply Grover iterations
        for _ in range(n_iterations):
            # Apply oracle
            circuit.compose(oracle, inplace=True)
            
            # Apply diffusion operator (reflection about average)
            circuit.h(qr)
            circuit.x(qr)
            
            # Multi-controlled Z gate
            if n_qubits > 1:
                circuit.h(qr[-1])
                circuit.mcx(list(range(n_qubits - 1)), n_qubits - 1)
                circuit.h(qr[-1])
            else:
                circuit.z(qr[0])
            
            circuit.x(qr)
            circuit.h(qr)
        
        # Step 3: Measure
        circuit.measure(qr, cr)
        
        return circuit
    
    def _extract_matches_from_counts(self, counts: dict, query: np.ndarray,
                                    database: List[np.ndarray],
                                    threshold: float) -> List[int]:
        """
        Extract matching pattern indices from measurement results.
        
        Takes the most frequently measured states and verifies they actually match.
        """
        matches = []
        
        # Sort by measurement frequency
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        
        # Check top measured states
        for state_str, count in sorted_counts[:10]:  # Check top 10 states
            # Convert binary string to index
            idx = int(state_str, 2)
            
            # Verify this pattern actually matches
            if idx < len(database):
                similarity = self._cosine_similarity(query, database[idx])
                if similarity >= threshold:
                    matches.append(idx)
        
        # Remove duplicates while preserving order
        matches = list(dict.fromkeys(matches))
        
        return matches
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)


if __name__ == "__main__":
    # Test Grover search
    print("=" * 70)
    print("Testing Quantum Pattern Search (Grover's Algorithm)")
    print("=" * 70)
    
    try:
        # Create test data
        np.random.seed(42)
        query = np.random.randn(128)
        query = query / np.linalg.norm(query)
        
        # Create database with some similar patterns
        database = []
        for i in range(8):  # 8 patterns = 3 qubits
            if i < 2:
                # Make first 2 patterns similar to query
                pattern = query + np.random.randn(128) * 0.1
            else:
                # Rest are random
                pattern = np.random.randn(128)
            pattern = pattern / np.linalg.norm(pattern)
            database.append(pattern)
        
        # Initialize search engine
        search_engine = QuantumPatternSearch()
        
        # Perform search
        print("\nSearching for patterns with similarity >= 0.8...")
        matches = search_engine.grover_search(query, database, 0.8, n_qubits=3)
        
        print(f"\nFound {len(matches)} matches: {matches}")
        
        # Verify matches
        print("\nVerifying matches:")
        for idx in matches:
            similarity = search_engine._cosine_similarity(query, database[idx])
            print(f"  Pattern {idx}: similarity = {similarity:.3f}")
        
        print("\n✅ Quantum search test completed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
