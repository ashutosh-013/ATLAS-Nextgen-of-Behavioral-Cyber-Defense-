"""
BADNA Quantum Optimization Module

This module implements quantum-enhanced optimization algorithms for BADNA's
large-scale behavioral analysis tasks using IBM Qiskit and quantum computing.

Quantum algorithms provide speedup for:
- Pattern search (Grover's algorithm)
- Clustering (Quantum K-means)
- Similarity calculations (Quantum distance estimation)
- Large-scale optimization (QAOA)

Requirements: qiskit, qiskit-aer, qiskit-ibm-runtime
"""

from .optimizer import QuantumOptimizer
from .quantum_search import QuantumPatternSearch
from .quantum_clustering import QuantumBehavioralClustering
from .quantum_similarity import QuantumSimilarityEngine

__all__ = [
    'QuantumOptimizer',
    'QuantumPatternSearch',
    'QuantumBehavioralClustering', 
    'QuantumSimilarityEngine'
]

__version__ = '1.0.0'
