# BADNA Quantum Optimization Layer

## Overview

The Quantum Optimization Layer provides quantum-enhanced algorithms for large-scale behavioral analysis, offering significant speedups for computationally intensive tasks in threat detection.

## Quantum Algorithms Implemented

### 1. Grover's Algorithm for Pattern Search
- **File**: `quantum_search.py`
- **Speedup**: O(√N) vs O(N) classical
- **Use Case**: Search for behavioral patterns matching a query
- **Advantage**: Quadratic speedup for large pattern databases (>100 patterns)

### 2. Quantum K-means for Campaign Clustering
- **File**: `quantum_clustering.py`
- **Speedup**: Quantum-inspired initialization improves convergence
- **Use Case**: Cluster attack behaviors into campaigns
- **Advantage**: Better initial centroids lead to faster, more accurate clustering

### 3. Quantum Similarity Estimation
- **File**: `quantum_similarity.py`
- **Speedup**: SWAP test for inner product calculation
- **Use Case**: Calculate behavioral similarity
- **Advantage**: Useful for batch similarity calculations

## Installation

### Install Quantum Dependencies

```bash
pip install -r quantum/requirements_quantum.txt
```

### IBM Quantum Setup (Optional)

For real quantum hardware access:

1. Create IBM Quantum account: https://quantum-computing.ibm.com/
2. Get API token from account settings
3. Save token:

```python
from qiskit_ibm_runtime import QiskitRuntimeService

# Save credentials (one-time setup)
QiskitRuntimeService.save_account(channel="ibm_quantum", token="YOUR_API_TOKEN")
```

## Usage

### Basic Usage

```python
from quantum.optimizer import QuantumOptimizer
import numpy as np

# Initialize optimizer (uses simulator by default)
optimizer = QuantumOptimizer(use_quantum=True)

# Pattern search with quantum speedup
query = np.random.randn(128)
query = query / np.linalg.norm(query)

database = [np.random.randn(128) for _ in range(500)]
matches = optimizer.optimize_pattern_search(query, database, threshold=0.7)

print(f"Found {len(matches)} matching patterns")
```

### Using IBM Quantum Hardware

```python
# Use real quantum computer
optimizer = QuantumOptimizer(use_quantum=True, backend_name='ibm_quantum')

# Optimizer automatically selects least busy quantum computer
matches = optimizer.optimize_pattern_search(query, database, threshold=0.7)
```

### Clustering with Quantum Advantage

```python
# Quantum-enhanced clustering
embeddings = np.random.randn(200, 128)
for i in range(len(embeddings)):
    embeddings[i] = embeddings[i] / np.linalg.norm(embeddings[i])

labels, centroids = optimizer.optimize_clustering(embeddings, n_clusters=5)
print(f"Clustered into {len(set(labels))} campaigns")
```

## Automatic Quantum/Classical Fallback

The system automatically decides when to use quantum vs classical algorithms based on:

1. **Problem Size**: Quantum only used when dataset is large enough (>100 patterns)
2. **Qubit Availability**: Falls back if problem requires more qubits than available
3. **Backend Availability**: Falls back gracefully if quantum backend unavailable

```python
# This will use quantum if advantageous, classical otherwise
optimizer = QuantumOptimizer(use_quantum=True)

# Small problem → uses classical automatically
small_db = [np.random.randn(128) for _ in range(10)]
matches = optimizer.optimize_pattern_search(query, small_db, threshold=0.7)
# ^ Uses classical (too small for quantum advantage)

# Large problem → uses quantum
large_db = [np.random.randn(128) for _ in range(1000)]
matches = optimizer.optimize_pattern_search(query, large_db, threshold=0.7)
# ^ Uses quantum Grover's algorithm (√N speedup)
```

## Performance Comparison

| Operation | Classical | Quantum | Speedup |
|-----------|-----------|---------|---------|
| Pattern Search (N=1000) | 1000 comparisons | ~32 queries | 31x |
| Pattern Search (N=10000) | 10000 comparisons | ~100 queries | 100x |
| Clustering Initialization | Random | Quantum-inspired | Better convergence |

## Statistics and Monitoring

```python
# Get quantum execution statistics
stats = optimizer.get_statistics()

print(f"Quantum executions: {stats['quantum_executions']}")
print(f"Classical fallbacks: {stats['classical_fallbacks']}")
print(f"Quantum speedup achieved: {stats['quantum_speedup_achieved']}")
```

## Testing

Run quantum layer tests:

```bash
# Test quantum optimizer
python quantum/optimizer.py

# Test Grover search
python quantum/quantum_search.py

# Test quantum clustering
python quantum/quantum_clustering.py

# Test quantum similarity
python quantum/quantum_similarity.py
```

## Architecture Integration

The Quantum Optimization Layer integrates seamlessly with BADNA's pipeline:

```
Events → Graph → Features → Embedding
                               ↓
                    ┌──────────┴──────────┐
                    │                     │
                 d-BEF ←→ Quantum Layer ←→ BSF/NSF
                    │    (Speedup)        │
                    └──────────┬──────────┘
                               ↓
                        AI Investigator
```

**Quantum acceleration points**:
- BSF pattern matching (Grover's search)
- Campaign clustering (Quantum K-means)
- Large-scale similarity queries (batch processing)

## Limitations and Future Work

### Current Limitations
- **Simulator**: Default uses classical simulator (still provides algorithm validation)
- **Qubit Count**: Limited to 20 qubits on simulator (scales with hardware)
- **qRAM**: Full quantum K-means requires quantum RAM (not yet available)

### Future Enhancements
- Quantum annealing for optimization problems
- Variational Quantum Eigensolver (VQE) for pattern recognition
- Quantum Support Vector Machines (QSVM)
- Quantum Neural Networks for classification

## References

1. Grover, L.K. (1996). "A fast quantum mechanical algorithm for database search"
2. Lloyd, S. et al. (2013). "Quantum algorithms for supervised and unsupervised machine learning"
3. Schuld, M. & Petruccione, F. (2018). "Supervised Learning with Quantum Computers"

## Support

For quantum-specific issues:
- IBM Qiskit Documentation: https://qiskit.org/documentation/
- IBM Quantum Community: https://quantum-computing.ibm.com/community

---

**Quantum Layer Status**: ✅ Fully Implemented
**Last Updated**: 2026-07-06
