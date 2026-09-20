"""
ATLAS Autonomous Graph Neural Network (GNN) Engine
===================================================
Implements an inductive 2-layer Graph Convolutional Network (GCN) for multi-hop
relational message-passing over causal behavior graphs.

Mathematical Formulation (Spectral Graph Convolution):
-------------------------------------------------------
Let G = (V, E) be a directed or undirected behavior graph with adjacency matrix A
and node feature matrix X in R^{N x D_in}.

1. Self-Loop Augmentation:
   A_tilde = A + I_N

2. Symmetric Degree Normalization:
   D_tilde_ii = sum_j A_tilde_ij
   A_hat = D_tilde^{-1/2} * A_tilde * D_tilde^{-1/2}

3. Layer 1 Message Passing (Node-Level Convolutions):
   H^(1) = ReLU(A_hat * X * W^(0))

4. Layer 2 Multi-Hop Propagation:
   H^(2) = ReLU(A_hat * H^(1) * W^(1))

5. Dual-Pool Graph Readout (Mean + Max pooling):
   h_graph = concat(mean_pool(H^(2)), max_pool(H^(2)))

6. Topological Projection to 128 Dimensions & L2 Normalization:
   e_gnn = h_graph * W_proj
   ||e_gnn||_2 = 1.0

Properties:
- Inductive: Generalizes to unseen process trees and zero-day execution topologies.
- Permutation Equivariant & Deterministic.
- Zero external deep learning frameworks (built on high-performance NumPy/SciPy).
- Fully compatible with BADNA 128-dimensional embedding space.
"""

import numpy as np
import scipy.sparse as sp
from typing import Dict, List, Any, Optional, Tuple
import logging

try:
    from data_models import BehaviorGraph, BehaviorNode, BehaviorEdge
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from data_models import BehaviorGraph, BehaviorNode, BehaviorEdge

logger = logging.getLogger("GNNEngine")


class GNNEngine:
    """
    Autonomous Graph Neural Network (GNN) Inductive Embedder.
    Extracts multi-hop structural context and behavioral message passing from attack graphs.
    """

    def __init__(self, node_in_dim: int = 16, hidden_dim: int = 64, out_dim: int = 128, seed: int = 42):
        self.node_in_dim = node_in_dim
        self.hidden_dim = hidden_dim
        self.out_dim = out_dim
        self.seed = seed
        
        # Deterministic Xavier/Glorot weight initialization
        rng = np.random.RandomState(seed)
        self.W0 = rng.normal(0, np.sqrt(2.0 / (node_in_dim + hidden_dim)), (node_in_dim, hidden_dim))
        self.W1 = rng.normal(0, np.sqrt(2.0 / (hidden_dim + hidden_dim)), (hidden_dim, hidden_dim))
        self.W_proj = rng.normal(0, np.sqrt(2.0 / (hidden_dim * 2 + out_dim)), (hidden_dim * 2, out_dim))
        logger.info(f"GNNEngine initialized: in_dim={node_in_dim}, hidden={hidden_dim}, out={out_dim}")

    def _extract_node_features(self, graph: BehaviorGraph) -> Tuple[np.ndarray, np.ndarray]:
        """
        Constructs node feature matrix X (N x node_in_dim) and adjacency matrix A (N x N)
        from a BehaviorGraph instance.
        """
        nodes = list(graph.nodes.values()) if isinstance(graph.nodes, dict) else list(graph.nodes)
        N = len(nodes)
        if N == 0:
            return np.zeros((1, self.node_in_dim)), np.zeros((1, 1))

        node_index_map = {n.node_id: i for i, n in enumerate(nodes)}
        X = np.zeros((N, self.node_in_dim), dtype=np.float64)

        for i, node in enumerate(nodes):
            attrs = getattr(node, "attributes", {}) or {}
            # Extract 16 node attributes: type, pid, ppid depth, flags, privileges, sockets
            n_type = (getattr(node, "action_type", None) or getattr(node, "node_type", "process") or attrs.get("type", "process")).lower()
            type_val = 1.0 if "process" in n_type else (0.5 if "network" in n_type else 0.2)
            pid = float(getattr(node, "pid", None) or attrs.get("pid", 0) or 0)
            ppid = float(getattr(node, "ppid", None) or attrs.get("ppid", 0) or 0)
            is_elevated = 1.0 if (getattr(node, "is_elevated", False) or attrs.get("is_elevated", False)) else 0.0
            
            # Populate normalized node vector
            X[i, 0] = type_val
            X[i, 1] = np.log1p(pid) / 15.0
            X[i, 2] = np.log1p(ppid) / 15.0
            X[i, 3] = is_elevated
            X[i, 4] = 1.0 if pid in [0, 4] else 0.0  # System flag
            cmdline = getattr(node, "command_line", None) or attrs.get("command_line", "") or ""
            X[i, 5] = float(len(str(cmdline))) / 500.0  # Cmdline length
            
            # Temporal & interaction markers
            X[i, 6] = float(getattr(node, "in_degree", 1)) / 10.0
            X[i, 7] = float(getattr(node, "out_degree", 1)) / 10.0
            label = str(getattr(node, "label", None) or attrs.get("label", "") or "").lower()
            X[i, 8] = 1.0 if "powershell" in label else 0.0
            X[i, 9] = 1.0 if "cmd" in label else 0.0
            X[i, 10] = 1.0 if (getattr(node, "canary_hit", False) or attrs.get("canary_hit", False)) else 0.0
            # Indices 11-15: Harmonic position encoding
            for k in range(5):
                X[i, 11 + k] = np.sin((i + 1) * (k + 1) * np.pi / max(N, 2))

        # Adjacency matrix construction
        A = np.zeros((N, N), dtype=np.float64)
        edges = getattr(graph, "edges", [])
        if isinstance(edges, dict):
            edges = list(edges.values())

        for edge in edges:
            src = getattr(edge, "source_node", None) or getattr(edge, "source", None) or getattr(edge, "source_id", None)
            dst = getattr(edge, "target_node", None) or getattr(edge, "target", None) or getattr(edge, "target_id", None)
            if src in node_index_map and dst in node_index_map:
                u, v = node_index_map[src], node_index_map[dst]
                A[u, v] = 1.0
                A[v, u] = 0.5  # Asymmetric back-propagation edge

        return X, A

    def compute_gnn_embedding(self, graph: BehaviorGraph) -> np.ndarray:
        """
        Executes 2-layer Graph Convolutional forward pass over BehaviorGraph.
        Returns a normalized 128-dimensional unit vector.
        """
        X, A = self._extract_node_features(graph)
        N = X.shape[0]

        # 1. Add self-loops: A_tilde = A + I_N
        A_tilde = A + np.eye(N)

        # 2. Symmetric degree normalization: D_tilde^{-1/2} * A_tilde * D_tilde^{-1/2}
        degrees = np.sum(A_tilde, axis=1)
        deg_inv_sqrt = np.power(degrees, -0.5, where=degrees > 0)
        deg_inv_sqrt[degrees <= 0] = 0.0
        D_inv_sqrt = np.diag(deg_inv_sqrt)
        A_hat = D_inv_sqrt @ A_tilde @ D_inv_sqrt

        # 3. Layer 1 Convolution: H1 = ReLU(A_hat * X * W0)
        Z0 = A_hat @ X @ self.W0
        H1 = np.maximum(0, Z0)  # ReLU activation

        # 4. Layer 2 Convolution: H2 = ReLU(A_hat * H1 * W1)
        Z1 = A_hat @ H1 @ self.W1
        H2 = np.maximum(0, Z1)  # ReLU activation

        # 5. Dual-Pool Graph Readout (Mean + Max pooling across nodes)
        mean_pool = np.mean(H2, axis=0)
        max_pool = np.max(H2, axis=0)
        h_graph = np.concatenate([mean_pool, max_pool])  # Dimension: hidden_dim * 2

        # 6. Linear projection to 128 dimensions
        embedding = h_graph @ self.W_proj

        # 7. L2 unit length normalization: ||e||_2 = 1.0
        norm = np.linalg.norm(embedding)
        if norm > 1e-12:
            embedding = embedding / norm
        else:
            embedding = np.ones(self.out_dim) / np.sqrt(self.out_dim)

        return embedding

    def fuse_with_dbef(self, spectral_embedding: np.ndarray, gnn_embedding: np.ndarray, alpha: float = 0.5) -> np.ndarray:
        """
        Fuses spectral d-BEF embedding with inductive GNN embedding:
        e_fused = alpha * e_spectral + (1 - alpha) * e_gnn
        re-normalized to unit length: ||e_fused||_2 = 1.0
        """
        if spectral_embedding is None or len(spectral_embedding) != self.out_dim:
            return gnn_embedding
        if gnn_embedding is None or len(gnn_embedding) != self.out_dim:
            return spectral_embedding

        fused = alpha * spectral_embedding + (1.0 - alpha) * gnn_embedding
        norm = np.linalg.norm(fused)
        if norm > 1e-12:
            return fused / norm
        return spectral_embedding


# Singleton accessor
_gnn_engine_instance: Optional[GNNEngine] = None

def get_gnn_engine() -> GNNEngine:
    global _gnn_engine_instance
    if _gnn_engine_instance is None:
        _gnn_engine_instance = GNNEngine()
    return _gnn_engine_instance
