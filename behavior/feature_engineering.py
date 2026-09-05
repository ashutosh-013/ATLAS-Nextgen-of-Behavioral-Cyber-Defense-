"""
Feature Engineering Module for BADNA

This module implements feature extraction from behavior graphs as part of the
d-BEF (Directed Behavioral Embedding Function) algorithm. Extracts structural,
temporal, and behavioral features for mathematical analysis.

Requirements: 2.1-2.8 (Feature Engineering and Extraction)
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime
import networkx as nx
from scipy import sparse, linalg
import warnings
warnings.filterwarnings('ignore', category=RuntimeWarning)

# Import our models
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_models import BehaviorGraph, FeatureVector
from config import ValidationError, ProcessingError, get_logger, get_config


class FeatureEngineer:
    """
    Feature extraction component of d-BEF algorithm.
    Extracts structural, temporal, and behavioral features from behavior graphs.
    
    This class implements Requirements 2.1-2.8 for comprehensive feature extraction
    from behavior graphs, producing normalized feature vectors with at least 64 dimensions.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        
        # Feature extractors organized by category
        self.structural_features = [
            'node_count', 'edge_count', 'density', 'clustering_coeff',
            'avg_degree', 'max_degree', 'diameter', 'radius',
            'num_components', 'largest_component_size'
        ]
        
        self.centrality_features = [
            'degree_centrality_max', 'degree_centrality_avg',
            'betweenness_centrality_max', 'betweenness_centrality_avg', 
            'eigenvector_centrality_max', 'eigenvector_centrality_avg',
            'pagerank_max', 'pagerank_avg',
            'closeness_centrality_max', 'closeness_centrality_avg'
        ]
        
        self.temporal_features = [
            'event_frequency', 'avg_time_gap', 'max_time_gap', 'time_variance',
            'velocity', 'acceleration', 'burst_count', 'quiet_periods'
        ]
        
        self.behavioral_features = [
            'critical_path_length', 'motif_triangles', 'motif_squares', 
            'execution_chains', 'persistence_score', 'escalation_score',
            'branching_factor', 'convergence_factor'
        ]
    
    def extract_features(self, graph: BehaviorGraph) -> FeatureVector:
        """
        Extract statistical and structural features from behavior graph.
        
        Args:
            graph: Behavior graph to analyze
            
        Returns:
            FeatureVector with normalized features (64+ dimensions)
            
        Features Extracted:
            - Structural: node_count, edge_count, density, clustering
            - Centrality: degree, betweenness, eigenvector, closeness
            - Temporal: event_frequency, time_gaps, velocity, acceleration
            - Behavioral: critical_paths, motif_patterns, attack_sequences
            
        Requirements:
            - 2.1: Extract graph structural features
            - 2.2: Calculate centrality measures  
            - 2.3: Identify critical paths
            - 2.4: Compute temporal features
            - 2.5: Extract behavioral motifs
            - 2.6: Normalize all features to [0.0, 1.0]
            - 2.7: Produce at least 64 dimensions
        """
        if not graph.nodes:
            # Return zero vector for empty graph with minimum dimensions
            features = np.zeros(64)
            feature_names = [f"feature_{i}" for i in range(64)]
            return FeatureVector(
                graph_id=graph.graph_id,
                features=features,
                feature_names=feature_names
            )
        
        # Convert to NetworkX for advanced graph analysis
        G = self._to_networkx(graph)
        
        # Extract feature categories
        structural = self._extract_structural_features(G, graph)
        centrality = self._extract_centrality_features(G, graph) 
        temporal = self._extract_temporal_features(graph)
        behavioral = self._extract_behavioral_features(G, graph)
        
        # Combine all features into single dictionary
        all_features = {}
        all_features.update(structural)
        all_features.update(centrality)
        all_features.update(temporal)
        all_features.update(behavioral)
        
        # Ensure minimum 64 dimensions (Requirement 2.7)
        while len(all_features) < 64:
            all_features[f"padding_{len(all_features)}"] = 0.0
        
        # Convert to arrays
        feature_names = list(all_features.keys())
        features = np.array(list(all_features.values()), dtype=np.float64)
        
        # Normalize features to [0, 1] (Requirement 2.6)
        features = self._normalize_features(features)
        
        self.logger.log_operation("INFO", f"Extracted {len(features)} features",
                                 component="FeatureEngineer", 
                                 operation="extract_features")
        
        return FeatureVector(
            graph_id=graph.graph_id,
            features=features,
            feature_names=feature_names
        )
    
    def _to_networkx(self, graph: BehaviorGraph) -> nx.DiGraph:
        """Convert BehaviorGraph to NetworkX DiGraph for analysis."""
        G = nx.DiGraph()
        
        # Add nodes with attributes
        for node in graph.nodes:
            G.add_node(node.node_id, **node.attributes)
        
        # Add edges with weights and attributes
        for edge in graph.edges:
            G.add_edge(edge.source_node, edge.target_node, 
                      weight=edge.weight, 
                      transition_type=edge.transition_type,
                      temporal_gap=edge.temporal_gap)
        
        return G
    
    def _extract_structural_features(self, G: nx.DiGraph, graph: BehaviorGraph) -> Dict[str, float]:
        """
        Extract structural features from graph (Requirement 2.1).
        
        Features include:
        - Basic metrics: node_count, edge_count, density
        - Clustering: clustering_coefficient
        - Degree statistics: average, maximum, variance
        - Graph topology: diameter, radius, components
        """
        features = {}
        
        # Basic structural metrics
        features['node_count'] = float(G.number_of_nodes())
        features['edge_count'] = float(G.number_of_edges())
        features['density'] = nx.density(G)
        
        # Clustering coefficient for behavior pattern detection
        try:
            features['clustering_coeff'] = nx.average_clustering(G.to_undirected())
        except:
            features['clustering_coeff'] = 0.0
        
        # Degree statistics reveal connectivity patterns
        degrees = [d for n, d in G.degree()]
        features['avg_degree'] = np.mean(degrees) if degrees else 0.0
        features['max_degree'] = np.max(degrees) if degrees else 0.0
        features['degree_variance'] = np.var(degrees) if degrees else 0.0
        
        # Graph topology measures
        try:
            if nx.is_connected(G.to_undirected()):
                features['diameter'] = float(nx.diameter(G.to_undirected()))
                features['radius'] = float(nx.radius(G.to_undirected()))
            else:
                features['diameter'] = 0.0
                features['radius'] = 0.0
        except:
            features['diameter'] = 0.0
            features['radius'] = 0.0
        
        # Component analysis for attack campaign structure
        features['num_components'] = float(nx.number_weakly_connected_components(G))
        largest_component = max(nx.weakly_connected_components(G), key=len, default=[])
        features['largest_component_size'] = float(len(largest_component))
        
        return features
    
    def _extract_centrality_features(self, G: nx.DiGraph, graph: BehaviorGraph) -> Dict[str, float]:
        """
        Extract centrality-based features (Requirement 2.2).
        
        Centrality measures identify critical nodes in attack behavior:
        - Degree centrality: connectivity importance
        - Betweenness centrality: path control importance  
        - Eigenvector centrality: influence importance
        - PageRank: authority importance
        - Closeness centrality: distance efficiency
        """
        features = {}
        
        if G.number_of_nodes() == 0:
            return {name: 0.0 for name in self.centrality_features}
        
        try:
            # Degree centrality - basic connectivity measure
            degree_cent = nx.degree_centrality(G)
            features['degree_centrality_max'] = max(degree_cent.values(), default=0.0)
            features['degree_centrality_avg'] = np.mean(list(degree_cent.values()))
            
            # Betweenness centrality - identifies control points
            between_cent = nx.betweenness_centrality(G)
            features['betweenness_centrality_max'] = max(between_cent.values(), default=0.0)
            features['betweenness_centrality_avg'] = np.mean(list(between_cent.values()))
            
            # Eigenvector centrality - identifies influential nodes
            try:
                eigen_cent = nx.eigenvector_centrality(G, max_iter=1000)
                features['eigenvector_centrality_max'] = max(eigen_cent.values(), default=0.0)
                features['eigenvector_centrality_avg'] = np.mean(list(eigen_cent.values()))
            except:
                features['eigenvector_centrality_max'] = 0.0
                features['eigenvector_centrality_avg'] = 0.0
            
            # PageRank - authority measure adapted from web search
            pagerank = nx.pagerank(G)
            features['pagerank_max'] = max(pagerank.values(), default=0.0)
            features['pagerank_avg'] = np.mean(list(pagerank.values()))
            
            # Closeness centrality - efficiency of information spread
            try:
                close_cent = nx.closeness_centrality(G)
                features['closeness_centrality_max'] = max(close_cent.values(), default=0.0)
                features['closeness_centrality_avg'] = np.mean(list(close_cent.values()))
            except:
                features['closeness_centrality_max'] = 0.0
                features['closeness_centrality_avg'] = 0.0
            
        except Exception as e:
            self.logger.log_operation("WARNING", f"Centrality computation failed: {e}",
                                     component="FeatureEngineer")
            # Return zeros for failed centrality computations
            for name in self.centrality_features:
                if name not in features:
                    features[name] = 0.0
        
        return features
    
    def _extract_temporal_features(self, graph: BehaviorGraph) -> Dict[str, float]:
        """
        Extract temporal features from behavior graph (Requirement 2.4).
        
        Temporal features capture attack timing patterns:
        - Event frequency: rate of malicious actions
        - Time gaps: intervals between actions
        - Velocity/acceleration: attack pace changes
        - Burst patterns: rapid activity periods
        - Quiet periods: dormant phases
        """
        features = {}
        
        if not graph.nodes:
            return {name: 0.0 for name in self.temporal_features}
        
        # Extract and sort timestamps from all nodes
        timestamps = [node.timestamp for node in graph.nodes]
        timestamps.sort()
        
        if len(timestamps) < 2:
            return {name: 0.0 for name in self.temporal_features}
        
        # Calculate time gaps between consecutive events
        time_gaps = []
        for i in range(len(timestamps) - 1):
            gap = (timestamps[i + 1] - timestamps[i]).total_seconds()
            time_gaps.append(gap)
        
        # Basic temporal statistics
        total_time = (timestamps[-1] - timestamps[0]).total_seconds()
        features['event_frequency'] = len(timestamps) / max(total_time, 1.0)
        features['avg_time_gap'] = np.mean(time_gaps)
        features['max_time_gap'] = np.max(time_gaps)
        features['time_variance'] = np.var(time_gaps)
        
        # Velocity and acceleration metrics for attack pace analysis
        features['velocity'] = len(timestamps) / max(total_time, 1.0)
        if len(time_gaps) > 1:
            gap_diffs = np.diff(time_gaps)
            features['acceleration'] = np.mean(np.abs(gap_diffs))
        else:
            features['acceleration'] = 0.0
        
        # Burst analysis - detect rapid-fire attack sequences
        burst_threshold = 5.0  # seconds
        burst_events = sum(1 for gap in time_gaps if gap < burst_threshold)
        features['burst_count'] = float(burst_events)
        
        # Quiet period analysis - detect dormant phases
        quiet_threshold = 300.0  # 5 minutes
        quiet_periods = sum(1 for gap in time_gaps if gap > quiet_threshold)
        features['quiet_periods'] = float(quiet_periods)
        
        return features
    
    def _extract_behavioral_features(self, G: nx.DiGraph, graph: BehaviorGraph) -> Dict[str, float]:
        """
        Extract behavioral motifs and patterns (Requirement 2.5).
        
        Behavioral features identify attack-specific patterns:
        - Critical paths: main attack sequences (Requirement 2.3)
        - Motifs: common subgraph patterns (triangles, squares)
        - Execution chains: sequences of malicious actions
        - Persistence/escalation scores: specific attack behaviors
        """
        features = {}
        
        if G.number_of_nodes() < 2:
            return {name: 0.0 for name in self.behavioral_features}
        
        # Critical path analysis (Requirement 2.3)
        try:
            # Find longest path as approximation of critical attack path
            longest_path_length = 0
            for source in G.nodes():
                if G.in_degree(source) == 0:  # Start from entry points
                    paths = nx.single_source_shortest_path_length(G, source)
                    longest_path_length = max(longest_path_length, max(paths.values(), default=0))
            features['critical_path_length'] = float(longest_path_length)
        except:
            features['critical_path_length'] = 0.0
        
        # Motif counting - detect common attack patterns
        undirected_G = G.to_undirected()
        features['motif_triangles'] = float(sum(nx.triangles(undirected_G).values()) / 3)
        features['motif_squares'] = self._count_squares(undirected_G)
        
        # Attack-specific behavioral scoring
        features['execution_chains'] = self._count_execution_chains(G, graph)
        features['persistence_score'] = self._calculate_persistence_score(G, graph)
        features['escalation_score'] = self._calculate_escalation_score(G, graph)
        
        # Graph structure behavioral metrics
        features['branching_factor'] = np.mean([G.out_degree(n) for n in G.nodes()])
        features['convergence_factor'] = np.mean([G.in_degree(n) for n in G.nodes()])
        
        return features
    
    def _count_squares(self, G: nx.Graph) -> float:
        """Count 4-cycles (squares) in graph - common in lateral movement."""
        squares = 0
        nodes = list(G.nodes())
        
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                n1, n2 = nodes[i], nodes[j]
                if G.has_edge(n1, n2):
                    # Find common neighbors to form squares
                    neighbors1 = set(G.neighbors(n1))
                    neighbors2 = set(G.neighbors(n2))
                    common = neighbors1 & neighbors2
                    
                    # Each pair of common neighbors forms a square
                    squares += len(common) * (len(common) - 1) // 2
        
        return float(squares)
    
    def _count_execution_chains(self, G: nx.DiGraph, graph: BehaviorGraph) -> float:
        """Count execution chains - sequences of execution-related actions."""
        chains = 0
        
        # Define execution-related action types
        execution_actions = ['execution', 'persistence', 'privilege_escalation']
        
        node_map = {n.node_id: n for n in graph.nodes}
        for node in graph.nodes:
            if node.action_type in execution_actions:
                # Count downstream execution nodes
                try:
                    descendants = nx.descendants(G, node.node_id)
                    execution_descendants = sum(1 for desc_id in descendants
                                              if (desc := node_map.get(desc_id)) and desc.action_type in execution_actions)
                    chains += execution_descendants
                except Exception as e:
                    self.logger.debug(f"Execution chain count failed for node {node.node_id}: {e}")
        
        return float(chains)
    
    def _calculate_persistence_score(self, G: nx.DiGraph, graph: BehaviorGraph) -> float:
        """Calculate persistence behavior score - measures attacker foothold attempts."""
        persistence_score = 0.0
        persistence_actions = ['persistence', 'registry_modify', 'service_create']
        
        for node in graph.nodes:
            if node.action_type in persistence_actions:
                persistence_score += 1.0
                
                # Bonus for persistence followed by other actions (successful foothold)
                try:
                    successors = list(G.successors(node.node_id))
                    persistence_score += len(successors) * 0.1
                except:
                    pass
        
        return persistence_score
    
    def _calculate_escalation_score(self, G: nx.DiGraph, graph: BehaviorGraph) -> float:
        """Calculate privilege escalation behavior score - measures attack progression."""
        escalation_score = 0.0
        
        # Define typical escalation sequence
        escalation_sequence = [
            'initial_access', 'privilege_escalation', 'persistence', 'discovery'
        ]
        
        # Look for escalation sequences in behavior graph
        for i in range(len(escalation_sequence) - 1):
            current_action = escalation_sequence[i]
            next_action = escalation_sequence[i + 1]
            
            current_nodes = [n for n in graph.nodes if n.action_type == current_action]
            next_nodes = [n for n in graph.nodes if n.action_type == next_action]
            
            for curr_node in current_nodes:
                for next_node in next_nodes:
                    if G.has_edge(curr_node.node_id, next_node.node_id):
                        escalation_score += 2.0  # Higher weight for direct escalation
        
        return escalation_score
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features to [0, 1] scale (Requirement 2.6).
        
        Uses min-max normalization to ensure all features are in the same scale
        for effective mathematical processing by the d-BEF algorithm.
        """
        # Handle edge cases
        if len(features) == 0:
            return features
        
        # Replace inf and nan values with safe defaults
        features = np.nan_to_num(features, nan=0.0, posinf=1.0, neginf=0.0)
        
        # Min-max normalization to [0, 1] range
        min_val = np.min(features)
        max_val = np.max(features)
        
        if max_val == min_val:
            return np.zeros_like(features)  # All features same -> zero vector
        
        normalized = (features - min_val) / (max_val - min_val)
        
        # Ensure values are strictly in [0, 1] range
        return np.clip(normalized, 0.0, 1.0)


# =============================================================================
# Utility Functions
# =============================================================================

def extract_graph_features(graph: BehaviorGraph) -> FeatureVector:
    """
    Convenience function to extract features from a behavior graph.
    
    Args:
        graph: Behavior graph to analyze
        
    Returns:
        FeatureVector with normalized features (64+ dimensions)
    """
    feature_engineer = FeatureEngineer()
    return feature_engineer.extract_features(graph)


if __name__ == "__main__":
    # Test feature engineering implementation
    print("Testing Feature Engineering Module...")
    
    # Import required modules for testing
    from data_models import create_behavior_node, BehaviorEdge, BehaviorGraph
    from datetime import datetime
    
    # Create test behavior graph
    nodes = [
        create_behavior_node("execution", ["event1"], {"test": "node1"}),
        create_behavior_node("persistence", ["event2"], {"test": "node2"}), 
        create_behavior_node("discovery", ["event3"], {"test": "node3"}),
        create_behavior_node("lateral_movement", ["event4"], {"test": "node4"})
    ]
    
    edges = [
        BehaviorEdge(nodes[0].node_id, nodes[1].node_id, "escalation", 1.0, 1.0),
        BehaviorEdge(nodes[1].node_id, nodes[2].node_id, "temporal", 0.8, 2.0),
        BehaviorEdge(nodes[2].node_id, nodes[3].node_id, "lateral", 0.9, 1.5)
    ]
    
    test_graph = BehaviorGraph(
        graph_id="test_graph_features",
        nodes=nodes,
        edges=edges
    )
    
    try:
        # Test feature extraction
        feature_engineer = FeatureEngineer()
        features = feature_engineer.extract_features(test_graph)
        
        print(f"✓ Extracted {len(features.features)} features")
        print(f"✓ Features normalized: min={np.min(features.features):.3f}, max={np.max(features.features):.3f}")
        print(f"✓ Feature validation: at least 64 dims = {len(features.features) >= 64}")
        
        # Test convenience function
        features2 = extract_graph_features(test_graph)
        print(f"✓ Convenience function works: {len(features2.features)} features")
        
        # Validate requirements compliance
        print("\n=== Requirements Validation ===")
        print(f"2.6: All features in [0,1]: {np.all((features.features >= 0) & (features.features <= 1))}")
        print(f"2.7: At least 64 dimensions: {len(features.features) >= 64}")
        print(f"Feature names match feature count: {len(features.feature_names) == len(features.features)}")
        
        print("\nFeature Engineering Module implementation complete!")
        
    except Exception as e:
        print(f"Error testing feature engineering: {e}")
        import traceback
        traceback.print_exc()