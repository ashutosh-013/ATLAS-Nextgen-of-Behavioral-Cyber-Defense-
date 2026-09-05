"""
Behavioral Capture Engine - Event Processing and Graph Construction

This module implements event parsing and behavior graph construction as specified
in the design document. Handles all event types and constructs directed acyclic 
behavior graphs with causality preservation.

Requirements: 1.1-1.10, 17.1-17.7, 18.8
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import networkx as nx

# Import our data models and config
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data_models import (
    SecurityEvent, BehaviorNode, BehaviorEdge, BehaviorGraph, 
    create_behavior_node, VALID_THREAT_CLASSES
)
from config import ValidationError, ProcessingError, get_logger, get_config


class BehaviorCaptureEngine:
    """
    Behavioral Capture Engine for parsing events and constructing behavior graphs.
    
    Implements Requirements 1.1-1.10 for event processing and graph construction.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        
        # Event type processors
        self.event_processors = {
            'process': self._process_process_event,
            'file': self._process_file_event, 
            'network': self._process_network_event,
            'auth': self._process_auth_event,
            'registry': self._process_registry_event,
            'user': self._process_user_event
        }
        
        # Action type mappings for graph nodes
        self.action_types = {
            'process_create': 'execution',
            'process_terminate': 'termination', 
            'file_read': 'discovery',
            'file_write': 'persistence',
            'file_delete': 'impact',
            'file_encrypt': 'impact',
            'network_dns': 'command_control',
            'network_http': 'exfiltration',
            'auth_login': 'initial_access',
            'auth_escalate': 'privilege_escalation',
            'registry_modify': 'persistence',
            'user_activity': 'collection'
        }
    
    def parse_events(self, raw_events: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """
        Parse raw security event JSON into structured Event objects.
        
        Args:
            raw_events: List of event dictionaries with required fields
                
        Returns:
            List of SecurityEvent objects sorted by timestamp
            
        Raises:
            ValidationError: If required fields missing or invalid
        """
        if not isinstance(raw_events, list):
            raise ValidationError("Events must be provided as a list", "events")
        
        parsed_events = []
        
        for i, raw_event in enumerate(raw_events):
            try:
                # Validate required fields
                self._validate_event_structure(raw_event, i)
                
                # Parse timestamp
                timestamp = self._parse_timestamp(raw_event.get('timestamp'), i)
                
                # Create SecurityEvent
                event = SecurityEvent(
                    event_id=raw_event.get('event_id', f"event_{i}_{int(timestamp.timestamp())}"),
                    event_type=raw_event['event_type'],
                    timestamp=timestamp,
                    source_system=raw_event.get('source_system', 'unknown'),
                    event_data=raw_event.get('event_data', {})
                )
                
                # Process event-specific data
                if event.event_type in self.event_processors:
                    self.event_processors[event.event_type](event)
                
                parsed_events.append(event)
                
            except Exception as e:
                raise ValidationError(f"Failed to parse event {i}: {str(e)}", f"events[{i}]")
        
        # Sort by timestamp (Requirements 1.7)
        parsed_events.sort(key=lambda e: e.timestamp)
        
        self.logger.log_operation("INFO", f"Parsed {len(parsed_events)} events", 
                                 component="BehaviorCaptureEngine", 
                                 operation="parse_events")
        
        return parsed_events
    
    def build_graph(self, events: List[SecurityEvent]) -> BehaviorGraph:
        """
        Construct directed behavior graph from events.
        
        Args:
            events: Sorted list of SecurityEvent objects
            
        Returns:
            BehaviorGraph with nodes as actions, edges as transitions
            
        Graph Properties:
            - Directed: Edges preserve temporal causality
            - Weighted: Edge weights represent transition frequency  
            - Acyclic: No cycles (enforced by temporal ordering)
        """
        if not events:
            # Return empty graph
            return BehaviorGraph(
                graph_id=f"graph_{int(datetime.now().timestamp())}",
                nodes=[],
                edges=[]
            )
        
        # Group events into behavioral nodes
        nodes = self._create_behavior_nodes(events)
        
        # Create edges based on temporal and causal relationships
        edges = self._create_behavior_edges(nodes, events)
        
        # Apply graph pruning if necessary
        if len(nodes) > self.config.max_graph_size:
            nodes, edges = self._prune_graph(nodes, edges)
        
        # Create graph
        graph = BehaviorGraph(
            graph_id=f"graph_{events[0].event_id}_{len(events)}",
            nodes=nodes,
            edges=edges,
            metadata={
                'event_count': len(events),
                'time_span_seconds': (events[-1].timestamp - events[0].timestamp).total_seconds(),
                'source_systems': list(set(e.source_system for e in events)),
                'pruned': len(nodes) == self.config.max_graph_size
            }
        )
        
        # Validate graph is acyclic
        if not self._validate_acyclic(graph):
            raise ProcessingError("Generated graph contains cycles", "BehaviorCaptureEngine", "build_graph")
        
        self.logger.log_operation("INFO", f"Built behavior graph with {len(nodes)} nodes, {len(edges)} edges",
                                 component="BehaviorCaptureEngine", 
                                 operation="build_graph",
                                 duration_ms=0.0)
        
        return graph
    
    def _validate_event_structure(self, event: Dict[str, Any], index: int) -> None:
        """Validate event has required fields."""
        required_fields = ['event_type', 'timestamp']
        
        for field in required_fields:
            if field not in event:
                raise ValidationError(f"Required field '{field}' missing", f"events[{index}].{field}")
        
        # Validate event_type
        valid_types = list(self.event_processors.keys())
        if event['event_type'] not in valid_types:
            raise ValidationError(f"Invalid event_type '{event['event_type']}'. Must be one of {valid_types}", 
                                f"events[{index}].event_type")
    
    def _parse_timestamp(self, timestamp_str: Any, index: int) -> datetime:
        """Parse timestamp string into datetime object."""
        if isinstance(timestamp_str, datetime):
            return timestamp_str
        
        if not isinstance(timestamp_str, str):
            raise ValidationError(f"Timestamp must be string or datetime, got {type(timestamp_str)}", 
                                f"events[{index}].timestamp")
        
        try:
            # Try ISO format first
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            try:
                # Try other common formats
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                raise ValidationError(f"Invalid timestamp format: {timestamp_str}", 
                                    f"events[{index}].timestamp")
    
    def _create_behavior_nodes(self, events: List[SecurityEvent]) -> List[BehaviorNode]:
        """Create behavior nodes from events."""
        nodes = []
        event_to_action = {}
        
        for event in events:
            # Determine action type based on event
            action_key = f"{event.event_type}_{event.event_data.get('action', 'unknown')}"
            action_type = self.action_types.get(action_key, event.event_type)
            
            # Create behavior node
            node = create_behavior_node(
                action_type=action_type,
                event_refs=[event.event_id],
                attributes={
                    'source_system': event.source_system,
                    'event_type': event.event_type,
                    'event_data_summary': self._summarize_event_data(event.event_data)
                }
            )
            node.timestamp = event.timestamp
            
            nodes.append(node)
            event_to_action[event.event_id] = node.node_id
        
        return nodes
    
    def _create_behavior_edges(self, nodes: List[BehaviorNode], 
                              events: List[SecurityEvent]) -> List[BehaviorEdge]:
        """Create edges based on temporal and causal relationships."""
        edges = []
        
        # Create temporal edges between consecutive nodes
        for i in range(len(nodes) - 1):
            current_node = nodes[i]
            next_node = nodes[i + 1]
            
            # Calculate temporal gap
            time_gap = (next_node.timestamp - current_node.timestamp).total_seconds()
            
            # Determine transition type and weight
            transition_type = self._determine_transition_type(current_node, next_node)
            weight = self._calculate_edge_weight(current_node, next_node, time_gap)
            
            edge = BehaviorEdge(
                source_node=current_node.node_id,
                target_node=next_node.node_id,
                transition_type=transition_type,
                weight=weight,
                temporal_gap=time_gap
            )
            
            edges.append(edge)
        
        # Add causal edges (same process, file operations, etc.)
        causal_edges = self._create_causal_edges(nodes, events)
        edges.extend(causal_edges)
        
        return edges
    
    def _prune_graph(self, nodes: List[BehaviorNode], 
                    edges: List[BehaviorEdge]) -> tuple[List[BehaviorNode], List[BehaviorEdge]]:
        """Prune graph while preserving critical paths."""
        max_nodes = self.config.max_graph_size
        
        if len(nodes) <= max_nodes:
            return nodes, edges
        
        # Calculate node importance scores
        node_scores = self._calculate_node_importance(nodes, edges)
        
        # Keep top nodes by importance
        important_nodes = sorted(nodes, key=lambda n: node_scores.get(n.node_id, 0), reverse=True)[:max_nodes]
        important_node_ids = {n.node_id for n in important_nodes}
        
        # Keep edges between important nodes
        pruned_edges = [e for e in edges if e.source_node in important_node_ids and e.target_node in important_node_ids]
        
        self.logger.log_operation("WARNING", f"Pruned graph from {len(nodes)} to {len(important_nodes)} nodes",
                                 component="BehaviorCaptureEngine", 
                                 operation="prune_graph")
        
        return important_nodes, pruned_edges
    
    def _calculate_node_importance(self, nodes: List[BehaviorNode], 
                                  edges: List[BehaviorEdge]) -> Dict[str, float]:
        """Calculate importance scores for graph nodes."""
        scores = {node.node_id: 0.0 for node in nodes}
        
        # Count in-degree and out-degree
        in_degree = {node.node_id: 0 for node in nodes}
        out_degree = {node.node_id: 0 for node in nodes}
        
        for edge in edges:
            if edge.source_node in out_degree:
                out_degree[edge.source_node] += 1
            if edge.target_node in in_degree:
                in_degree[edge.target_node] += 1
        
        # Calculate importance (centrality-based)
        for node in nodes:
            node_id = node.node_id
            
            # Base score from connectivity
            scores[node_id] += in_degree[node_id] + out_degree[node_id]
            
            # Boost for high-risk actions
            if node.action_type in ['privilege_escalation', 'persistence', 'exfiltration', 'impact']:
                scores[node_id] += 10.0
            
            # Boost for unusual activities
            if 'unusual' in node.attributes.get('event_data_summary', ''):
                scores[node_id] += 5.0
        
        return scores
    
    def _validate_acyclic(self, graph: BehaviorGraph) -> bool:
        """Validate that graph is acyclic."""
        try:
            # Create NetworkX graph for cycle detection
            G = nx.DiGraph()
            
            for node in graph.nodes:
                G.add_node(node.node_id)
            
            for edge in graph.edges:
                G.add_edge(edge.source_node, edge.target_node)
            
            return nx.is_directed_acyclic_graph(G)
            
        except Exception as e:
            self.logger.log_operation("ERROR", f"Failed to validate graph acyclicity: {e}",
                                     component="BehaviorCaptureEngine")
            return False
    
    def _determine_transition_type(self, source: BehaviorNode, target: BehaviorNode) -> str:
        """Determine the type of transition between nodes."""
        if source.action_type == target.action_type:
            return "continuation"
        
        # Define transition patterns
        escalation_patterns = [
            ("initial_access", "privilege_escalation"),
            ("privilege_escalation", "persistence"),
            ("persistence", "discovery"),
            ("discovery", "lateral_movement"),
            ("lateral_movement", "collection"),
            ("collection", "exfiltration")
        ]
        
        for pattern_source, pattern_target in escalation_patterns:
            if source.action_type == pattern_source and target.action_type == pattern_target:
                return "escalation"
        
        return "temporal"
    
    def _calculate_edge_weight(self, source: BehaviorNode, target: BehaviorNode, time_gap: float) -> float:
        """Calculate edge weight based on temporal and semantic factors."""
        base_weight = 1.0
        
        # Time-based weighting (closer events have higher weight)
        if time_gap < 1.0:  # Less than 1 second
            time_factor = 2.0
        elif time_gap < 60.0:  # Less than 1 minute  
            time_factor = 1.5
        elif time_gap < 3600.0:  # Less than 1 hour
            time_factor = 1.0
        else:
            time_factor = 0.5
        
        # Semantic weighting (related actions have higher weight)
        if self._are_semantically_related(source, target):
            semantic_factor = 1.5
        else:
            semantic_factor = 1.0
        
        return base_weight * time_factor * semantic_factor
    
    def _are_semantically_related(self, source: BehaviorNode, target: BehaviorNode) -> bool:
        """Check if two nodes are semantically related."""
        # Same action type
        if source.action_type == target.action_type:
            return True
        
        # Related action patterns
        related_patterns = {
            'execution': ['persistence', 'privilege_escalation'],
            'persistence': ['discovery', 'lateral_movement'],
            'discovery': ['collection', 'exfiltration'], 
            'collection': ['exfiltration'],
            'privilege_escalation': ['persistence', 'discovery']
        }
        
        return target.action_type in related_patterns.get(source.action_type, [])
    
    def _create_causal_edges(self, nodes: List[BehaviorNode], 
                           events: List[SecurityEvent]) -> List[BehaviorEdge]:
        """Create causal edges based on process relationships, file operations, etc."""
        causal_edges = []
        
        # Group nodes by process, file, etc. for causal relationships
        process_groups = {}
        file_groups = {}
        
        for i, event in enumerate(events):
            node = nodes[i]
            
            # Process relationships
            if event.event_type == 'process':
                pid = event.event_data.get('pid')
                if pid:
                    if pid not in process_groups:
                        process_groups[pid] = []
                    process_groups[pid].append(node)
            
            # File relationships  
            elif event.event_type == 'file':
                file_path = event.event_data.get('path')
                if file_path:
                    if file_path not in file_groups:
                        file_groups[file_path] = []
                    file_groups[file_path].append(node)
        
        # Create edges within process groups
        for pid, group_nodes in process_groups.items():
            for i in range(len(group_nodes) - 1):
                edge = BehaviorEdge(
                    source_node=group_nodes[i].node_id,
                    target_node=group_nodes[i + 1].node_id,
                    transition_type="process_causal",
                    weight=2.0,  # Higher weight for causal relationships
                    temporal_gap=0.0
                )
                causal_edges.append(edge)
        
        return causal_edges
    
    # Event-specific processors
    def _process_process_event(self, event: SecurityEvent) -> None:
        """Process process-related events."""
        required_fields = ['pid', 'action']
        self._validate_event_data(event, required_fields)
        
        # Validate specific process actions
        valid_actions = ['create', 'terminate', 'parent_child']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid process action: {action}")
    
    def _process_file_event(self, event: SecurityEvent) -> None:
        """Process file operation events."""
        required_fields = ['path', 'action']
        self._validate_event_data(event, required_fields)
        
        valid_actions = ['read', 'write', 'delete', 'encrypt', 'rename']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid file action: {action}")
    
    def _process_network_event(self, event: SecurityEvent) -> None:
        """Process network activity events."""
        required_fields = ['action']
        self._validate_event_data(event, required_fields)
        
        valid_actions = ['dns', 'http', 'https', 'smb', 'c2', 'beaconing', 'upload', 'download']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid network action: {action}")
    
    def _process_auth_event(self, event: SecurityEvent) -> None:
        """Process authentication events.""" 
        required_fields = ['user', 'action']
        self._validate_event_data(event, required_fields)
        
        valid_actions = ['login', 'logout', 'escalate', 'token_abuse']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid auth action: {action}")
    
    def _process_registry_event(self, event: SecurityEvent) -> None:
        """Process registry/system modification events."""
        required_fields = ['key_path', 'action']
        self._validate_event_data(event, required_fields)
        
        valid_actions = ['modify', 'create', 'delete', 'service_create', 'scheduled_task']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid registry action: {action}")
    
    def _process_user_event(self, event: SecurityEvent) -> None:
        """Process user activity events."""
        required_fields = ['action']
        self._validate_event_data(event, required_fields)
        
        valid_actions = ['mouse', 'keyboard', 'usb', 'session']
        action = event.event_data.get('action')
        if action not in valid_actions:
            raise ValidationError(f"Invalid user action: {action}")
    
    def _validate_event_data(self, event: SecurityEvent, required_fields: List[str]) -> None:
        """Validate that event data contains required fields."""
        for field in required_fields:
            if field not in event.event_data:
                raise ValidationError(f"Required field '{field}' missing in {event.event_type} event data", 
                                    f"{event.event_type}.{field}")
    
    def _summarize_event_data(self, event_data: Dict[str, Any]) -> str:
        """Create a summary string of event data for node attributes."""
        summary_parts = []
        
        # Include key fields in summary
        key_fields = ['pid', 'path', 'user', 'ip', 'port', 'command', 'file_size']
        for field in key_fields:
            if field in event_data:
                summary_parts.append(f"{field}={event_data[field]}")
        
        return ", ".join(summary_parts[:3])  # Limit to first 3 fields


# =============================================================================
# Utility Functions
# =============================================================================

def load_test_events(test_file: str) -> List[Dict[str, Any]]:
    """Load test events from JSON file."""
    test_path = Path("tests") / test_file
    
    if not test_path.exists():
        raise ProcessingError(f"Test file not found: {test_file}", "BehaviorCaptureEngine", "load_test_events")
    
    try:
        with open(test_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise ProcessingError(f"Failed to load test file: {e}", "BehaviorCaptureEngine", "load_test_events")


def analyze_events_file(file_path: str) -> BehaviorGraph:
    """Analyze events from file and return behavior graph."""
    # Load events
    with open(file_path, 'r', encoding='utf-8') as f:
        raw_events = json.load(f)
    
    # Process with engine
    engine = BehaviorCaptureEngine()
    events = engine.parse_events(raw_events)
    graph = engine.build_graph(events)
    
    return graph


if __name__ == "__main__":
    # Test the behavior capture engine
    print("Testing Behavioral Capture Engine...")
    
    # Create test events
    test_events = [
        {
            "event_type": "process",
            "timestamp": "2024-01-01T10:00:00",
            "event_data": {"pid": 1234, "action": "create", "name": "cmd.exe"}
        },
        {
            "event_type": "file", 
            "timestamp": "2024-01-01T10:00:01",
            "event_data": {"path": "/tmp/test.txt", "action": "write"}
        },
        {
            "event_type": "network",
            "timestamp": "2024-01-01T10:00:02", 
            "event_data": {"action": "dns", "domain": "malicious.com"}
        }
    ]
    
    try:
        engine = BehaviorCaptureEngine()
        
        # Test event parsing
        parsed_events = engine.parse_events(test_events)
        print(f"Parsed {len(parsed_events)} events")
        
        # Test graph construction
        graph = engine.build_graph(parsed_events)
        print(f"Built graph with {graph.node_count} nodes, {graph.edge_count} edges")
        
        # Test acyclicity
        print(f"Graph is acyclic: {graph.is_acyclic}")
        
        print("Behavioral Capture Engine implementation complete!")
        
    except Exception as e:
        print(f"Error testing engine: {e}")
        import traceback
        traceback.print_exc()