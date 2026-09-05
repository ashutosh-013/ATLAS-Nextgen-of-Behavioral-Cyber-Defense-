"""
Dataset Ingestion Loader - Orchestrate dataset parsing and Knowledge Base population

Converts parsed dataset events into behavior graphs, generates 128D embeddings using d-BEF,
and stores the resulting patterns in the BADNA Knowledge Base.
"""

import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import numpy as np

try:
    from ingestion.dataset_registry import DatasetRegistry, DatasetMetadata
    from knowledge_base.knowledge_base import KnowledgeBase
    from data_models import BehaviorPattern, BADNAEmbedding, BehaviorGraph
    from behavior.capture_engine import BehaviorCaptureEngine
    from behavior.dbef import compute_badna_embedding
    
    # Factory imports
    from ingestion.parsers.darpa_optc_parser import create_darpa_optc_parser
    from ingestion.parsers.ctu13_parser import create_ctu13_parser
    from ingestion.parsers.cicids_parser import create_cicids_parser
    from ingestion.parsers.ember_parser import create_ember_parser, create_ember_pickle_parser
    from ingestion.parsers.sorel_parser import create_sorel_parser
    from ingestion.parsers.tpot_parser import create_tpot_parser
except ImportError:
    # STANDALONE FALLBACK PATHS
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.dataset_registry import DatasetRegistry, DatasetMetadata
    from knowledge_base.knowledge_base import KnowledgeBase
    from data_models import BehaviorPattern, BADNAEmbedding, BehaviorGraph
    from behavior.capture_engine import BehaviorCaptureEngine
    from behavior.dbef import compute_badna_embedding
    
    from ingestion.parsers.darpa_optc_parser import create_darpa_optc_parser
    from ingestion.parsers.ctu13_parser import create_ctu13_parser
    from ingestion.parsers.cicids_parser import create_cicids_parser
    from ingestion.parsers.ember_parser import create_ember_parser, create_ember_pickle_parser
    from ingestion.parsers.sorel_parser import create_sorel_parser
    from ingestion.parsers.tpot_parser import create_tpot_parser

logger = logging.getLogger("dataset_loader")


class DatasetLoader:
    """
    Dataset Ingestion Pipeline Orchestrator.
    
    Reads datasets from the registry, parses them, runs the capture engine and d-BEF
    to generate attack behavioral DNA, and populates the Knowledge Base.
    """
    
    def __init__(self, registry: DatasetRegistry):
        self.registry = registry
        self.capture_engine = BehaviorCaptureEngine()
        self.kb = KnowledgeBase()
        
    def _get_parser(self, metadata: DatasetMetadata) -> Any:
        """Instantiate the appropriate parser based on metadata settings"""
        parser_name = metadata.parser_class
        path = metadata.path
        
        if parser_name == "DARPAOpTCParser":
            return create_darpa_optc_parser(path)
        elif parser_name == "CTU13Parser":
            return create_ctu13_parser(path)
        elif parser_name == "CICIDSParser":
            return create_cicids_parser(path)
        elif parser_name == "EMBERParser":
            return create_ember_parser(path)
        elif parser_name == "EMBERPickleParser":
            return create_ember_pickle_parser(path)
        elif parser_name == "SORELParser":
            return create_sorel_parser(path)
        elif parser_name == "TPotParser":
            return create_tpot_parser(path)
        else:
            raise ValueError(f"Unknown parser class: {parser_name}")
            
    def populate_knowledge_base(self, datasets: Optional[List[str]] = None) -> Dict[str, int]:
        """
        Orchestrate loading of behavioral datasets into the Knowledge Base.
        
        Args:
            datasets: List of dataset IDs to ingest. If None, ingests all.
            
        Returns:
            Dict mapping dataset_id to count of ingested patterns
        """
        if datasets is None:
            datasets = [meta.dataset_id for meta in self.registry.list_all()]
            
        ingestion_results = {}
        
        for dataset_id in datasets:
            logger.info(f"Ingesting dataset: {dataset_id}")
            
            metadata = self.registry.get(dataset_id)
            if not metadata:
                logger.error(f"Dataset {dataset_id} metadata not found")
                continue
                
            # Skip threat intelligence datasets (parsed directly during fusion, not in KB patterns)
            if metadata.dataset_type.name in ["THREAT_INTELLIGENCE", "VULNERABILITIES"]:
                logger.info(f"Skipping threat intelligence dataset {dataset_id} for KB population")
                continue
                
            try:
                # Instantiate parser
                parser = self._get_parser(metadata)
                
                # Check path existence
                if not metadata.path.exists():
                    logger.warning(f"Path does not exist for dataset {dataset_id}: {metadata.path}")
                    continue
                    
                # Parse and normalize
                events = parser.parse_and_normalize(metadata.path)
                logger.info(f"Parsed {len(events)} events for {dataset_id}")
                
                if not events:
                    continue
                    
                # Ingest events to behavior graphs (split into chunks/groups of 100 events for graph construction)
                chunk_size = 100
                patterns_stored = 0
                
                for offset in range(0, len(events), chunk_size):
                    chunk_events = events[offset : offset + chunk_size]
                    
                    # Convert events to raw dictionaries for capture engine
                    raw_event_dicts = []
                    for ev in chunk_events:
                        raw_event_dicts.append({
                            'event_id': ev.event_id,
                            'event_type': ev.event_type,
                            'timestamp': ev.timestamp,
                            'source_system': ev.source_system,
                            'event_data': ev.event_data
                        })
                        
                    try:
                        # 1. Events -> Behavior Graph
                        parsed_events = self.capture_engine.parse_events(raw_event_dicts)
                        graph = self.capture_engine.build_graph(parsed_events)
                        
                        if graph.node_count == 0:
                            continue
                            
                        # 2. Graph -> Embedding
                        embedding = compute_badna_embedding(graph)
                        
                        # 3. Determine Threat Class
                        is_malicious = any(
                            ev.event_data.get('is_malicious') or ev.event_data.get('is_botnet')
                            for ev in chunk_events
                        )
                        threat_class = "Malware" if is_malicious else "Benign"
                        
                        # Special threat class mapping for DARPA (APT simulation)
                        if "darpa" in dataset_id.lower() and is_malicious:
                            threat_class = "APT"
                            
                        # 4. Save pattern in KB
                        pattern = BehaviorPattern(
                            embedding=embedding.vector,
                            threat_class=threat_class,
                            source="imported",
                            confidence_score=0.9,
                            metadata={
                                "dataset_source": dataset_id,
                                "source_graph_id": graph.graph_id,
                                "event_count": len(chunk_events)
                            }
                        )
                        
                        self.kb.store_pattern(pattern)
                        patterns_stored += 1
                        
                    except Exception as step_error:
                        logger.warning(f"Error processing event chunk for {dataset_id} at offset {offset}: {step_error}")
                        continue
                        
                logger.info(f"Ingested {patterns_stored} patterns from {dataset_id} into Knowledge Base")
                ingestion_results[dataset_id] = patterns_stored
                
            except Exception as e:
                logger.error(f"Failed to ingest dataset {dataset_id}: {e}")
                continue
                
        return ingestion_results
