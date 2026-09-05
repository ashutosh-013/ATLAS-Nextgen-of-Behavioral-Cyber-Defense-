"""
ATLAS Data Ingestion Infrastructure

This package provides the data ingestion layer that feeds production datasets
into the existing BADNA/ATLAS pipeline.

Modules:
- dataset_registry: Central registry for all datasets
- unified_schema: Common event format for all parsers
- base_parser: Abstract base class for dataset parsers
- dataset_loader: Orchestrates dataset ingestion
- graph_extraction_pipeline: Converts raw data to behavioral graphs
- update_scheduler: Manages continuous updates from live APIs

The ingestion layer converts raw cybersecurity datasets into UnifiedEvent format,
which feeds directly into the existing BehaviorCaptureEngine.

Architecture Integration:
    Raw Datasets → Parser → UnifiedEvent → BehaviorCaptureEngine → BADNA Pipeline
"""

__version__ = "1.0.0"
__author__ = "ATLAS Research Team"

# Import key components for easy access
from .dataset_registry import DatasetRegistry, DatasetMetadata
from .unified_schema import UnifiedEvent, EventType
from .base_parser import BaseDatasetParser, ParserError

__all__ = [
    'DatasetRegistry',
    'DatasetMetadata',
    'UnifiedEvent',
    'EventType',
    'BaseDatasetParser',
    'ParserError'
]
