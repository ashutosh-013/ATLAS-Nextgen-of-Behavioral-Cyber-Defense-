"""
Unit tests for Dataset Ingestion Loader
"""

import pytest
import sys
from pathlib import Path

from ingestion.dataset_loader import DatasetLoader
from ingestion.dataset_registry import DatasetRegistry
from knowledge_base.knowledge_base import KnowledgeBase


@pytest.fixture
def registry():
    """Create DatasetRegistry"""
    return DatasetRegistry()


@pytest.fixture
def loader(registry):
    """Create DatasetLoader"""
    return DatasetLoader(registry)


def test_loader_initialization(loader):
    """Test loader properties initialized successfully"""
    assert loader.registry is not None
    assert loader.capture_engine is not None
    assert loader.kb is not None
    assert isinstance(loader.kb, KnowledgeBase)


def test_get_parser(loader):
    """Test instantiation of correct parser class from registry metadata"""
    # Grab any registered metadata
    dataset_metas = loader.registry.list_all()
    assert len(dataset_metas) > 0
    
    # We check a few known ones
    for meta in dataset_metas:
        if meta.parser_class in ["DARPAOpTCParser", "CTU13Parser", "CICIDSParser"]:
            parser = loader._get_parser(meta)
            assert parser is not None
            assert parser.metadata.parser_class == meta.parser_class


def test_populate_knowledge_base_dry_run(loader):
    """Test populate_knowledge_base on non-existing path returns safely without errors"""
    # Passing an empty list should result in empty results immediately
    res = loader.populate_knowledge_base(datasets=[])
    assert res == {}
    
    # Ingesting with empty or non-existent files should skip and return cleanly
    res = loader.populate_knowledge_base(datasets=["sorel_20m"])
    # If the local SOREL folder doesn't exist, it should return safely
    assert isinstance(res, dict)


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
