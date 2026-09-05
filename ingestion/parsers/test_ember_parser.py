"""
Unit tests for EMBER Parser and EMBERPickleParser
"""

import pytest
import tempfile
import json
import pickle
import sys
from pathlib import Path

from ember_parser import (
    EMBERParser,
    EMBERPickleParser,
    create_ember_parser,
    create_ember_pickle_parser
)
from ingestion.unified_schema import UnifiedEvent
from ingestion.base_parser import ValidationError


@pytest.fixture
def json_parser():
    """Create EMBERParser instance"""
    dataset_path = Path("e:/BADNA/datasets/ember-master")
    return create_ember_parser(dataset_path)


@pytest.fixture
def pkl_parser():
    """Create EMBERPickleParser instance"""
    dataset_path = Path("e:/BADNA/datasets")
    return create_ember_pickle_parser(dataset_path)


@pytest.fixture
def sample_ember_json_record():
    """Sample raw EMBER JSON record"""
    return {
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "label": 1,
        "size": 204800,
        "imports": {
            "kernel32.dll": ["CreateFileW", "WriteFile", "CloseHandle"]
        }
    }


def test_ember_json_parsing(json_parser, sample_ember_json_record):
    """Test parsing EMBER JSON record"""
    event = json_parser.normalize_to_schema(sample_ember_json_record)
    assert event.event_type == "file"
    assert event.event_data["hash"] == sample_ember_json_record["sha256"]
    assert event.event_data["is_malicious"] is True
    assert event.event_data["label"] == "malware"
    assert event.event_data["file_size"] == 204800


# Mock objects to simulate unpickled angr structures
class MockMainObject:
    def __init__(self):
        self.imports = {
            "CreateFileW": 1,
            "WriteFile": 2,
            "RegSetValueExW": 3,
            "InternetConnectW": 4,
            "CreateProcessW": 5
        }
        self.deps = ["kernel32.dll", "advapi32.dll", "wininet.dll"]

class MockLoader:
    def __init__(self):
        self._main_object = MockMainObject()

class MockProject:
    def __init__(self):
        self.filename = "/path/to/samples/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        self.loader = MockLoader()

class MockCFG:
    def __init__(self):
        self.project = MockProject()


def test_ember_pickle_parsing(pkl_parser):
    """Test unpickling and event mapping of mock angr structure"""
    cfg = MockCFG()
    
    # Save the mock object as pickle
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pkl', delete=False) as f:
        pickle.dump(cfg, f)
        temp_path = Path(f.name)
        
    try:
        events = pkl_parser.parse_and_normalize(temp_path, validate=True)
        
        # We expect:
        # 1. Base file drop event
        # 2. Process execution event
        # 3. File event (from CreateFileW/WriteFile)
        # 4. Registry event (from RegSetValueExW)
        # 5. Network event (from InternetConnectW)
        # 6. Process event (from CreateProcessW)
        assert len(events) >= 6
        
        # Verify types
        types = [e.event_type for e in events]
        assert "file" in types
        assert "process" in types
        assert "registry" in types
        assert "network" in types
        
        # Verify timestamp ordering (causality)
        for i in range(len(events) - 1):
            assert events[i].timestamp <= events[i+1].timestamp
            
    finally:
        temp_path.unlink()


def test_real_dataset_pickle_parsing(pkl_parser):
    """Test parser on one of the actual pickle files in the datasets directory"""
    real_pkl_path = Path("e:/BADNA/datasets/0004cec68fdb95507c6161d84e4965db60f997a679ce20786075992f1e5b340c.pkl")
    if real_pkl_path.exists():
        events = pkl_parser.parse_and_normalize(real_pkl_path, validate=True)
        assert len(events) > 0
        print(f"\n[OK] Successfully parsed {len(events)} events from real pickle file")
        types = set(e.event_type for e in events)
        print(f"  Generated event types: {types}")
    else:
        pytest.skip("Real pickle file not found, skipping real-file test")


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
