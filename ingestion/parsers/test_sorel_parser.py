"""
Unit tests for SOREL-20M Parser
"""

import pytest
import tempfile
import json
from pathlib import Path

from sorel_parser import SORELParser, create_sorel_parser
from ingestion.unified_schema import UnifiedEvent
from ingestion.base_parser import ValidationError


@pytest.fixture
def parser():
    """Create SORELParser instance"""
    dataset_path = Path("e:/BADNA/datasets/SOREL-20M-master")
    return create_sorel_parser(dataset_path)


@pytest.fixture
def sample_sorel_record():
    """Sample raw SOREL-20M JSON record format"""
    return {
        "0": {
            "DOS_HEADER": {
                "e_magic": {"Value": 23117}
            },
            "FILE_HEADER": {
                "NumberOfSections": {"Value": 1}
            },
            "OPTIONAL_HEADER": {
                "SizeOfImage": {"Value": 4096}
            },
            "PE Sections": [
                {
                    "Name": {"Value": ".text\\x00\\x00\\x00"},
                    "Flags": ["IMAGE_SCN_MEM_EXECUTE"]
                }
            ],
            "Imported symbols": [
                [
                    {"DLL": "kernel32.dll"},
                    {"Name": "CreateFileW"},
                    {"Name": "WriteFile"}
                ],
                [
                    {"DLL": "advapi32.dll"},
                    {"Name": "RegSetValueExW"}
                ]
            ]
        }
    }


def test_basic_normalization(parser, sample_sorel_record):
    """Test standard PE properties extraction and event translation"""
    record = sample_sorel_record.copy()
    record['__filepath__'] = "e:/BADNA/datasets/SOREL-20M-master/SOREL-20M-master/pe_full_metadata_example/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.json"
    
    events = parser.normalize_to_events(record)
    
    # Expected:
    # 1. Base file drop event
    # 2. Process execution event
    # 3. Section execution mapping event (.text)
    # 4. File event (from CreateFileW/WriteFile)
    # 5. Registry event (from RegSetValueExW)
    assert len(events) >= 5
    
    # Check types
    types = [e.event_type for e in events]
    assert "file" in types
    assert "process" in types
    assert "registry" in types
    
    # Check hashes and pids
    assert events[0].event_data["hash"] == "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    assert events[1].event_data["pid"] == 8500


def test_real_sorel_file_parsing(parser):
    """Test parsing the real SOREL-20M example JSON file"""
    real_json_path = Path("e:/BADNA/datasets/SOREL-20M-master/SOREL-20M-master/pe_full_metadata_example/32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74.json")
    if real_json_path.exists():
        events = parser.parse_and_normalize(real_json_path, validate=True)
        assert len(events) > 0
        print(f"\n[OK] Successfully parsed {len(events)} events from real SOREL JSON file")
        types = set(e.event_type for e in events)
        print(f"  Generated event types: {types}")
    else:
        pytest.skip("Real SOREL JSON file not found, skipping real-file test")


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
