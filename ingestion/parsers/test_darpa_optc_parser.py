"""
Unit tests for DARPA OpTC Parser

Tests:
- Event type mapping (PROCESS → process, FILE → file, FLOW → network)
- Timestamp conversion (milliseconds epoch → ISO 8601)
- Field extraction for different event types
- Error handling for malformed data
- UnifiedEvent validation
- BehaviorCaptureEngine compatibility

Run with: pytest test_darpa_optc_parser.py
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime

from darpa_optc_parser import DARPAOpTCParser, create_darpa_optc_parser
from ingestion.unified_schema import UnifiedEvent
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create DARPA OpTC parser for testing"""
    dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
    return create_darpa_optc_parser(dataset_path)


@pytest.fixture
def sample_process_event():
    """Sample eCAR process creation event"""
    return {
        "timestamp": 1539120748904,
        "id": "proc-001",
        "hostname": "TEST-HOST",
        "objectID": "proc-obj-001",
        "object": "PROCESS",
        "action": "CREATE",
        "actorID": "actor-001",
        "pid": 1234,
        "ppid": 500,
        "tid": 1,
        "principal": "TEST\\admin",
        "properties": {
            "image_path": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c dir",
            "user": "TEST\\admin"
        }
    }


@pytest.fixture
def sample_file_event():
    """Sample eCAR file write event"""
    return {
        "timestamp": 1539120749000,
        "id": "file-001",
        "hostname": "TEST-HOST",
        "objectID": "file-obj-001",
        "object": "FILE",
        "action": "WRITE",
        "actorID": "actor-002",
        "pid": 1235,
        "ppid": 1234,
        "tid": 1,
        "principal": "TEST\\admin",
        "properties": {
            "file_path": "C:\\temp\\output.txt",
            "file_name": "output.txt",
            "size": 1024
        }
    }


@pytest.fixture
def sample_network_event():
    """Sample eCAR network flow event"""
    return {
        "timestamp": 1539120750000,
        "id": "net-001",
        "hostname": "TEST-HOST",
        "objectID": "net-obj-001",
        "object": "FLOW",
        "action": "START",
        "actorID": "actor-003",
        "pid": 1236,
        "ppid": 1234,
        "tid": 1,
        "principal": "TEST\\admin",
        "properties": {
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.50",
            "src_port": 50000,
            "dest_port": 443,
            "protocol": "TCP",
            "domain": "example.com"
        }
    }


class TestEventTypeMapping:
    """Test eCAR object type to UnifiedEvent event_type mapping"""
    
    def test_process_mapping(self, parser, sample_process_event):
        """Test PROCESS → process mapping"""
        unified = parser.normalize_to_schema(sample_process_event)
        assert unified.event_type == "process"
    
    def test_file_mapping(self, parser, sample_file_event):
        """Test FILE → file mapping"""
        unified = parser.normalize_to_schema(sample_file_event)
        assert unified.event_type == "file"
    
    def test_network_mapping(self, parser, sample_network_event):
        """Test FLOW → network mapping"""
        unified = parser.normalize_to_schema(sample_network_event)
        assert unified.event_type == "network"
    
    def test_flow_start_mapping(self, parser):
        """Test FLOW-START → network mapping"""
        event = {
            "timestamp": 1539120750000,
            "id": "net-002",
            "hostname": "TEST",
            "object": "FLOW-START",
            "action": "START",
            "objectID": "obj",
            "actorID": "actor",
            "pid": 1000,
            "properties": {}
        }
        unified = parser.normalize_to_schema(event)
        assert unified.event_type == "network"


class TestActionMapping:
    """Test eCAR action to UnifiedEvent action mapping"""
    
    def test_create_action(self, parser):
        """Test CREATE → create mapping"""
        event = {
            "timestamp": 1539120748904,
            "id": "test",
            "hostname": "TEST",
            "object": "PROCESS",
            "action": "CREATE",
            "objectID": "obj",
            "actorID": "actor",
            "pid": 1000,
            "properties": {}
        }
        unified = parser.normalize_to_schema(event)
        assert unified.event_data["action"] == "create"
    
    def test_write_action(self, parser):
        """Test WRITE → write mapping"""
        event = {
            "timestamp": 1539120748904,
            "id": "test",
            "hostname": "TEST",
            "object": "FILE",
            "action": "WRITE",
            "objectID": "obj",
            "actorID": "actor",
            "pid": 1000,
            "properties": {"file_path": "/test"}
        }
        unified = parser.normalize_to_schema(event)
        assert unified.event_data["action"] == "write"
    
    def test_connect_action(self, parser):
        """Test CONNECT → connect mapping"""
        event = {
            "timestamp": 1539120748904,
            "id": "test",
            "hostname": "TEST",
            "object": "FLOW",
            "action": "CONNECT",
            "objectID": "obj",
            "actorID": "actor",
            "pid": 1000,
            "properties": {}
        }
        unified = parser.normalize_to_schema(event)
        assert unified.event_data["action"] == "connect"


class TestTimestampConversion:
    """Test timestamp conversion from milliseconds epoch to ISO 8601"""
    
    def test_valid_timestamp(self, parser):
        """Test valid timestamp conversion"""
        # Oct 10, 2018 03:02:28.904
        timestamp_ms = 1539120748904
        iso_timestamp = parser._parse_timestamp(timestamp_ms)
        
        # Parse back to verify
        dt = datetime.fromisoformat(iso_timestamp)
        assert dt.year == 2018
        assert dt.month == 10
        assert dt.day == 10
    
    def test_none_timestamp(self, parser):
        """Test handling of None timestamp"""
        iso_timestamp = parser._parse_timestamp(None)
        assert iso_timestamp is not None
        # Should be current time
        dt = datetime.fromisoformat(iso_timestamp)
        assert dt.year == datetime.now().year
    
    def test_invalid_timestamp(self, parser):
        """Test handling of invalid timestamp"""
        iso_timestamp = parser._parse_timestamp("invalid")
        assert iso_timestamp is not None
        # Should fallback to current time


class TestProcessEventParsing:
    """Test process event field extraction"""
    
    def test_basic_fields(self, parser, sample_process_event):
        """Test basic process event fields"""
        unified = parser.normalize_to_schema(sample_process_event)
        
        assert unified.event_id == "proc-001"
        assert unified.event_type == "process"
        assert unified.event_data["pid"] == 1234
        assert unified.event_data["parent_pid"] == 500
        assert unified.event_data["hostname"] == "TEST-HOST"
    
    def test_process_name_extraction(self, parser, sample_process_event):
        """Test process name extraction from image_path"""
        unified = parser.normalize_to_schema(sample_process_event)
        assert unified.event_data["name"] == "cmd.exe"
    
    def test_command_line(self, parser, sample_process_event):
        """Test command line extraction"""
        unified = parser.normalize_to_schema(sample_process_event)
        assert "cmd.exe /c dir" in unified.event_data["command_line"]
    
    def test_parent_child_relationship(self, parser, sample_process_event):
        """Test parent-child process relationship preservation"""
        unified = parser.normalize_to_schema(sample_process_event)
        assert unified.event_data["pid"] == 1234
        assert unified.event_data["parent_pid"] == 500
        # Provenance should be preserved
        assert "provenance" in unified.event_data


class TestFileEventParsing:
    """Test file event field extraction"""
    
    def test_file_path(self, parser, sample_file_event):
        """Test file path extraction"""
        unified = parser.normalize_to_schema(sample_file_event)
        assert unified.event_data["path"] == "C:\\temp\\output.txt"
    
    def test_file_action(self, parser, sample_file_event):
        """Test file action mapping"""
        unified = parser.normalize_to_schema(sample_file_event)
        assert unified.event_data["action"] == "write"
    
    def test_file_size(self, parser, sample_file_event):
        """Test file size extraction"""
        unified = parser.normalize_to_schema(sample_file_event)
        assert unified.event_data["file_size"] == 1024


class TestNetworkEventParsing:
    """Test network event field extraction"""
    
    def test_network_addresses(self, parser, sample_network_event):
        """Test IP address extraction"""
        unified = parser.normalize_to_schema(sample_network_event)
        assert unified.event_data["source_ip"] == "192.168.1.100"
        assert unified.event_data["dest_ip"] == "10.0.0.50"
    
    def test_network_ports(self, parser, sample_network_event):
        """Test port extraction"""
        unified = parser.normalize_to_schema(sample_network_event)
        assert unified.event_data["source_port"] == 50000
        assert unified.event_data["dest_port"] == 443
    
    def test_network_protocol(self, parser, sample_network_event):
        """Test protocol extraction"""
        unified = parser.normalize_to_schema(sample_network_event)
        assert unified.event_data["protocol"] == "TCP"
    
    def test_domain_extraction(self, parser, sample_network_event):
        """Test domain name extraction"""
        unified = parser.normalize_to_schema(sample_network_event)
        assert unified.event_data["domain"] == "example.com"


class TestProvenanceMetadata:
    """Test provenance metadata preservation for graph construction"""
    
    def test_provenance_preservation(self, parser, sample_process_event):
        """Test that provenance metadata is preserved"""
        unified = parser.normalize_to_schema(sample_process_event)
        
        assert "provenance" in unified.event_data
        prov = unified.event_data["provenance"]
        assert prov["object_id"] == "proc-obj-001"
        assert prov["actor_id"] == "actor-001"
        assert prov["ecar_object"] == "PROCESS"
        assert prov["ecar_action"] == "CREATE"


class TestFileFormatParsing:
    """Test parsing different file formats"""
    
    def test_json_array_parsing(self, parser):
        """Test parsing JSON array format"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            events = [
                {"timestamp": 1539120748904, "id": "e1", "hostname": "H1", 
                 "object": "PROCESS", "action": "CREATE", "objectID": "o1",
                 "actorID": "a1", "pid": 100, "properties": {}},
                {"timestamp": 1539120749000, "id": "e2", "hostname": "H1",
                 "object": "FILE", "action": "WRITE", "objectID": "o2",
                 "actorID": "a2", "pid": 101, "properties": {"file_path": "/test"}}
            ]
            json.dump(events, f)
            temp_path = Path(f.name)
        
        try:
            raw_events = parser.parse_file(temp_path)
            assert len(raw_events) == 2
        finally:
            temp_path.unlink()
    
    def test_jsonl_parsing(self, parser):
        """Test parsing JSONL format (one JSON per line)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            f.write(json.dumps({"timestamp": 1539120748904, "id": "e1", "hostname": "H1",
                                "object": "PROCESS", "action": "CREATE", "objectID": "o1",
                                "actorID": "a1", "pid": 100, "properties": {}}) + '\n')
            f.write(json.dumps({"timestamp": 1539120749000, "id": "e2", "hostname": "H1",
                                "object": "FILE", "action": "WRITE", "objectID": "o2",
                                "actorID": "a2", "pid": 101, "properties": {"file_path": "/test"}}) + '\n')
            temp_path = Path(f.name)
        
        try:
            raw_events = parser.parse_file(temp_path)
            assert len(raw_events) == 2
        finally:
            temp_path.unlink()


class TestUnifiedEventValidation:
    """Test UnifiedEvent validation"""
    
    def test_valid_process_event(self, parser, sample_process_event):
        """Test valid process event passes validation"""
        unified = parser.normalize_to_schema(sample_process_event)
        # Should not raise
        unified.validate_required_fields()
    
    def test_valid_file_event(self, parser, sample_file_event):
        """Test valid file event passes validation"""
        unified = parser.normalize_to_schema(sample_file_event)
        # Should not raise
        unified.validate_required_fields()
    
    def test_valid_network_event(self, parser, sample_network_event):
        """Test valid network event passes validation"""
        unified = parser.normalize_to_schema(sample_network_event)
        # Should not raise
        unified.validate_required_fields()


class TestBehaviorCaptureCompatibility:
    """Test compatibility with BehaviorCaptureEngine input format"""
    
    def test_to_dict_conversion(self, parser, sample_process_event):
        """Test conversion to dict for BehaviorCaptureEngine"""
        unified = parser.normalize_to_schema(sample_process_event)
        event_dict = unified.to_dict()
        
        # Check required keys
        assert "event_id" in event_dict
        assert "event_type" in event_dict
        assert "timestamp" in event_dict
        assert "source_system" in event_dict
        assert "event_data" in event_dict
    
    def test_source_system(self, parser, sample_process_event):
        """Test source_system is set correctly"""
        unified = parser.normalize_to_schema(sample_process_event)
        assert unified.source_system == "darpa_optc"


class TestErrorHandling:
    """Test parser error handling"""
    
    def test_empty_file(self, parser):
        """Test handling of empty file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            raw_events = parser.parse_file(temp_path)
            assert len(raw_events) == 0
        finally:
            temp_path.unlink()
    
    def test_malformed_json(self, parser):
        """Test handling of malformed JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid json")
            temp_path = Path(f.name)
        
        try:
            # JSONL fallback should also fail, return empty list
            raw_events = parser.parse_file(temp_path)
            # Parser logs warning but doesn't crash
            assert isinstance(raw_events, list)
        finally:
            temp_path.unlink()


class TestEndToEndParsing:
    """Test complete end-to-end parsing workflow"""
    
    def test_parse_and_normalize_workflow(self, parser):
        """Test complete parse and normalize workflow"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            events = [
                {
                    "timestamp": 1539120748904,
                    "id": "proc-001",
                    "hostname": "TEST-HOST",
                    "objectID": "obj-001",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "actorID": "actor-001",
                    "pid": 1234,
                    "ppid": 500,
                    "tid": 1,
                    "principal": "TEST\\admin",
                    "properties": {
                        "image_path": "C:\\test.exe",
                        "command_line": "test.exe"
                    }
                }
            ]
            json.dump(events, f)
            temp_path = Path(f.name)
        
        try:
            # Complete workflow
            unified_events = parser.parse_and_normalize(temp_path, validate=True)
            
            assert len(unified_events) == 1
            assert unified_events[0].event_type == "process"
            assert unified_events[0].event_id == "proc-001"
            
            # Check statistics
            stats = parser.get_statistics()
            assert stats['total_records'] == 1
            assert stats['valid_records'] == 1
            assert stats['invalid_records'] == 0
            assert stats['success_rate'] == 1.0
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
