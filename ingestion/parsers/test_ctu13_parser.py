"""
Integration tests for CTU-13 NetFlow Parser

Tests:
- NetFlow CSV format parsing
- Timestamp conversion (various formats → ISO 8601)
- Network flow field extraction
- Label preservation (botnet/background/normal)
- UnifiedEvent validation
- Streaming mode for large files
- BehaviorCaptureEngine compatibility

Run with: pytest test_ctu13_parser.py -v
"""

import pytest
import tempfile
import csv
from pathlib import Path
from datetime import datetime

from ingestion.parsers.ctu13_parser import CTU13Parser
from ingestion.unified_schema import UnifiedEvent
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create CTU-13 parser for testing"""
    metadata = DatasetMetadata(
        dataset_id="ctu13_test",
        name="CTU-13 Botnet Dataset (Test)",
        dataset_type=DatasetType.NETWORK_TRAFFIC,
        format=DatasetFormat.CSV,
        path=Path("e:/BADNA/datasets/CTU-13-Dataset"),
        parser_class="CTU13Parser",
        description="Test instance of CTU-13 parser",
        source="CTU-13 Dataset",
        record_count=0,
        label_field="Label"
    )
    return CTU13Parser(metadata)


@pytest.fixture
def sample_botnet_flow():
    """Sample CTU-13 botnet flow record"""
    return {
        'StartTime': '2011/08/10 09:46:53.047277',
        'Dur': '0.001',
        'Proto': 'TCP',
        'SrcAddr': '147.32.84.165',
        'Sport': '1038',
        'Dir': '->',
        'DstAddr': '147.32.80.9',
        'Dport': '6667',
        'State': 'CON',
        'sTos': '0',
        'dTos': '0',
        'TotPkts': '10',
        'TotBytes': '1200',
        'SrcBytes': '500',
        'Label': 'botnet'
    }


@pytest.fixture
def sample_background_flow():
    """Sample CTU-13 background traffic flow"""
    return {
        'StartTime': '2011/08/10 09:47:00.123456',
        'Dur': '120.5',
        'Proto': 'UDP',
        'SrcAddr': '192.168.1.100',
        'Sport': '50000',
        'Dir': '<->',
        'DstAddr': '8.8.8.8',
        'Dport': '53',
        'State': 'FIN',
        'sTos': '0',
        'dTos': '0',
        'TotPkts': '2',
        'TotBytes': '150',
        'SrcBytes': '75',
        'Label': 'background'
    }


@pytest.fixture
def sample_normal_flow():
    """Sample CTU-13 normal traffic flow"""
    return {
        'StartTime': '2011/08/10 10:00:00.000000',
        'Dur': '5.25',
        'Proto': 'ICMP',
        'SrcAddr': '10.0.0.1',
        'Sport': '0',
        'Dir': '->',
        'DstAddr': '10.0.0.2',
        'Dport': '0',
        'State': 'INT',
        'sTos': '0',
        'dTos': '0',
        'TotPkts': '4',
        'TotBytes': '200',
        'SrcBytes': '100',
        'Label': 'normal'
    }


class TestNetFlowFieldExtraction:
    """Test extraction of NetFlow fields from CSV"""
    
    def test_basic_fields(self, parser, sample_botnet_flow):
        """Test basic NetFlow field extraction"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        
        assert unified.event_type == "network"
        assert unified.event_data["src_ip"] == "147.32.84.165"
        assert unified.event_data["src_port"] == 1038
        assert unified.event_data["dst_ip"] == "147.32.80.9"
        assert unified.event_data["dst_port"] == 6667
    
    def test_protocol_extraction(self, parser, sample_botnet_flow):
        """Test protocol extraction and normalization"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_data["protocol"] == "TCP"
    
    def test_byte_counts(self, parser, sample_botnet_flow):
        """Test byte count calculations"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        
        assert unified.event_data["bytes_sent"] == 500
        assert unified.event_data["total_bytes"] == 1200
        # bytes_received = total_bytes - src_bytes = 1200 - 500 = 700
        assert unified.event_data["bytes_received"] == 700
    
    def test_packet_count(self, parser, sample_botnet_flow):
        """Test packet count extraction"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_data["total_packets"] == 10
    
    def test_duration(self, parser, sample_background_flow):
        """Test duration extraction"""
        unified = parser.normalize_to_schema(sample_background_flow)
        assert unified.event_data["duration"] == 120.5
    
    def test_flow_state(self, parser, sample_botnet_flow):
        """Test flow state extraction"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_data["flow_state"] == "CON"
    
    def test_flow_direction(self, parser, sample_botnet_flow):
        """Test flow direction extraction"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_data["direction"] == "->"


class TestLabelPreservation:
    """Test preservation of botnet/background/normal labels"""
    
    def test_botnet_label(self, parser, sample_botnet_flow):
        """Test botnet label preservation"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_data["label"] == "botnet"
    
    def test_background_label(self, parser, sample_background_flow):
        """Test background label preservation"""
        unified = parser.normalize_to_schema(sample_background_flow)
        assert unified.event_data["label"] == "background"
    
    def test_normal_label(self, parser, sample_normal_flow):
        """Test normal label preservation"""
        unified = parser.normalize_to_schema(sample_normal_flow)
        assert unified.event_data["label"] == "normal"
    
    def test_missing_label(self, parser):
        """Test handling of missing label"""
        flow = {
            'StartTime': '2011/08/10 09:46:53',
            'Dur': '1.0',
            'Proto': 'TCP',
            'SrcAddr': '1.1.1.1',
            'Sport': '1000',
            'Dir': '->',
            'DstAddr': '2.2.2.2',
            'Dport': '80',
            'State': 'CON',
            'sTos': '0',
            'dTos': '0',
            'TotPkts': '5',
            'TotBytes': '500',
            'SrcBytes': '250',
            # No Label field
        }
        unified = parser.normalize_to_schema(flow)
        assert unified.event_data["label"] == "unknown"


class TestTimestampConversion:
    """Test timestamp parsing and conversion to ISO 8601"""
    
    def test_ctu13_format_with_microseconds(self, parser):
        """Test CTU-13 format: 2011/08/10 09:46:53.047277"""
        timestamp_str = "2011/08/10 09:46:53.047277"
        iso_timestamp = parser._parse_timestamp(timestamp_str)
        
        dt = datetime.fromisoformat(iso_timestamp)
        assert dt.year == 2011
        assert dt.month == 8
        assert dt.day == 10
        assert dt.hour == 9
        assert dt.minute == 46
        assert dt.second == 53
    
    def test_ctu13_format_without_microseconds(self, parser):
        """Test CTU-13 format without microseconds"""
        timestamp_str = "2011/08/10 09:46:53"
        iso_timestamp = parser._parse_timestamp(timestamp_str)
        
        dt = datetime.fromisoformat(iso_timestamp)
        assert dt.year == 2011
        assert dt.month == 8
        assert dt.day == 10
    
    def test_alternative_format(self, parser):
        """Test alternative date format: YYYY-MM-DD HH:MM:SS"""
        timestamp_str = "2011-08-10 09:46:53"
        iso_timestamp = parser._parse_timestamp(timestamp_str)
        
        dt = datetime.fromisoformat(iso_timestamp)
        assert dt.year == 2011
        assert dt.month == 8
    
    def test_unix_timestamp(self, parser):
        """Test Unix timestamp parsing"""
        timestamp_str = "1312970813"  # Unix timestamp
        iso_timestamp = parser._parse_timestamp(timestamp_str)
        
        dt = datetime.fromisoformat(iso_timestamp)
        # Should be around Aug 10, 2011
        assert dt.year == 2011
        assert dt.month == 8
    
    def test_invalid_timestamp(self, parser):
        """Test handling of invalid timestamp"""
        timestamp_str = "invalid_timestamp"
        iso_timestamp = parser._parse_timestamp(timestamp_str)
        # Should return original string with warning
        assert iso_timestamp == timestamp_str


class TestEventIDGeneration:
    """Test unique event ID generation"""
    
    def test_unique_event_ids(self, parser, sample_botnet_flow):
        """Test that event IDs are unique based on flow characteristics"""
        unified1 = parser.normalize_to_schema(sample_botnet_flow)
        
        # Modify timestamp slightly
        flow2 = sample_botnet_flow.copy()
        flow2['StartTime'] = '2011/08/10 09:46:54.047277'
        unified2 = parser.normalize_to_schema(flow2)
        
        # Should have different IDs due to different timestamps
        assert unified1.event_id != unified2.event_id
    
    def test_event_id_contains_flow_info(self, parser, sample_botnet_flow):
        """Test that event ID contains flow 5-tuple info"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        event_id = unified.event_id
        
        # Event ID should start with ctu13_flow_ prefix
        assert event_id.startswith("ctu13_flow_")


class TestCSVFileParsing:
    """Test parsing of actual CSV files"""
    
    def test_parse_csv_file(self, parser):
        """Test parsing complete CSV file"""
        # Create temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
                'TotBytes', 'SrcBytes', 'Label'
            ])
            writer.writeheader()
            writer.writerow({
                'StartTime': '2011/08/10 09:46:53',
                'Dur': '0.5',
                'Proto': 'TCP',
                'SrcAddr': '1.1.1.1',
                'Sport': '1000',
                'Dir': '->',
                'DstAddr': '2.2.2.2',
                'Dport': '80',
                'State': 'CON',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '10',
                'TotBytes': '1000',
                'SrcBytes': '500',
                'Label': 'botnet'
            })
            writer.writerow({
                'StartTime': '2011/08/10 09:47:00',
                'Dur': '1.0',
                'Proto': 'UDP',
                'SrcAddr': '3.3.3.3',
                'Sport': '2000',
                'Dir': '<->',
                'DstAddr': '4.4.4.4',
                'Dport': '53',
                'State': 'FIN',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '2',
                'TotBytes': '200',
                'SrcBytes': '100',
                'Label': 'background'
            })
            temp_path = Path(f.name)
        
        try:
            raw_records = parser.parse_file(temp_path)
            assert len(raw_records) == 2
            assert raw_records[0]['Proto'] == 'TCP'
            assert raw_records[1]['Proto'] == 'UDP'
        finally:
            temp_path.unlink()
    
    def test_missing_columns_handling(self, parser):
        """Test handling of CSV with missing columns"""
        # Create CSV with fewer columns
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'SrcAddr', 'DstAddr', 'Proto'
            ])
            writer.writeheader()
            writer.writerow({
                'StartTime': '2011/08/10 09:46:53',
                'SrcAddr': '1.1.1.1',
                'DstAddr': '2.2.2.2',
                'Proto': 'TCP'
            })
            temp_path = Path(f.name)
        
        try:
            # Should parse but log warning about missing columns
            raw_records = parser.parse_file(temp_path)
            assert len(raw_records) == 1
        finally:
            temp_path.unlink()
    
    def test_empty_csv_file(self, parser):
        """Test handling of empty CSV file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['StartTime', 'SrcAddr'])
            writer.writeheader()
            temp_path = Path(f.name)
        
        try:
            raw_records = parser.parse_file(temp_path)
            assert len(raw_records) == 0
        finally:
            temp_path.unlink()


class TestUnifiedEventValidation:
    """Test UnifiedEvent validation for CTU-13 events"""
    
    def test_valid_network_event(self, parser, sample_botnet_flow):
        """Test valid network event passes validation"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        # Should not raise
        unified.validate_required_fields()
    
    def test_event_type_is_network(self, parser, sample_botnet_flow):
        """Test that all CTU-13 events have event_type='network'"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.event_type == "network"
    
    def test_action_field_present(self, parser, sample_botnet_flow):
        """Test that action field is present in event_data"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert "action" in unified.event_data
        assert unified.event_data["action"] == "flow"


class TestBehaviorCaptureCompatibility:
    """Test compatibility with BehaviorCaptureEngine input format"""
    
    def test_to_dict_conversion(self, parser, sample_botnet_flow):
        """Test conversion to dict for BehaviorCaptureEngine"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        event_dict = unified.to_dict()
        
        # Check required keys for BehaviorCaptureEngine
        assert "event_id" in event_dict
        assert "event_type" in event_dict
        assert "timestamp" in event_dict
        assert "source_system" in event_dict
        assert "event_data" in event_dict
    
    def test_source_system(self, parser, sample_botnet_flow):
        """Test source_system is set correctly"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        assert unified.source_system == "ctu13_test"
    
    def test_event_data_structure(self, parser, sample_botnet_flow):
        """Test event_data contains network-specific fields"""
        unified = parser.normalize_to_schema(sample_botnet_flow)
        event_data = unified.event_data
        
        # Required network event fields
        assert "action" in event_data
        assert "src_ip" in event_data
        assert "dst_ip" in event_data
        assert "protocol" in event_data


class TestStreamingMode:
    """Test streaming mode for large files"""
    
    def test_streaming_batch_generation(self, parser):
        """Test that streaming mode yields batches"""
        # Create temporary CSV with multiple records
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
                'TotBytes', 'SrcBytes', 'Label'
            ])
            writer.writeheader()
            
            # Write 150 records (should create 2 batches of 100 + 1 batch of 50)
            for i in range(150):
                writer.writerow({
                    'StartTime': '2011/08/10 09:46:53',
                    'Dur': '0.5',
                    'Proto': 'TCP',
                    'SrcAddr': f'1.1.1.{i % 256}',
                    'Sport': str(1000 + i),
                    'Dir': '->',
                    'DstAddr': '2.2.2.2',
                    'Dport': '80',
                    'State': 'CON',
                    'sTos': '0',
                    'dTos': '0',
                    'TotPkts': '10',
                    'TotBytes': '1000',
                    'SrcBytes': '500',
                    'Label': 'botnet'
                })
            temp_path = Path(f.name)
        
        try:
            batches = list(parser.parse_and_normalize_streaming(
                temp_path, 
                validate=True, 
                batch_size=100
            ))
            
            # Should have at least 2 batches
            assert len(batches) >= 2
            # First batch should have 100 events
            assert len(batches[0]) == 100
            # Total events should be 150
            total_events = sum(len(batch) for batch in batches)
            assert total_events == 150
        finally:
            temp_path.unlink()
    
    def test_streaming_memory_efficiency(self, parser):
        """Test that streaming doesn't load entire file into memory"""
        # This test verifies that streaming processes incrementally
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
                'TotBytes', 'SrcBytes', 'Label'
            ])
            writer.writeheader()
            
            for i in range(50):
                writer.writerow({
                    'StartTime': '2011/08/10 09:46:53',
                    'Dur': '0.5',
                    'Proto': 'TCP',
                    'SrcAddr': '1.1.1.1',
                    'Sport': '1000',
                    'Dir': '->',
                    'DstAddr': '2.2.2.2',
                    'Dport': '80',
                    'State': 'CON',
                    'sTos': '0',
                    'dTos': '0',
                    'TotPkts': '10',
                    'TotBytes': '1000',
                    'SrcBytes': '500',
                    'Label': 'botnet'
                })
            temp_path = Path(f.name)
        
        try:
            # Process with small batch size
            batch_count = 0
            event_count = 0
            
            for batch in parser.parse_and_normalize_streaming(temp_path, batch_size=10):
                batch_count += 1
                event_count += len(batch)
                # Each batch should have at most 10 events
                assert len(batch) <= 10
            
            assert event_count == 50
            assert batch_count == 5  # 50 events / 10 per batch
        finally:
            temp_path.unlink()


class TestEndToEndIntegration:
    """Test complete end-to-end parsing and validation"""
    
    def test_complete_workflow(self, parser):
        """Test complete parse → normalize → validate workflow"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
                'TotBytes', 'SrcBytes', 'Label'
            ])
            writer.writeheader()
            writer.writerow({
                'StartTime': '2011/08/10 09:46:53',
                'Dur': '0.5',
                'Proto': 'TCP',
                'SrcAddr': '147.32.84.165',
                'Sport': '1038',
                'Dir': '->',
                'DstAddr': '147.32.80.9',
                'Dport': '6667',
                'State': 'CON',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '10',
                'TotBytes': '1200',
                'SrcBytes': '500',
                'Label': 'botnet'
            })
            temp_path = Path(f.name)
        
        try:
            # Complete workflow with validation
            unified_events = parser.parse_and_normalize(temp_path, validate=True)
            
            assert len(unified_events) == 1
            event = unified_events[0]
            
            # Verify event type
            assert event.event_type == "network"
            
            # Verify flow characteristics
            assert event.event_data["src_ip"] == "147.32.84.165"
            assert event.event_data["dst_port"] == 6667
            assert event.event_data["label"] == "botnet"
            
            # Verify statistics
            stats = parser.get_statistics()
            assert stats['total_records'] == 1
            assert stats['valid_records'] == 1
            assert stats['invalid_records'] == 0
            assert stats['success_rate'] == 1.0
        finally:
            temp_path.unlink()
    
    def test_mixed_label_parsing(self, parser):
        """Test parsing file with mixed labels (botnet, background, normal)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
                'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
                'TotBytes', 'SrcBytes', 'Label'
            ])
            writer.writeheader()
            
            # Botnet flow
            writer.writerow({
                'StartTime': '2011/08/10 09:46:53',
                'Dur': '0.5',
                'Proto': 'TCP',
                'SrcAddr': '1.1.1.1',
                'Sport': '1000',
                'Dir': '->',
                'DstAddr': '2.2.2.2',
                'Dport': '6667',
                'State': 'CON',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '10',
                'TotBytes': '1000',
                'SrcBytes': '500',
                'Label': 'botnet'
            })
            
            # Background flow
            writer.writerow({
                'StartTime': '2011/08/10 09:47:00',
                'Dur': '1.0',
                'Proto': 'UDP',
                'SrcAddr': '3.3.3.3',
                'Sport': '2000',
                'Dir': '<->',
                'DstAddr': '8.8.8.8',
                'Dport': '53',
                'State': 'FIN',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '2',
                'TotBytes': '200',
                'SrcBytes': '100',
                'Label': 'background'
            })
            
            # Normal flow
            writer.writerow({
                'StartTime': '2011/08/10 09:48:00',
                'Dur': '2.0',
                'Proto': 'TCP',
                'SrcAddr': '5.5.5.5',
                'Sport': '3000',
                'Dir': '->',
                'DstAddr': '6.6.6.6',
                'Dport': '443',
                'State': 'CON',
                'sTos': '0',
                'dTos': '0',
                'TotPkts': '20',
                'TotBytes': '5000',
                'SrcBytes': '2500',
                'Label': 'normal'
            })
            
            temp_path = Path(f.name)
        
        try:
            unified_events = parser.parse_and_normalize(temp_path, validate=True)
            
            assert len(unified_events) == 3
            
            # Verify labels are preserved
            labels = [event.event_data["label"] for event in unified_events]
            assert "botnet" in labels
            assert "background" in labels
            assert "normal" in labels
            
            # Verify all are network events
            assert all(event.event_type == "network" for event in unified_events)
        finally:
            temp_path.unlink()


class TestErrorHandling:
    """Test parser error handling"""
    
    def test_missing_required_fields(self, parser):
        """Test handling of records with missing required fields"""
        flow = {
            'StartTime': '2011/08/10 09:46:53',
            # Missing SrcAddr
            'DstAddr': '2.2.2.2',
            'Proto': 'TCP'
        }
        
        with pytest.raises(Exception):  # Should raise ValidationError
            parser.normalize_to_schema(flow)
    
    def test_invalid_numeric_fields(self, parser):
        """Test handling of invalid numeric values"""
        flow = {
            'StartTime': '2011/08/10 09:46:53',
            'Dur': 'invalid',
            'Proto': 'TCP',
            'SrcAddr': '1.1.1.1',
            'Sport': 'not_a_number',
            'Dir': '->',
            'DstAddr': '2.2.2.2',
            'Dport': '80',
            'State': 'CON',
            'sTos': '0',
            'dTos': '0',
            'TotPkts': 'bad',
            'TotBytes': '1000',
            'SrcBytes': '500',
            'Label': 'botnet'
        }
        
        # Should not crash, but use default values
        unified = parser.normalize_to_schema(flow)
        assert unified.event_data["src_port"] == 0  # default value
        assert unified.event_data["duration"] == 0.0  # default value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
