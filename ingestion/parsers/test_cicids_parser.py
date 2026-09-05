"""
Unit tests for CICIDS Parser
"""

import pytest
import tempfile
import csv
from pathlib import Path
from datetime import datetime

from cicids_parser import CICIDSParser, create_cicids_parser
from ingestion.unified_schema import UnifiedEvent
from ingestion.base_parser import ValidationError
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create a CICIDSParser instance for testing"""
    dataset_path = Path("e:/BADNA/datasets/1000.csv")
    return create_cicids_parser(dataset_path)


@pytest.fixture
def sample_cicids_record():
    """Sample valid CICIDS 2017 record with spaces in keys"""
    return {
        'Timestamp': '14/07/2017 03:00:00',
        ' Source IP': '192.168.10.3',
        ' Source Port': '80',
        ' Destination IP': '192.168.10.50',
        ' Destination Port': '54321',
        ' Protocol': '6',
        ' Flow Duration': '1000000',  # 1s in us
        ' Total Fwd Packets': '5',
        ' Total Backward Packets': '4',
        ' Total Length of Fwd Packets': '1000',
        ' Total Length of Bwd Packets': '800',
        ' FIN Flag Count': '0',
        ' SYN Flag Count': '1',
        ' RST Flag Count': '0',
        ' PSH Flag Count': '1',
        ' ACK Flag Count': '1',
        ' URG Flag Count': '0',
        ' Label': 'DDoS'
    }


def test_basic_normalization(parser, sample_cicids_record):
    """Test standard flow fields are extracted correctly"""
    event = parser.normalize_to_schema(sample_cicids_record)
    
    assert event.event_type == "network"
    assert event.source_system == "cicids_1000"
    
    data = event.event_data
    assert data["action"] == "flow"
    assert data["src_ip"] == "192.168.10.3"
    assert data["src_port"] == 80
    assert data["dst_ip"] == "192.168.10.50"
    assert data["dst_port"] == 54321
    assert data["protocol"] == "TCP"
    assert data["duration"] == 1.0  # converted from 1,000,000 us
    assert data["total_packets"] == 9
    assert data["total_bytes"] == 1800
    assert data["bytes_sent"] == 1000
    assert data["bytes_received"] == 800
    assert data["label"] == "DDoS"
    assert data["is_malicious"] is True


def test_benign_label(parser, sample_cicids_record):
    """Test that benign label is marked as not malicious"""
    record = sample_cicids_record.copy()
    record[' Label'] = 'BENIGN'
    
    event = parser.normalize_to_schema(record)
    assert event.event_data["is_malicious"] is False
    assert event.event_data["label"] == "BENIGN"


def test_capec_detection(parser):
    """Test that trying to parse CAPEC data fails with ValidationError"""
    capec_record = {
        'ID': '1',
        'Name': 'Accessing Functionality Not Properly Constrained by ACLs',
        'Abstraction': 'Standard',
        'Likelihood Of Attack': 'High',
        'Typical Severity': 'High',
        'Description': 'Some capec description'
    }
    
    with pytest.raises(ValidationError) as excinfo:
        parser.normalize_to_schema(capec_record)
    assert "capec attack pattern" in str(excinfo.value).lower()


def test_invalid_record(parser):
    """Test validation errors for missing critical fields"""
    invalid_record = {
        'Timestamp': '14/07/2017 03:00:00',
        ' Protocol': '6'
    }
    
    with pytest.raises(ValidationError):
        parser.normalize_to_schema(invalid_record)


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
