"""
Unit tests for T-Pot Honeypot Parser
"""

import pytest
import tempfile
import json
from pathlib import Path

from ingestion.parsers.tpot_parser import TPotParser, create_tpot_parser
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create TPotParser instance"""
    dataset_path = Path("e:/BADNA/datasets/tpotce-master")
    return create_tpot_parser(dataset_path)


@pytest.fixture
def sample_tpot_events():
    """Sample T-Pot JSON events for testing"""
    return [
        # SSH Cowrie brute force
        {
            "timestamp": "2026-07-13T22:50:00Z",
            "type": "cowrie",
            "src_ip": "185.220.101.4",
            "src_port": 49152,
            "dest_ip": "192.168.1.10",
            "dest_port": 22,
            "username": "root",
            "password": "password123",
            "session": "session_ssh_123"
        },
        # SSH Cowrie command
        {
            "timestamp": "2026-07-13T22:51:00Z",
            "type": "cowrie",
            "src_ip": "185.220.101.4",
            "src_port": 49152,
            "dest_ip": "192.168.1.10",
            "dest_port": 22,
            "input": "whoami",
            "session": "session_ssh_123"
        },
        # Dionaea SMB exploit
        {
            "timestamp": "2026-07-13T22:52:00Z",
            "type": "dionaea",
            "src_ip": "45.120.21.32",
            "src_port": 53214,
            "dest_ip": "192.168.1.10",
            "dest_port": 445,
            "protocol": "tcp"
        }
    ]


def test_tpot_parsing_and_normalization(parser, sample_tpot_events):
    """Test parsing and normalizing T-Pot logs"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_tpot_events, f)
        temp_path = Path(f.name)
        
    try:
        raw_events = parser.parse_file(temp_path)
        assert len(raw_events) == 3
        
        # Normalize ssh brute force (should be auth type)
        ev1 = parser.normalize_to_schema(raw_events[0])
        assert ev1.event_type == 'auth'
        assert ev1.event_data['user'] == 'root'
        assert ev1.event_data['action'] == 'login'
        assert ev1.event_data['success'] is False

        # Normalize ssh command (should be process type)
        ev2 = parser.normalize_to_schema(raw_events[1])
        assert ev2.event_type == 'process'
        assert ev2.event_data['command_line'] == 'whoami'
        assert ev2.event_data['action'] == 'create'

        # Normalize Dionaea smb connection (should be network type)
        ev3 = parser.normalize_to_schema(raw_events[2])
        assert ev3.event_type == 'network'
        assert ev3.event_data['action'] == 'smb'
        assert ev3.event_data['dest_port'] == 445
    finally:
        temp_path.unlink()
