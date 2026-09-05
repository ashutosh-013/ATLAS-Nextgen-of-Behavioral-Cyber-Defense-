"""
Unit tests for CISA KEV Parser
"""

import pytest
import tempfile
import csv
from pathlib import Path

from cisa_kev_parser import CISAKEVParser, create_cisa_kev_parser
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create CISAKEVParser instance"""
    dataset_path = Path("e:/BADNA/datasets")
    return create_cisa_kev_parser(dataset_path)


@pytest.fixture
def sample_kev_record():
    """Sample valid KEV CSV row"""
    return {
        'cveID': 'CVE-2026-12345',
        'vendorProject': 'Microsoft',
        'product': 'Windows',
        'vulnerabilityName': 'Windows Privilege Escalation',
        'dateAdded': '2026-07-07',
        'shortDescription': 'Some Windows vulnerability',
        'requiredAction': 'Apply updates',
        'dueDate': '2026-07-10',
        'knownRansomwareCampaignUse': 'Yes',
        'notes': 'Some notes',
        'cwes': 'CWE-269,CWE-20'
    }


def test_basic_normalization(parser, sample_kev_record):
    """Test standard KEV fields are extracted correctly"""
    threat_intel = parser.normalize_to_schema(sample_kev_record)
    
    assert threat_intel["cve_id"] == "CVE-2026-12345"
    assert threat_intel["vendor"] == "Microsoft"
    assert threat_intel["product"] == "Windows"
    assert threat_intel["vulnerability_name"] == "Windows Privilege Escalation"
    assert threat_intel["date_added"] == "2026-07-07"
    assert threat_intel["description"] == "Some Windows vulnerability"
    assert threat_intel["ransomware_usage"] is True
    assert threat_intel["cwes"] == ["CWE-269", "CWE-20"]
    assert threat_intel["source"] == "CISA KEV"


def test_ransomware_use_handling(parser, sample_kev_record):
    """Test mapping of different ransomware campaign use values"""
    record = sample_kev_record.copy()
    
    # Test Unknown
    record['knownRansomwareCampaignUse'] = 'Unknown'
    threat_intel = parser.normalize_to_schema(record)
    assert threat_intel["ransomware_usage"] is False
    
    # Test No
    record['knownRansomwareCampaignUse'] = 'No'
    threat_intel = parser.normalize_to_schema(record)
    assert threat_intel["ransomware_usage"] is False


def test_csv_file_parsing(parser, sample_kev_record):
    """Test parsing complete KEV CSV file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
            'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse',
            'notes', 'cwes'
        ])
        writer.writeheader()
        writer.writerow(sample_kev_record)
        temp_path = Path(f.name)
        
    try:
        kev_dict = parser.parse_and_normalize_to_dict(temp_path)
        assert "CVE-2026-12345" in kev_dict
        v = kev_dict["CVE-2026-12345"]
        assert v["vendor"] == "Microsoft"
        assert v["product"] == "Windows"
    finally:
        temp_path.unlink()


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
