"""
Unit tests for MITRE ATT&CK Parser
"""

import pytest
import tempfile
import json
from pathlib import Path

from mitre_attack_parser import MITREAttackParser, create_mitre_attack_parser
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat


@pytest.fixture
def parser():
    """Create MITREAttackParser instance"""
    dataset_path = Path("e:/BADNA/datasets/cti-master")
    return create_mitre_attack_parser(dataset_path)


@pytest.fixture
def sample_stix_bundle():
    """Sample STIX 2.1 bundle with one attack-pattern"""
    return {
        "type": "bundle",
        "id": "bundle--123",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--ewm",
                "name": "Extra Window Memory Injection",
                "description": "Adversaries may inject malicious code...",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "url": "https://attack.mitre.org/techniques/T1055/011",
                        "external_id": "T1055.011"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "stealth"
                    },
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "privilege-escalation"
                    }
                ],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_is_subtechnique": True,
                "x_mitre_version": "2.0"
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt28",
                "name": "APT28"
            }
        ]
    }


def test_bundle_parsing_and_normalization(parser, sample_stix_bundle):
    """Test parsing and normalizing STIX bundle"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_stix_bundle, f)
        temp_path = Path(f.name)
        
    try:
        raw_objects = parser.parse_file(temp_path)
        # Should only parse the attack-pattern object
        assert len(raw_objects) == 1
        assert raw_objects[0]["id"] == "attack-pattern--ewm"
        
        normalized = parser.normalize_to_schema(raw_objects[0])
        assert normalized["technique_id"] == "T1055.011"
        assert normalized["name"] == "Extra Window Memory Injection"
        assert normalized["tactics"] == ["stealth", "privilege-escalation"]
        assert normalized["platforms"] == ["Windows"]
        assert normalized["is_subtechnique"] is True
        assert normalized["source"] == "MITRE ATT&CK"
    finally:
        temp_path.unlink()


def test_parse_and_normalize_to_dict(parser, sample_stix_bundle):
    """Test parsing and converting to dictionary mapping"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_stix_bundle, f)
        temp_path = Path(f.name)
        
    try:
        tech_dict = parser.parse_and_normalize_to_dict(temp_path)
        assert "T1055.011" in tech_dict
        tech = tech_dict["T1055.011"]
        assert tech["name"] == "Extra Window Memory Injection"
    finally:
        temp_path.unlink()


def test_directory_parsing(parser, sample_stix_bundle):
    """Test parsing recursively from a folder structure"""
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        sub_dir = dir_path / "attack-pattern"
        sub_dir.mkdir()
        
        file_path = sub_dir / "attack-pattern--test.json"
        with open(file_path, 'w') as f:
            json.dump(sample_stix_bundle, f)
            
        tech_dict = parser.parse_and_normalize_to_dict(dir_path)
        assert "T1055.011" in tech_dict
        assert len(tech_dict) == 1


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
