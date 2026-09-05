"""
MITRE ATT&CK Parser - Parse MITRE ATT&CK techniques from STIX 2.1 JSON

This parser extracts MITRE ATT&CK techniques, tactics, descriptions, and platforms
from STIX JSON files and represents them as threat intelligence records.

Dataset: MITRE ATT&CK
Format: STIX 2.1 JSON
Source: datasets/cti-master/enterprise-attack/
Output: Threat intel dict (NOT UnifiedEvent - threat intelligence)
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from ingestion.base_parser import BaseDatasetParser
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.base_parser import BaseDatasetParser
    from ingestion.dataset_registry import DatasetMetadata


class MITREAttackParser(BaseDatasetParser):
    """
    Parser for MITRE ATT&CK STIX 2.1 JSON format.
    
    Extracts techniques:
    - ID: T#### or T####.### (e.g. T1055.011)
    - Name
    - Description
    - Tactics (kill chain phases)
    - Platforms
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """Initialize MITRE ATT&CK parser"""
        super().__init__(dataset_metadata)
        self.logger.info("MITRE ATT&CK Parser initialized")
        
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """
        Parse MITRE ATT&CK JSON file(s) into raw STIX object dictionaries.
        
        Supports:
        1. Single JSON file (STIX bundle or single technique)
        2. Directory of JSON files (traverses recursively for files starting with attack-pattern)
        
        Args:
            filepath: Path to JSON file or enterprise-attack directory
            
        Returns:
            List of raw attack-pattern STIX dictionaries
        """
        self.logger.info(f"Parsing MITRE ATT&CK path: {filepath}")
        
        raw_objects = []
        
        # Resolve target files
        if filepath.is_dir():
            # Try to find individual attack-pattern files first
            json_files = list(filepath.glob("**/attack-pattern--*.json"))
            if not json_files:
                # Fallback to any json files
                json_files = list(filepath.glob("**/*.json"))
                # Filter out the main enterprise-attack.json if we are parsing folder to avoid double parsing
                if len(json_files) > 1:
                    json_files = [f for f in json_files if f.name != "enterprise-attack.json"]
            
            self.logger.info(f"Found {len(json_files)} JSON files to parse in directory")
            for jf in json_files:
                try:
                    raw_objects.extend(self._parse_single_json_file(jf))
                except Exception as e:
                    self.logger.warning(f"Error parsing file {jf}: {e}")
                    continue
        else:
            raw_objects = self._parse_single_json_file(filepath)
            
        return raw_objects
        
    def _parse_single_json_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse a single JSON file and return raw STIX objects of type attack-pattern"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        objects = []
        if isinstance(data, dict):
            # Check if it is a STIX bundle
            if data.get('type') == 'bundle' and 'objects' in data:
                for obj in data['objects']:
                    if obj.get('type') == 'attack-pattern':
                        objects.append(obj)
            elif data.get('type') == 'attack-pattern':
                objects.append(data)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('type') == 'attack-pattern':
                    objects.append(item)
                    
        return objects
        
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert raw STIX attack-pattern to normalized threat intelligence format.
        
        Note: MITRE ATT&CK is threat intelligence, NOT UnifiedEvent.
        Returns dict for Knowledge Base storage.
        
        Args:
            raw_record: Raw STIX dict of type attack-pattern
            
        Returns:
            Threat intel dictionary
        """
        # Extract technique ID (T#### or T####.###)
        technique_id = "T-UNKNOWN"
        external_references = raw_record.get('external_references', [])
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id', technique_id)
                break
                
        # Extract tactics (kill chain phases)
        tactics = []
        kill_chain_phases = raw_record.get('kill_chain_phases', [])
        for phase in kill_chain_phases:
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))
                
        # Filter empty tactics
        tactics = [t for t in tactics if t]
        
        # Build normalized format
        threat_intel = {
            'technique_id': technique_id,
            'name': raw_record.get('name', ''),
            'description': raw_record.get('description', ''),
            'tactics': tactics,
            'platforms': raw_record.get('x_mitre_platforms', []),
            'is_subtechnique': raw_record.get('x_mitre_is_subtechnique', False),
            'version': raw_record.get('x_mitre_version', '1.0'),
            'deprecated': raw_record.get('x_mitre_deprecated', False),
            'source': 'MITRE ATT&CK',
            'parsed_at': datetime.now().isoformat()
        }
        
        return threat_intel
        
    def parse_and_normalize_to_dict(self, filepath: Path) -> Dict[str, Dict[str, Any]]:
        """
        Parse MITRE files and return dictionary keyed by technique_id.
        
        Args:
            filepath: Path to file or directory
            
        Returns:
            Dict mapping technique_id to threat intel record
        """
        raw_records = self.parse_file(filepath)
        techniques_dict = {}
        
        for raw_record in raw_records:
            self.stats['total_records'] += 1
            try:
                # Skip deprecated if needed, but we parse it
                threat_intel = self.normalize_to_schema(raw_record)
                tech_id = threat_intel['technique_id']
                techniques_dict[tech_id] = threat_intel
                self.stats['valid_records'] += 1
            except Exception as e:
                self.stats['invalid_records'] += 1
                self.logger.warning(f"Error normalizing MITRE record: {e}")
                continue
                
        self.logger.info(f"Successfully normalized {len(techniques_dict)} MITRE ATT&CK techniques")
        return techniques_dict


def create_mitre_attack_parser(dataset_path: Path) -> MITREAttackParser:
    """Factory function for MITRE ATT&CK parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="mitre_attack",
        name="MITRE ATT&CK",
        dataset_type=DatasetType.THREAT_INTELLIGENCE,
        format=DatasetFormat.STIX,
        path=dataset_path,
        parser_class="MITREAttackParser",
        description="MITRE ATT&CK parser",
        source="MITRE",
        event_types=[],
        timestamp_field=None
    )
    return MITREAttackParser(metadata)
