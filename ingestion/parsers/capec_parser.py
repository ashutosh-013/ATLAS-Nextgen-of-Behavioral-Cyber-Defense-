"""
CAPEC Parser - Parse CAPEC attack patterns from XML schema

This parser extracts CAPEC attack patterns from the capec_v3.9.xml file.

Dataset: CAPEC
Format: XML
Source: datasets/capec_latest/capec_v3.9.xml
Output: Attack patterns dictionary (threat intelligence)
"""

import xml.etree.ElementTree as ET
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


class CAPECParser(BaseDatasetParser):
    """
    Parser for CAPEC XML threat intelligence format.
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        super().__init__(dataset_metadata)
        self.logger.info("CAPEC Parser initialized")
        
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """
        Parse CAPEC XML file into raw attack pattern dictionaries.
        """
        self.logger.info(f"Parsing CAPEC XML: {filepath}")
        
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            # CAPEC XML has Attack_Patterns container under root
            attack_patterns = []
            
            # Use XPath to find all Attack_Pattern elements, ignoring namespaces
            for ap_elem in root.findall(".//{*}Attack_Pattern"):
                ap_id = ap_elem.get("ID")
                name = ap_elem.get("Name")
                
                # Get Description
                desc_elem = ap_elem.find(".//{*}Description")
                description = ""
                if desc_elem is not None:
                    # Get all text inside description element
                    description = "".join(desc_elem.itertext()).strip()
                    
                # Get severity and likelihood
                severity = ""
                sev_elem = ap_elem.find(".//{*}Typical_Severity")
                if sev_elem is not None:
                    severity = sev_elem.text.strip() if sev_elem.text else ""
                    
                likelihood = ""
                lik_elem = ap_elem.find(".//{*}Likelihood_Of_Attack")
                if lik_elem is not None:
                    likelihood = lik_elem.text.strip() if lik_elem.text else ""
                    
                attack_patterns.append({
                    "capec_id": f"CAPEC-{ap_id}",
                    "name": name,
                    "description": description,
                    "severity": severity,
                    "likelihood": likelihood
                })
                
            return attack_patterns
            
        except Exception as e:
            self.logger.error(f"Error parsing CAPEC XML: {e}")
            raise ValidationError(f"Failed to parse CAPEC XML: {e}")
            
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw CAPEC dict to normalized threat intelligence format"""
        return {
            "capec_id": raw_record.get("capec_id", ""),
            "name": raw_record.get("name", ""),
            "description": raw_record.get("description", ""),
            "severity": raw_record.get("severity", ""),
            "likelihood": raw_record.get("likelihood", ""),
            "source": "CAPEC",
            "parsed_at": datetime.now().isoformat()
        }
        
    def parse_and_normalize_to_dict(self, filepath: Path) -> Dict[str, Dict[str, Any]]:
        """Parse CAPEC XML and return dictionary keyed by CAPEC ID"""
        raw_records = self.parse_file(filepath)
        capec_dict = {}
        for r in raw_records:
            self.stats['total_records'] += 1
            try:
                threat_intel = self.normalize_to_schema(r)
                cid = threat_intel["capec_id"]
                capec_dict[cid] = threat_intel
                self.stats['valid_records'] += 1
            except Exception as e:
                self.stats['invalid_records'] += 1
                self.logger.warning(f"Error normalizing CAPEC: {e}")
                continue
        return capec_dict


def create_capec_parser(dataset_path: Path) -> CAPECParser:
    """Factory function for CAPEC parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="capec",
        name="CAPEC Attack Patterns",
        dataset_type=DatasetType.THREAT_INTELLIGENCE,
        format=DatasetFormat.XML,
        path=dataset_path,
        parser_class="CAPECParser",
        description="CAPEC XML parser",
        source="CAPEC",
        event_types=[],
        timestamp_field=None
    )
    return CAPECParser(metadata)
