"""
CISA KEV Parser - Parse CISA Known Exploited Vulnerabilities catalog

This parser extracts known exploited vulnerabilities from the CISA KEV CSV file
and represents them as threat intelligence records.

Dataset: CISA KEV
Format: CSV
Source: datasets/known_exploited_vulnerabilities.csv
Output: Vulnerability records dict (NOT UnifiedEvent - threat intelligence)
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from ingestion.base_parser import CSVParser
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.base_parser import CSVParser
    from ingestion.dataset_registry import DatasetMetadata


class CISAKEVParser(CSVParser):
    """
    Parser for CISA Known Exploited Vulnerabilities CSV format.
    
    Extracts vulnerabilities:
    - CVE ID
    - Vendor / Project
    - Product
    - Vulnerability Name
    - Date Added
    - Short Description
    - Known Ransomware Campaign Use
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """Initialize CISA KEV parser"""
        super().__init__(dataset_metadata)
        try:
            self.logger.info("CISA KEV Parser initialized")
        except Exception:
            pass
        
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert raw KEV record to threat intelligence format.
        
        Note: CISA KEV is threat intelligence, NOT UnifiedEvent.
        Returns dict for Knowledge Base storage.
        
        Args:
            raw_record: Raw CSV row as dictionary
            
        Returns:
            Threat intel dictionary
        """
        cve_id = raw_record.get('cveID', 'CVE-UNKNOWN').strip()
        ransomware_use = raw_record.get('knownRansomwareCampaignUse', 'Unknown').strip()
        
        threat_intel = {
            'cve_id': cve_id,
            'vendor': raw_record.get('vendorProject', '').strip(),
            'product': raw_record.get('product', '').strip(),
            'vulnerability_name': raw_record.get('vulnerabilityName', '').strip(),
            'date_added': raw_record.get('dateAdded', '').strip(),
            'description': raw_record.get('shortDescription', '').strip(),
            'required_action': raw_record.get('requiredAction', '').strip(),
            'due_date': raw_record.get('dueDate', '').strip(),
            'ransomware_usage': ransomware_use.lower() == 'yes',
            'cwes': [c.strip() for c in raw_record.get('cwes', '').split(',') if c.strip()],
            'source': 'CISA KEV',
            'parsed_at': datetime.now().isoformat()
        }
        
        return threat_intel
        
    def parse_and_normalize_to_dict(self, filepath: Path) -> Dict[str, Dict[str, Any]]:
        """
        Parse KEV CSV and return dictionary keyed by CVE ID.
        
        Args:
            filepath: Path to KEV CSV file
            
        Returns:
            Dict mapping cve_id to threat intel record
        """
        raw_records = self.parse_file(filepath)
        kev_dict = {}
        
        for raw_record in raw_records:
            self.stats['total_records'] += 1
            try:
                threat_intel = self.normalize_to_schema(raw_record)
                cve_id = threat_intel['cve_id']
                kev_dict[cve_id] = threat_intel
                self.stats['valid_records'] += 1
            except Exception as e:
                self.stats['invalid_records'] += 1
                self.logger.warning(f"Error normalizing KEV record: {e}")
                continue
                
        self.logger.info(f"Successfully normalized {len(kev_dict)} CISA KEV records")
        return kev_dict


def create_cisa_kev_parser(dataset_path: Path) -> CISAKEVParser:
    """Factory function for CISA KEV parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="cisa_kev",
        name="CISA KEV",
        dataset_type=DatasetType.VULNERABILITIES,
        format=DatasetFormat.CSV,
        path=dataset_path,
        parser_class="CISAKEVParser",
        description="CISA KEV parser",
        source="CISA",
        event_types=[],
        timestamp_field="dateAdded"
    )
    return CISAKEVParser(metadata)
