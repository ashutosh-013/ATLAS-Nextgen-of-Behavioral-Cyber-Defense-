"""
Dataset Parsers - Format-specific parsers for cybersecurity datasets

This package contains parsers for all supported datasets. Each parser:
1. Inherits from BaseDatasetParser
2. Implements parse_file() for dataset-specific format
3. Implements normalize_to_schema() to map fields to UnifiedEvent
4. Handles validation and error cases

Available Parsers:
- DARPAOpTCParser - DARPA OpTC CDM format
- CTU13Parser - CTU-13 NetFlow CSV
- CICIDSParser - CICIDS network CSV
- EMBERParser - EMBER malware features JSON
- SORELParser - SOREL-20M malware JSON
- TPotParser - T-Pot honeypot JSON
- MHNParser - MHN honeypot JSON
- MITREAttackParser - MITRE ATT&CK STIX
- CAPECParser - CAPEC attack patterns XML
- CISAKEVParser - CISA KEV vulnerabilities CSV
- CVEParser - CVE database JSON

Usage:
    from ingestion.parsers import DARPAOpTCParser
    from ingestion.dataset_registry import DatasetRegistry
    
    registry = DatasetRegistry()
    dataset = registry.get('darpa_optc')
    parser = DARPAOpTCParser(dataset)
    events = parser.parse_and_normalize(filepath)
"""

__all__ = []

# Parsers will be added as they are implemented:
# from .darpa_optc_parser import DARPAOpTCParser
# from .ctu13_parser import CTU13Parser
# ...
