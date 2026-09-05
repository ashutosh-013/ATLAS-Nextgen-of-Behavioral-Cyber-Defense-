"""
Dataset Registry - Central registry for all cybersecurity datasets

This module maintains a comprehensive registry of all datasets available to ATLAS,
including their locations, formats, parsers, and metadata. It serves as the single
source of truth for dataset management.

Task: 1.1 - Create Dataset Registry
Integration: Standalone registry accessed by all ingestion modules
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum


class DatasetFormat(Enum):
    """Supported dataset formats"""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    PARQUET = "parquet"
    PKL = "pkl"
    NETFLOW = "netflow"
    PCAP = "pcap"
    STIX = "stix"
    CDM = "cdm"  # DARPA Common Data Model


class DatasetType(Enum):
    """Dataset categories"""
    ENDPOINT_TELEMETRY = "endpoint_telemetry"
    NETWORK_TRAFFIC = "network_traffic"
    AUTHENTICATION_LOGS = "authentication_logs"
    MALWARE_SAMPLES = "malware_samples"
    THREAT_INTELLIGENCE = "threat_intelligence"
    ATTACK_PATTERNS = "attack_patterns"
    VULNERABILITIES = "vulnerabilities"
    HONEYPOT_LOGS = "honeypot_logs"


class DatasetStatus(Enum):
    """Dataset processing status"""
    AVAILABLE = "available"
    PROCESSING = "processing"
    INGESTED = "ingested"
    ERROR = "error"
    NOT_FOUND = "not_found"


@dataclass
class DatasetMetadata:
    """
    Comprehensive metadata for a cybersecurity dataset.
    
    Attributes:
        dataset_id: Unique identifier for the dataset
        name: Human-readable dataset name
        dataset_type: Category of dataset (endpoint, network, etc.)
        format: File format (JSON, CSV, XML, etc.)
        path: Absolute path to dataset files
        parser_class: Name of parser class to use
        description: Dataset description
        source: Original data source/organization
        record_count: Estimated number of records
        size_mb: Dataset size in megabytes
        event_types: Types of security events present
        label_field: Field containing threat labels (if any)
        timestamp_field: Field containing timestamps
        status: Current processing status
        ingested_at: Timestamp of last ingestion
        metadata: Additional custom metadata
    """
    dataset_id: str
    name: str
    dataset_type: DatasetType
    format: DatasetFormat
    path: Path
    parser_class: str
    description: str
    source: str
    record_count: Optional[int] = None
    size_mb: Optional[float] = None
    event_types: List[str] = field(default_factory=list)
    label_field: Optional[str] = None
    timestamp_field: Optional[str] = None
    status: DatasetStatus = DatasetStatus.AVAILABLE
    ingested_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary with enum serialization"""
        data = asdict(self)
        data['dataset_type'] = self.dataset_type.value
        data['format'] = self.format.value
        data['status'] = self.status.value
        data['path'] = str(self.path)
        if self.ingested_at:
            data['ingested_at'] = self.ingested_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DatasetMetadata':
        """Create metadata from dictionary"""
        data['dataset_type'] = DatasetType(data['dataset_type'])
        data['format'] = DatasetFormat(data['format'])
        data['status'] = DatasetStatus(data['status'])
        data['path'] = Path(data['path'])
        if data.get('ingested_at'):
            data['ingested_at'] = datetime.fromisoformat(data['ingested_at'])
        return cls(**data)


class DatasetRegistry:
    """
    Central registry for all cybersecurity datasets.
    
    Maintains metadata for all available datasets and provides query/management
    functionality. Persists to disk for resuming operations.
    """
    
    def __init__(self, registry_path: Optional[Path] = None):
        """
        Initialize dataset registry.
        
        Args:
            registry_path: Path to registry JSON file (default: datasets/registry.json)
        """
        if registry_path is None:
            registry_path = Path("datasets") / "registry.json"
        
        self.registry_path = registry_path
        self.datasets: Dict[str, DatasetMetadata] = {}
        
        # Load existing registry if available
        if self.registry_path.exists():
            self.load()
        else:
            # Initialize with default datasets
            self._initialize_default_datasets()
    
    def _initialize_default_datasets(self):
        """Initialize registry with all available datasets in datasets/ folder"""
        
        base_path = Path("datasets")
        
        # 1. DARPA OpTC (Operational Transparent Computing)
        self.register(DatasetMetadata(
            dataset_id="darpa_optc",
            name="DARPA OpTC",
            dataset_type=DatasetType.ENDPOINT_TELEMETRY,
            format=DatasetFormat.CDM,
            path=base_path / "OpTC-data-master",
            parser_class="DARPAOpTCParser",
            description="DARPA Operational Transparent Computing dataset with provenance graphs",
            source="DARPA",
            event_types=["process", "file", "network", "auth"],
            timestamp_field="timestamp_nanos",
            metadata={"cdm_version": "20", "has_ground_truth": True}
        ))
        
        # 2. DARPA Transparent Computing (via CTI STIX)
        self.register(DatasetMetadata(
            dataset_id="darpa_tc_cti",
            name="DARPA TC CTI",
            dataset_type=DatasetType.ATTACK_PATTERNS,
            format=DatasetFormat.STIX,
            path=base_path / "cti-master" / "cti-master",
            parser_class="DARPATCParser",
            description="DARPA Transparent Computing with STIX threat intelligence",
            source="DARPA",
            event_types=["threat_pattern", "campaign", "malware"],
            metadata={"stix_version": "2.1"}
        ))
        
        # 3. CTU-13 Botnet Traffic
        self.register(DatasetMetadata(
            dataset_id="ctu13",
            name="CTU-13 Botnet Dataset",
            dataset_type=DatasetType.NETWORK_TRAFFIC,
            format=DatasetFormat.NETFLOW,
            path=base_path / "CTU-13-Dataset",
            parser_class="CTU13Parser",
            description="CTU-13 dataset with labeled botnet network flows",
            source="CTU Czech Technical University",
            event_types=["network"],
            label_field="Label",
            timestamp_field="StartTime",
            metadata={"scenarios": 13, "has_labels": True, "botnet_types": ["Neris", "Rbot", "Virut"]}
        ))
        
        # 4. CICIDS 2017/2018 (CSV files in 1000.csv, 333.csv, 658.csv folders)
        for csv_folder in ["1000.csv", "333.csv", "658.csv"]:
            csv_path = base_path / csv_folder / f"{csv_folder}"
            if csv_path.exists():
                self.register(DatasetMetadata(
                    dataset_id=f"cicids_{csv_folder.replace('.csv', '')}",
                    name=f"CICIDS-{csv_folder}",
                    dataset_type=DatasetType.NETWORK_TRAFFIC,
                    format=DatasetFormat.CSV,
                    path=csv_path,
                    parser_class="CICIDSParser",
                    description=f"CICIDS network intrusion detection dataset - {csv_folder}",
                    source="Canadian Institute for Cybersecurity",
                    event_types=["network"],
                    label_field="Label",
                    timestamp_field="Timestamp",
                    metadata={"has_labels": True, "attack_types": ["DDoS", "PortScan", "BruteForce"]}
                ))
        
        # 5. EMBER (Endgame Malware BEnchmark for Research)
        self.register(DatasetMetadata(
            dataset_id="ember",
            name="EMBER Malware Dataset",
            dataset_type=DatasetType.MALWARE_SAMPLES,
            format=DatasetFormat.JSON,
            path=base_path / "ember-master",
            parser_class="EMBERParser",
            description="EMBER malware classification dataset with PE features",
            source="Endgame (Elastic)",
            record_count=1100000,
            event_types=["file"],
            label_field="label",
            metadata={"version": "2018", "feature_count": 2381}
        ))
        
        # 6. SOREL-20M
        self.register(DatasetMetadata(
            dataset_id="sorel_20m",
            name="SOREL-20M",
            dataset_type=DatasetType.MALWARE_SAMPLES,
            format=DatasetFormat.JSON,
            path=base_path / "SOREL-20M-master",
            parser_class="SORELParser",
            description="SOREL 20 million malware samples with metadata",
            source="Sophos-ReversingLabs",
            record_count=20000000,
            event_types=["file"],
            label_field="label",
            metadata={"has_disassembly": True, "has_strings": True}
        ))
        
        # 7. T-Pot Honeypot (tpotce)
        self.register(DatasetMetadata(
            dataset_id="tpot_honeypot",
            name="T-Pot Community Edition",
            dataset_type=DatasetType.HONEYPOT_LOGS,
            format=DatasetFormat.JSON,
            path=base_path / "tpotce-master",
            parser_class="TPotParser",
            description="T-Pot honeypot attack logs",
            source="T-Pot Community",
            event_types=["network", "auth", "file"],
            timestamp_field="@timestamp",
            metadata={"honeypot_types": ["Cowrie", "Dionaea", "Conpot", "Honeytrap"]}
        ))
        
        # 8. MHN (Modern Honey Network)
        self.register(DatasetMetadata(
            dataset_id="mhn_honeypot",
            name="Modern Honey Network",
            dataset_type=DatasetType.HONEYPOT_LOGS,
            format=DatasetFormat.JSON,
            path=base_path / "mhn-master",
            parser_class="MHNParser",
            description="Modern Honey Network attack logs",
            source="MHN Project",
            event_types=["network", "auth"],
            timestamp_field="timestamp",
            metadata={"protocol_support": ["SSH", "Telnet", "HTTP", "FTP"]}
        ))
        
        # 9. MITRE ATT&CK
        self.register(DatasetMetadata(
            dataset_id="mitre_attack",
            name="MITRE ATT&CK",
            dataset_type=DatasetType.THREAT_INTELLIGENCE,
            format=DatasetFormat.STIX,
            path=base_path / "cti-master" / "cti-master" / "enterprise-attack",
            parser_class="MITREAttackParser",
            description="MITRE ATT&CK framework techniques and tactics",
            source="MITRE Corporation",
            event_types=["threat_pattern", "technique"],
            metadata={"framework": "enterprise", "version": "latest", "technique_count": 16000}
        ))
        
        # 10. CAPEC (Common Attack Pattern Enumeration and Classification)
        self.register(DatasetMetadata(
            dataset_id="capec",
            name="CAPEC Attack Patterns",
            dataset_type=DatasetType.ATTACK_PATTERNS,
            format=DatasetFormat.XML,
            path=base_path / "capec_latest" / "capec_v3.9.xml",
            parser_class="CAPECParser",
            description="CAPEC attack pattern catalog",
            source="MITRE Corporation",
            event_types=["attack_pattern"],
            metadata={"version": "3.9", "pattern_count": 559}
        ))
        
        # 11. CISA KEV (Known Exploited Vulnerabilities)
        self.register(DatasetMetadata(
            dataset_id="cisa_kev",
            name="CISA KEV Catalog",
            dataset_type=DatasetType.VULNERABILITIES,
            format=DatasetFormat.CSV,
            path=base_path / "known_exploited_vulnerabilities.csv",
            parser_class="CISAKEVParser",
            description="CISA Known Exploited Vulnerabilities catalog",
            source="CISA",
            event_types=["vulnerability"],
            timestamp_field="dateAdded",
            metadata={"actively_exploited": True}
        ))
        
        # 12. CVE List v5
        self.register(DatasetMetadata(
            dataset_id="cve_list",
            name="CVE List v5",
            dataset_type=DatasetType.VULNERABILITIES,
            format=DatasetFormat.JSON,
            path=base_path / "cvelistV5-main",
            parser_class="CVEParser",
            description="CVE (Common Vulnerabilities and Exposures) database v5.0",
            source="MITRE/NVD",
            event_types=["vulnerability"],
            metadata={"cve_format": "5.0"}
        ))
        
        # 13. EMBER Pickled Models (if these are feature vectors)
        pkl_files = list(base_path.glob("*.pkl"))
        if pkl_files:
            self.register(DatasetMetadata(
                dataset_id="ember_features_pkl",
                name="EMBER Pre-extracted Features",
                dataset_type=DatasetType.MALWARE_SAMPLES,
                format=DatasetFormat.PKL,
                path=base_path,
                parser_class="EMBERPickleParser",
                description="Pre-extracted EMBER malware features in pickle format",
                source="EMBER Dataset",
                event_types=["file"],
                metadata={"pickle_files": [f.name for f in pkl_files]}
            ))
    
    def register(self, dataset: DatasetMetadata) -> None:
        """
        Register a new dataset in the registry.
        
        Args:
            dataset: Dataset metadata to register
        """
        self.datasets[dataset.dataset_id] = dataset
    
    def get(self, dataset_id: str) -> Optional[DatasetMetadata]:
        """
        Retrieve dataset metadata by ID.
        
        Args:
            dataset_id: Unique dataset identifier
            
        Returns:
            Dataset metadata or None if not found
        """
        return self.datasets.get(dataset_id)
    
    def list_all(self) -> List[DatasetMetadata]:
        """Get all registered datasets"""
        return list(self.datasets.values())
    
    def list_by_type(self, dataset_type: DatasetType) -> List[DatasetMetadata]:
        """
        Get all datasets of a specific type.
        
        Args:
            dataset_type: Type of datasets to retrieve
            
        Returns:
            List of matching datasets
        """
        return [d for d in self.datasets.values() if d.dataset_type == dataset_type]
    
    def list_by_status(self, status: DatasetStatus) -> List[DatasetMetadata]:
        """
        Get all datasets with a specific status.
        
        Args:
            status: Dataset status to filter by
            
        Returns:
            List of matching datasets
        """
        return [d for d in self.datasets.values() if d.status == status]
    
    def update_status(self, dataset_id: str, status: DatasetStatus, 
                     ingested_at: Optional[datetime] = None) -> bool:
        """
        Update dataset processing status.
        
        Args:
            dataset_id: Dataset to update
            status: New status
            ingested_at: Timestamp of ingestion (optional)
            
        Returns:
            True if updated, False if dataset not found
        """
        dataset = self.get(dataset_id)
        if dataset:
            dataset.status = status
            if ingested_at:
                dataset.ingested_at = ingested_at
            return True
        return False
    
    def save(self) -> None:
        """Persist registry to disk"""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        
        registry_data = {
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'datasets': {
                dataset_id: dataset.to_dict() 
                for dataset_id, dataset in self.datasets.items()
            }
        }
        
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(registry_data, f, indent=2, ensure_ascii=False)
    
    def load(self) -> None:
        """Load registry from disk"""
        with open(self.registry_path, 'r', encoding='utf-8') as f:
            registry_data = json.load(f)
        
        self.datasets = {
            dataset_id: DatasetMetadata.from_dict(dataset_dict)
            for dataset_id, dataset_dict in registry_data['datasets'].items()
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Dictionary with counts by type, status, format
        """
        stats = {
            'total_datasets': len(self.datasets),
            'by_type': {},
            'by_status': {},
            'by_format': {},
            'total_records': 0,
            'total_size_mb': 0.0
        }
        
        for dataset in self.datasets.values():
            # Count by type
            type_key = dataset.dataset_type.value
            stats['by_type'][type_key] = stats['by_type'].get(type_key, 0) + 1
            
            # Count by status
            status_key = dataset.status.value
            stats['by_status'][status_key] = stats['by_status'].get(status_key, 0) + 1
            
            # Count by format
            format_key = dataset.format.value
            stats['by_format'][format_key] = stats['by_format'].get(format_key, 0) + 1
            
            # Accumulate totals
            if dataset.record_count:
                stats['total_records'] += dataset.record_count
            if dataset.size_mb:
                stats['total_size_mb'] += dataset.size_mb
        
        return stats
    
    def validate_paths(self) -> Dict[str, bool]:
        """
        Validate that all dataset paths exist.
        
        Returns:
            Dictionary mapping dataset_id to path existence status
        """
        return {
            dataset_id: dataset.path.exists()
            for dataset_id, dataset in self.datasets.items()
        }
    
    def print_summary(self) -> None:
        """Print human-readable registry summary"""
        print("=" * 80)
        print("ATLAS Dataset Registry Summary")
        print("=" * 80)
        
        stats = self.get_statistics()
        print(f"\nTotal Datasets: {stats['total_datasets']}")
        print(f"Total Records: {stats['total_records']:,}" if stats['total_records'] > 0 else "")
        print(f"Total Size: {stats['total_size_mb']:.2f} MB" if stats['total_size_mb'] > 0 else "")
        
        print("\nBy Type:")
        for type_name, count in sorted(stats['by_type'].items()):
            print(f"  {type_name}: {count}")
        
        print("\nBy Status:")
        for status_name, count in sorted(stats['by_status'].items()):
            print(f"  {status_name}: {count}")
        
        print("\nBy Format:")
        for format_name, count in sorted(stats['by_format'].items()):
            print(f"  {format_name}: {count}")
        
        print("\nPath Validation:")
        path_status = self.validate_paths()
        exists_count = sum(1 for exists in path_status.values() if exists)
        print(f"  Valid paths: {exists_count}/{len(path_status)}")
        
        # Show missing paths
        missing = [dataset_id for dataset_id, exists in path_status.items() if not exists]
        if missing:
            print(f"\n  Missing datasets: {', '.join(missing)}")
        
        print("=" * 80)


def create_default_registry() -> DatasetRegistry:
    """
    Create and return a default dataset registry.
    
    Returns:
        Initialized DatasetRegistry with all available datasets
    """
    registry = DatasetRegistry()
    registry.save()
    return registry


if __name__ == "__main__":
    # Create registry and display summary
    print("Initializing ATLAS Dataset Registry...")
    registry = create_default_registry()
    registry.print_summary()
    
    print("\nRegistry saved to:", registry.registry_path)
    print("\nSample dataset details:")
    
    # Show details for a few key datasets
    for dataset_id in ["darpa_optc", "mitre_attack", "ember"]:
        dataset = registry.get(dataset_id)
        if dataset:
            print(f"\n{dataset.name} ({dataset.dataset_id}):")
            print(f"  Type: {dataset.dataset_type.value}")
            print(f"  Format: {dataset.format.value}")
            print(f"  Path: {dataset.path}")
            print(f"  Parser: {dataset.parser_class}")
            print(f"  Status: {dataset.status.value}")
            if dataset.event_types:
                print(f"  Event Types: {', '.join(dataset.event_types)}")
