"""
CICIDS Network Parser - Parse CICIDS network traffic datasets

This parser converts CICIDS 2017/2018 CSV format to UnifiedEvent objects.
Supports handling spaces in CSV headers, normalizing protocols, mapping attack labels,
and parsing timestamps.

Dataset: CICIDS 2017/2018
Format: CSV (80+ flow features)
Output: UnifiedEvent with event_type='network'
"""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import CSVParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import CSVParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata


class CICIDSParser(CSVParser):
    """
    Parser for CICIDS CSV format.
    
    Standard CICIDS features include:
    Timestamp, Source IP, Source Port, Destination IP, Destination Port, Protocol, Flow Duration,
    Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets,
    FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, Label
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """Initialize CICIDS parser"""
        super().__init__(dataset_metadata)
        
        # Protocol mapping: CICIDS uses numeric values (6=TCP, 17=UDP, 1=ICMP, etc.)
        self.protocol_map = {
            '6': 'TCP',
            '17': 'UDP',
            '1': 'ICMP',
            'tcp': 'TCP',
            'udp': 'UDP',
            'icmp': 'ICMP'
        }
        
        self.logger.info("CICIDS Network Parser initialized")
        
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """
        Convert CICIDS flow record to UnifiedEvent.
        
        Args:
            raw_record: Raw CSV row
            
        Returns:
            UnifiedEvent with event_type='network'
        """
        # Clean keys/values to handle leading/trailing spaces
        record = {str(k).strip(): str(v).strip() for k, v in raw_record.items()}
        
        # Perform quick header format validation
        has_required = any(k in record for k in ['Timestamp', 'Timestamp_field']) and \
                       any(k in record for k in ['Source IP', 'Src IP', 'SrcAddr'])
        
        if not has_required:
            # Check if this looks like CAPEC file
            if 'Abstraction' in record or 'Likelihood Of Attack' in record:
                raise ValidationError("CSV file appears to be a CAPEC attack pattern catalog, not a CICIDS network flow dataset")
            raise ValidationError("Record missing required CICIDS fields (Timestamp, Source IP)")
            
        # Extract 5-tuple fields
        src_ip = record.get('Source IP', record.get('Src IP', ''))
        dst_ip = record.get('Destination IP', record.get('Dst IP', ''))
        src_port = record.get('Source Port', record.get('Src Port', '0'))
        dst_port = record.get('Destination Port', record.get('Dst Port', '0'))
        proto_str = record.get('Protocol', '6')
        
        if not src_ip or not dst_ip:
            raise ValidationError("Missing source or destination IP addresses")
            
        # Parse timestamp
        timestamp = self._parse_timestamp(record.get('Timestamp', ''))
        
        # Generate flow ID
        flow_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto_str}-{timestamp}"
        event_id = f"cicids_flow_{hash(flow_str) & 0xFFFFFFFF:08x}"
        
        # Parse packet counts
        tot_fwd_pkts = self._parse_int(record.get('Total Fwd Packets', record.get('Total Fwd Pkts', '0')))
        tot_bwd_pkts = self._parse_int(record.get('Total Backward Packets', record.get('Total Bwd Pkts', '0')))
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        
        # Parse byte counts
        fwd_bytes = self._parse_int(record.get('Total Length of Fwd Packets', record.get('Fwd Packets Length Total', '0')))
        bwd_bytes = self._parse_int(record.get('Total Length of Bwd Packets', record.get('Bwd Packets Length Total', '0')))
        tot_bytes = fwd_bytes + bwd_bytes
        
        # Extract TCP flags
        flags = {
            'FIN': self._parse_int(record.get('FIN Flag Count', record.get('FIN Flag Cnt', '0'))) > 0,
            'SYN': self._parse_int(record.get('SYN Flag Count', record.get('SYN Flag Cnt', '0'))) > 0,
            'RST': self._parse_int(record.get('RST Flag Count', record.get('RST Flag Cnt', '0'))) > 0,
            'PSH': self._parse_int(record.get('PSH Flag Count', record.get('PSH Flag Cnt', '0'))) > 0,
            'ACK': self._parse_int(record.get('ACK Flag Count', record.get('ACK Flag Cnt', '0'))) > 0,
            'URG': self._parse_int(record.get('URG Flag Count', record.get('URG Flag Cnt', '0'))) > 0,
        }
        
        # Determine flow duration (CICIDS is in microseconds, convert to seconds)
        duration_us = self._parse_float(record.get('Flow Duration', '0.0'))
        duration = duration_us / 1000000.0
        
        # Extract attack labels
        label = record.get('Label', 'Benign')
        is_malicious = label.lower() != 'benign'
        
        event_data = {
            'action': 'flow',
            'src_ip': src_ip,
            'src_port': self._parse_port(src_port),
            'dst_ip': dst_ip,
            'dst_port': self._parse_port(dst_port),
            'protocol': self.protocol_map.get(proto_str.lower(), proto_str.upper()),
            'duration': duration,
            'total_packets': tot_pkts,
            'total_bytes': tot_bytes,
            'bytes_sent': fwd_bytes,
            'bytes_received': bwd_bytes,
            'flags': flags,
            'label': label,
            'is_malicious': is_malicious
        }
        
        return UnifiedEvent(
            event_id=event_id,
            event_type='network',
            timestamp=timestamp,
            source_system=self.metadata.dataset_id,
            event_data=event_data
        )
        
    def _parse_timestamp(self, timestamp_str: Any) -> str:
        """Parse CICIDS timestamps to ISO 8601"""
        if not timestamp_str:
            return datetime.now().isoformat()
            
        t_str = str(timestamp_str).strip()
        
        # Try Unix timestamp first
        try:
            val = float(t_str)
            if val > 100000000:
                dt = datetime.fromtimestamp(val)
                return dt.isoformat()
        except (ValueError, TypeError, OSError):
            pass
            
        # CICIDS uses various formats, like:
        # dd/MM/yyyy HH:mm:ss
        # dd/MM/yyyy HH:mm
        # yyyy-MM-dd HH:mm:ss
        for fmt in ('%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S.%f'):
            try:
                dt = datetime.strptime(t_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
                
        # Fallback
        self.logger.warning(f"Failed to parse timestamp: {timestamp_str}")
        return t_str
        
    def _parse_port(self, port_str: str) -> int:
        """Parse port number"""
        try:
            return int(port_str)
        except (ValueError, TypeError):
            return 0
            
    def _parse_int(self, val_str: str) -> int:
        """Parse int"""
        try:
            return int(float(val_str))
        except (ValueError, TypeError):
            return 0
            
    def _parse_float(self, val_str: str) -> float:
        """Parse float"""
        try:
            return float(val_str)
        except (ValueError, TypeError):
            return 0.0


def create_cicids_parser(dataset_path: Path) -> CICIDSParser:
    """Factory function for CICIDS parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="cicids_1000",
        name="CICIDS dataset",
        dataset_type=DatasetType.NETWORK_TRAFFIC,
        format=DatasetFormat.CSV,
        path=dataset_path,
        parser_class="CICIDSParser",
        description="CICIDS network traffic parser",
        source="CICIDS",
        event_types=["network"],
        timestamp_field="Timestamp"
    )
    return CICIDSParser(metadata)
