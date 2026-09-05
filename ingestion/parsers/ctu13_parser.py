"""
CTU-13 NetFlow Parser - Parse CTU-13 botnet traffic dataset

This parser converts CTU-13 NetFlow CSV format to UnifiedEvent objects 
compatible with BADNA's BehaviorCaptureEngine.

Dataset: CTU-13 Botnet Dataset
Format: NetFlow CSV
Source: datasets/CTU-13-Dataset/

Task: 2.1 - Implement CTU-13 NetFlow Parser
Requirements: 3.1-3.7
"""

import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import logging

try:
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser, CSVParser
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser, CSVParser
    from ingestion.dataset_registry import DatasetMetadata


class CTU13Parser(CSVParser):
    """
    Parser for CTU-13 NetFlow CSV format.
    
    CTU-13 Format (CSV columns):
    StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, 
    sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
    
    Example row:
    2011/08/10 09:46:53.047277,0.000000,udp,147.32.84.165,1026,->,239.255.255.250,1900,CON,0,0,1,375,375,flow=Background-UDP-Established
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """Initialize CTU-13 parser"""
        super().__init__(dataset_metadata)
        
        # NetFlow protocol mapping
        self.protocol_map = {
            'tcp': 'TCP',
            'udp': 'UDP',
            'icmp': 'ICMP',
            'igmp': 'IGMP',
            'esp': 'ESP',
            'ah': 'AH',
            'sctp': 'SCTP'
        }
        
        # NetFlow state descriptions
        self.state_map = {
            'CON': 'connection',
            'INT': 'internal',
            'FIN': 'finished',
            'RST': 'reset',
            'REQ': 'request',
            'ACC': 'accepted',
            'CLO': 'closed'
        }
        
        self.logger.info("CTU-13 NetFlow Parser initialized")
    
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """
        Convert NetFlow record to UnifiedEvent.
        
        Args:
            raw_record: Raw NetFlow CSV row as dict
            
        Returns:
            UnifiedEvent with event_type='network'
        """
        # Check for missing required fields
        if 'SrcAddr' not in raw_record or not raw_record.get('SrcAddr'):
            from ingestion.base_parser import ValidationError
            raise ValidationError("Missing required field: SrcAddr")
        if 'DstAddr' not in raw_record or not raw_record.get('DstAddr'):
            from ingestion.base_parser import ValidationError
            raise ValidationError("Missing required field: DstAddr")
        if 'Proto' not in raw_record or not raw_record.get('Proto'):
            from ingestion.base_parser import ValidationError
            raise ValidationError("Missing required field: Proto")

        # Generate event ID from flow tuple
        event_id = self._generate_flow_id(raw_record)
        
        # Parse timestamp
        timestamp = self._parse_timestamp(raw_record.get('StartTime', ''))
        
        tot_bytes = self._parse_int(raw_record.get('TotBytes', '0'))
        src_bytes = self._parse_int(raw_record.get('SrcBytes', '0'))
        bytes_received = tot_bytes - src_bytes
        if bytes_received < 0:
            bytes_received = 0

        # Extract network flow data
        event_data = {
            'action': 'flow',
            'src_ip': raw_record.get('SrcAddr', ''),
            'src_port': self._parse_port(raw_record.get('Sport', '0')),
            'dst_ip': raw_record.get('DstAddr', ''),
            'dst_port': self._parse_port(raw_record.get('Dport', '0')),
            'protocol': self.protocol_map.get(
                raw_record.get('Proto', 'tcp').lower(), 
                raw_record.get('Proto', 'TCP').upper()
            ),
            'direction': raw_record.get('Dir', '->'),
            'duration': self._parse_float(raw_record.get('Dur', '0.0')),
            'flow_state': raw_record.get('State', 'CON'),
            'total_packets': self._parse_int(raw_record.get('TotPkts', '0')),
            'total_bytes': tot_bytes,
            'src_bytes': src_bytes,
            'bytes_sent': src_bytes,
            'bytes_received': bytes_received,
            'src_tos': raw_record.get('sTos', '0'),
            'dst_tos': raw_record.get('dTos', '0'),
            # Preserve label for supervised learning
            'label': self._parse_label(raw_record.get('Label', '')),
            'is_botnet': self._is_botnet(raw_record.get('Label', ''))
        }
        
        return UnifiedEvent(
            event_id=event_id,
            event_type='network',
            timestamp=timestamp,
            source_system=self.metadata.dataset_id,
            event_data=event_data
        )
    
    def _generate_flow_id(self, record: Dict[str, Any]) -> str:
        """Generate unique flow ID from 5-tuple"""
        src_ip = record.get('SrcAddr', 'unknown')
        dst_ip = record.get('DstAddr', 'unknown')
        src_port = record.get('Sport', '0')
        dst_port = record.get('Dport', '0')
        proto = record.get('Proto', 'tcp')
        timestamp = record.get('StartTime', '')
        
        # Simple hash-based ID
        flow_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}-{timestamp}"
        return f"ctu13_flow_{hash(flow_str) & 0xFFFFFFFF:08x}"
    
    def _parse_timestamp(self, timestamp_str: Any) -> str:
        """
        Parse timestamp to ISO 8601 format.
        
        Supports CTU-13 formats, alternative formats, Unix timestamps, and returns original on failure.
        """
        if not timestamp_str:
            return datetime.now().isoformat()
        
        # Convert to string if not already
        t_str = str(timestamp_str).strip()
        
        # Check if Unix timestamp
        try:
            # Check if it consists only of digits (allowing integer/float string)
            val = float(t_str)
            if val > 100000000:
                dt = datetime.fromtimestamp(val)
                return dt.isoformat()
        except (ValueError, TypeError, OSError):
            pass
            
        # Try CTU-13 formats and standard ISO formats
        for fmt in ('%Y/%m/%d %H:%M:%S.%f', '%Y/%m/%d %H:%M:%S', '%Y-%m-%d %H:%M:%S'):
            try:
                dt = datetime.strptime(t_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
                
        # If all parsing fails, return original string as expected by test_invalid_timestamp
        self.logger.warning(f"Failed to parse timestamp: {timestamp_str}")
        return t_str
    
    def _parse_netflow_timestamp(self, timestamp_str: str) -> str:
        """Deprecated alias, use _parse_timestamp instead"""
        return self._parse_timestamp(timestamp_str)
    
    def _parse_port(self, port_str: str) -> int:
        """Parse port number"""
        try:
            return int(port_str)
        except (ValueError, TypeError):
            return 0
    
    def _parse_int(self, value_str: str) -> int:
        """Parse integer value"""
        try:
            return int(float(value_str))
        except (ValueError, TypeError):
            return 0
    
    def _parse_float(self, value_str: str) -> float:
        """Parse float value"""
        try:
            return float(value_str)
        except (ValueError, TypeError):
            return 0.0
    
    def _parse_label(self, label_str: str) -> str:
        """
        Parse label field.
        
        Examples:
        - flow=Background-UDP-Established
        - Botnet
        - Normal
        
        Returns:
            Parsed label string
        """
        if not label_str:
            return 'unknown'
        
        # Extract label from flow= format
        if 'flow=' in label_str:
            return label_str.split('flow=')[1].strip()
        
        return label_str.strip()
    
    def _is_botnet(self, label_str: str) -> bool:
        """Check if flow is botnet traffic"""
        if not label_str:
            return False
        
        label_lower = label_str.lower()
        botnet_keywords = ['botnet', 'malware', 'c&c', 'cc', 'cnc']
        
        return any(keyword in label_lower for keyword in botnet_keywords)


def create_ctu13_parser(dataset_path: Path) -> CTU13Parser:
    """
    Factory function to create CTU-13 parser.
    
    Args:
        dataset_path: Path to CTU-13 dataset directory
        
    Returns:
        Initialized CTU13Parser instance
    """
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="ctu13",
        name="CTU-13 Botnet Dataset",
        dataset_type=DatasetType.NETWORK_TRAFFIC,
        format=DatasetFormat.CSV,
        path=dataset_path,
        parser_class="CTU13Parser",
        description="CTU-13 botnet network traffic dataset",
        source="CTU Prague",
        event_types=["network"],
        timestamp_field="StartTime"
    )
    
    return CTU13Parser(metadata)


if __name__ == "__main__":
    print("=" * 80)
    print("CTU-13 NetFlow Parser Test")
    print("=" * 80)
    
    # Sample NetFlow record
    sample_record = {
        'StartTime': '2011/08/10 09:46:53.047277',
        'Dur': '0.128',
        'Proto': 'tcp',
        'SrcAddr': '147.32.84.165',
        'Sport': '1026',
        'Dir': '->',
        'DstAddr': '239.255.255.250',
        'Dport': '1900',
        'State': 'CON',
        'sTos': '0',
        'dTos': '0',
        'TotPkts': '5',
        'TotBytes': '1024',
        'SrcBytes': '512',
        'Label': 'Botnet'
    }
    
    # Create parser
    dataset_path = Path("e:/BADNA/datasets/CTU-13-Dataset")
    parser = create_ctu13_parser(dataset_path)
    
    # Parse sample
    print("\nParsing sample NetFlow record...")
    unified_event = parser.normalize_to_schema(sample_record)
    
    print("\nUnifiedEvent Output:")
    print(f"  Event ID: {unified_event.event_id}")
    print(f"  Event Type: {unified_event.event_type}")
    print(f"  Timestamp: {unified_event.timestamp}")
    print(f"  Source: {unified_event.source_system}")
    print(f"\n  Network Flow:")
    ed = unified_event.event_data
    print(f"    {ed['src_ip']}:{ed['src_port']} {ed['direction']} {ed['dst_ip']}:{ed['dst_port']}")
    print(f"    Protocol: {ed['protocol']}")
    print(f"    Duration: {ed['duration']}s")
    print(f"    Bytes: {ed['total_bytes']} (src: {ed['src_bytes']})")
    print(f"    Label: {ed['label']}")
    print(f"    Is Botnet: {ed['is_botnet']}")
    
    # Validate
    try:
        unified_event.validate_required_fields()
        print("\n✓ UnifiedEvent validation passed")
    except ValueError as e:
        print(f"\n✗ Validation failed: {e}")
    
    print("\n" + "=" * 80)
    print("Parser test complete!")
    print("=" * 80)
