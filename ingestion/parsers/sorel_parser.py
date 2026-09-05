"""
SOREL-20M Parser - Parse SOREL-20M PE metadata JSON files

This parser extracts PE headers, sections, and imported symbols from SOREL JSON files,
and generates simulated behavioral UnifiedEvents (process, file, registry, network).

Dataset: SOREL-20M
Format: JSON PE Metadata
Source: datasets/SOREL-20M-master/
Output: UnifiedEvent sequence
"""

import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import JSONParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import JSONParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata


# --- API to UnifiedEvent Mapping ---
API_MAPPING = {
    # File operations
    'copyfile': ('file', 'write'),
    'createfile': ('file', 'create'),
    'writefile': ('file', 'write'),
    'readfile': ('file', 'read'),
    'deletefile': ('file', 'delete'),
    'movefile': ('file', 'rename'),
    'setfileattributes': ('file', 'modify'),
    'getfileattributes': ('file', 'read'),
    
    # Process operations
    'createprocess': ('process', 'create'),
    'winexec': ('process', 'create'),
    'shellexecute': ('process', 'create'),
    'terminateprocess': ('process', 'terminate'),
    
    # Registry operations
    'regcreatekey': ('registry', 'create'),
    'regopenkey': ('registry', 'modify'),
    'regsetvalue': ('registry', 'modify'),
    'regdeletekey': ('registry', 'delete'),
    
    # Network operations
    'internetopen': ('network', 'connect'),
    'internetconnect': ('network', 'connect'),
    'httpsendrequest': ('network', 'connect'),
    'gethostbyname': ('network', 'dns'),
    'socket': ('network', 'connect'),
    'connect': ('network', 'connect'),
    'send': ('network', 'send'),
    'recv': ('network', 'receive'),
}


class SORELParser(JSONParser):
    """
    Parser for SOREL-20M metadata JSON format.
    Translates static imported symbols and sections to simulated behavioral events.
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        super().__init__(dataset_metadata)
        self.logger.info("SOREL Parser initialized")
        
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """This method is required by base class interface, but we implement normalize_to_events for multi-event return"""
        events = self.normalize_to_events(raw_record)
        if events:
            return events[0]
        raise ValidationError("No events generated from SOREL record")
        
    def normalize_to_events(self, raw_record: Dict[str, Any]) -> List[UnifiedEvent]:
        """
        Convert raw SOREL-20M JSON metadata to a sequence of causal UnifiedEvents.
        
        Maps imported symbols and PE sections to simulated events.
        """
        # Find the first top-level key which has DOS_HEADER (usually "0")
        pe_key = None
        for k in raw_record.keys():
            if isinstance(raw_record[k], dict) and 'DOS_HEADER' in raw_record[k]:
                pe_key = k
                break
                
        if not pe_key:
            raise ValidationError("SOREL JSON record missing valid PE metadata object structure")
            
        pe_data = raw_record[pe_key]
        
        # Get SHA256 from filename metadata if available
        filepath = raw_record.get('__filepath__', '')
        sha256 = "unknown_sha256"
        if filepath:
            name = Path(filepath).stem
            # Verify if name looks like a 64 hex char hash
            if len(name) == 64:
                sha256 = name
                
        # Extract imported functions and DLLs
        funcs = []
        dlls = []
        imported_symbols = pe_data.get('Imported symbols', [])
        for sublist in imported_symbols:
            if isinstance(sublist, list):
                for item in sublist:
                    if not isinstance(item, dict):
                        continue
                    if 'DLL' in item:
                        dlls.append(item['DLL'])
                    if 'Name' in item and 'Structure' not in item:
                        funcs.append(item['Name'])
                        
        # Extract sections
        sections = []
        pe_sections = pe_data.get('PE Sections', [])
        for sec in pe_sections:
            if isinstance(sec, dict) and 'Name' in sec:
                name_val = sec['Name'].get('Value', '')
                # Clean clean null bytes or padding in section name
                name_val = name_val.replace('\\x00', '').strip()
                sections.append(name_val)
                
        # Generate base timestamp
        base_time = int(datetime.now().timestamp()) - 3600 # 1 hour ago
        events = []
        pid = 8500
        
        # 1. Base file drop event
        filename = f"C:\\Windows\\System32\\{sha256[:16]}.exe"
        events.append(UnifiedEvent(
            event_id=f"sorel_file_{sha256[:8]}_drop",
            event_type='file',
            timestamp=datetime.fromtimestamp(base_time).isoformat(),
            source_system=self.metadata.dataset_id,
            event_data={
                'action': 'write',
                'path': filename,
                'file_size': pe_data.get('OPTIONAL_HEADER', {}).get('SizeOfImage', {}).get('Value', 0),
                'hash': sha256
            }
        ))
        
        # 2. Process execution event
        base_time += 1
        events.append(UnifiedEvent(
            event_id=f"sorel_proc_{sha256[:8]}_exec",
            event_type='process',
            timestamp=datetime.fromtimestamp(base_time).isoformat(),
            source_system=self.metadata.dataset_id,
            event_data={
                'action': 'create',
                'pid': pid,
                'name': Path(filename).name,
                'command_line': f'"{filename}"',
                'parent_pid': 1000
            }
        ))
        
        # 3. Simulated events for executable PE sections (like .text, UPX0 etc.)
        for sec_name in sections:
            if sec_name.lower() in ('.text', 'code', 'upx0', 'upx1'):
                base_time += 1
                events.append(UnifiedEvent(
                    event_id=f"sorel_sec_{sha256[:8]}_{sec_name.replace('.', '')}",
                    event_type='file',
                    timestamp=datetime.fromtimestamp(base_time).isoformat(),
                    source_system=self.metadata.dataset_id,
                    event_data={
                        'action': 'modify',
                        'path': f"{filename}:{sec_name}",
                        'pid': pid,
                        'properties': {'description': f"Executable section memory mapping: {sec_name}"}
                    }
                ))
                
        # 4. Simulated events for imported API triggers
        for i, api in enumerate(funcs):
            api_lower = api.lower()
            for trigger, (etype, action) in API_MAPPING.items():
                if trigger in api_lower:
                    base_time += 1
                    event_id = f"sorel_sim_{sha256[:8]}_{etype}_{i}"
                    
                    if etype == 'process':
                        ed = {
                            'action': action,
                            'pid': pid + 10 + i,
                            'name': f"spawned_{api_lower}.exe",
                            'parent_pid': pid
                        }
                    elif etype == 'file':
                        ed = {
                            'action': action,
                            'path': f"C:\\Windows\\Temp\\sorel_file_{i}.tmp",
                            'pid': pid
                        }
                    elif etype == 'registry':
                        ed = {
                            'action': action,
                            'key_path': f"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{api}",
                            'pid': pid
                        }
                    elif etype == 'network':
                        ed = {
                            'action': action,
                            'src_ip': '192.168.1.101',
                            'dest_ip': '8.8.8.8',
                            'dest_port': 53 if 'dns' in api_lower else 443,
                            'protocol': 'UDP' if 'dns' in api_lower else 'TCP',
                            'pid': pid
                        }
                        
                    ed['properties'] = {
                        'triggered_by_api': api,
                        'imported_dlls': dlls
                    }
                    
                    events.append(UnifiedEvent(
                        event_id=event_id,
                        event_type=etype,
                        timestamp=datetime.fromtimestamp(base_time).isoformat(),
                        source_system=self.metadata.dataset_id,
                        event_data=ed
                    ))
                    break
                    
        return events
        
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Overridden to inject filepath metadata into parsed record dict"""
        raw_records = super().parse_file(filepath)
        for r in raw_records:
            if isinstance(r, dict):
                r['__filepath__'] = str(filepath)
        return raw_records
        
    def parse_and_normalize(self, filepath: Path, 
                            validate: bool = True,
                            max_records: Optional[int] = None) -> List[UnifiedEvent]:
        """Overridden to handle multi-event emission from single JSON file"""
        self.logger.info(f"Parsing and normalizing SOREL JSON: {filepath}")
        raw_records = self.parse_file(filepath)
        
        all_events = []
        for raw_record in raw_records:
            try:
                events = self.normalize_to_events(raw_record)
                if validate:
                    for ev in events:
                        self.validate_record(ev)
                all_events.extend(events)
                self.stats['valid_records'] += 1
            except Exception as e:
                self.stats['invalid_records'] += 1
                self.logger.error(f"Error parsing SOREL record: {e}")
                continue
                
        self.stats['total_records'] = len(raw_records)
        return all_events


def create_sorel_parser(dataset_path: Path) -> SORELParser:
    """Factory function for SOREL parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    
    metadata = DatasetMetadata(
        dataset_id="sorel_20m",
        name="SOREL-20M Malware Dataset",
        dataset_type=DatasetType.MALWARE_SAMPLES,
        format=DatasetFormat.JSON,
        path=dataset_path,
        parser_class="SORELParser",
        description="SOREL-20M JSON metadata parser",
        source="SOREL-20M",
        event_types=["file", "process", "registry", "network"],
        timestamp_field=None
    )
    return SORELParser(metadata)
