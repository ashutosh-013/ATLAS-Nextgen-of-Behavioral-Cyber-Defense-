"""
EMBER Parser - Parse EMBER PE malware feature datasets

This module contains:
1. EMBERParser - Parses EMBER JSON feature records.
2. EMBERPickleParser - Parses pickled angr CFG/PE objects from the dataset.

Uses dynamic import mocking to unpickle angr CFG/PE structures without requiring
the installation of angr and its complex binary dependencies.
"""

import sys
import json
import pickle
import logging
import types
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser, JSONParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser, JSONParser, ValidationError
    from ingestion.dataset_registry import DatasetMetadata

# --- Angr Import Mocking for Pickle Unserialization ---
class MockModule(types.ModuleType):
    def __init__(self, name):
        super().__init__(name)
        self.__path__ = []
        
    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        class DummyClass:
            def __init__(self, *args, **kwargs):
                pass
            def __setstate__(self, state):
                if isinstance(state, dict):
                    self.__dict__.update(state)
                elif isinstance(state, tuple):
                    for s in state:
                        if isinstance(s, dict):
                            self.__dict__.update(s)
        DummyClass.__name__ = name
        DummyClass.__qualname__ = name
        setattr(self, name, DummyClass)
        return DummyClass

class MockFinder:
    def find_spec(self, fullname, path, target=None):
        prefixes = ['angr', 'cle', 'claripy', 'pyvex', 'archinfo', 'z3', 'ailment']
        if any(fullname.startswith(p) for p in prefixes):
            from importlib.machinery import ModuleSpec
            return ModuleSpec(fullname, MockLoader())
        return None

class MockLoader:
    def create_module(self, spec):
        return MockModule(spec.name)
    def exec_module(self, module):
        pass

# Register the meta_path finder if not already registered
if not any(isinstance(f, MockFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, MockFinder())


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


class EMBERParser(JSONParser):
    """
    Parser for EMBER JSON PE feature format.
    Maps static PE features to simulated behavioral events.
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        super().__init__(dataset_metadata)
        self.logger.info("EMBER JSON Parser initialized")
        
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """Simulate a UnifiedEvent from raw EMBER JSON features (e.g. PE structure)"""
        # Validates that this looks like EMBER record (should have sha256 or general PE features)
        sha256 = raw_record.get('sha256', '')
        if not sha256:
            raise ValidationError("Record missing required EMBER field: sha256")
            
        # Try to extract imports or generic features
        imports = raw_record.get('imports', {})
        label = raw_record.get('label', 0)
        
        # Build simulated event
        event_id = f"ember_sim_{sha256[:8]}_file"
        timestamp = datetime.now().isoformat()
        
        # Default file event representing the malware execution
        event_data = {
            'action': 'write',
            'path': f"C:\\Windows\\Temp\\{sha256[:16]}.exe",
            'file_size': raw_record.get('size', 102400),
            'hash': sha256,
            'label': 'malware' if label == 1 else 'benign',
            'is_malicious': label == 1,
            'api_imports': list(imports.keys())
        }
        
        return UnifiedEvent(
            event_id=event_id,
            event_type='file',
            timestamp=timestamp,
            source_system=self.metadata.dataset_id,
            event_data=event_data
        )


class EMBERPickleParser(BaseDatasetParser):
    """
    Parser for EMBER pre-extracted features in pickle format.
    Unpickles angr CFG/PE dumps and converts static API imports to event chains.
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        super().__init__(dataset_metadata)
        self.logger.info("EMBER Pickle Parser initialized")
        
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Unpickle the file and wrap the unpickled object in a raw record dictionary"""
        self.logger.info(f"Unpickling EMBER file: {filepath}")
        try:
            with open(filepath, 'rb') as f:
                d = pickle.load(f)
            return [{'unpickled_obj': d, 'filepath': str(filepath)}]
        except Exception as e:
            self.logger.error(f"Error unpickling file {filepath}: {e}")
            raise ValidationError(f"Failed to parse pickle: {e}")
            
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """This method is required by interface but we implement parse_and_normalize for multi-event return"""
        events = self.normalize_to_events(raw_record)
        if events:
            return events[0]
        raise ValidationError("No events generated from pickled record")
        
    def normalize_to_events(self, raw_record: Dict[str, Any]) -> List[UnifiedEvent]:
        """
        Convert unpickled PE/angr structure to a sequence of causal UnifiedEvents.
        
        Maps imported APIs to corresponding file, registry, network, and process events.
        """
        d = raw_record.get('unpickled_obj')
        filepath_str = raw_record.get('filepath', '')
        
        if not d:
            raise ValidationError("Raw record missing unpickled object")
            
        # Extract filename and sha256 from project
        filename = "unknown_binary"
        sha256 = "unknown_sha256"
        if hasattr(d, 'project') and d.project:
            filename = getattr(d.project, 'filename', filename)
            # Use file name as sha256 if it is 64 hex chars
            basename = Path(filename).name
            if len(basename) == 64:
                sha256 = basename
                
        # Get imported APIs from loader main object
        imports = []
        if hasattr(d, 'project') and d.project and hasattr(d.project, 'loader') and d.project.loader:
            main_obj = getattr(d.project.loader, '_main_object', None)
            if main_obj and hasattr(main_obj, 'imports') and isinstance(main_obj.imports, dict):
                imports = list(main_obj.imports.keys())
                
        # Generate base timestamp
        base_time = int(datetime.now().timestamp()) - 3600 # 1 hour ago
        
        events = []
        
        # 1. Generate base file write/execute event representing binary drop
        events.append(UnifiedEvent(
            event_id=f"ember_file_{sha256[:8]}_drop",
            event_type='file',
            timestamp=datetime.fromtimestamp(base_time).isoformat(),
            source_system=self.metadata.dataset_id,
            event_data={
                'action': 'write',
                'path': filename,
                'file_size': 0,
                'hash': sha256
            }
        ))
        
        # 2. Generate process execution event
        base_time += 1
        pid = 9000
        events.append(UnifiedEvent(
            event_id=f"ember_proc_{sha256[:8]}_exec",
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
        
        # 3. Translate API imports to events
        for i, api in enumerate(imports):
            api_lower = api.lower()
            mapped = False
            for trigger, (etype, action) in API_MAPPING.items():
                if trigger in api_lower:
                    base_time += 1
                    event_id = f"ember_sim_{sha256[:8]}_{etype}_{i}"
                    
                    # Build event_data based on event type
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
                            'path': f"C:\\Windows\\Temp\\file_{i}.dat",
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
                            'src_ip': '192.168.1.100',
                            'dest_ip': '10.0.0.50',
                            'dest_port': 80 if 'http' in api_lower else 443,
                            'protocol': 'TCP',
                            'pid': pid
                        }
                        
                    ed['properties'] = {'triggered_by_api': api}
                    
                    events.append(UnifiedEvent(
                        event_id=event_id,
                        event_type=etype,
                        timestamp=datetime.fromtimestamp(base_time).isoformat(),
                        source_system=self.metadata.dataset_id,
                        event_data=ed
                    ))
                    mapped = True
                    break
                    
        return events
        
    def parse_and_normalize(self, filepath: Path, 
                            validate: bool = True,
                            max_records: Optional[int] = None) -> List[UnifiedEvent]:
        """Override parse_and_normalize to handle multi-event emission from single pickle file"""
        self.logger.info(f"Parsing and normalizing pickle: {filepath}")
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
                self.logger.error(f"Error parsing record: {e}")
                continue
                
        self.stats['total_records'] = len(raw_records)
        return all_events


def create_ember_parser(dataset_path: Path) -> EMBERParser:
    """Factory function for EMBER parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    metadata = DatasetMetadata(
        dataset_id="ember",
        name="EMBER Malware Dataset",
        dataset_type=DatasetType.MALWARE_SAMPLES,
        format=DatasetFormat.JSON,
        path=dataset_path,
        parser_class="EMBERParser",
        description="EMBER JSON parser",
        source="EMBER",
        event_types=["file"],
        timestamp_field=None
    )
    return EMBERParser(metadata)


def create_ember_pickle_parser(dataset_path: Path) -> EMBERPickleParser:
    """Factory function for EMBER Pickle parser"""
    from ingestion.dataset_registry import DatasetType, DatasetFormat
    metadata = DatasetMetadata(
        dataset_id="ember_features_pkl",
        name="EMBER Pickled Features",
        dataset_type=DatasetType.MALWARE_SAMPLES,
        format=DatasetFormat.PKL,
        path=dataset_path,
        parser_class="EMBERPickleParser",
        description="EMBER Pickle parser",
        source="EMBER",
        event_types=["file", "process", "registry", "network"],
        timestamp_field=None
    )
    return EMBERPickleParser(metadata)
