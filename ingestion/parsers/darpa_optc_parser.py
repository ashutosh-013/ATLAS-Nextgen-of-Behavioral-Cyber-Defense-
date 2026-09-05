"""
DARPA OpTC Parser - Parse DARPA Operational Transparent Computing dataset

This parser converts DARPA OpTC eCAR (extended Cyber Analytics Repository) JSON format
to UnifiedEvent objects compatible with BADNA's BehaviorCaptureEngine.

Dataset: DARPA OpTC (Operationally Transparent Cyber)
Format: eCAR JSON (event-based provenance graphs)
Source: datasets/OpTC-data-master/

Task: 1.1 - Implement DARPA OpTC Parser
Requirements: 2.1-2.8
Integration: Inherits from BaseDatasetParser, outputs UnifiedEvent objects
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

# Handle imports for both module and standalone execution
try:
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser
    from ingestion.dataset_registry import DatasetMetadata
except ImportError:
    # Fallback for standalone execution
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ingestion.unified_schema import UnifiedEvent
    from ingestion.base_parser import BaseDatasetParser
    from ingestion.dataset_registry import DatasetMetadata


class DARPAOpTCParser(BaseDatasetParser):
    """
    Parser for DARPA OpTC eCAR format.
    
    The eCAR format is event-based with structure:
    {
        "timestamp": <ms since epoch>,
        "id": <UUID>,
        "hostname": <string>,
        "objectID": <UUID of object involved>,
        "object": <ObjectType: PROCESS, FILE, FLOW, etc.>,
        "action": <ActionType: CREATE, OPEN, CONNECT, etc.>,
        "actorID": <UUID of actor (process/host)>,
        "pid": <process ID>,
        "ppid": <parent process ID>,
        "tid": <thread ID>,
        "principal": <user entity>,
        "properties": {<key: value pairs>}
    }
    
    Mapping to UnifiedEvent:
    - PROCESS events with CREATE/TERMINATE actions → event_type='process'
    - FILE events with OPEN/READ/WRITE/DELETE → event_type='file'
    - FLOW events with START/CONNECT → event_type='network'
    - Authentication events → event_type='auth'
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """Initialize DARPA OpTC parser"""
        super().__init__(dataset_metadata)
        
        # eCAR object type to UnifiedEvent event_type mapping
        self.object_type_map = {
            "PROCESS": "process",
            "FILE": "file",
            "FLOW": "network",
            "FLOW-START": "network",
            "FLOW-END": "network",
            "REGISTRY": "registry",
            "USER_SESSION": "auth",
            "THREAD": "process",  # Thread events map to process
        }
        
        # eCAR action type mapping to UnifiedEvent action verbs
        self.action_map = {
            # Process actions
            "CREATE": "create",
            "TERMINATE": "terminate",
            "OPEN": "open",
            
            # File actions
            "READ": "read",
            "WRITE": "write",
            "DELETE": "delete",
            "MODIFY": "modify",
            "RENAME": "rename",
            "ENCRYPT": "encrypt",
            
            # Network actions
            "CONNECT": "connect",
            "START": "connect",
            "END": "disconnect",
            "SEND": "send",
            "RECEIVE": "receive",
            
            # Auth actions
            "LOGIN": "login",
            "LOGOUT": "logout",
            "ESCALATE": "escalate",
            
            # Registry actions
            "ADD_KEY": "create",
            "EDIT_KEY": "modify",
            "REMOVE_KEY": "delete",
        }
        
        self.logger.info("DARPA OpTC Parser initialized")
    
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """
        Parse eCAR JSON file.
        
        eCAR files can be:
        1. Single JSON object per file
        2. JSON array of objects
        3. JSONL (one JSON object per line)
        
        Args:
            filepath: Path to eCAR JSON file
            
        Returns:
            List of raw eCAR event dictionaries
        """
        self.logger.info(f"Parsing eCAR file: {filepath.name}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Try to read entire file as JSON
                content = f.read().strip()
                
                if not content:
                    self.logger.warning(f"Empty file: {filepath}")
                    return []
                
                # Try parsing as JSON array or single object
                try:
                    data = json.loads(content)
                    
                    if isinstance(data, list):
                        self.logger.info(f"Parsed JSON array with {len(data)} events")
                        return data
                    elif isinstance(data, dict):
                        self.logger.info(f"Parsed single JSON object")
                        return [data]
                    else:
                        self.logger.error(f"Unexpected JSON type: {type(data)}")
                        return []
                
                except json.JSONDecodeError:
                    # Try parsing as JSONL (one JSON object per line)
                    self.logger.info("JSON parsing failed, trying JSONL format...")
                    events = []
                    
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if not line:
                                continue
                            
                            try:
                                event = json.loads(line)
                                events.append(event)
                            except json.JSONDecodeError as e:
                                self.logger.warning(
                                    f"Failed to parse line {line_num}: {e}"
                                )
                                continue
                    
                    self.logger.info(f"Parsed JSONL with {len(events)} events")
                    return events
        
        except Exception as e:
            self.logger.error(f"Failed to parse file {filepath}: {e}")
            raise
    
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """
        Convert eCAR event to UnifiedEvent.
        
        Args:
            raw_record: Raw eCAR event dictionary
            
        Returns:
            UnifiedEvent instance
        """
        # Extract basic fields
        event_id = raw_record.get("id", "unknown")
        
        # Map eCAR object type to UnifiedEvent event_type
        ecar_object = raw_record.get("object", "PROCESS")
        event_type = self.object_type_map.get(ecar_object, "process")
        
        # Parse timestamp (eCAR uses milliseconds since epoch)
        timestamp = self._parse_timestamp(raw_record.get("timestamp"))
        
        # Map eCAR action
        ecar_action = raw_record.get("action", "")
        action = self.action_map.get(ecar_action, ecar_action.lower())
        
        # Build event_data based on event type
        event_data = self._build_event_data(
            raw_record, event_type, action
        )
        
        return UnifiedEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source_system=self.metadata.dataset_id,
            event_data=event_data
        )
    
    def _parse_timestamp(self, timestamp_ms: Any) -> str:
        """
        Convert eCAR timestamp (milliseconds since epoch) to ISO 8601.
        
        Args:
            timestamp_ms: Timestamp in milliseconds since epoch
            
        Returns:
            ISO 8601 formatted datetime string
        """
        if timestamp_ms is None:
            return datetime.now().isoformat()
        
        try:
            # Convert milliseconds to seconds
            timestamp_sec = int(timestamp_ms) / 1000.0
            dt = datetime.fromtimestamp(timestamp_sec)
            return dt.isoformat()
        except (ValueError, TypeError, OSError) as e:
            self.logger.warning(f"Failed to parse timestamp {timestamp_ms}: {e}")
            return datetime.now().isoformat()
    
    def _build_event_data(self, raw_record: Dict[str, Any], 
                          event_type: str, action: str) -> Dict[str, Any]:
        """
        Build event_data dictionary based on event type.
        
        Args:
            raw_record: Raw eCAR event
            event_type: Unified event type
            action: Mapped action string
            
        Returns:
            Event-specific data dictionary
        """
        properties = raw_record.get("properties", {})
        
        # Base data present in all events
        event_data = {
            "action": action,
            "hostname": raw_record.get("hostname", "unknown"),
            "principal": raw_record.get("principal", ""),
            "object_id": raw_record.get("objectID", ""),
            "actor_id": raw_record.get("actorID", ""),
        }
        
        if event_type == "process":
            # Process event data
            pid = raw_record.get("pid", -1)
            ppid = raw_record.get("ppid", -1)
            
            event_data.update({
                "pid": pid if pid != -1 else None,
                "parent_pid": ppid if ppid != -1 else None,
                "tid": raw_record.get("tid", -1),
                "name": self._extract_process_name(properties),
                "command_line": properties.get("command_line", ""),
                "image_path": properties.get("image_path", ""),
                "parent_image_path": properties.get("parent_image_path", ""),
                "user": properties.get("user", ""),
                "sid": properties.get("sid", ""),
            })
        
        elif event_type == "file":
            # File event data
            event_data.update({
                "path": properties.get("file_path", properties.get("image_path", "")),
                "file_name": properties.get("file_name", ""),
                "file_size": properties.get("size", 0),
                "hash": properties.get("hash", properties.get("md5", "")),
                "pid": raw_record.get("pid", -1),
            })
        
        elif event_type == "network":
            # Network event data
            event_data.update({
                "source_ip": properties.get("src_ip", properties.get("source_ip", "")),
                "dest_ip": properties.get("dest_ip", properties.get("destination_ip", "")),
                "source_port": properties.get("src_port", properties.get("source_port", 0)),
                "dest_port": properties.get("dest_port", properties.get("destination_port", 0)),
                "protocol": properties.get("protocol", properties.get("proto", "")),
                "domain": properties.get("domain", properties.get("hostname", "")),
                "url": properties.get("url", ""),
                "bytes_sent": properties.get("bytes_sent", 0),
                "bytes_received": properties.get("bytes_received", 0),
                "pid": raw_record.get("pid", -1),
            })
        
        elif event_type == "auth":
            # Authentication event data
            event_data.update({
                "user": raw_record.get("principal", properties.get("user", "")),
                "success": properties.get("success", properties.get("result", "") == "SUCCESS"),
                "source_ip": properties.get("src_ip", properties.get("source_ip", "")),
                "session_id": properties.get("session_id", ""),
                "logon_type": properties.get("logon_type", ""),
            })
        
        elif event_type == "registry":
            # Registry event data
            event_data.update({
                "key_path": properties.get("key_path", properties.get("path", "")),
                "value": properties.get("value", properties.get("data", "")),
                "value_name": properties.get("value_name", ""),
                "pid": raw_record.get("pid", -1),
            })
        
        # Add all properties for additional context
        event_data["properties"] = properties
        
        # Preserve provenance metadata for graph construction
        event_data["provenance"] = {
            "object_id": raw_record.get("objectID", ""),
            "actor_id": raw_record.get("actorID", ""),
            "ecar_object": raw_record.get("object", ""),
            "ecar_action": raw_record.get("action", ""),
        }
        
        return event_data
    
    def _extract_process_name(self, properties: Dict[str, Any]) -> str:
        """
        Extract process name from properties.
        
        Tries to extract from:
        1. process_name field
        2. Last component of image_path
        3. Last component of command_line
        
        Args:
            properties: eCAR event properties
            
        Returns:
            Process name or empty string
        """
        # Try process_name field
        if "process_name" in properties:
            return properties["process_name"]
        
        # Try extracting from image_path
        image_path = properties.get("image_path", "")
        if image_path:
            # Extract filename from path (handle both Windows and Unix paths)
            name = image_path.split("\\")[-1].split("/")[-1]
            if name:
                return name
        
        # Try extracting from command_line
        command_line = properties.get("command_line", "")
        if command_line:
            # Extract first token (often the executable)
            parts = command_line.strip().split()
            if parts:
                # Get filename from path
                name = parts[0].split("\\")[-1].split("/")[-1]
                # Remove quotes
                name = name.strip('"').strip("'")
                if name:
                    return name
        
        return ""


def create_darpa_optc_parser(dataset_path: Path) -> DARPAOpTCParser:
    """
    Factory function to create DARPA OpTC parser.
    
    Args:
        dataset_path: Path to OpTC dataset directory
        
    Returns:
        Initialized DARPAOpTCParser instance
    """
    from ingestion.dataset_registry import DatasetType, DatasetFormat, DatasetStatus
    
    metadata = DatasetMetadata(
        dataset_id="darpa_optc",
        name="DARPA OpTC",
        dataset_type=DatasetType.ENDPOINT_TELEMETRY,
        format=DatasetFormat.CDM,
        path=dataset_path,
        parser_class="DARPAOpTCParser",
        description="DARPA Operational Transparent Computing dataset",
        source="DARPA",
        event_types=["process", "file", "network", "auth"],
        timestamp_field="timestamp"
    )
    
    return DARPAOpTCParser(metadata)


if __name__ == "__main__":
    # Test parser with sample data
    print("=" * 80)
    print("DARPA OpTC Parser Test")
    print("=" * 80)
    
    # Create sample eCAR event for testing
    sample_event = {
        "timestamp": 1539120748904,
        "id": "b9af81fb-066c-4cd6-97cb-b284aabd2d4f",
        "hostname": "VAGRANT-C2FDBFN",
        "objectID": "ece465ca-edf9-48c0-b2be-642ee2dd86d6",
        "object": "PROCESS",
        "action": "CREATE",
        "actorID": "0f0b0dfe-5744-4361-9611-d3a59a1bdfbf",
        "pid": 3648,
        "ppid": 6260,
        "tid": 292,
        "principal": "VAGRANT-C2FDBFN\\vagrant",
        "properties": {
            "parent_image_path": "\\Device\\HarddiskVolume1\\cygwin64\\bin\\bash.exe",
            "user": "VAGRANT-C2FDBFN\\vagrant",
            "command_line": "\"C:\\cygwin64\\bin\\locale.exe\"",
            "image_path": "\\Device\\HarddiskVolume1\\cygwin64\\bin\\locale.exe",
            "sid": "S-1-5-21-23003595-3114578871-2621762399-1000"
        }
    }
    
    # Create parser
    dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
    parser = create_darpa_optc_parser(dataset_path)
    
    # Parse sample event
    print("\nParsing sample eCAR event...")
    print(f"eCAR Object: {sample_event['object']}")
    print(f"eCAR Action: {sample_event['action']}")
    
    unified_event = parser.normalize_to_schema(sample_event)
    
    print("\nUnifiedEvent Output:")
    print(f"  Event ID: {unified_event.event_id}")
    print(f"  Event Type: {unified_event.event_type}")
    print(f"  Timestamp: {unified_event.timestamp}")
    print(f"  Source System: {unified_event.source_system}")
    print(f"  Event Data:")
    for key, value in unified_event.event_data.items():
        if key != "properties" and key != "provenance":
            print(f"    {key}: {value}")
    
    # Validate
    try:
        unified_event.validate_required_fields()
        print("\n✓ UnifiedEvent validation passed")
    except ValueError as e:
        print(f"\n✗ Validation failed: {e}")
    
    # Test conversion to dict (for BehaviorCaptureEngine)
    event_dict = unified_event.to_dict()
    print("\n✓ Converted to dict for BehaviorCaptureEngine")
    print(f"  Dict keys: {list(event_dict.keys())}")
    
    print("\n" + "=" * 80)
    print("Parser test complete!")
    print("=" * 80)
