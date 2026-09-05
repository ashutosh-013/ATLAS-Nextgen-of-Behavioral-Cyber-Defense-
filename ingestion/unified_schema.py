"""
Unified Event Schema - Common format for all security events

This module defines the UnifiedEvent schema that all dataset parsers output to.
This schema is designed to be directly consumable by the existing BehaviorCaptureEngine.

Task: 1.2 - Unified Event Schema
Integration: Feeds directly into BehaviorCaptureEngine.parse_events()
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
import json


class EventType(Enum):
    """
    Security event types supported by BADNA BehaviorCaptureEngine.
    
    These must match the event types defined in behavior/capture_engine.py
    """
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    AUTH = "auth"
    REGISTRY = "registry"
    USER = "user"


@dataclass
class UnifiedEvent:
    """
    Unified security event format compatible with BehaviorCaptureEngine.
    
    This schema matches the input format expected by BehaviorCaptureEngine.parse_events().
    All dataset parsers MUST output this format.
    
    Schema Specification:
    ---------------------
    event_id: str
        Unique identifier for this event
        
    event_type: str
        Type of security event (process, file, network, auth, registry, user)
        Must be one of EventType enum values
        
    timestamp: str or datetime
        Event occurrence time (ISO 8601 format preferred)
        Will be parsed by BehaviorCaptureEngine
        
    source_system: str (optional)
        Origin system/dataset identifier
        Default: "unknown"
        
    event_data: dict
        Flexible dictionary containing event-specific fields
        Structure depends on event_type:
        
        Process Events (event_type='process'):
            - pid: int (required)
            - action: str (required) - create, terminate, parent_child
            - name: str (optional) - process name
            - command_line: str (optional)
            - parent_pid: int (optional)
            
        File Events (event_type='file'):
            - path: str (required)
            - action: str (required) - read, write, delete, encrypt, rename
            - file_size: int (optional)
            - hash: str (optional)
            
        Network Events (event_type='network'):
            - action: str (required) - dns, http, https, smb, c2, beaconing, upload, download
            - source_ip: str (optional)
            - dest_ip: str (optional)
            - source_port: int (optional)
            - dest_port: int (optional)
            - protocol: str (optional)
            - domain: str (optional)
            - url: str (optional)
            
        Auth Events (event_type='auth'):
            - user: str (required)
            - action: str (required) - login, logout, escalate, token_abuse
            - success: bool (optional)
            - source_ip: str (optional)
            
        Registry Events (event_type='registry'):
            - key_path: str (required)
            - action: str (required) - modify, create, delete, service_create, scheduled_task
            - value: str (optional)
            
        User Events (event_type='user'):
            - action: str (required) - mouse, keyboard, usb, session
            - user: str (optional)
    
    Design Rationale:
    -----------------
    - Flexible event_data dict allows dataset-specific fields without schema changes
    - event_type enum ensures compatibility with BehaviorCaptureEngine
    - Required fields enforce minimum data quality
    - Optional fields enable enrichment without breaking parsers
    - Direct compatibility with existing BADNA pipeline
    
    Example Usage:
    --------------
    >>> event = UnifiedEvent(
    ...     event_id="evt_001",
    ...     event_type="process",
    ...     timestamp="2024-01-01T10:00:00",
    ...     source_system="darpa_optc",
    ...     event_data={
    ...         "pid": 1234,
    ...         "action": "create",
    ...         "name": "powershell.exe",
    ...         "command_line": "powershell.exe -enc ..."
    ...     }
    ... )
    >>> event.to_dict()
    {'event_id': 'evt_001', 'event_type': 'process', ...}
    """
    
    event_id: str
    event_type: str  # Will be validated against EventType
    timestamp: Any  # str or datetime, BehaviorCaptureEngine handles both
    source_system: str = "unknown"
    event_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate event_type and ensure event_data is dict"""
        # Validate event_type
        if isinstance(self.event_type, EventType):
            self.event_type = self.event_type.value
        
        valid_types = [et.value for et in EventType]
        if self.event_type not in valid_types:
            raise ValueError(
                f"Invalid event_type '{self.event_type}'. "
                f"Must be one of: {', '.join(valid_types)}"
            )
        
        # Ensure event_data is a dict
        if not isinstance(self.event_data, dict):
            raise TypeError(f"event_data must be dict, got {type(self.event_data)}")
        
        # Convert timestamp to string if datetime
        if isinstance(self.timestamp, datetime):
            self.timestamp = self.timestamp.isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format expected by BehaviorCaptureEngine.
        
        Returns:
            Dictionary with event_id, event_type, timestamp, source_system, event_data
        """
        return asdict(self)
    
    def to_json(self) -> str:
        """Serialize to JSON string"""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UnifiedEvent':
        """
        Create UnifiedEvent from dictionary.
        
        Args:
            data: Dictionary with event fields
            
        Returns:
            UnifiedEvent instance
        """
        return cls(**data)
    
    def validate_required_fields(self) -> bool:
        """
        Validate that required fields are present in event_data based on event_type.
        
        Returns:
            True if valid, raises ValueError if invalid
        """
        event_type = self.event_type
        data = self.event_data
        
        if event_type == "process":
            if "pid" not in data:
                raise ValueError("Process event missing required field: pid")
            if "action" not in data:
                raise ValueError("Process event missing required field: action")
                
        elif event_type == "file":
            if "path" not in data:
                raise ValueError("File event missing required field: path")
            if "action" not in data:
                raise ValueError("File event missing required field: action")
                
        elif event_type == "network":
            if "action" not in data:
                raise ValueError("Network event missing required field: action")
                
        elif event_type == "auth":
            if "user" not in data:
                raise ValueError("Auth event missing required field: user")
            if "action" not in data:
                raise ValueError("Auth event missing required field: action")
                
        elif event_type == "registry":
            if "key_path" not in data:
                raise ValueError("Registry event missing required field: key_path")
            if "action" not in data:
                raise ValueError("Registry event missing required field: action")
                
        elif event_type == "user":
            if "action" not in data:
                raise ValueError("User event missing required field: action")
        
        return True


# Helper functions for common event creation patterns

def create_process_event(event_id: str, timestamp: Any, pid: int, action: str,
                        name: Optional[str] = None, command_line: Optional[str] = None,
                        parent_pid: Optional[int] = None, source_system: str = "unknown",
                        **kwargs) -> UnifiedEvent:
    """
    Create a process event.
    
    Args:
        event_id: Unique event identifier
        timestamp: Event timestamp
        pid: Process ID
        action: Process action (create, terminate, parent_child)
        name: Process name (optional)
        command_line: Command line (optional)
        parent_pid: Parent process ID (optional)
        source_system: Source dataset/system
        **kwargs: Additional event_data fields
        
    Returns:
        UnifiedEvent with process event data
    """
    event_data = {
        "pid": pid,
        "action": action,
        **kwargs
    }
    
    if name:
        event_data["name"] = name
    if command_line:
        event_data["command_line"] = command_line
    if parent_pid:
        event_data["parent_pid"] = parent_pid
    
    return UnifiedEvent(
        event_id=event_id,
        event_type="process",
        timestamp=timestamp,
        source_system=source_system,
        event_data=event_data
    )


def create_file_event(event_id: str, timestamp: Any, path: str, action: str,
                     file_size: Optional[int] = None, hash: Optional[str] = None,
                     source_system: str = "unknown", **kwargs) -> UnifiedEvent:
    """Create a file event"""
    event_data = {
        "path": path,
        "action": action,
        **kwargs
    }
    
    if file_size:
        event_data["file_size"] = file_size
    if hash:
        event_data["hash"] = hash
    
    return UnifiedEvent(
        event_id=event_id,
        event_type="file",
        timestamp=timestamp,
        source_system=source_system,
        event_data=event_data
    )


def create_network_event(event_id: str, timestamp: Any, action: str,
                        source_ip: Optional[str] = None, dest_ip: Optional[str] = None,
                        source_port: Optional[int] = None, dest_port: Optional[int] = None,
                        protocol: Optional[str] = None, domain: Optional[str] = None,
                        source_system: str = "unknown", **kwargs) -> UnifiedEvent:
    """Create a network event"""
    event_data = {
        "action": action,
        **kwargs
    }
    
    if source_ip:
        event_data["source_ip"] = source_ip
    if dest_ip:
        event_data["dest_ip"] = dest_ip
    if source_port:
        event_data["source_port"] = source_port
    if dest_port:
        event_data["dest_port"] = dest_port
    if protocol:
        event_data["protocol"] = protocol
    if domain:
        event_data["domain"] = domain
    
    return UnifiedEvent(
        event_id=event_id,
        event_type="network",
        timestamp=timestamp,
        source_system=source_system,
        event_data=event_data
    )


def create_auth_event(event_id: str, timestamp: Any, user: str, action: str,
                     success: Optional[bool] = None, source_ip: Optional[str] = None,
                     source_system: str = "unknown", **kwargs) -> UnifiedEvent:
    """Create an authentication event"""
    event_data = {
        "user": user,
        "action": action,
        **kwargs
    }
    
    if success is not None:
        event_data["success"] = success
    if source_ip:
        event_data["source_ip"] = source_ip
    
    return UnifiedEvent(
        event_id=event_id,
        event_type="auth",
        timestamp=timestamp,
        source_system=source_system,
        event_data=event_data
    )


if __name__ == "__main__":
    # Test UnifiedEvent creation and validation
    print("Testing UnifiedEvent Schema...")
    
    # Test 1: Process event
    print("\n1. Creating process event...")
    process_event = create_process_event(
        event_id="test_001",
        timestamp="2024-01-01T10:00:00",
        pid=1234,
        action="create",
        name="powershell.exe",
        command_line="powershell.exe -enc ABC123",
        source_system="test"
    )
    print(f"   Event Type: {process_event.event_type}")
    print(f"   Event Data: {process_event.event_data}")
    process_event.validate_required_fields()
    print("   ✓ Process event valid")
    
    # Test 2: File event
    print("\n2. Creating file event...")
    file_event = create_file_event(
        event_id="test_002",
        timestamp="2024-01-01T10:00:01",
        path="/tmp/malicious.exe",
        action="write",
        file_size=102400,
        source_system="test"
    )
    print(f"   Event Type: {file_event.event_type}")
    print(f"   Event Data: {file_event.event_data}")
    file_event.validate_required_fields()
    print("   ✓ File event valid")
    
    # Test 3: Network event
    print("\n3. Creating network event...")
    network_event = create_network_event(
        event_id="test_003",
        timestamp="2024-01-01T10:00:02",
        action="dns",
        domain="malicious.com",
        source_ip="192.168.1.10",
        dest_ip="8.8.8.8",
        source_system="test"
    )
    print(f"   Event Type: {network_event.event_type}")
    print(f"   Event Data: {network_event.event_data}")
    network_event.validate_required_fields()
    print("   ✓ Network event valid")
    
    # Test 4: Auth event
    print("\n4. Creating auth event...")
    auth_event = create_auth_event(
        event_id="test_004",
        timestamp="2024-01-01T10:00:03",
        user="admin",
        action="login",
        success=False,
        source_ip="10.0.0.50",
        source_system="test"
    )
    print(f"   Event Type: {auth_event.event_type}")
    print(f"   Event Data: {auth_event.event_data}")
    auth_event.validate_required_fields()
    print("   ✓ Auth event valid")
    
    # Test 5: Conversion to dict (for BehaviorCaptureEngine)
    print("\n5. Testing conversion to dict...")
    event_dict = process_event.to_dict()
    print(f"   Keys: {list(event_dict.keys())}")
    print(f"   ✓ Dict conversion successful")
    
    # Test 6: Invalid event type
    print("\n6. Testing validation...")
    try:
        invalid_event = UnifiedEvent(
            event_id="test_invalid",
            event_type="invalid_type",
            timestamp="2024-01-01T10:00:00",
            event_data={}
        )
        print("   ✗ Validation failed - should have raised error")
    except ValueError as e:
        print(f"   ✓ Validation caught invalid type: {e}")
    
    print("\n✓ All UnifiedEvent tests passed!")
