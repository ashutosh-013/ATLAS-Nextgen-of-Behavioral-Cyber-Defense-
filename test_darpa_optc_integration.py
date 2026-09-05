"""
Integration test for DARPA OpTC Parser

Tests complete parsing workflow:
1. Parse eCAR JSON file (or simulated file)
2. Normalize to UnifiedEvent format
3. Validate UnifiedEvent schema
4. Verify compatibility with BehaviorCaptureEngine
5. Test error handling
"""

import sys
import json
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from ingestion.parsers.darpa_optc_parser import create_darpa_optc_parser
from ingestion.unified_schema import UnifiedEvent


def create_sample_ecar_file(filepath: Path, num_events: int = 10):
    """Create a sample eCAR JSON file for testing"""
    events = []
    
    # Process creation events
    for i in range(num_events // 3):
        events.append({
            "timestamp": 1539120748904 + i * 1000,
            "id": f"proc-event-{i:03d}",
            "hostname": "TEST-HOST-01",
            "objectID": f"proc-obj-{i:03d}",
            "object": "PROCESS",
            "action": "CREATE",
            "actorID": f"actor-{i:03d}",
            "pid": 1000 + i,
            "ppid": 500,
            "tid": 1,
            "principal": "TEST\\admin",
            "properties": {
                "image_path": f"C:\\Windows\\System32\\process{i}.exe",
                "command_line": f"process{i}.exe -arg1 -arg2",
                "user": "TEST\\admin",
                "sid": "S-1-5-21-1234567890-1234567890-1234567890-500"
            }
        })
    
    # File write events
    for i in range(num_events // 3):
        events.append({
            "timestamp": 1539120750000 + i * 1000,
            "id": f"file-event-{i:03d}",
            "hostname": "TEST-HOST-01",
            "objectID": f"file-obj-{i:03d}",
            "object": "FILE",
            "action": "WRITE",
            "actorID": f"actor-proc-{i:03d}",
            "pid": 2000 + i,
            "ppid": 1000,
            "tid": 1,
            "principal": "TEST\\admin",
            "properties": {
                "file_path": f"C:\\Users\\admin\\Documents\\file{i}.txt",
                "file_name": f"file{i}.txt",
                "size": 1024 * (i + 1),
                "hash": f"abc{i:03d}def{i:03d}"
            }
        })
    
    # Network connection events
    for i in range(num_events - 2 * (num_events // 3)):
        events.append({
            "timestamp": 1539120752000 + i * 1000,
            "id": f"net-event-{i:03d}",
            "hostname": "TEST-HOST-01",
            "objectID": f"net-obj-{i:03d}",
            "object": "FLOW",
            "action": "START",
            "actorID": f"actor-net-{i:03d}",
            "pid": 3000 + i,
            "ppid": 1500,
            "tid": 1,
            "principal": "TEST\\admin",
            "properties": {
                "src_ip": f"192.168.1.{100 + i}",
                "dest_ip": f"10.0.0.{50 + i}",
                "src_port": 50000 + i,
                "dest_port": 443,
                "protocol": "TCP",
                "domain": f"server{i}.example.com"
            }
        })
    
    # Write as JSON array
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(events, f, indent=2)
    
    return len(events)


def create_sample_jsonl_file(filepath: Path, num_events: int = 5):
    """Create a sample JSONL file (one JSON object per line)"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = {
                "timestamp": 1539120760000 + i * 1000,
                "id": f"jsonl-event-{i:03d}",
                "hostname": "JSONL-HOST",
                "objectID": f"obj-{i:03d}",
                "object": "PROCESS",
                "action": "TERMINATE",
                "actorID": f"actor-{i:03d}",
                "pid": 4000 + i,
                "ppid": 3000,
                "tid": 1,
                "principal": "JSONL\\user",
                "properties": {
                    "image_path": f"C:\\Programs\\app{i}.exe",
                    "exit_code": 0
                }
            }
            f.write(json.dumps(event) + '\n')
    
    return num_events


def test_json_array_parsing():
    """Test parsing JSON array format"""
    print("\n" + "=" * 80)
    print("Test 1: JSON Array Format Parsing")
    print("=" * 80)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = Path(f.name)
    
    try:
        # Create sample file
        num_events = create_sample_ecar_file(temp_file, num_events=15)
        print(f"\nCreated sample eCAR file with {num_events} events")
        
        # Create parser
        dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
        parser = create_darpa_optc_parser(dataset_path)
        
        # Parse and normalize
        print("Parsing file...")
        events = parser.parse_and_normalize(temp_file, validate=True)
        
        print(f"\n✓ Successfully parsed {len(events)} events")
        
        # Check event types distribution
        event_types = {}
        for event in events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        print("\nEvent Type Distribution:")
        for event_type, count in event_types.items():
            print(f"  {event_type}: {count}")
        
        # Validate all events have required fields
        for i, event in enumerate(events):
            try:
                event.validate_required_fields()
            except ValueError as e:
                print(f"  ✗ Event {i} validation failed: {e}")
                return False
        
        print(f"\n✓ All {len(events)} events validated successfully")
        
        # Check statistics
        stats = parser.get_statistics()
        print("\nParser Statistics:")
        print(f"  Total records: {stats['total_records']}")
        print(f"  Valid records: {stats['valid_records']}")
        print(f"  Invalid records: {stats['invalid_records']}")
        print(f"  Success rate: {stats['success_rate']:.2%}")
        
        return True
    
    finally:
        # Cleanup
        if temp_file.exists():
            temp_file.unlink()


def test_jsonl_parsing():
    """Test parsing JSONL format (one JSON object per line)"""
    print("\n" + "=" * 80)
    print("Test 2: JSONL Format Parsing")
    print("=" * 80)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        temp_file = Path(f.name)
    
    try:
        # Create sample JSONL file
        num_events = create_sample_jsonl_file(temp_file, num_events=5)
        print(f"\nCreated sample JSONL file with {num_events} events")
        
        # Create parser
        dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
        parser = create_darpa_optc_parser(dataset_path)
        
        # Parse and normalize
        print("Parsing JSONL file...")
        events = parser.parse_and_normalize(temp_file, validate=True)
        
        print(f"\n✓ Successfully parsed {len(events)} events from JSONL")
        
        # Validate
        for event in events:
            event.validate_required_fields()
        
        print(f"✓ All {len(events)} events validated successfully")
        
        return True
    
    finally:
        # Cleanup
        if temp_file.exists():
            temp_file.unlink()


def test_error_handling():
    """Test parser error handling"""
    print("\n" + "=" * 80)
    print("Test 3: Error Handling")
    print("=" * 80)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = Path(f.name)
    
    try:
        # Create file with mixed valid and invalid events
        events = [
            # Valid event
            {
                "timestamp": 1539120748904,
                "id": "valid-001",
                "hostname": "TEST-HOST",
                "objectID": "obj-001",
                "object": "PROCESS",
                "action": "CREATE",
                "actorID": "actor-001",
                "pid": 1234,
                "ppid": 500,
                "tid": 1,
                "principal": "TEST\\user",
                "properties": {
                    "image_path": "C:\\test.exe",
                    "command_line": "test.exe"
                }
            },
            # Missing required field (should be handled gracefully)
            {
                "id": "invalid-001",
                # Missing timestamp
                "hostname": "TEST-HOST",
                "object": "FILE",
                "action": "READ"
            },
            # Another valid event
            {
                "timestamp": 1539120749000,
                "id": "valid-002",
                "hostname": "TEST-HOST",
                "objectID": "obj-002",
                "object": "FILE",
                "action": "WRITE",
                "actorID": "actor-002",
                "pid": 1235,
                "ppid": 1234,
                "tid": 1,
                "principal": "TEST\\user",
                "properties": {
                    "file_path": "C:\\output.txt",
                    "size": 1024
                }
            }
        ]
        
        with open(temp_file, 'w') as f:
            json.dump(events, f)
        
        print("\nCreated file with mixed valid/invalid events")
        
        # Create parser
        dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
        parser = create_darpa_optc_parser(dataset_path)
        
        # Parse with validation
        print("Parsing file with error handling...")
        parsed_events = parser.parse_and_normalize(temp_file, validate=True)
        
        print(f"\n✓ Parser handled errors gracefully")
        print(f"  Valid events parsed: {len(parsed_events)}")
        
        # Check statistics
        stats = parser.get_statistics()
        print(f"  Total records processed: {stats['total_records']}")
        print(f"  Valid records: {stats['valid_records']}")
        print(f"  Invalid records: {stats['invalid_records']}")
        
        # Should have parsed at least the valid events
        if len(parsed_events) >= 2:
            print("\n✓ Error handling test passed")
            return True
        else:
            print("\n✗ Expected at least 2 valid events")
            return False
    
    finally:
        # Cleanup
        if temp_file.exists():
            temp_file.unlink()


def test_behavior_capture_compatibility():
    """Test compatibility with BehaviorCaptureEngine input format"""
    print("\n" + "=" * 80)
    print("Test 4: BehaviorCaptureEngine Compatibility")
    print("=" * 80)
    
    # Create parser
    dataset_path = Path("e:/BADNA/datasets/OpTC-data-master")
    parser = create_darpa_optc_parser(dataset_path)
    
    # Create sample event
    sample_event = {
        "timestamp": 1539120748904,
        "id": "compat-test-001",
        "hostname": "TEST-HOST",
        "objectID": "obj-001",
        "object": "PROCESS",
        "action": "CREATE",
        "actorID": "actor-001",
        "pid": 5000,
        "ppid": 4000,
        "tid": 1,
        "principal": "TEST\\admin",
        "properties": {
            "image_path": "C:\\Windows\\System32\\malware.exe",
            "command_line": "malware.exe -payload",
            "user": "TEST\\admin"
        }
    }
    
    # Normalize to UnifiedEvent
    unified_event = parser.normalize_to_schema(sample_event)
    
    # Convert to dict (format expected by BehaviorCaptureEngine)
    event_dict = unified_event.to_dict()
    
    print("\nUnifiedEvent → Dict conversion:")
    print(f"  Keys: {list(event_dict.keys())}")
    
    # Verify required fields
    required_fields = ['event_id', 'event_type', 'timestamp', 'source_system', 'event_data']
    missing = [f for f in required_fields if f not in event_dict]
    
    if missing:
        print(f"\n✗ Missing required fields: {missing}")
        return False
    
    print(f"\n✓ All required fields present")
    
    # Verify event_data structure for process events
    event_data = event_dict['event_data']
    required_process_fields = ['pid', 'action']
    missing_process = [f for f in required_process_fields if f not in event_data]
    
    if missing_process:
        print(f"✗ Missing required process fields: {missing_process}")
        return False
    
    print(f"✓ Process event_data structure correct")
    
    # Verify provenance metadata is preserved
    if 'provenance' in event_data:
        print(f"✓ Provenance metadata preserved for graph construction")
        prov = event_data['provenance']
        print(f"  - object_id: {prov.get('object_id')}")
        print(f"  - actor_id: {prov.get('actor_id')}")
    
    print("\n✓ BehaviorCaptureEngine compatibility test passed")
    return True


def main():
    """Run all integration tests"""
    print("=" * 80)
    print("DARPA OpTC Parser - Integration Test Suite")
    print("=" * 80)
    
    tests = [
        ("JSON Array Parsing", test_json_array_parsing),
        ("JSONL Parsing", test_jsonl_parsing),
        ("Error Handling", test_error_handling),
        ("BehaviorCaptureEngine Compatibility", test_behavior_capture_compatibility),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All integration tests passed!")
        return True
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
