# Dataset Parsers

This directory contains parsers for all supported cybersecurity datasets.

## Implementation Status

| Parser | Status | Priority | Lines | Complexity |
|--------|--------|----------|-------|------------|
| DARPAOpTCParser | ⏳ TODO | HIGH | ~800 | High |
| CTU13Parser | ⏳ TODO | HIGH | ~300 | Medium |
| CICIDSParser | ⏳ TODO | MEDIUM | ~300 | Medium |
| EMBERParser | ⏳ TODO | MEDIUM | ~400 | Medium |
| SORELParser | ⏳ TODO | MEDIUM | ~400 | Medium |
| TPotParser | ⏳ TODO | LOW | ~300 | Low |
| MHNParser | ⏳ TODO | LOW | ~300 | Low |
| MITREAttackParser | ⏳ TODO | HIGH | ~500 | High |
| CAPECParser | ⏳ TODO | MEDIUM | ~400 | Medium |
| CISAKEVParser | ⏳ TODO | MEDIUM | ~200 | Low |
| CVEParser | ⏳ TODO | LOW | ~300 | Medium |

## Parser Template

```python
from ingestion.base_parser import BaseDatasetParser, JSONParser, CSVParser
from ingestion.unified_schema import UnifiedEvent, create_process_event
from pathlib import Path
from typing import Dict, Any, List

class MyDatasetParser(JSONParser):  # or CSVParser
    """
    Parser for MyDataset format.
    
    Dataset: MyDataset
    Format: JSON
    Events: process, file, network
    """
    
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """
        Convert raw dataset record to UnifiedEvent.
        
        Args:
            raw_record: Raw record from parse_file()
            
        Returns:
            UnifiedEvent instance
        """
        # Determine event type
        if 'process' in raw_record:
            return create_process_event(
                event_id=raw_record['id'],
                timestamp=raw_record['timestamp'],
                pid=raw_record['process']['pid'],
                action='create',
                name=raw_record['process']['name'],
                source_system=self.metadata.dataset_id
            )
        
        # Add more event type mappings...
        
        raise ValueError(f"Unknown event type in record: {raw_record}")
```

## Implementation Order

### Phase 1: High Priority (Week 2)
1. **DARPAOpTCParser** - Most complex, sets foundation
2. **CTU13Parser** - Network flows, simpler
3. **MITREAttackParser** - Threat intelligence

### Phase 2: Medium Priority (Week 3)
4. **CICIDSParser** - Network intrusion
5. **EMBERParser** - Malware features
6. **SORELParser** - Malware metadata
7. **CAPECParser** - Attack patterns
8. **CISAKEVParser** - Vulnerabilities

### Phase 3: Low Priority (Week 4)
9. **TPotParser** - Honeypot logs
10. **MHNParser** - Honeypot logs
11. **CVEParser** - CVE database

## Testing Each Parser

```python
# Test template
from ingestion.dataset_registry import DatasetRegistry
from ingestion.parsers.my_parser import MyParser

# Load dataset metadata
registry = DatasetRegistry()
dataset = registry.get('dataset_id')

# Create parser
parser = MyParser(dataset)

# Parse small sample
events = parser.parse_and_normalize(
    dataset.path / 'sample_file.json',
    max_records=100
)

# Verify results
print(f"Parsed: {len(events)} events")
print(f"Event types: {set(e.event_type for e in events)}")
print(f"Stats: {parser.get_statistics()}")

# Test with BehaviorCaptureEngine
from behavior.capture_engine import BehaviorCaptureEngine
engine = BehaviorCaptureEngine()
event_dicts = [e.to_dict() for e in events]
parsed = engine.parse_events(event_dicts)
print(f"✓ BehaviorCaptureEngine accepted {len(parsed)} events")
```

## Next Steps

1. Create `darpa_optc_parser.py`
2. Implement parse and normalize methods
3. Test with sample data
4. Integrate with BehaviorCaptureEngine
5. Move to next parser
