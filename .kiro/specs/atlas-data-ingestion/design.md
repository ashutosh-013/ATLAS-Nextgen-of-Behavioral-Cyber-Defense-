# Design Document: ATLAS Data Ingestion Infrastructure

## Architecture Overview

The ATLAS Data Ingestion Infrastructure is a **NON-INVASIVE EXTENSION** to the existing BADNA behavioral analysis framework. It provides the missing data pipeline layer that connects 15 real-world cybersecurity datasets (21.1M records) to the frozen BADNA architecture.

**Critical Design Principle:** The existing BADNA pipeline is COMPLETE and FROZEN. This design adds ONLY new modules in `ingestion/` and `intelligence/threat_intel_fusion.py`. Zero modifications to existing BADNA code.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Raw Datasets (15)                            │
│  • DARPA OpTC (CDM JSON)                                         │
│  • CTU-13 (NetFlow CSV)                                          │
│  • CICIDS (CSV flows)                                            │
│  • EMBER (JSON/PKL malware)                                      │
│  • SOREL-20M (JSON/PKL malware)                                  │
│  • T-Pot/MHN (JSON honeypot logs)                                │
│  • MITRE ATT&CK (STIX JSON)                                      │
│  • CAPEC (XML)                                                   │
│  • CISA KEV (CSV)                                                │
│  • CVE (JSON)                                                    │
│  Location: e:\BADNA\datasets\                                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Dataset Registry (✓ COMPLETE)                       │
│  File: ingestion/dataset_registry.py                             │
│  • Tracks 15 datasets with metadata                              │
│  • Validates paths                                               │
│  • Provides query API                                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         Dataset-Specific Parsers (NEW - TO IMPLEMENT)            │
│  Directory: ingestion/parsers/                                   │
│  • darpa_optc_parser.py (CDM → UnifiedEvent)                     │
│  • ctu13_parser.py (NetFlow CSV → UnifiedEvent)                  │
│  • cicids_parser.py (CSV flows → UnifiedEvent)                   │
│  • ember_parser.py (malware JSON → UnifiedEvent)                 │
│  • sorel_parser.py (malware PKL → UnifiedEvent)                  │
│  • honeypot_parser.py (JSON logs → UnifiedEvent)                 │
│  • mitre_attack_parser.py (STIX → KnowledgeBase)                 │
│  • capec_parser.py (XML → KnowledgeBase)                         │
│  • cisa_kev_parser.py (CSV → KnowledgeBase)                      │
│  • cve_parser.py (JSON → KnowledgeBase)                          │
│  All inherit from: BaseDatasetParser                             │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│           Unified Event Schema (✓ COMPLETE)                      │
│  File: ingestion/unified_schema.py                               │
│  Format: {                                                       │
│    event_id: str,                                                │
│    event_type: str,  # process|file|network|auth|registry|user   │
│    timestamp: datetime,                                          │
│    source_system: str,                                           │
│    event_data: dict                                              │
│  }                                                               │
│  Compatible with: BehaviorCaptureEngine.parse_events()           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│        Behavior Capture Engine (✓ EXISTS - NO CHANGES)           │
│  File: behavior/capture_engine.py                                │
│  • parse_events(UnifiedEvent[]) → ParsedEvent[]                  │
│  • build_graph(ParsedEvent[]) → BehaviorGraph                    │
│  Outputs: BehaviorGraph (nodes, edges, causality)                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│     Feature Engineering + d-BEF (✓ EXISTS - NO CHANGES)          │
│  Files: behavior/feature_engineering.py, behavior/dbef.py        │
│  • extract_features(BehaviorGraph) → FeatureVector               │
│  • compute_embedding(FeatureVector) → 128D Embedding             │
│  Outputs: BADNAEmbedding (128D unit vector)                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│         BSF + NSF + CCF Engines (✓ EXISTS - NO CHANGES)          │
│  Files: similarity/bsf.py, novelty/nsf.py, confidence/ccf.py    │
│  • BSF: calculate_similarity() → SimilarityResult                │
│  • NSF: compute_novelty() → NoveltyResult                        │
│  • CCF: calibrate_confidence() → ConfidenceResult                │
│  Outputs: Similarity, Novelty, Confidence scores                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│        AI Investigator (✓ EXISTS - NO CHANGES)                   │
│  File: intelligence/investigator.py                              │
│  • classify_threat() → ThreatClassification                      │
│  • predict_intent() → IntentPrediction                           │
│  • generate_evidence() → Evidence                                │
│  Outputs: Threat class, Intent, Evidence                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│      Threat Intel Fusion (NEW - TO IMPLEMENT)                    │
│  File: intelligence/threat_intel_fusion.py                       │
│  • enrich_with_mitre(BADNAProfile) → adds ATT&CK techniques      │
│  • enrich_with_capec(BADNAProfile) → adds attack patterns        │
│  • enrich_with_cve_kev(BADNAProfile) → adds vulnerability data   │
│  • correlate_malware_feeds(BADNAProfile) → MalwareBazaar/URLhaus │
│  Outputs: EnrichedProfile (BADNAProfile + ThreatIntelContext)    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│       Knowledge Base (✓ EXISTS - NO CHANGES)                     │
│  File: knowledge_base/storage.py                                 │
│  • store_pattern(embedding, metadata)                            │
│  • query_by_similarity(embedding, threshold)                     │
│  • cluster_campaigns()                                           │
│  Storage: behavior_memory.json, campaigns.json                   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow: Never Train on Raw Data

**Critical Rule:** ALL datasets MUST be converted to behavioral graphs before storage/training.

```
Raw Data (CSV/JSON/XML/PKL)
  ↓
[Dataset Parser] ← Task: Implement 10 parsers
  ↓
UnifiedEvent (standardized schema)
  ↓
[BehaviorCaptureEngine.parse_events()] ← Existing, no changes
  ↓
BehaviorGraph (nodes, edges, causality)
  ↓
[FeatureEngineering + d-BEF] ← Existing, no changes
  ↓
BADNAEmbedding (128D unit vector)
  ↓
[KnowledgeBase.store_pattern()] ← Existing, no changes
  ↓
Stored Pattern (embedding + metadata)
```

**What We're Building:**
- Row 1-2: Dataset Parsers (10 parsers)
- Last step before KB: Threat Intel Fusion

**What Already Exists (DO NOT MODIFY):**
- Rows 3-6: BehaviorCaptureEngine, Feature Engineering, d-BEF, BSF, NSF, CCF, AI Investigator, Knowledge Base

## Module Designs

### Module 1: Dataset Parsers (ingestion/parsers/)

**Purpose:** Convert dataset-specific formats to UnifiedEvent schema.

**Base Class:** BaseDatasetParser (already complete)

**Implementation Pattern:**
```python
class DARPAOpTCParser(BaseDatasetParser):
    def __init__(self, dataset_metadata: Dict):
        super().__init__(dataset_metadata)
        self.cdm_event_type_map = {
            "EVENT_EXECUTE": "process",
            "EVENT_READ": "file",
            "EVENT_CONNECT": "network",
            "EVENT_LOGIN": "auth"
        }
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Read CDM JSON files and extract raw events."""
        with open(filepath, 'r') as f:
            cdm_data = json.load(f)
        return cdm_data.get("events", [])
    
    def normalize_to_schema(self, raw_record: Dict) -> UnifiedEvent:
        """Convert CDM event to UnifiedEvent."""
        event_type = self.cdm_event_type_map.get(
            raw_record.get("type"), "process"
        )
        return UnifiedEvent(
            event_id=raw_record["uuid"],
            event_type=event_type,
            timestamp=self._parse_cdm_timestamp(raw_record["timestampNanos"]),
            source_system="DARPA_OpTC",
            event_data={
                "subject": raw_record.get("subject"),
                "object": raw_record.get("predicateObject"),
                "predicate": raw_record.get("predicateType"),
                "provenance": raw_record.get("provenanceMetadata")
            }
        )
```

**Parsers to Implement:**
1. **DARPAOpTCParser** - CDM JSON → UnifiedEvent (process, file, network, auth events)
2. **CTU13Parser** - NetFlow CSV → UnifiedEvent (network events)
3. **CICIDSParser** - CSV flows → UnifiedEvent (network events with labels)
4. **EMBERParser** - JSON/PKL malware → UnifiedEvent (file events)
5. **SORELParser** - JSON/PKL malware → UnifiedEvent (file events)
6. **HoneypotParser** - JSON logs → UnifiedEvent (multi-type events)
7. **MITREAttackParser** - STIX JSON → KnowledgeBase technique mappings
8. **CAPECParser** - XML → KnowledgeBase attack patterns
9. **CISAKEVParser** - CSV → KnowledgeBase vulnerability records
10. **CVEParser** - JSON → KnowledgeBase CVE records

### Module 2: Threat Intel API Clients (ingestion/api_clients/)

**Purpose:** Fetch live threat intelligence from external APIs.

**Implementation:**
```python
class MalwareBazaarClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://mb-api.abuse.ch/api/v1/"
    
    def get_recent_samples(self, hours: int = 24) -> List[Dict]:
        """Fetch malware samples from last N hours."""
        endpoint = f"{self.base_url}query"
        payload = {
            "query": "get_recent",
            "selector": f"{hours}h"
        }
        headers = {"API-KEY": self.api_key}
        
        response = requests.post(endpoint, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json().get("data", [])
        elif response.status_code == 429:
            # Rate limit - exponential backoff
            raise RateLimitError("API rate limit exceeded")
        else:
            raise APIError(f"API call failed: {response.status_code}")
    
    def query_hash(self, hash_value: str) -> Dict:
        """Query specific malware sample by hash."""
        # Implementation for hash lookup
        pass
```

**Clients to Implement:**
1. **MalwareBazaarClient** - Fetch recent malware samples, query by hash
2. **URLhausClient** - Fetch recent malicious URLs, query by URL

### Module 3: Threat Intel Fusion (intelligence/threat_intel_fusion.py)

**Purpose:** Enrich BADNA detections with threat intelligence context.

**Integration Point:** Between AI Investigator and Knowledge Base.

**Implementation:**
```python
class ThreatIntelFusion:
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.mitre_techniques = {}  # Loaded from MITRE parser
        self.capec_patterns = {}    # Loaded from CAPEC parser
        self.cve_database = {}      # Loaded from CVE parser
        self.recent_malware = []    # Updated hourly from MalwareBazaar
        self.recent_urls = []       # Updated hourly from URLhaus
    
    def enrich_profile(self, badna_profile: BADNAProfile) -> EnrichedProfile:
        """Add threat intelligence context to BADNA detection."""
        enriched = EnrichedProfile(
            base_profile=badna_profile,
            threat_intel_context={}
        )
        
        # Enrich with MITRE ATT&CK
        if badna_profile.intent:
            techniques = self._map_intent_to_mitre(badna_profile.intent)
            enriched.threat_intel_context["mitre_techniques"] = techniques
        
        # Enrich with CAPEC patterns
        attack_patterns = self._match_capec_patterns(badna_profile.evidence)
        enriched.threat_intel_context["capec_patterns"] = attack_patterns
        
        # Correlate with recent malware feeds (last 7 days)
        if self._has_file_indicators(badna_profile):
            matches = self._correlate_malware_feeds(badna_profile)
            enriched.threat_intel_context["malware_correlation"] = matches
        
        # Check CVE/KEV for vulnerability indicators
        if badna_profile.novelty_score > 0.8:
            vulns = self._check_vulnerability_indicators(badna_profile)
            enriched.threat_intel_context["related_vulnerabilities"] = vulns
        
        return enriched
    
    def _map_intent_to_mitre(self, intent: IntentPrediction) -> List[Dict]:
        """Map predicted intent to MITRE ATT&CK techniques."""
        techniques = []
        for intent_category in intent.ranked_intents:
            # Lookup MITRE techniques for this intent category
            matching_techniques = self.mitre_techniques.get(intent_category.category, [])
            techniques.extend(matching_techniques)
        return techniques
```

### Module 4: Dataset Loader (ingestion/dataset_loader.py)

**Purpose:** Orchestrate ingestion of all 15 datasets into Knowledge Base.

**Implementation:**
```python
class DatasetLoader:
    def __init__(self, registry: DatasetRegistry):
        self.registry = registry
        self.graph_extractor = BehavioralGraphExtractor()
        self.kb = KnowledgeBase()
    
    def populate_knowledge_base(self, datasets: List[str] = None):
        """Load all datasets into Knowledge Base."""
        if datasets is None:
            datasets = self.registry.list_all_datasets()
        
        for dataset_name in datasets:
            logger.info(f"Processing dataset: {dataset_name}")
            
            # Get dataset metadata
            metadata = self.registry.get_dataset(dataset_name)
            
            # Initialize appropriate parser
            parser = self._get_parser(metadata)
            
            # Parse and normalize data
            events = parser.parse_and_normalize(
                metadata["path"], 
                streaming=True  # For large files
            )
            
            # Extract behavioral graphs and embeddings
            patterns = self.graph_extractor.extract_patterns(events)
            
            # Store in Knowledge Base
            for pattern in patterns:
                self.kb.store_pattern(
                    embedding=pattern.embedding,
                    metadata={
                        "threat_class": pattern.label,
                        "dataset_source": dataset_name,
                        "timestamp": datetime.now().isoformat()
                    }
                )
            
            logger.info(f"Stored {len(patterns)} patterns from {dataset_name}")
        
        # Cluster patterns into campaigns
        self.kb.cluster_campaigns()
        logger.info("Knowledge Base population complete")
```

### Module 5: Behavioral Graph Extractor (ingestion/graph_extraction_pipeline.py)

**Purpose:** Convert UnifiedEvent → BehaviorGraph → d-BEF embedding.

**Critical:** This ensures we NEVER train on raw data.

**Implementation:**
```python
class BehavioralGraphExtractor:
    def __init__(self):
        self.capture_engine = BehaviorCaptureEngine()
        self.feature_engineering = FeatureEngineering()
        self.dbef = DBEF()
    
    def extract_patterns(self, events: List[UnifiedEvent]) -> List[BehaviorPattern]:
        """Convert events to behavioral patterns with embeddings."""
        patterns = []
        
        # Convert UnifiedEvent to dict for BehaviorCaptureEngine
        event_dicts = [e.to_dict() for e in events]
        
        # Step 1: Parse events (existing BADNA code)
        parsed_events = self.capture_engine.parse_events(event_dicts)
        
        # Step 2: Build behavior graph (existing BADNA code)
        graph = self.capture_engine.build_graph(parsed_events)
        
        # Step 3: Extract features (existing BADNA code)
        features = self.feature_engineering.extract_features(graph)
        
        # Step 4: Compute d-BEF embedding (existing BADNA code)
        embedding = self.dbef.compute_embedding(features)
        
        # Step 5: Create pattern object
        pattern = BehaviorPattern(
            graph=graph,
            features=features,
            embedding=embedding,
            label=self._extract_label(events)
        )
        patterns.append(pattern)
        
        return patterns
```

### Module 6: Continuous Update Scheduler (ingestion/update_scheduler.py)

**Purpose:** Automated hourly/daily updates from threat feeds.

**Implementation:**
```python
class ContinuousUpdateScheduler:
    def __init__(self):
        self.malwarebazaar = MalwareBazaarClient(MALWAREBAZAAR_API_KEY)
        self.urlhaus = URLhausClient(URLHAUS_API_KEY)
        self.update_history = []
    
    def run_hourly_updates(self):
        """Fetch hourly threat intel updates."""
        logger.info("Running hourly updates...")
        
        # MalwareBazaar updates
        try:
            samples = self.malwarebazaar.get_recent_samples(hours=1)
            self._process_malware_samples(samples)
            self.update_history.append({
                "source": "MalwareBazaar",
                "timestamp": datetime.now().isoformat(),
                "records": len(samples),
                "status": "success"
            })
        except Exception as e:
            logger.error(f"MalwareBazaar update failed: {e}")
        
        # URLhaus updates
        try:
            urls = self.urlhaus.get_recent_urls(hours=1)
            self._process_malicious_urls(urls)
            self.update_history.append({
                "source": "URLhaus",
                "timestamp": datetime.now().isoformat(),
                "records": len(urls),
                "status": "success"
            })
        except Exception as e:
            logger.error(f"URLhaus update failed: {e}")
    
    def run_daily_updates(self):
        """Fetch daily threat intel updates."""
        logger.info("Running daily updates...")
        # MITRE ATT&CK, CAPEC, CISA KEV updates
        pass
```

## Performance Considerations

1. **Streaming for Large Files:** Use `parse_and_normalize_streaming()` for files >100MB
2. **Batch Processing:** Process datasets in parallel where possible
3. **Memory Management:** Clear processed data from memory after embedding extraction
4. **Caching:** Cache frequently accessed threat intel (MITRE techniques, CAPEC patterns)
5. **Indexing:** Index Knowledge Base by threat_class, dataset_source for fast queries

## Testing Strategy

1. **Unit Tests:** Test each parser with sample dataset files
2. **Integration Tests:** Test UnifiedEvent → BehaviorGraph → Embedding pipeline
3. **End-to-End Tests:** Load sample dataset → populate KB → query patterns
4. **API Tests:** Mock API responses for MalwareBazaar/URLhaus clients
5. **Validation Tests:** Verify no modifications to existing BADNA code

## Success Criteria

1. ✅ All 10 dataset parsers produce valid UnifiedEvent output
2. ✅ All parsers inherit from BaseDatasetParser (zero violations)
3. ✅ Threat intel fusion module enriches profiles without modifying BADNAProfile structure
4. ✅ Knowledge Base populated with ≥100,000 patterns from 15 datasets
5. ✅ Continuous updates run hourly/daily without failures
6. ✅ Zero modifications to existing BADNA code (behavior/, confidence/, etc.)
7. ✅ Model accuracy improves from 25% to ≥85% after KB population

## File Locations

**New Modules (To Implement):**
- `ingestion/parsers/darpa_optc_parser.py`
- `ingestion/parsers/ctu13_parser.py`
- `ingestion/parsers/cicids_parser.py`
- `ingestion/parsers/ember_parser.py`
- `ingestion/parsers/sorel_parser.py`
- `ingestion/parsers/honeypot_parser.py`
- `ingestion/parsers/mitre_attack_parser.py`
- `ingestion/parsers/capec_parser.py`
- `ingestion/parsers/cisa_kev_parser.py`
- `ingestion/parsers/cve_parser.py`
- `ingestion/api_clients/malwarebazaar_client.py`
- `ingestion/api_clients/urlhaus_client.py`
- `intelligence/threat_intel_fusion.py`
- `ingestion/dataset_loader.py`
- `ingestion/graph_extraction_pipeline.py`
- `ingestion/update_scheduler.py`

**Existing Modules (DO NOT MODIFY):**
- `main.py`
- `behavior/capture_engine.py`
- `behavior/feature_engineering.py`
- `behavior/dbef.py`
- `similarity/bsf.py`
- `novelty/nsf.py`
- `confidence/ccf.py`
- `intelligence/investigator.py`
- `intelligence/adaptive_defense.py`
- `knowledge_base/storage.py`

**Foundation (Already Complete):**
- `ingestion/dataset_registry.py` ✅
- `ingestion/unified_schema.py` ✅
- `ingestion/base_parser.py` ✅
