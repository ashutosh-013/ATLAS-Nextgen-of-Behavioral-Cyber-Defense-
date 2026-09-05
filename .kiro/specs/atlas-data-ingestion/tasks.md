# Implementation Tasks: ATLAS Data Ingestion Infrastructure

## Overview

This implementation adds production data infrastructure to the existing BADNA behavioral analysis framework. The foundation infrastructure (Dataset Registry, Unified Event Schema, Base Parser) is already complete. This task list focuses on implementing 10 dataset parsers, 2 API clients, threat intelligence fusion, and pipeline orchestration to populate the Knowledge Base with 21.1M historical security event records.

**Critical Rule:** The existing BADNA architecture is FROZEN. This implementation adds ONLY new modules in `ingestion/` and `intelligence/threat_intel_fusion.py`. Zero modifications to existing BADNA code.

## Foundation Status

✅ **Phase 1 Complete** (already implemented):
- Dataset Registry (`ingestion/dataset_registry.py`) - 15 datasets registered
- Unified Event Schema (`ingestion/unified_schema.py`) - 6 event types defined
- Base Parser Framework (`ingestion/base_parser.py`) - Abstract base class ready

## Tasks

### 1. Dataset Parsers - Endpoint Telemetry

- [x] 1.1 Implement DARPA OpTC Parser
  - Create `ingestion/parsers/darpa_optc_parser.py` inheriting from BaseDatasetParser
  - Parse CDM JSON format with provenance graph structure
  - Map CDM event types: EVENT_EXECUTE→process, EVENT_READ/WRITE→file, EVENT_CONNECT→network, EVENT_LOGIN→auth
  - Extract subject (process), predicateObject (target), predicateType (action), provenanceMetadata (causality)
  - Convert CDM timestampNanos (nanoseconds epoch) to ISO 8601 datetime
  - Preserve parent-child process relationships in event_data for graph construction
  - Handle nested CDM structures: Process, File, NetFlowObject, Principal objects
  - Test with sample from `datasets/OpTC-data-master/` (if available)
  - Validate output: UnifiedEvent objects with event_type in {process, file, network, auth}
  - _Requirements: 1.1-1.8, 2.1-2.8_

- [x] 1.2 Write integration test for DARPA OpTC Parser
  - Load sample CDM JSON file from `datasets/OpTC-data-master/`
  - Parse with DARPAOpTCParser and verify UnifiedEvent output format
  - Feed UnifiedEvent objects to BehaviorCaptureEngine.parse_events()
  - Verify BehaviorGraph creation with correct node/edge structure
  - Extract d-BEF embedding and verify 128D unit vector output
  - Test error handling: malformed JSON, missing fields, invalid timestamps
  - _Requirements: 2.8, 12.1-12.7_

### 2. Dataset Parsers - Network Traffic

- [ ] 2.1 Implement CTU-13 NetFlow Parser
  - Create `ingestion/parsers/ctu13_parser.py` inheriting from CSVParser base class
  - Parse NetFlow CSV format: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
  - Map to UnifiedEvent with event_type='network'
  - Extract event_data: {src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, duration, flow_state, label}
  - Convert StartTime to ISO 8601 datetime
  - Preserve Label field (botnet/background/normal) for supervised learning
  - Implement streaming mode for large CSV files (>1GB)
  - Test with sample from `datasets/CTU-13-Dataset/` scenarios
  - _Requirements: 3.1-3.7, 1.5_

- [ ] 2.2 Implement CICIDS Parser
  - Create `ingestion/parsers/cicids_parser.py` inheriting from CSVParser base class
  - Parse CICIDS CSV format with 80+ flow features
  - Map to UnifiedEvent with event_type='network'
  - Extract key features: src/dst IPs, ports, protocol, flow duration, packet counts, byte counts, flags, attack label
  - Handle CICIDS 2017 and 2018 variants with different column names
  - Convert timestamp columns to ISO 8601 datetime (handle multiple formats)
  - Preserve attack type labels: DDoS, PortScan, Bot, Infiltration, DoS, Web Attack, Brute Force, Benign
  - Implement streaming for multi-gigabyte files
  - Test with samples from `datasets/*.csv/` (CICIDS folders)
  - _Requirements: 3.1-3.7, 1.5_

- [ ] 2.3 Write integration tests for network parsers
  - Test CTU-13 parser with sample NetFlow CSV
  - Test CICIDS parser with sample labeled flow CSV
  - Verify UnifiedEvent format and network event_type
  - Feed to BehaviorCaptureEngine and verify graph creation
  - Verify preservation of attack labels for supervised learning
  - Test streaming mode with large file simulation
  - _Requirements: 12.1-12.7_

### 3. Dataset Parsers - Malware Datasets

- [ ] 3.1 Implement EMBER Parser
  - Create `ingestion/parsers/ember_parser.py` inheriting from JSONParser base class
  - Parse EMBER JSON/PKL format with PE malware features
  - Extract: sha256 hash, label (malware/benign), appearance timestamp, PE metadata (imports, exports, sections), byte histogram, string features
  - Convert static features to behavioral event sequences:
    * PE imports → file read events for DLL dependencies
    * Section characteristics → file write events (executable sections)
    * String features → potential C2/URL indicators → network events
  - Map to UnifiedEvent with event_type='file' primarily, network for C2 indicators
  - Handle both JSON and pickle (.pkl) file formats
  - Implement batch processing for 1.1M samples with progress logging
  - Test with samples from `datasets/ember-master/`
  - _Requirements: 4.1-4.7, 1.5_

- [ ] 3.2 Implement SOREL-20M Parser
  - Create `ingestion/parsers/sorel_parser.py` inheriting from JSONParser base class
  - Parse SOREL-20M JSON/PKL format with disassembly features
  - Extract: sha256, label, metadata (file size, compile time), disassembly features, opcode n-grams, API call sequences
  - Convert static features to behavioral sequences:
    * API call sequences → process execution events
    * Suspicious API calls (CreateRemoteThread, WriteProcessMemory) → privilege escalation events
    * Registry/file APIs → registry/file modification events
  - Map to UnifiedEvent with event_type based on feature type
  - Handle massive scale: 20M samples requires efficient batch processing
  - Implement sampling strategy if full ingestion is too large (prioritize malware samples)
  - Test with samples from `datasets/SOREL-20M-master/`
  - _Requirements: 4.1-4.7, 1.5_

- [ ] 3.3 Write integration tests for malware parsers
  - Test EMBER parser with sample malware JSON/PKL
  - Test SOREL parser with sample features JSON/PKL
  - Verify conversion of static features to behavioral event sequences
  - Verify UnifiedEvent format with appropriate event_types
  - Feed to BehaviorCaptureEngine and verify graph creation represents malware behavior
  - Test batch processing with 100 samples and verify memory efficiency
  - _Requirements: 12.1-12.7_

### 4. Dataset Parsers - Honeypot Data

- [ ] 4.1 Implement Honeypot Parser (T-Pot, MHN)
  - Create `ingestion/parsers/honeypot_parser.py` inheriting from JSONParser base class
  - Parse T-Pot JSON logs: sensor type, attacker IP, attack timestamp, payload, exploit type, service targeted
  - Parse MHN JSON logs: honeypot sensor ID, attack events, payloads, attacker metadata
  - Convert attack attempts to behavioral event sequences:
    * Reconnaissance → network scan events
    * Exploit attempt → process execution or file write events
    * Payload delivery → file write + network events
    * Post-exploitation → command execution events
  - Map honeypot events to MITRE ATT&CK tactic phases: initial_access, execution, persistence
  - Preserve attacker IP, exploit CVE (if available), payload content for attribution
  - Test with samples from `datasets/tpotce-master/` and `datasets/mhn-master/`
  - _Requirements: 5.1-5.6, 1.5_

- [ ] 4.2 Write integration test for honeypot parser
  - Test with sample T-Pot JSON logs
  - Test with sample MHN JSON logs
  - Verify conversion of attack attempts to behavioral sequences
  - Verify UnifiedEvent format with appropriate event_types
  - Verify preservation of attacker attribution data
  - Feed to BehaviorCaptureEngine and verify attack chain graph construction
  - _Requirements: 12.1-12.7_

### 5. Threat Intelligence Parsers

- [ ] 5.1 Implement MITRE ATT&CK Parser
  - Create `ingestion/parsers/mitre_attack_parser.py` inheriting from JSONParser base class
  - Parse STIX 2.1 JSON from `datasets/cti-master/enterprise-attack/`
  - Extract attack patterns (techniques): technique ID (T####), name, description, tactics, sub-techniques
  - Extract relationships: technique-to-tactic, technique-to-mitigation, technique-to-group
  - Store in KnowledgeBase-compatible format: {technique_id, name, tactics[], description, related_techniques[], apt_groups[]}
  - Build technique-to-tactic mapping for intent prediction enrichment
  - Parse 858 technique JSON files from `datasets/cti-master/cti-master/enterprise-attack/attack-pattern/`
  - _Requirements: 6.1-6.7_

- [ ] 5.2 Implement CAPEC Parser
  - Create `ingestion/parsers/capec_parser.py` with XML parsing capability
  - Parse `datasets/capec_latest/capec_v3.9.xml` XML attack pattern database
  - Extract attack patterns: CAPEC ID, name, description, prerequisites, typical severity, related weaknesses (CWE)
  - Extract relationships: CAPEC-to-CAPEC (parent/child patterns), CAPEC-to-CWE
  - Cross-reference with MITRE ATT&CK techniques where mappings exist
  - Store in KnowledgeBase format: {capec_id, name, description, severity, related_techniques[], related_cwe[]}
  - _Requirements: 6.1-6.7_

- [ ] 5.3 Implement CISA KEV Parser
  - Create `ingestion/parsers/cisa_kev_parser.py` inheriting from CSVParser base class
  - Parse `datasets/known_exploited_vulnerabilities.csv` CSV file
  - Extract fields: CVE ID, Vendor/Project, Product, Vulnerability Name, Date Added, Short Description, Required Action, Due Date, Known Ransomware Use
  - Store in KnowledgeBase format: {cve_id, product, description, date_added, ransomware_usage, exploitation_status}
  - Flag vulnerabilities actively exploited in ransomware campaigns (Known Ransomware Use = true)
  - _Requirements: 6.1-6.7_

- [ ] 5.4 Implement CVE Parser
  - Create `ingestion/parsers/cve_parser.py` inheriting from JSONParser base class
  - Parse CVE JSON 5.0 format from `datasets/cvelistV5-main/`
  - Extract: CVE ID, description, CVSS scores (v2/v3), affected products, references, published/modified dates
  - Handle large directory structure: `cvelistV5-main/cves/YYYY/####x/CVE-YYYY-####.json`
  - Implement directory traversal with progress logging (100,000+ CVEs)
  - Store in KnowledgeBase format: {cve_id, description, cvss_score, affected_products[], references[], published_date}
  - Index by CVE ID for fast lookups during enrichment
  - _Requirements: 6.1-6.7_

- [ ] 5.5 Write integration tests for threat intel parsers
  - Test MITRE ATT&CK parser with sample technique JSON
  - Test CAPEC parser with sample attack pattern from XML
  - Test CISA KEV parser with sample CSV rows
  - Test CVE parser with sample CVE JSON
  - Verify storage format compatible with threat intel fusion queries
  - Verify relationship extraction (technique-to-tactic, CAPEC-to-technique)
  - _Requirements: 12.1-12.7_

### 6. Threat Intelligence API Clients

- [ ] 6.1 Implement MalwareBazaar API Client
  - Create `ingestion/api_clients/malwarebazaar_client.py`
  - Implement `get_recent_samples(hours=24)` method querying recent malware uploads
  - Implement `query_hash(hash)` method for hash lookups (MD5, SHA256)
  - Use API endpoint: `https://mb-api.abuse.ch/api/v1/` with API key header
  - Handle API responses: success (200), rate limit (429 with retry-after), errors (4xx/5xx)
  - Implement exponential backoff for rate limit handling: wait 60s, 120s, 240s...
  - Parse response fields: sha256_hash, md5_hash, file_name, file_type_mime, file_size, signature (malware family), tags[], first_seen
  - Return normalized format compatible with UnifiedEvent conversion
  - Implement request logging: timestamp, endpoint, status, samples_fetched
  - _Requirements: 7.1-7.7_

- [ ] 6.2 Implement URLhaus API Client
  - Create `ingestion/api_clients/urlhaus_client.py`
  - Implement `get_recent_urls(hours=24)` method querying recent malicious URLs
  - Implement `query_url(url)` method for URL lookups
  - Use API endpoint: `https://urlhaus-api.abuse.ch/v1/` with API key header
  - Handle API responses with same error handling as MalwareBazaar client
  - Implement exponential backoff for rate limits
  - Parse response fields: url, url_status, host, date_added, threat (malware family), tags[], payloads[]
  - Return normalized format compatible with UnifiedEvent conversion
  - Implement request logging: timestamp, endpoint, status, urls_fetched
  - _Requirements: 7.1-7.7_

- [ ] 6.3 Write integration tests for API clients
  - Mock API responses for success, rate limit, and error scenarios
  - Test MalwareBazaar client: get_recent_samples() and query_hash()
  - Test URLhaus client: get_recent_urls() and query_url()
  - Verify exponential backoff retry logic on rate limit (429)
  - Verify error handling on network failures (timeout, connection error)
  - Verify request logging and statistics tracking
  - Test with actual API calls (limited to avoid rate limits) to verify integration
  - _Requirements: 12.1-12.7_

### 7. Threat Intelligence Fusion Module

- [ ] 7.1 Implement Threat Intel Fusion Module
  - Create `intelligence/threat_intel_fusion.py` with ThreatIntelFusion class
  - Load threat intel databases on initialization: MITRE techniques, CAPEC patterns, CVE records, KEV data
  - Implement `enrich_profile(badna_profile: BADNAProfile) → EnrichedProfile` method
  - Create EnrichedProfile dataclass extending BADNAProfile with threat_intel_context field
  - Implement `_map_intent_to_mitre(intent: IntentPrediction) → List[Dict]` - map predicted intents to MITRE ATT&CK techniques
  - Implement `_match_capec_patterns(evidence: Evidence) → List[Dict]` - match behavioral evidence to CAPEC attack patterns
  - Implement `_correlate_malware_feeds(profile: BADNAProfile) → List[Dict]` - correlate file hashes/network indicators with MalwareBazaar/URLhaus data (last 7 days)
  - Implement `_check_vulnerability_indicators(profile: BADNAProfile) → List[Dict]` - check for CVE/KEV matches based on behavioral patterns
  - Preserve original BADNAProfile structure - only ADD enrichment fields, never modify existing fields
  - Handle missing threat intel gracefully - proceed with partial enrichment if data unavailable
  - _Requirements: 8.1-8.8_

- [ ] 7.2 Write integration test for threat intel fusion
  - Create sample BADNAProfile with intent predictions and behavioral evidence
  - Enrich with ThreatIntelFusion module
  - Verify enriched profile contains MITRE ATT&CK technique mappings
  - Verify CAPEC pattern matches when applicable
  - Verify malware feed correlation when file indicators present
  - Verify original BADNAProfile fields are unchanged
  - Test graceful degradation when threat intel data is missing
  - _Requirements: 12.1-12.7_

### 8. Pipeline Orchestration

- [ ] 8.1 Implement Behavioral Graph Extraction Pipeline
  - Create `ingestion/graph_extraction_pipeline.py` with BehavioralGraphExtractor class
  - Implement `extract_patterns(events: List[UnifiedEvent]) → List[BehaviorPattern]` method
  - Step 1: Convert UnifiedEvent objects to dicts for BehaviorCaptureEngine compatibility
  - Step 2: Call `BehaviorCaptureEngine.parse_events(event_dicts)` - use existing implementation
  - Step 3: Call `BehaviorCaptureEngine.build_graph(parsed_events)` - use existing implementation
  - Step 4: Call `FeatureEngineering.extract_features(graph)` - use existing implementation
  - Step 5: Call `DBEF.compute_embedding(features)` - use existing d-BEF implementation
  - Step 6: Create BehaviorPattern object: {graph, features, embedding, label, metadata}
  - Implement batch processing with progress logging: every 100 patterns log progress
  - Implement error handling: skip corrupted records, log errors, continue processing
  - CRITICAL: Enforce "never train on raw data" rule - all data MUST pass through this pipeline
  - _Requirements: 10.1-10.8_

- [ ] 8.2 Implement Dataset Loader
  - Create `ingestion/dataset_loader.py` with DatasetLoader class
  - Initialize with DatasetRegistry, BehavioralGraphExtractor, KnowledgeBase instances
  - Implement `populate_knowledge_base(datasets: List[str] = None)` method
  - For each dataset: get metadata from registry → initialize appropriate parser → parse and normalize data → extract behavioral patterns → store in Knowledge Base
  - Support both sequential and parallel dataset processing (configurable)
  - Implement progress logging: dataset_name, records_processed, patterns_stored, elapsed_time
  - Implement error recovery: skip failed datasets, log errors, continue with remaining datasets
  - After all datasets processed, call `KnowledgeBase.cluster_campaigns()` to identify behavioral families
  - Generate final summary: total_patterns, patterns_by_threat_class, campaign_profiles_created, total_time
  - Support streaming mode for large datasets to manage memory usage
  - _Requirements: 9.1-9.7_

- [ ] 8.3 Write end-to-end integration test
  - Load small sample dataset (100 records)
  - Parse with appropriate dataset parser → UnifiedEvent objects
  - Extract behavioral patterns with BehavioralGraphExtractor → verify graphs and embeddings
  - Store patterns in Knowledge Base
  - Query Knowledge Base for stored patterns → verify retrievability
  - Verify behavioral graphs have correct structure (nodes, edges, causality)
  - Verify embeddings are 128D unit vectors
  - Verify Knowledge Base statistics: pattern count, threat class distribution
  - Test error handling: malformed data, missing fields, invalid timestamps
  - _Requirements: 12.1-12.7_

### 9. Continuous Learning

- [ ] 9.1 Implement Continuous Update Scheduler
  - Create `ingestion/update_scheduler.py` with ContinuousUpdateScheduler class
  - Initialize MalwareBazaarClient and URLhausClient with API keys from config
  - Implement `run_hourly_updates()` method:
    * Fetch MalwareBazaar recent samples (last 1 hour)
    * Fetch URLhaus recent URLs (last 1 hour)
    * Parse and normalize to UnifiedEvent format
    * Extract behavioral patterns via BehavioralGraphExtractor
    * Store patterns in Knowledge Base
    * Log update statistics: source, timestamp, records_added, status
  - Implement `run_daily_updates()` method:
    * Fetch MITRE ATT&CK updates (if available)
    * Fetch CAPEC updates (if available)
    * Fetch CISA KEV updates (if available)
    * Update threat intel databases
    * Log update statistics
  - Implement error handling: API failures, network errors, rate limits (retry with backoff)
  - Maintain update history: last_update_time, records_added, failures
  - Trigger model retraining if Knowledge Base grows by 100+ patterns (call `ModelEvolution.trigger_retraining()`)
  - _Requirements: 11.1-11.7_

- [ ] 9.2 Write integration test for continuous updates
  - Mock MalwareBazaar API responses with sample data
  - Mock URLhaus API responses with sample data
  - Run hourly update cycle
  - Verify patterns are extracted and stored in Knowledge Base
  - Verify update history is logged correctly
  - Test error handling: API failures, rate limits, network errors
  - Verify retraining trigger when Knowledge Base growth threshold exceeded
  - _Requirements: 12.1-12.7_

### 10. Knowledge Base Population Script

- [ ] 10.1 Create Knowledge Base population script
  - Create `scripts/populate_knowledge_base.py` executable script
  - Load configuration: dataset list, parser mappings, Knowledge Base path
  - Initialize empty Knowledge Base (or load existing if resuming)
  - Initialize DatasetLoader with all components
  - Call `DatasetLoader.populate_knowledge_base()` with all 15 datasets
  - Log progress to console and file: dataset name, progress percentage, patterns stored
  - Display final statistics: total patterns, patterns by threat class, campaign profiles, total time
  - Support command-line arguments: --datasets (specify subset), --resume (resume from last checkpoint), --parallel (parallel processing)
  - Implement checkpointing: save progress every 10,000 patterns to allow resume on failure
  - _Requirements: 9.1-9.7_

- [ ] 10.2 Create continuous update startup script
  - Create `scripts/start_continuous_updates.py` executable script
  - Initialize ContinuousUpdateScheduler
  - Implement scheduling: hourly updates (top of each hour), daily updates (midnight)
  - Use APScheduler or similar for robust scheduling with error recovery
  - Run as background service/daemon process
  - Implement graceful shutdown handling (SIGTERM, SIGINT)
  - Log all operations to `logs/continuous_updates.log` with rotation
  - Support command-line arguments: --hourly-only, --daily-only, --test (run once)
  - _Requirements: 11.1-11.7_

### 11. Documentation and Final Validation

- [ ] 11.1 Create parser implementation documentation
  - Document each parser: dataset format, mapping to UnifiedEvent, special handling
  - Provide usage examples for each parser with sample code
  - Document error handling: common issues, recovery strategies
  - Create parser selection guide: which parser for which dataset format
  - Document extension guide: how to add new dataset parsers
  - File: `docs/PARSER_DOCUMENTATION.md`
  - _Requirements: 12.1-12.7_

- [ ] 11.2 Create end-to-end usage guide
  - Document complete workflow: dataset registration → parsing → graph extraction → KB population
  - Provide step-by-step tutorial with real dataset examples
  - Document Knowledge Base query patterns for threat intel enrichment
  - Document continuous update configuration and monitoring
  - Provide troubleshooting guide: common issues, debugging steps
  - Document performance tuning: batch sizes, parallelization, memory management
  - File: `docs/DATA_INGESTION_GUIDE.md`
  - _Requirements: 12.1-12.7_

- [ ] 11.3 Run comprehensive validation test suite
  - Execute all unit tests for parsers, API clients, fusion module
  - Execute all integration tests for pipelines and end-to-end flows
  - Validate with real dataset samples (at least 1,000 records per dataset)
  - Verify zero modifications to existing BADNA code (run git diff on frozen modules)
  - Verify all parsers produce valid UnifiedEvent output (schema validation)
  - Verify behavioral graph extraction produces valid embeddings (128D unit vectors)
  - Verify threat intel fusion enriches profiles without breaking original structure
  - Verify continuous updates work without errors (run for 24-hour test period)
  - Generate test coverage report (target: >80% coverage for new modules)
  - _Requirements: 12.1-12.7_

- [ ] 11.4 Performance benchmarking and optimization
  - Benchmark parser throughput: records/second for each parser
  - Benchmark graph extraction: embeddings/minute for behavioral patterns
  - Benchmark Knowledge Base queries: query time for 10,000 pattern KB
  - Benchmark full pipeline: time to ingest 100,000 records end-to-end
  - Identify bottlenecks: parsing, graph construction, embedding computation, storage
  - Optimize if needed: vectorization, caching, indexing, parallelization
  - Document performance metrics in `docs/PERFORMANCE_METRICS.md`
  - Verify performance targets: <10 seconds per 1,000 records
  - _Requirements: 9.7, 12.1-12.7_

### 12. Final Checkpoint

- [ ] 12.1 Verify project completion criteria
  - ✅ All 10 dataset parsers implemented and tested
  - ✅ All 2 API clients implemented and tested
  - ✅ Threat intel fusion module implemented and tested
  - ✅ Pipeline orchestration implemented and tested
  - ✅ Continuous update scheduler implemented and tested
  - ✅ Knowledge Base population script working
  - ✅ Zero modifications to existing BADNA code (frozen architecture preserved)
  - ✅ All integration tests passing
  - ✅ Documentation complete
  - ✅ Performance benchmarks meet targets
  - ✅ Ready for production deployment

## Notes

- **Foundation Complete:** Dataset Registry, Unified Event Schema, Base Parser are already implemented (Phase 1)
- **Architecture Preservation:** All new code is in `ingestion/` and `intelligence/threat_intel_fusion.py` only
- **Data Flow:** Raw Data → Parser → UnifiedEvent → BehaviorCaptureEngine → BehaviorGraph → d-BEF → Embedding → Knowledge Base
- **Testing Strategy:** Unit tests for parsers, integration tests for pipelines, end-to-end tests for complete flow
- **Performance:** Target <10 seconds per 1,000 records, streaming for large files, parallel processing where possible
- **Error Handling:** Graceful degradation, logging, continue on errors, checkpointing for resume
- **API Keys:** MalwareBazaar and URLhaus keys provided in requirements.md

## Task Dependencies

```json
{
  "waves": [
    {"id": 0, "tasks": ["1.1"]},
    {"id": 1, "tasks": ["1.2", "2.1", "2.2"]},
    {"id": 2, "tasks": ["2.3", "3.1", "3.2"]},
    {"id": 3, "tasks": ["3.3", "4.1"]},
    {"id": 4, "tasks": ["4.2", "5.1", "5.2", "5.3", "5.4"]},
    {"id": 5, "tasks": ["5.5", "6.1", "6.2"]},
    {"id": 6, "tasks": ["6.3", "7.1"]},
    {"id": 7, "tasks": ["7.2", "8.1"]},
    {"id": 8, "tasks": ["8.2"]},
    {"id": 9, "tasks": ["8.3", "9.1"]},
    {"id": 10, "tasks": ["9.2", "10.1", "10.2"]},
    {"id": 11, "tasks": ["11.1", "11.2", "11.3", "11.4"]},
    {"id": 12, "tasks": ["12.1"]}
  ]
}
```

## Success Metrics

- **Knowledge Base Size:** ≥100,000 behavioral patterns from 15 datasets
- **Campaign Profiles:** ≥500 unique attack campaign signatures
- **Threat Intel Coverage:** MITRE (16,000+ techniques), CAPEC (500+ patterns), CISA KEV (1,000+ CVEs)
- **Pipeline Performance:** <10 seconds per 1,000 records
- **Model Accuracy:** Improvement from 25% baseline to ≥85% after KB population
- **Architecture Preservation:** Zero modifications to existing BADNA code
