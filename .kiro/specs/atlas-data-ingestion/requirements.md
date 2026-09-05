# Requirements Document: ATLAS Data Ingestion Infrastructure

## Introduction

The ATLAS Data Ingestion Infrastructure connects real-world cybersecurity datasets to the existing BADNA behavioral analysis pipeline. This infrastructure enables the system to learn from 21.1 million historical security events across 15 datasets, improving threat detection accuracy from baseline 25% to target 85%+.

**Critical Context:** The BADNA/ATLAS architecture is COMPLETE and FROZEN. This implementation adds ONLY the missing data infrastructure layer. The existing pipeline must NOT be modified.

## Glossary

- **UnifiedEvent**: Common event schema that all parsers output to feed BehaviorCaptureEngine
- **Dataset_Parser**: Component that converts dataset-specific format to UnifiedEvent format
- **Dataset_Registry**: Central registry tracking all 15 datasets with metadata and paths
- **Behavioral_Graph_Extraction**: Process converting UnifiedEvent → BehaviorGraph → d-BEF embedding
- **Knowledge_Base_Population**: Process storing extracted behavioral patterns in BADNA Knowledge Base
- **Threat_Intel_Fusion**: Module enriching detections with MITRE ATT&CK, CAPEC, CVE, KEV data
- **Continuous_Learning_Loop**: Hourly/daily updates from threat intelligence APIs
- **DARPA_OpTC**: Dataset containing endpoint telemetry in CDM format (provenance graphs)
- **CTU-13**: Dataset containing botnet network traffic in NetFlow CSV format
- **EMBER**: Dataset containing 1.1M malware samples with PE metadata
- **SOREL-20M**: Dataset containing 20M malware samples with features
- **MalwareBazaar_API**: Live threat feed providing recent malware samples
- **URLhaus_API**: Live threat feed providing malicious URL intelligence

## Architecture Context

**Existing FROZEN Pipeline:**
```
Telemetry Sources
↓
Behavior Capture Engine (✓ EXISTS) ← UnifiedEvent input
↓
Feature Engineering Layer (✓ EXISTS)
↓
BADNA Engine (d-BEF → BSF → NSF → CCF) (✓ EXISTS)
↓
AI Investigator (✓ EXISTS)
↓
Campaign Memory (✓ EXISTS)
↓
Threat Intelligence Fusion (NEW MODULE - THIS PROJECT)
↓
Adaptive Defense Intelligence (✓ EXISTS)
↓
Behavioral Knowledge Base (✓ EXISTS)
```

**What We're Building:**
- Dataset parsers (ingestion/parsers/)
- Threat intel parsers (ingestion/parsers/)
- API clients (ingestion/api_clients/)
- Threat intel fusion module (intelligence/threat_intel_fusion.py)
- Pipeline orchestration (ingestion/dataset_loader.py, graph_extraction_pipeline.py)
- Continuous update scheduler (ingestion/update_scheduler.py)

## Requirements

### Requirement 1: Dataset Parser Infrastructure

**User Story:** As a data engineer, I want standardized parsers for all 15 datasets, so that diverse data formats can feed into the BADNA pipeline uniformly.

#### Acceptance Criteria

1. WHEN a dataset-specific parser is implemented, IT SHALL inherit from BaseDatasetParser providing common infrastructure
2. WHEN a parser processes raw data, IT SHALL output UnifiedEvent objects with fields: event_id, event_type, timestamp, source_system, event_data
3. WHEN a parser encounters malformed data, IT SHALL log the error and continue processing valid records
4. WHEN a parser completes processing, IT SHALL return statistics: total_records, valid_records, invalid_records, error_count
5. THE parser SHALL support both batch and streaming modes for large files
6. THE parser SHALL validate that event_type is one of: process, file, network, auth, registry, user
7. THE parser SHALL preserve timestamp ordering when converting events
8. THE parser SHALL NOT modify any existing BADNA code in behavior/, confidence/, intelligence/, knowledge_base/ directories

### Requirement 2: DARPA OpTC Dataset Parser

**User Story:** As a security researcher, I want to parse DARPA OpTC endpoint telemetry data, so that provenance graph behaviors can be analyzed by BADNA.

#### Acceptance Criteria

1. WHEN DARPA OpTC CDM JSON files are provided, THE parser SHALL extract process, file, network, and authentication events
2. WHEN extracting process events, THE parser SHALL capture creation, termination, and parent-child relationships
3. WHEN extracting file events, THE parser SHALL capture read, write, delete, and modify operations
4. WHEN extracting network events, THE parser SHALL capture DNS queries, HTTP requests, and socket connections
5. WHEN parsing timestamps, THE parser SHALL convert CDM timestamp format to ISO 8601 datetime
6. WHEN a CDM event references provenance relationships, THE parser SHALL preserve causality for graph construction
7. THE parser SHALL handle nested CDM event structures and extract relevant behavioral data
8. THE parser SHALL map CDM event types to UnifiedEvent event_type enum values

### Requirement 3: Network Traffic Dataset Parsers (CTU-13, CICIDS)

**User Story:** As a network security analyst, I want to parse network intrusion datasets, so that BADNA can learn attack traffic patterns.

#### Acceptance Criteria

1. WHEN CTU-13 NetFlow CSV files are provided, THE parser SHALL extract network flow records with source/dest IPs, ports, protocols, and timestamps
2. WHEN CICIDS CSV files are provided, THE parser SHALL extract labeled network flows with attack type annotations
3. WHEN parsing network flows, THE parser SHALL normalize them to UnifiedEvent with event_type='network'
4. WHEN flow records contain attack labels, THE parser SHALL preserve them in event_data for supervised learning
5. THE parser SHALL handle large CSV files (>1GB) using streaming mode
6. THE parser SHALL convert network flow timestamps to consistent datetime format
7. WHEN flow records indicate botnet traffic (CTU-13), THE parser SHALL flag them for campaign clustering

### Requirement 4: Malware Dataset Parsers (EMBER, SOREL-20M)

**User Story:** As a malware analyst, I want to parse malware feature datasets, so that BADNA can learn file-based attack behaviors.

#### Acceptance Criteria

1. WHEN EMBER JSON files are provided, THE parser SHALL extract PE metadata, import tables, section features, and malware labels
2. WHEN SOREL-20M pickle files are provided, THE parser SHALL extract disassembly features, strings, and behavioral indicators
3. WHEN parsing malware samples, THE parser SHALL create file operation events representing malware execution behaviors
4. WHEN malware labels indicate family/type, THE parser SHALL preserve classification for supervised learning
5. THE parser SHALL handle large-scale batch processing of 1M+ samples efficiently
6. THE parser SHALL convert static features into behavioral event sequences for graph construction
7. WHEN malware features indicate persistence mechanisms, THE parser SHALL create registry/file modification events

### Requirement 5: Honeypot Dataset Parsers (T-Pot, MHN)

**User Story:** As a threat intelligence analyst, I want to parse honeypot attack logs, so that BADNA can learn real-world attack attempt patterns.

#### Acceptance Criteria

1. WHEN T-Pot JSON logs are provided, THE parser SHALL extract attack attempts, exploit payloads, and attacker IPs
2. WHEN MHN JSON logs are provided, THE parser SHALL extract honeypot sensor events and attack sequences
3. WHEN parsing attack attempts, THE parser SHALL create event sequences representing reconnaissance, exploitation, and post-exploitation
4. WHEN honeypot logs contain exploit payloads, THE parser SHALL preserve them for technique attribution
5. THE parser SHALL map honeypot events to MITRE ATT&CK tactic phases (initial_access, execution, etc.)
6. WHEN multiple attack stages are detected, THE parser SHALL preserve temporal ordering for behavioral sequencing

### Requirement 6: Threat Intelligence Parsers (MITRE ATT&CK, CAPEC, CVE, KEV)

**User Story:** As a threat intelligence analyst, I want to ingest structured threat intelligence, so that BADNA detections can be enriched with attribution and context.

#### Acceptance Criteria

1. WHEN MITRE ATT&CK STIX JSON is provided, THE parser SHALL extract techniques, tactics, procedures, and associated metadata
2. WHEN CAPEC XML is provided, THE parser SHALL extract attack patterns with IDs, descriptions, and related techniques
3. WHEN CISA KEV CSV is provided, THE parser SHALL extract known exploited vulnerabilities with CVE IDs and metadata
4. WHEN CVE JSON files are provided, THE parser SHALL extract vulnerability descriptions, CVSS scores, and affected products
5. THE parsers SHALL store threat intel in KnowledgeBase-compatible format for enrichment queries
6. WHEN parsing MITRE ATT&CK techniques, THE parser SHALL preserve technique IDs, parent techniques, and sub-techniques
7. WHEN parsing CAPEC patterns, THE parser SHALL link them to corresponding MITRE ATT&CK techniques where mappings exist

### Requirement 7: Threat Intelligence API Clients (MalwareBazaar, URLhaus)

**User Story:** As a security operations analyst, I want continuous updates from live threat feeds, so that BADNA stays current with emerging threats.

#### Acceptance Criteria

1. WHEN MalwareBazaar API is queried, THE client SHALL fetch recent malware samples (last 24 hours) using provided API key
2. WHEN URLhaus API is queried, THE client SHALL fetch recent malicious URLs (last 24 hours) using provided API key
3. WHEN API calls succeed, THE client SHALL return normalized data in UnifiedEvent-compatible format
4. WHEN API rate limits are encountered, THE client SHALL implement exponential backoff retry logic
5. WHEN API calls fail due to network errors, THE client SHALL log errors and retry with timeout
6. THE clients SHALL support querying by hash (MalwareBazaar) and URL (URLhaus) for threat lookups
7. WHEN fetching malware samples, THE client SHALL extract family, tags, and behavioral indicators

### Requirement 8: Threat Intelligence Fusion Module

**User Story:** As a security analyst, I want detections enriched with threat intelligence context, so that I can understand attack attribution and techniques.

#### Acceptance Criteria

1. WHEN a BADNAProfile is generated, THE fusion module SHALL enrich it with matching MITRE ATT&CK techniques
2. WHEN behavioral patterns match CAPEC attack patterns, THE fusion module SHALL add CAPEC references
3. WHEN file hashes or network indicators are present, THE fusion module SHALL cross-reference with MalwareBazaar/URLhaus recent data (last 7 days)
4. WHEN vulnerabilities are suspected, THE fusion module SHALL check CVE/KEV databases for known exploits
5. WHEN similar campaigns are matched, THE fusion module SHALL add APT group attribution if available
6. THE fusion module SHALL create EnrichedProfile = BADNAProfile + ThreatIntelContext
7. THE fusion module SHALL NOT modify existing BADNAProfile structure, only add enrichment fields
8. WHEN enrichment queries fail, THE fusion module SHALL proceed with base detection and log missing intel

### Requirement 9: Dataset Loader and Pipeline Orchestration

**User Story:** As a system administrator, I want automated ingestion of all 15 datasets, so that the Knowledge Base is populated with historical patterns.

#### Acceptance Criteria

1. WHEN the dataset loader is executed, IT SHALL process all 15 registered datasets sequentially or in parallel
2. FOR EACH dataset, THE loader SHALL: parse raw data → normalize to UnifiedEvent → feed to BehaviorCaptureEngine → build graphs → extract embeddings → store in Knowledge Base
3. WHEN processing a dataset, THE loader SHALL log progress: dataset_name, records_processed, patterns_stored, elapsed_time
4. WHEN all datasets are processed, THE loader SHALL generate summary statistics: total_patterns, patterns_by_threat_class, campaign_profiles_created
5. WHEN Knowledge Base population completes, THE loader SHALL trigger campaign clustering to identify behavioral families
6. THE loader SHALL implement graceful error handling: skip corrupted files, log errors, continue processing
7. WHEN memory usage exceeds thresholds, THE loader SHALL process datasets in smaller batches

### Requirement 10: Behavioral Graph Extraction Pipeline

**User Story:** As a data scientist, I want all data converted to behavioral graphs before training, so that BADNA never trains on raw CSV/JSON data directly.

#### Acceptance Criteria

1. WHEN raw dataset records are available, THE pipeline SHALL convert them to UnifiedEvent format first
2. WHEN UnifiedEvent data is available, THE pipeline SHALL feed it to BehaviorCaptureEngine.parse_events()
3. WHEN parsed events are available, THE pipeline SHALL call BehaviorCaptureEngine.build_graph() to create BehaviorGraph
4. WHEN BehaviorGraph is created, THE pipeline SHALL extract d-BEF 128D embeddings via compute_badna_embedding()
5. WHEN embedding is extracted, THE pipeline SHALL store it in Knowledge Base with metadata: threat_class, dataset_source, timestamp
6. THE pipeline SHALL NEVER pass raw CSV/JSON data directly to training algorithms
7. THE pipeline SHALL validate that every stored pattern has associated BehaviorGraph and embedding
8. WHEN graph extraction fails for a record, THE pipeline SHALL log the failure and continue with next record

### Requirement 11: Continuous Update Scheduler

**User Story:** As a security operations analyst, I want automated hourly/daily updates from threat feeds, so that BADNA continuously learns new threats.

#### Acceptance Criteria

1. WHEN the scheduler runs hourly, IT SHALL fetch updates from MalwareBazaar and URLhaus APIs
2. WHEN the scheduler runs daily, IT SHALL fetch updates from MITRE ATT&CK, CAPEC, and CISA KEV sources
3. WHEN new threat intel is fetched, THE scheduler SHALL parse it and update the Knowledge Base
4. WHEN Knowledge Base grows by 100+ new patterns, THE scheduler SHALL trigger model retraining
5. WHEN API fetch fails, THE scheduler SHALL log the error and retry on next scheduled run
6. THE scheduler SHALL maintain update history: source, timestamp, records_added, status
7. WHEN scheduler detects significant changes in threat landscape, IT SHALL alert administrators

### Requirement 12: Integration Testing and Validation

**User Story:** As a QA engineer, I want comprehensive tests validating end-to-end data flow, so that I can verify the ingestion pipeline works correctly.

#### Acceptance Criteria

1. WHEN a sample dataset is parsed, THE test SHALL verify UnifiedEvent output format correctness
2. WHEN UnifiedEvent data is fed to BehaviorCaptureEngine, THE test SHALL verify BehaviorGraph creation
3. WHEN BehaviorGraph is processed, THE test SHALL verify d-BEF embedding extraction produces 128D unit vectors
4. WHEN embeddings are stored, THE test SHALL verify Knowledge Base queries return correct patterns
5. WHEN threat intel fusion is applied, THE test SHALL verify enriched profiles contain MITRE ATT&CK mappings
6. THE test suite SHALL validate all 15 dataset parsers produce valid UnifiedEvent output
7. THE test suite SHALL validate API clients handle success, rate limits, and network errors correctly

## Success Metrics

1. **Knowledge Base Size:** ≥100,000 behavioral patterns stored from historical datasets
2. **Campaign Profiles:** ≥500 unique attack campaign signatures clustered
3. **Threat Intel Coverage:** MITRE ATT&CK (16,000+ techniques), CAPEC (500+ patterns), CISA KEV (1,000+ CVEs)
4. **API Update Success Rate:** ≥95% successful hourly/daily updates
5. **Pipeline Performance:** <10 seconds per 1,000 records ingestion throughput
6. **Model Accuracy:** Improvement from 25% baseline to ≥85% after Knowledge Base population
7. **Zero Architecture Violations:** No modifications to existing BADNA code in behavior/, confidence/, intelligence/, knowledge_base/

## Critical Design Constraints

1. **Never Train on Raw Data:** All data MUST be converted: Raw → Parser → UnifiedEvent → BehaviorGraph → d-BEF → Embedding → Knowledge Base
2. **Preserve Existing Architecture:** Zero modifications to main.py, behavior/, confidence/, novelty/, similarity/, intelligence/, knowledge_base/
3. **Unified Schema Compliance:** All parsers MUST output UnifiedEvent format compatible with BehaviorCaptureEngine
4. **Modular Parser Design:** Each dataset gets dedicated parser inheriting from BaseDatasetParser
5. **Backward Compatibility:** New modules MUST NOT break existing BADNA functionality

## API Keys

- **MalwareBazaar API:** `a0e979341fa8d75d3d29ea0ad09bbcd733d6d52de2d21c18`
- **URLhaus API:** `3ee64b3c43c091d055eeed31b686d4bb4cfb35fd21f72e63`

## Dataset Locations

All datasets are located in: `e:\BADNA\datasets\`

Registered datasets (15 total, 21.1M records):
1. DARPA OpTC - `OpTC-data-master/` (CDM JSON)
2. CTU-13 - `CTU-13-Dataset/` (NetFlow CSV)
3. CICIDS 2017/2018 - `*.csv/` (CSV flows)
4. EMBER - `ember-master/` (JSON/PKL)
5. SOREL-20M - `SOREL-20M-master/` (JSON/PKL)
6. T-Pot - `tpotce-master/` (JSON logs)
7. MHN - `mhn-master/` (JSON logs)
8. MITRE ATT&CK - `cti-master/enterprise-attack/` (STIX JSON)
9. CAPEC - `capec_latest/` (XML)
10. CISA KEV - `known_exploited_vulnerabilities.csv` (CSV)
11. CVE - `cvelistV5-main/` (JSON)

Foundation infrastructure (already complete):
- Dataset Registry: `ingestion/dataset_registry.py`
- Unified Event Schema: `ingestion/unified_schema.py`
- Base Parser Framework: `ingestion/base_parser.py`
