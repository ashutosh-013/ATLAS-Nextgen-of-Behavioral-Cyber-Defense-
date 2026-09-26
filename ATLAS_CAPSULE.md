# ATLAS: Master AI Context Capsule & System Knowledge Base

> **Version**: 2.5.4 (Enterprise Edition)  
> **Repository**: `ashutosh-013/ATLAS-Nextgen-of-Behavioral-Cyber-Defense-`  
> **Primary Technology Stack**: Python 3.10+, SQLite3, Vanilla Modern HTML5/CSS3/ES6, Windows Win32/Netsh APIs, PyInstaller, Inno Setup 6.  
> **Purpose**: This capsule provides complete, unambiguous context for any AI assistant or developer to instantly understand, maintain, debug, and extend the ATLAS Behavioral Cyber-Intelligence Platform without regression or architectural drift.

---

## 1. PROJECT IDENTITY & MISSION

**ATLAS** (**A**utonomous **T**elemetry & **L**earning **A**ttack **S**hield), powered by **BADNA** (**B**ehavioral **A**ttack **D**NA **A**nalysis), is a behavior-first cyber-defense platform. 

### Core Scientific Philosophy
1. **Behavior Over Signatures**: Traditional AV/EDR relies on signatures and hash matching which fail against zero-days, polymorphic malware, and living-off-the-land (LotL) techniques. ATLAS observes **behavioral causality** (process ancestry, network sockets, memory injection, file system touches).
2. **Empirical Science, Not AI Hype**: ATLAS does not make ungrounded marketing claims. Every detection is backed by calibrated statistical functions (CCF), Graph Neural Network (GNN) graph topology, and verifiable MITRE ATT&CK mapping.
3. **Behavioral DNA Core**:
   - **`d-BEF`** (*differential Behavioral Embedding Function*): Projects behavior graphs into continuous 128-dimensional dense vector embeddings.
   - **`BSF`** (*Behavioral Similarity Function*): Measures cosine/Euclidean distance against known benign and malicious historical behavior memory.
   - **`NSF`** (*Novelty Scoring Function*): Evaluates zero-day anomalies using Local Outlier Factor (LOF) and Locality-Sensitive Hashing (LSH).
   - **`CCF`** (*Confidence Calibration Function*): Calibrates multi-source evidence using Platt scaling and KB sample-size penalties to produce an honest [0.0, 1.0] confidence score without arbitrary hardcoding.

---

## 2. THE 10 INVARIANT DEVELOPMENT RULES

Any AI or developer working on this codebase **MUST ALWAYS** obey these rules without exception:

1. **Keep ATLAS Behavior-First**: Signature detection is a secondary supporting module. Telemetry events MUST pass through the behavioral pipeline even if an IOC matches.
2. **Never Let Any Module Bypass BADNA**: Every ingested event (Sysmon, socket, T-Pot, host agent) must route through the behavioral graph.
3. **Separate Responsibilities**:
   - `IOC Repository`: Stores static hashes, IPs, domains, CVEs (`intelligence/ioc_repository.py`).
   - `Behavioral Knowledge Base`: Stores 128D embeddings, campaigns, analyst feedback, and causal patterns (`knowledge_base/knowledge_base.py`). Never mix them.
4. **Use CCF for Confidence**: NEVER use hardcoded confidence boosts (e.g. `confidence += 0.15`). All confidence must be mathematically calibrated via `CCF` in `confidence/ccf.py`.
5. **Keep Quantum Optional**: The `quantum/` module is an experimental optimization service. ATLAS must always function identically using classical algorithms if quantum packages (`qiskit`) are missing.
6. **Optimize, Don't Overengineer (Ponytail Rules)**: Follow `.agents/rules/ponytail.md`. The shortest working diff wins. YAGNI (You Aren't Gonna Need It). Deletion over addition.
7. **Build for Real Data**: Prioritize real telemetry ingestion, parser fidelity, and end-to-end operational stability over adding abstract models.
8. **Keep Everything Modular**: Every subsystem (smart scan, firewall, GNN, rollback, web console) must be loosely coupled and replaceable.
9. **Measure Everything**: Modules must expose metrics (latency, memory usage, confidence distributions, false positive/negative rates).
10. **Preserve Working Functionality**: When "make the project smaller" conflicts with "preserve working behavior", ALWAYS preserve working behavior.

---

## 3. CORE APPLICATION ENTRY POINTS & EXECUTION FLOWS

```
                  ┌────────────────────────────────────────┐
                  │          Real Windows Host             │
                  │  (Processes, Sockets, Event Logs, WMI) │
                  └───────────────────┬────────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
   ┌───────────────────────────┐             ┌───────────────────────────┐
   │      atlas_agent.py       │             │   smart_scan_engine.py    │
   │ (Host Telemetry Daemon)   │             │ (7-Layer Empirical Scan)  │
   └─────────────┬─────────────┘             └─────────────┬─────────────┘
                 │                                         │
                 │ JSON Telemetry Stream                   │ Diagnostic Scan
                 ▼                                         ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │                    web_app.py (Flask SOC Backend)                   │
   │          - REST Endpoints (/api/scan, /api/playbook, /api/kb)       │
   │          - Server-Sent Events SSE (/api/stream)                     │
   │          - Host Containment Firewall API                            │
   └───────────────────┬─────────────────────────────────┬───────────────┘
                       │                                 │
                       ▼                                 ▼
   ┌──────────────────────────────────────┐  ┌───────────────────────────┐
   │         main.py (Orchestrator)       │  │     frontend/ (Web HUD)   │
   │  - 8-Stage Frozen BADNA Pipeline     │  │  - Single Page Interface  │
   │  - d-BEF -> BSF -> NSF -> CCF        │  │  - Real-time Graph & HUD  │
   └───────────────────┬──────────────────┘  └───────────────────────────┘
                       │
                       ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │              Database & Storage (SQLite: atlas_state.db)            │
   │        - incidents, telemetry_events, scan_reports, feedback        │
   └─────────────────────────────────────────────────────────────────────┘
```

### Primary Entry Points
* **`main.py` (`BADNAAnalysisOrchestrator`)**: The canonical 8-stage pipeline:
  1. *Raw Telemetry Ingestion* -> 2. *Behavior Graph Builder* (`capture_engine.py`) -> 3. *Feature Vector Formulation* -> 4. *d-BEF 128D Embedding* (`dbef.py`) -> 5. *BSF Similarity Scoring* (`bsf.py`) -> 6. *NSF Novelty Scoring* (`nsf.py`) -> 7. *CCF Calibration & RiskScorer* (`ccf.py`) -> 8. *AI Investigator & Response* (`investigator.py`).
* **`web_app.py`**: The production Flask REST server and real-time SSE event broadcaster (`/api/stream`). Also hosts the static SPA UI from `frontend/`.
* **`atlas_desktop.py`**: The desktop distribution entry point compiled by PyInstaller. Automatically binds an ephemeral/configured port, starts `web_app.py` in a background daemon, initializes the host agent, and launches the desktop browser/webview interface.
* **`atlas_agent.py`**: High-frequency endpoint daemon polling process creation, listening sockets, PowerShell scripts, and emulating T-Pot honeypot services.
* **`smart_scan_engine.py`**: Comprehensive 7-layer empirical scanner (Processes, Network Connections, Startup Persistence, Suspicious Directories, Decoy Canaries, Authenticode Signatures, AMSI inspection).

---

## 4. SUBSYSTEM & MODULE DIRECTORY REFERENCE

| Directory / File | Core Responsibility | Key Classes / Functions |
| :--- | :--- | :--- |
| **`behavior/`** | Behavioral causality graph construction and feature projection | `CaptureEngine`, `BehaviorGraph`, `dBEFEmbeddingModel` (128D embedding), `CanaryTrapEngine` (decoy files), `GNNTopologyClassifier` (spectral graph topology) |
| **`similarity/`** | Similarity analysis against behavioral memory | `BSFSimilarityEngine`, `cosine_similarity`, `euclidean_distance` |
| **`novelty/`** | Zero-day attack and outlier identification | `NSFNoveltyEngine`, `LocalOutlierFactor`, `LSHIndex` |
| **`confidence/`** | Calibrated threat and risk scoring | `ConfidenceCalibrationEngine` (CCF with Platt scaling), `RiskScorer` |
| **`intelligence/`** | Automated investigation, containment, and threat intelligence | `AIInvestigator`, `AdaptiveDefenseIntelligence`, `ThreatIntelFusion`, `IOCRepository`, `IOCMonitorEngine`, `VSSRollbackManager`, `AMSIScanner`, `AuthenticodeEngine`, `SelfDefenseEngine` |
| **`knowledge_base/`** | Persistent behavioral patterns and trained model weights | `BehavioralKnowledgeBase`, `behavior_memory.json`, `campaigns.json`, `models/*.pkl` |
| **`ingestion/`** | Real-world cybersecurity dataset parsers and normalization | `DatasetRegistry`, `UnifiedSchema`, Parsers: `cisa_kev`, `mitre_attack`, `capec`, `cicids`, `ctu13`, `darpa_optc`, `ember`, `sorel`, `tpot` |
| **`tpot_live_service.py`** | Decoy Honeypot Simulation & Ingestion | Emulates Honeytrap/Cowrie/Dionaea on ports 2222 (SSH), 4455 (SMB), 8080 (HTTP) |
| **`firewall_manager.py`** | Automated host isolation and containment | `CrossPlatformFirewallManager`, `WindowsNetshEngine` (creates and manages `ATLAS-Containment-*` firewall rules) |
| **`playbook_engine.py`** | SOAR-style incident response playbooks | `DefenceResponseEngine`, `Playbook`, state-machine execution, blast radius verification |
| **`privacy/sanitizer.py`** | PII and sensitive data masking | `DataSanitizer`, regex scrubbing for IPv4, emails, credentials, API tokens |
| **`database.py`** | SQLite relational storage | Database schema for `incidents`, `events`, `scans`, `quarantine`, `settings` in `atlas_state.db` |
| **`config_manager.py`** | Dynamic multi-module configuration | 85 configuration parameters across 10 security subsystems loaded from `config.json` |
| **`frontend/`** | SOC Cyber HUD User Interface | `index.html` (Cyber HUD layout), `app.js` (UI logic, SSE streaming, causal graph rendering), `styles.css` (Glassmorphic dark design) |
| **`atlas_desktop.spec`** | PyInstaller Compilation Specification | Packages python dependencies, models, frontend assets into Windows executable |
| **`atlas_setup.iss`** | Inno Setup 6 Installer Script | Compiles `dist_installer/ATLAS_v2.5_Enterprise_Setup.exe` with administrative privilege elevation (`RequireAdministrator`) |

---

## 5. DATABASE SCHEMA (`atlas_state.db`)

ATLAS utilizes SQLite with WAL (Write-Ahead Logging) mode enabled for high concurrency:

* **`incidents`**: `incident_id` (TEXT PK), `timestamp` (TEXT), `threat_class` (TEXT), `risk_score` (REAL), `confidence` (REAL), `severity` (TEXT), `iocs` (TEXT JSON), `summary` (TEXT), `raw_profile` (TEXT JSON).
* **`telemetry_events`**: `event_id` (TEXT PK), `timestamp` (TEXT), `event_type` (TEXT), `source_ip` (TEXT), `target_ip` (TEXT), `process_name` (TEXT), `pid` (INTEGER), `raw_data` (TEXT JSON).
* **`scan_reports`**: `scan_id` (TEXT PK), `timestamp` (TEXT), `scan_type` (TEXT), `total_findings` (INTEGER), `max_severity` (TEXT), `details` (TEXT JSON).
* **`quarantine`**: `id` (INTEGER PK), `file_path` (TEXT), `original_location` (TEXT), `quarantine_time` (TEXT), `sha256` (TEXT).
* **`audit_log`**: `id` (INTEGER PK), `timestamp` (TEXT), `action` (TEXT), `user` (TEXT), `status` (TEXT), `details` (TEXT JSON).

---

## 6. BUILD, RUN, & DEPLOYMENT INSTRUCTIONS

### Running Locally (Development Mode)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run active host telemetry agent (in background or separate terminal)
python atlas_agent.py

# 3. Run the Web SOC Dashboard
python web_app.py
# Access dashboard at: http://localhost:5000
```

### Automated Scripts
* **`start_atlas.bat`**: Launches both `web_app.py` and `atlas_agent.py` in synchronized background processes and opens the default browser.
* **`install_atlas.bat`**: One-click environment bootstrap, checks Python installation, installs `requirements.txt`, creates SQLite database, and pre-seeds initial Knowledge Base patterns.

### Compiling Desktop Application & Setup Wizard
```bash
# 1. Compile PyInstaller Desktop Standalone (Generates dist/ATLAS_Desktop/)
build_desktop.bat
# (Or: python build_desktop_app.py)

# 2. Compile Windows Setup Installer (Requires Inno Setup 6)
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" atlas_setup.iss
# Generates: dist_installer/ATLAS_v2.5_Enterprise_Setup.exe
```

---

## 7. IMPORTANT CONSTRAINTS & GOTCHAS

1. **Elevation (UAC Administrator)**:
   - Several features require Windows Administrator privileges:
     - `firewall_manager.py` (running `netsh advfirewall firewall add rule...`)
     - `intelligence/rollback.py` (VSS Shadow Copies via `vssadmin`)
     - `smart_scan_engine.py` (scanning protected system memory & startup registry keys)
   - The compiled desktop app and installer are pre-configured to request elevation (`requestedExecutionLevel level="requireAdministrator"`).
2. **Never Add Heavyweight Unrequested Dependencies**:
   - Do NOT introduce heavy C++ or PyTorch dependencies unless explicitly requested. The GNN classifier uses an optimized Spectral Graph NumPy/SciPy implementation.
3. **No Hardcoded Confidence Numbers**:
   - Always run multi-factor evidence through `confidence/ccf.py`.
4. **Honeypot Socket Binding**:
   - `atlas_agent.py` and `tpot_live_service.py` bind ports 2222, 4455, and 8080. If another process occupies these ports, the socket listener falls back gracefully to software emulation without crashing.
5. **UI Scaling & Viewport**:
   - The UI in `frontend/` is built with a responsive viewport layout (`height: 100vh`, `overflow: hidden`, inner scroll containers). Ensure elements adapt fluidly to 1080p, 1440p, and 4K displays.

---

## 8. SYSTEM VERIFICATION CHECKLIST FOR ANY AI AGENT

Before committing or pushing any modification to this repository, run this exact test cycle:

```bash
# 1. Python Syntax Verification
python -m py_compile main.py web_app.py smart_scan_engine.py atlas_agent.py telemetry_engine.py playbook_engine.py

# 2. Subsystem Unit & Supervisor Tests
pytest tests/test_behavioral_core_supervisor.py tests/test_smart_scan_engine.py tests/test_settings_system.py -q

# 3. Honeypot Telemetry Ingestion Verification
python test_tpot_full.py

# 4. Git Status Hygiene Check
git status -s
# Ensure no large test incident dumps or binary artifacts are tracked.
```
