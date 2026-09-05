"""
ATLAS Central Configuration Manager and Subsystem Synchronization Engine.
Provides schema validation, default seeding, persistent storage via database,
and real-time event distribution to Telemetry, Detection, Campaigns, AI, and Defence modules.
"""

import json
import logging
import os
import psutil
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import database

logger = logging.getLogger("ConfigManager")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Master Setting Definitions & Schema
# =============================================================================

SETTING_SCHEMA: Dict[str, Dict[str, Any]] = {
    # --- 1. GENERAL ---
    "general.instance_name": {
        "module": "general", "type": "string", "default": "ATLAS-CORE-PROD-01",
        "description": "Unique identifier for this ATLAS deployment cluster instance.",
        "requires_restart": False
    },
    "general.environment": {
        "module": "general", "type": "string", "default": "Production",
        "enum": ["Production", "Staging", "Lab/Research"],
        "description": "Operating environment mode (governs strictness of logging and containment).",
        "requires_restart": False
    },
    "general.timezone": {
        "module": "general", "type": "string", "default": "UTC",
        "description": "Standardized timestamp localization timezone.",
        "requires_restart": False
    },
    "general.datetime_format": {
        "module": "general", "type": "string", "default": "ISO-8601",
        "enum": ["ISO-8601", "UTC / Unix Epoch", "Local 24h (YYYY-MM-DD HH:mm:ss)"],
        "description": "Timestamp display representation across telemetry tables and reports.",
        "requires_restart": False
    },
    "general.default_dashboard": {
        "module": "general", "type": "string", "default": "dashboard",
        "enum": ["dashboard", "threats", "investigation", "analytics", "ai-report"],
        "description": "Initial landing view upon SOC operator login.",
        "requires_restart": False
    },
    "general.auto_refresh_seconds": {
        "module": "general", "type": "int", "default": 5, "min": 2, "max": 300,
        "description": "Interval in seconds for polling live telemetry, stream updates, and health gauges.",
        "requires_restart": False
    },
    "general.theme": {
        "module": "general", "type": "string", "default": "dark-cyber",
        "enum": ["dark-cyber", "slate-navy", "high-contrast"],
        "description": "Visual contrast profile and graphical display theme.",
        "requires_restart": False
    },

    # --- 2. TELEMETRY & COLLECTORS ---
    "telemetry.winevent_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "Ingest Windows Security and System Event Logs via ETW.",
        "requires_restart": False
    },
    "telemetry.process_monitor_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "Differential process snapshotting and process-tree lineage reconstruction.",
        "requires_restart": False
    },
    "telemetry.network_sockets_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "Active socket connection monitoring, remote IP correlation, and port tracking.",
        "requires_restart": False
    },
    "telemetry.dns_monitor_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "DNS query resolution logging and DGA domain detection.",
        "requires_restart": False
    },
    "telemetry.powershell_monitor_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "Script block logging and base64-encoded argument inspection.",
        "requires_restart": False
    },
    "telemetry.sysmon_collector_enabled": {
        "module": "telemetry", "type": "bool", "default": True,
        "description": "Microsoft Sysmon XML telemetry stream parser.",
        "requires_restart": False
    },
    "telemetry.collection_interval_ms": {
        "module": "telemetry", "type": "int", "default": 1000, "min": 100, "max": 10000,
        "description": "Sampling interval in milliseconds between telemetry dispatcher ticks.",
        "requires_restart": False
    },
    "telemetry.collector_timeout_ms": {
        "module": "telemetry", "type": "int", "default": 5000, "min": 500, "max": 30000,
        "description": "Maximum execution time permitted for a single collector pass before threshold timeout.",
        "requires_restart": False
    },
    "telemetry.buffer_size": {
        "module": "telemetry", "type": "int", "default": 5000, "min": 100, "max": 50000,
        "description": "In-memory circular ring buffer capacity for real-time telemetry spikes.",
        "requires_restart": True
    },
    "telemetry.queue_size": {
        "module": "telemetry", "type": "int", "default": 10000, "min": 500, "max": 100000,
        "description": "Persistent asynchronous processing queue depth.",
        "requires_restart": True
    },
    "telemetry.max_event_rate_eps": {
        "module": "telemetry", "type": "int", "default": 500, "min": 10, "max": 5000,
        "description": "Maximum events-per-second ingestion ceiling before adaptive throttle engaging.",
        "requires_restart": False
    },
    "telemetry.dropped_event_threshold": {
        "module": "telemetry", "type": "int", "default": 50, "min": 1, "max": 1000,
        "description": "Number of dropped events before triggering an administrative collector warning.",
        "requires_restart": False
    },

    # --- 3. DETECTION & THREAT INTELLIGENCE ---
    "detection.sensitivity": {
        "module": "detection", "type": "string", "default": "Balanced (Standard)",
        "enum": ["Low (Conservative)", "Balanced (Standard)", "High (Aggressive)"],
        "description": "Governs behavioral anomaly sensitivity and threshold multipliers.",
        "requires_restart": False
    },
    "detection.min_confidence_threshold": {
        "module": "detection", "type": "float", "default": 0.60, "min": 0.10, "max": 0.99,
        "description": "Minimum calibrated confidence required before raising an active threat profile.",
        "requires_restart": False
    },
    "detection.ioc_matching_enabled": {
        "module": "detection", "type": "bool", "default": True,
        "description": "Match observed hashes, IPs, and domains against local Threat Intel feeds.",
        "requires_restart": False
    },
    "detection.hash_reputation_enabled": {
        "module": "detection", "type": "bool", "default": True,
        "description": "Query SHA256/MD5 malware hashes against MalwareBazaar / local cache.",
        "requires_restart": False
    },
    "detection.ip_reputation_enabled": {
        "module": "detection", "type": "bool", "default": True,
        "description": "Correlate external destination IPs against threat feed reputation databases.",
        "requires_restart": False
    },
    "detection.domain_reputation_enabled": {
        "module": "detection", "type": "bool", "default": True,
        "description": "Inspect URLhaus feed for malicious domain correlation.",
        "requires_restart": False
    },
    "detection.mitre_mapping_enabled": {
        "module": "detection", "type": "bool", "default": True,
        "description": "Automatically align detected behavior graphs with MITRE ATT&CK techniques.",
        "requires_restart": False
    },
    "detection.cisa_kev_sync_hours": {
        "module": "detection", "type": "int", "default": 24, "min": 1, "max": 168,
        "description": "Frequency in hours to refresh the CISA Known Exploited Vulnerabilities catalog.",
        "requires_restart": False
    },
    "detection.ioc_refresh_interval_hours": {
        "module": "detection", "type": "int", "default": 1, "min": 1, "max": 72,
        "description": "Interval for scheduled hourly threat feed synchronizations.",
        "requires_restart": False
    },
    "detection.ioc_expiration_days": {
        "module": "detection", "type": "int", "default": 30, "min": 1, "max": 365,
        "description": "Automatic expiration lifetime for transient IP and URL indicators.",
        "requires_restart": False
    },
    "detection.allowlist_processes": {
        "module": "detection", "type": "json",
        "default": ["explorer.exe", "svchost.exe", "SearchIndexer.exe", "RuntimeBroker.exe", "chrome.exe"],
        "description": "Verified system process names excluded from automated termination.",
        "requires_restart": False
    },
    "detection.blocklist_ips": {
        "module": "detection", "type": "json",
        "default": ["185.220.101.5", "194.26.29.112", "45.142.214.88"],
        "description": "Explicit threat IPs permanently blocked at local host firewall.",
        "requires_restart": False
    },

    # --- 4. CAMPAIGN INTELLIGENCE ---
    "campaigns.correlation_window_minutes": {
        "module": "campaigns", "type": "int", "default": 60, "min": 5, "max": 1440,
        "description": "Time window in minutes to cluster related multi-stage telemetry into single campaign.",
        "requires_restart": False
    },
    "campaigns.min_candidate_events": {
        "module": "campaigns", "type": "int", "default": 3, "min": 2, "max": 50,
        "description": "Minimum related security events required to promote a cluster into a Campaign Candidate.",
        "requires_restart": False
    },
    "campaigns.actor_correlation_threshold": {
        "module": "campaigns", "type": "float", "default": 0.65, "min": 0.30, "max": 0.95,
        "description": "Cosine similarity threshold for attributing campaign clusters to known adversary actors.",
        "requires_restart": False
    },
    "campaigns.process_tree_correlation": {
        "module": "campaigns", "type": "bool", "default": True,
        "description": "Use parent-child PID lineage to group lateral execution steps.",
        "requires_restart": False
    },
    "campaigns.network_correlation": {
        "module": "campaigns", "type": "bool", "default": True,
        "description": "Group shared destination subnets and C2 port trajectories into campaigns.",
        "requires_restart": False
    },
    "campaigns.mitre_technique_correlation": {
        "module": "campaigns", "type": "bool", "default": True,
        "description": "Correlate kill-chain technique sequences (e.g. Execution -> Credential Access).",
        "requires_restart": False
    },
    "campaigns.campaign_confidence_threshold": {
        "module": "campaigns", "type": "float", "default": 0.70, "min": 0.50, "max": 0.99,
        "description": "Confidence score required for high-risk campaign state promotion.",
        "requires_restart": False
    },
    "campaigns.campaign_expiration_hours": {
        "module": "campaigns", "type": "int", "default": 72, "min": 1, "max": 720,
        "description": "Hours of telemetry inactivity before marking an active campaign as INACTIVE.",
        "requires_restart": False
    },
    "campaigns.historical_memory_days": {
        "module": "campaigns", "type": "int", "default": 90, "min": 1, "max": 365,
        "description": "Duration in days to maintain campaign vector graphs in memory for similarity search.",
        "requires_restart": False
    },

    # --- 5. AI & NEURAL ANALYSIS ---
    "ai.enabled": {
        "module": "ai", "type": "bool", "default": True,
        "description": "Master toggle for neural embedding and AI cognitive investigator reasoning.",
        "requires_restart": False
    },
    "ai.model_provider": {
        "module": "ai", "type": "string", "default": "Local PyTorch (d-BEF 128D)",
        "enum": ["Local PyTorch (d-BEF 128D)", "Ensemble Random Forest/SVM/NN", "Hybrid Cognitive Router"],
        "description": "Neural architecture employed for behavioral representation embedding.",
        "requires_restart": False
    },
    "ai.temperature": {
        "module": "ai", "type": "float", "default": 0.20, "min": 0.0, "max": 1.0,
        "description": "Cognitive inference variance (lower = deterministic, higher = exploratory).",
        "requires_restart": False
    },
    "ai.max_context_events": {
        "module": "ai", "type": "int", "default": 100, "min": 10, "max": 1000,
        "description": "Maximum correlated event records provided to AI Investigator reasoning prompt.",
        "requires_restart": False
    },
    "ai.analysis_frequency_sec": {
        "module": "ai", "type": "int", "default": 5, "min": 1, "max": 60,
        "description": "Cadence in seconds for periodic neural clustering runs.",
        "requires_restart": False
    },
    "ai.confidence_gating_threshold": {
        "module": "ai", "type": "float", "default": 0.85, "min": 0.50, "max": 0.95,
        "description": "Confidence threshold required to bypass human review and authorize automated actions.",
        "requires_restart": False
    },
    "ai.explainability_level": {
        "module": "ai", "type": "string", "default": "Detailed (SOC Tier-2)",
        "enum": ["Concise (Executive)", "Detailed (SOC Tier-2)", "Deep-Dive (Research/Forensics)"],
        "description": "Depth of causal chain and evidence justification rendered in AI reports.",
        "requires_restart": False
    },
    "ai.continuous_model_retraining": {
        "module": "ai", "type": "bool", "default": True,
        "description": "Enable continuous model retraining on validated analyst feedback loops.",
        "requires_restart": False
    },
    "ai.quantum_fallback_layer": {
        "module": "ai", "type": "bool", "default": True,
        "description": "Enable Quantum-inspired optimization fallback for complex graph partitioning.",
        "requires_restart": False
    },
    "ai.model_timeout_sec": {
        "module": "ai", "type": "int", "default": 5, "min": 1, "max": 30,
        "description": "Maximum latency permitted for inference before falling back to classical heuristics.",
        "requires_restart": False
    },

    # --- 6. DEFENCE & PLAYBOOKS ---
    "defence.automation_mode": {
        "module": "defence", "type": "string", "default": "Approval Required",
        "enum": ["Recommendation Only", "Approval Required", "Automatic Low Risk", "Automatic Adaptive"],
        "description": "Gating protocol policy governing automated defensive playbook executions.",
        "requires_restart": False
    },
    "defence.global_kill_switch": {
        "module": "defence", "type": "bool", "default": False,
        "description": "EMERGENCY KILL SWITCH: Immediately blocks ALL automated destructive response actions while maintaining passive detection.",
        "requires_restart": False
    },
    "defence.policy_block_outbound_ip": {
        "module": "defence", "type": "bool", "default": True,
        "description": "Authorize Windows Firewall rule creation for confirmed C2 destination IPs.",
        "requires_restart": False
    },
    "defence.policy_terminate_process": {
        "module": "defence", "type": "bool", "default": True,
        "description": "Authorize process tree termination for verified high-severity malware executions.",
        "requires_restart": False
    },
    "defence.policy_isolate_endpoint": {
        "module": "defence", "type": "bool", "default": True,
        "description": "Authorize network adapter isolation for ransomware-infected hosts.",
        "requires_restart": False
    },
    "defence.policy_quarantine_file": {
        "module": "defence", "type": "bool", "default": True,
        "description": "Authorize AES-encrypted file staging into local quarantine vault.",
        "requires_restart": False
    },
    "defence.policy_firewall_rule": {
        "module": "defence", "type": "bool", "default": True,
        "description": "Authorize Netsh / WFP packet filtering rules.",
        "requires_restart": False
    },
    "defence.min_destructive_confidence": {
        "module": "defence", "type": "float", "default": 0.85, "min": 0.70, "max": 0.99,
        "description": "Minimum CCF calibrated confidence required before executing automated process kills.",
        "requires_restart": False
    },
    "defence.min_destructive_risk": {
        "module": "defence", "type": "float", "default": 0.75, "min": 0.50, "max": 0.99,
        "description": "Minimum risk score required to authorize host quarantine.",
        "requires_restart": False
    },

    # --- 7. DATA & STORAGE RETENTION ---
    "data.hot_telemetry_retention_days": {
        "module": "data", "type": "int", "default": 14, "min": 1, "max": 90,
        "description": "Days to maintain granular raw telemetry in active SQLite database.",
        "requires_restart": False
    },
    "data.historical_retention_days": {
        "module": "data", "type": "int", "default": 90, "min": 7, "max": 365,
        "description": "Days to preserve aggregated campaign summaries and threat timelines.",
        "requires_restart": False
    },
    "data.evidence_retention_days": {
        "module": "data", "type": "int", "default": 180, "min": 30, "max": 730,
        "description": "Duration to retain forensically validated incident evidence packages.",
        "requires_restart": False
    },
    "data.audit_log_retention_days": {
        "module": "data", "type": "int", "default": 365, "min": 90, "max": 1825,
        "description": "Retention period for administrative action audits and playbook logs.",
        "requires_restart": False
    },
    "data.auto_vacuum_enabled": {
        "module": "data", "type": "bool", "default": True,
        "description": "Automatically run SQLite VACUUM during low-activity night windows.",
        "requires_restart": False
    },
    "data.max_db_size_mb": {
        "module": "data", "type": "int", "default": 5000, "min": 100, "max": 50000,
        "description": "Storage capacity threshold in MB before triggering proactive cleanup.",
        "requires_restart": False
    },

    # --- 8. NOTIFICATIONS & ALERTS ---
    "notifications.critical_threat_alerts": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Emit immediate notifications when a Critical Risk threat is recognized.",
        "requires_restart": False
    },
    "notifications.campaign_detection_alerts": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Emit notification upon new adversary campaign formation.",
        "requires_restart": False
    },
    "notifications.playbook_execution_alerts": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Notify SOC operators when a defensive response action executes.",
        "requires_restart": False
    },
    "notifications.failed_response_alerts": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Raise high-priority alert if a defensive playbook execution errors.",
        "requires_restart": False
    },
    "notifications.collector_outage_alerts": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Alert when a live telemetry collector stops emitting events.",
        "requires_restart": False
    },
    "notifications.in_app_channel": {
        "module": "notifications", "type": "bool", "default": True,
        "description": "Display live in-app HUD toast banners and audio chimes.",
        "requires_restart": False
    },
    "notifications.webhook_channel": {
        "module": "notifications", "type": "bool", "default": False,
        "description": "POST structured JSON incident payloads to configured Webhook URI.",
        "requires_restart": False
    },
    "notifications.webhook_url": {
        "module": "notifications", "type": "string", "default": "",
        "description": "External Webhook URL (e.g. Slack / MS Teams / Splunk SIEM).",
        "requires_restart": False
    },
    "notifications.email_channel": {
        "module": "notifications", "type": "bool", "default": False,
        "description": "Send formatted incident summary emails via SMTP gateway.",
        "requires_restart": False
    },
    "notifications.email_recipient": {
        "module": "notifications", "type": "string", "default": "",
        "description": "SOC mailing list address for incident alerts.",
        "requires_restart": False
    },

    # --- 9. RBAC & ACCESS CONTROL ---
    "rbac.active_role": {
        "module": "rbac", "type": "string", "default": "SOC Administrator",
        "enum": [
            "Viewer (Read-Only)",
            "Tier-1 Analyst (Triage)",
            "Senior Analyst (Investigation)",
            "Incident Responder (Mitigation)",
            "SOC Administrator (Full Control)",
            "Security Administrator (Superuser)"
        ],
        "description": "Active session role and authority boundary.",
        "requires_restart": False
    },
    "rbac.enforce_mfa": {
        "module": "rbac", "type": "bool", "default": False,
        "description": "Require Multi-Factor Authentication for destructive playbook authorizations.",
        "requires_restart": False
    },
    "rbac.session_timeout_minutes": {
        "module": "rbac", "type": "int", "default": 60, "min": 5, "max": 480,
        "description": "Inactivity duration before requiring analyst re-authentication.",
        "requires_restart": False
    },
    "rbac.require_reason_for_destructive_actions": {
        "module": "rbac", "type": "bool", "default": True,
        "description": "Mandate an audit explanation string prior to host isolation or process kill.",
        "requires_restart": False
    },

    # --- 10. INTEGRATIONS ---
    "integrations.cisa_kev_endpoint": {
        "module": "integrations", "type": "string",
        "default": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "CISA Known Exploited Vulnerabilities JSON Catalog URL.",
        "requires_restart": False
    },
    "integrations.malwarebazaar_endpoint": {
        "module": "integrations", "type": "string",
        "default": "https://mb-api.abuse.ch/api/v1/",
        "description": "MalwareBazaar API endpoint for malware hash reputation lookups.",
        "requires_restart": False
    },
    "integrations.urlhaus_endpoint": {
        "module": "integrations", "type": "string",
        "default": "https://urlhaus-api.abuse.ch/v1/",
        "description": "URLhaus API endpoint for malicious payload URL lookups.",
        "requires_restart": False
    },
    "integrations.virustotal_api_key": {
        "module": "integrations", "type": "string", "default": "",
        "description": "VirusTotal v3 API Key for external hash analysis (masked in UI).",
        "requires_restart": False
    },
    "integrations.misp_url": {
        "module": "integrations", "type": "string", "default": "",
        "description": "MISP Threat Intelligence Sharing instance base URL.",
        "requires_restart": False
    },
    "integrations.opencti_url": {
        "module": "integrations", "type": "string", "default": "",
        "description": "OpenCTI Cyber Threat Intelligence platform API URL.",
        "requires_restart": False
    }
}


# =============================================================================
# Configuration Manager Class
# =============================================================================

class ConfigManager:
    """Central Configuration Service with Validation, Persistence, and Runtime Dispatch."""

    def __init__(self):
        database.init_db()
        self._seed_defaults_if_empty()
        self._listeners: List[Any] = []

    def _seed_defaults_if_empty(self):
        """Ensures all schema keys have initial persistent records in SQLite."""
        existing = database.get_all_settings()
        to_seed = {}
        for key, meta in SETTING_SCHEMA.items():
            if key not in existing:
                to_seed[key] = {
                    "value": meta["default"],
                    "type": meta["type"],
                    "module": meta["module"],
                    "requires_restart": meta.get("requires_restart", False)
                }
        if to_seed:
            database.set_bulk_settings(to_seed, actor="SYSTEM", reason="Initial System Initialization")
            logger.info(f"[+] ConfigManager seeded {len(to_seed)} default settings into DB")

    def register_listener(self, callback):
        """Registers a runtime component to receive configuration updates."""
        if callback not in self._listeners:
            self._listeners.append(callback)

    def validate_setting(self, key: str, value: Any) -> Tuple[bool, Optional[str], Any]:
        """Validates a single setting value against schema rules."""
        if key not in SETTING_SCHEMA:
            return False, f"Unknown configuration key: {key}", None

        meta = SETTING_SCHEMA[key]
        expected_type = meta["type"]

        # Type conversion & validation
        try:
            if expected_type == "bool":
                if isinstance(value, str):
                    converted = value.lower() in ["true", "1", "yes"]
                else:
                    converted = bool(value)
            elif expected_type == "int":
                converted = int(value)
                if "min" in meta and converted < meta["min"]:
                    return False, f"{key} must be >= {meta['min']}", None
                if "max" in meta and converted > meta["max"]:
                    return False, f"{key} must be <= {meta['max']}", None
            elif expected_type == "float":
                converted = float(value)
                if "min" in meta and converted < meta["min"]:
                    return False, f"{key} must be >= {meta['min']}", None
                if "max" in meta and converted > meta["max"]:
                    return False, f"{key} must be <= {meta['max']}", None
            elif expected_type == "string":
                converted = str(value).strip()
                if "enum" in meta and converted not in meta["enum"]:
                    return False, f"{key} must be one of: {meta['enum']}", None
            elif expected_type == "json":
                if isinstance(value, str):
                    converted = json.loads(value)
                else:
                    converted = value
                if not isinstance(converted, (list, dict)):
                    return False, f"{key} must be a valid JSON array or object", None
            else:
                converted = value

            return True, None, converted
        except Exception as e:
            return False, f"Invalid value format for {key} ({expected_type}): {str(e)}", None

    def get_all(self) -> Dict[str, Any]:
        """Returns all configuration items formatted by module with current values."""
        db_settings = database.get_all_settings()
        grouped: Dict[str, Dict[str, Any]] = {
            "general": {}, "telemetry": {}, "detection": {}, "campaigns": {},
            "ai": {}, "defence": {}, "data": {}, "notifications": {},
            "rbac": {}, "integrations": {}
        }

        for key, meta in SETTING_SCHEMA.items():
            mod = meta["module"]
            if mod not in grouped:
                grouped[mod] = {}

            db_record = db_settings.get(key, {})
            current_val = db_record.get("parsed_value", meta["default"])
            
            # Mask API keys if non-empty
            display_val = current_val
            if "api_key" in key and current_val:
                display_val = "••••••••••••••••"

            grouped[mod][key] = {
                "key": key,
                "value": current_val,
                "display_value": display_val,
                "default": meta["default"],
                "type": meta["type"],
                "description": meta.get("description", ""),
                "requires_restart": meta.get("requires_restart", False),
                "enum": meta.get("enum"),
                "min": meta.get("min"),
                "max": meta.get("max"),
                "version": db_record.get("version", 1),
                "updated_at": db_record.get("updated_at", "Factory Default"),
                "updated_by": db_record.get("updated_by", "SYSTEM")
            }

        return grouped

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a single setting value from persistent store or default schema."""
        if key in SETTING_SCHEMA and default is None:
            default = SETTING_SCHEMA[key]["default"]
        return database.get_setting(key, default)

    def set(self, key: str, value: Any, actor: str = "SOC Operator", 
            reason: str = "", ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """Validates, persists, notifies runtime modules, and writes audit record."""
        valid, err, converted = self.validate_setting(key, value)
        if not valid:
            raise ValueError(err)

        meta = SETTING_SCHEMA[key]
        result = database.set_setting(
            key=key,
            value=converted,
            type_hint=meta["type"],
            module=meta["module"],
            requires_restart=1 if meta.get("requires_restart") else 0,
            actor=actor,
            reason=reason or f"Updated {key}",
            ip_address=ip_address
        )

        # Notify runtime listeners
        self._notify_listeners(meta["module"], {key: converted})
        return result

    def set_bulk(self, updates: Dict[str, Any], actor: str = "SOC Operator", 
                 reason: str = "", ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """Validates and applies a batch of configuration updates atomically."""
        validated_batch = {}
        errors = {}
        restart_required_keys = []

        for key, val in updates.items():
            valid, err, converted = self.validate_setting(key, val)
            if not valid:
                errors[key] = err
            else:
                meta = SETTING_SCHEMA[key]
                validated_batch[key] = {
                    "value": converted,
                    "type": meta["type"],
                    "module": meta["module"],
                    "requires_restart": meta.get("requires_restart", False)
                }
                if meta.get("requires_restart"):
                    restart_required_keys.append(key)

        if errors:
            return {"success": False, "errors": errors}

        res = database.set_bulk_settings(validated_batch, actor=actor, reason=reason, ip_address=ip_address)
        
        # Group changes by module for targeted runtime dispatch
        by_module: Dict[str, Dict[str, Any]] = {}
        for k, v in validated_batch.items():
            mod = v["module"]
            if mod not in by_module:
                by_module[mod] = {}
            by_module[mod][k] = v["value"]

        for mod, mod_changes in by_module.items():
            self._notify_listeners(mod, mod_changes)

        return {
            "success": True,
            "updated_count": len(res),
            "restart_required": len(restart_required_keys) > 0,
            "restart_keys": restart_required_keys,
            "results": res
        }

    def reset_to_defaults(self, module: Optional[str] = None, actor: str = "SOC Operator", 
                          reason: str = "Reset to factory defaults") -> Dict[str, Any]:
        """Restores default values for a module or all settings."""
        to_reset = {}
        for key, meta in SETTING_SCHEMA.items():
            if not module or meta["module"] == module:
                to_reset[key] = {
                    "value": meta["default"],
                    "type": meta["type"],
                    "module": meta["module"],
                    "requires_restart": meta.get("requires_restart", False)
                }
        
        database.reset_settings(module=module, actor=actor, reason=reason)
        database.set_bulk_settings(to_reset, actor=actor, reason=reason)
        
        if module:
            self._notify_listeners(module, {k: v["value"] for k, v in to_reset.items()})
        else:
            for mod in ["general", "telemetry", "detection", "campaigns", "ai", "defence", "data", "notifications", "rbac", "integrations"]:
                mod_changes = {k: v["value"] for k, v in to_reset.items() if v["module"] == mod}
                if mod_changes:
                    self._notify_listeners(mod, mod_changes)

        return {"success": True, "reset_count": len(to_reset), "module": module or "ALL"}

    def toggle_defence_kill_switch(self, enabled: bool, actor: str = "SOC Operator", 
                                  reason: str = "Emergency Kill Switch Toggle") -> Dict[str, Any]:
        """High-priority instant toggle for the Global Defence Automation Kill Switch."""
        res = self.set(
            key="defence.global_kill_switch",
            value=enabled,
            actor=actor,
            reason=f"Emergency Kill Switch {'ENGAGED' if enabled else 'DISENGAGED'}: {reason}"
        )
        logger.warning(f"[!] GLOBAL DEFENCE KILL SWITCH {'ENGAGED' if enabled else 'DISENGAGED'} by {actor}")
        return {"success": True, "kill_switch_active": enabled, "result": res}

    def export_config(self) -> Dict[str, Any]:
        """Exports full JSON configuration bundle with metadata."""
        db_settings = database.get_all_settings()
        export_data = {}
        for key, record in db_settings.items():
            export_data[key] = record.get("parsed_value")

        return {
            "atlas_version": "2.4.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "instance_name": export_data.get("general.instance_name", "ATLAS-CORE-PROD-01"),
            "configuration": export_data
        }

    def import_config(self, bundle: Dict[str, Any], actor: str = "SOC Operator") -> Dict[str, Any]:
        """Imports and validates a configuration bundle."""
        if not isinstance(bundle, dict) or "configuration" not in bundle:
            return {"success": False, "error": "Invalid configuration bundle structure."}

        configs = bundle["configuration"]
        return self.set_bulk(configs, actor=actor, reason=f"Imported configuration bundle exported at {bundle.get('exported_at', 'Unknown')}")

    def _notify_listeners(self, module: str, changes: Dict[str, Any]):
        """Dispatches configuration changes to registered runtime listeners."""
        for callback in self._listeners:
            try:
                callback(module, changes)
            except Exception as e:
                logger.error(f"Error notifying config listener for module {module}: {e}")


# =============================================================================
# Global Config Manager Singleton
# =============================================================================

_CONFIG_MANAGER_INSTANCE: Optional[ConfigManager] = None

def get_config_manager() -> ConfigManager:
    global _CONFIG_MANAGER_INSTANCE
    if _CONFIG_MANAGER_INSTANCE is None:
        _CONFIG_MANAGER_INSTANCE = ConfigManager()
    return _CONFIG_MANAGER_INSTANCE
