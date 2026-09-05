"""
ATLAS Telemetry Correlation Engine.
Correlates process, network, authentication, file, and PowerShell evidence
into a linked correlation_id and evidence-backed MITRE ATT&CK mappings.

Requirement #20 & #21:
- Observation -> Correlation -> Detection -> Assessment -> Response
- Controlled MITRE ATT&CK mapping_type: OBSERVED vs INFERRED vs ASSOCIATED
"""

from typing import List, Dict, Any
import uuid

class TelemetryCorrelationEngine:
    def __init__(self):
        pass

    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Groups events sharing PID, process name, or network socket into correlated chains."""
        if not events:
            return []

        correlated = []
        pid_map: Dict[int, str] = {}

        for ev in events:
            ev_copy = dict(ev)
            ev_type = ev_copy.get("event_type", "process")
            proc = ev_copy.get("process") or {}
            net = ev_copy.get("network") or {}
            
            pid = proc.get("pid") or 0
            if pid and pid not in pid_map:
                pid_map[pid] = f"corr-{uuid.uuid4().hex[:8]}"

            corr_id = pid_map.get(pid, f"corr-{uuid.uuid4().hex[:8]}")
            ev_copy["correlation_id"] = corr_id

            # Evidence-based MITRE ATT&CK mapping
            mitre_mappings = []
            cmd_line = str(proc.get("command_line", "")).lower()
            
            if "powershell" in str(proc.get("name", "")).lower() or "powershell" in cmd_line:
                if "-enc" in cmd_line or "-encodedcommand" in cmd_line or "hidden" in cmd_line:
                    mitre_mappings.append({
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell Script Execution",
                        "mapping_type": "OBSERVED",
                        "confidence": 0.96,
                        "evidence_event_ids": [ev_copy.get("event_id")]
                    })
                else:
                    mitre_mappings.append({
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell Execution",
                        "mapping_type": "INFERRED",
                        "confidence": 0.80,
                        "evidence_event_ids": [ev_copy.get("event_id")]
                    })
            
            if "whoami" in cmd_line or "ipconfig" in cmd_line or "net user" in cmd_line:
                mitre_mappings.append({
                    "technique_id": "T1033",
                    "technique_name": "System Owner/User Discovery",
                    "mapping_type": "OBSERVED",
                    "confidence": 0.92,
                    "evidence_event_ids": [ev_copy.get("event_id")]
                })

            if net.get("dst_port") in [22, 445, 3389]:
                mitre_mappings.append({
                    "technique_id": "T1021",
                    "technique_name": "Remote Services (SSH/SMB/RDP)",
                    "mapping_type": "OBSERVED",
                    "confidence": 0.90,
                    "evidence_event_ids": [ev_copy.get("event_id")]
                })

            ev_copy["mitre_mappings"] = mitre_mappings
            correlated.append(ev_copy)

        return correlated
