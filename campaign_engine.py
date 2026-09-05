"""
ATLAS Campaign Intelligence & Behavioral Correlation Engine.
Correlates multi-source telemetry (T-Pot, Endpoint, Network, Process, PowerShell, DNS, File, Auth, IOCs)
into evidence-backed behavioral campaign candidates, attack sessions, lifecycle chains, and relationship graphs.
"""

import uuid
import time
import json
import logging
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple

from telemetry_schema import normalize_raw_event, get_stable_host_id

LIFECYCLE_STAGES = [
    "RECONNAISSANCE",
    "INITIAL_ACCESS",
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "DEFENSE_EVASION",
    "CREDENTIAL_ACCESS",
    "DISCOVERY",
    "LATERAL_MOVEMENT",
    "COMMAND_AND_CONTROL",
    "COLLECTION",
    "EXFILTRATION"
]


@dataclass
class Attribution:
    type: str = "UNKNOWN"  # UNKNOWN, OBSERVED, INFERRED, ASSOCIATED
    name: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name if self.type != "UNKNOWN" else None,
            "confidence": round(self.confidence, 2)
        }


@dataclass
class AttackSession:
    session_id: str
    source_ip: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_ports: List[int] = field(default_factory=list)
    event_types: List[str] = field(default_factory=list)
    lifecycle_stages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "event_count": len(self.events),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "target_ports": self.target_ports,
            "event_types": self.event_types,
            "lifecycle_stages": self.lifecycle_stages
        }


@dataclass
class Campaign:
    campaign_id: str
    campaign_name: str
    campaign_type: str = "BEHAVIORAL"  # BEHAVIORAL, INFRASTRUCTURE, MULTI_STAGE
    status: str = "ACTIVE"  # CANDIDATE, ACTIVE, ESCALATED, MONITORING, CONTAINED, RESOLVED, ARCHIVED, FALSE_POSITIVE
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_mode: str = "LIVE"  # LIVE, SCENARIO
    confidence: float = 0.80
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    attribution: Attribution = field(default_factory=Attribution)
    evidence_event_ids: List[str] = field(default_factory=list)
    attack_session_ids: List[str] = field(default_factory=list)
    ioc_ids: List[str] = field(default_factory=list)
    technique_ids: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    target_ports: List[int] = field(default_factory=list)
    honeypots: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    behavior_fingerprint: Dict[str, Any] = field(default_factory=dict)
    campaign_stage: str = "INITIAL_ACCESS"
    observed_stages: List[str] = field(default_factory=list)
    mapping_type: str = "INFERRED"  # OBSERVED, INFERRED, ASSOCIATED
    analyst_status: str = "UNVALIDATED"  # UNVALIDATED, VALIDATED, REJECTED
    confidence_reasons: List[str] = field(default_factory=list)
    severity_reasons: List[str] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["attribution"] = self.attribution.to_dict() if isinstance(self.attribution, Attribution) else self.attribution
        return d


class CampaignEngine:
    """Core behavioral correlation and campaign discovery engine for ATLAS."""
    
    def __init__(self):
        self.logger = logging.getLogger("CampaignEngine")

    def build_attack_sessions(self, events: List[Dict[str, Any]], source_mode: str = "LIVE") -> List[AttackSession]:
        """Groups raw/normalized telemetry into AttackSession objects."""
        filtered = [e for e in events if e.get("source_mode") == source_mode]
        if not filtered:
            return []

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for ev in filtered:
            key = ev.get("src_ip") or ev.get("source") or "internal_host"
            grouped.setdefault(key, []).append(ev)

        sessions = []
        s_idx = 1
        for src_ip, evs in grouped.items():
            s_id = f"SESS-{src_ip}-{s_idx}"
            ports = sorted(list(set(int(e["dst_port"]) for e in evs if e.get("dst_port"))))
            types = sorted(list(set(e.get("event_type", "proc") for e in evs if e.get("event_type"))))
            stages = self.evaluate_lifecycle_stages(evs)
            
            timestamps = [e.get("timestamp") for e in evs if e.get("timestamp")]
            first_ts = min(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()
            last_ts = max(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()

            sessions.append(AttackSession(
                session_id=s_id,
                source_ip=src_ip,
                events=evs,
                first_seen=first_ts,
                last_seen=last_ts,
                target_ports=ports,
                event_types=types,
                lifecycle_stages=stages
            ))
            s_idx += 1

        return sessions

    def extract_behavior_fingerprint(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extracts structured behavioral fingerprint features from event stream."""
        protocols = set()
        ports = set()
        auth_signals = set()
        commands = set()
        has_payload = False
        has_execution = False

        for ev in events:
            ev_type = (ev.get("event_type") or "").lower()
            cmd = (ev.get("command") or "").lower()
            proto = (ev.get("protocol") or "").upper()
            dst_p = ev.get("dst_port")

            if proto:
                protocols.add(proto)
            if dst_p:
                ports.add(int(dst_p))

            if ev_type == "authentication" or "auth" in ev_type:
                auth_signals.add("authentication_observed")
                if "fail" in cmd or "brute" in cmd:
                    auth_signals.add("bruteforce_attempt")
                if "success" in cmd or "login" in cmd:
                    auth_signals.add("login_success")

            if ev_type in ["process", "powershell"]:
                has_execution = True
                if "wget" in cmd or "curl" in cmd or "download" in cmd or "http" in cmd:
                    has_payload = True
                    commands.add("payload_retrieval")
                if "powershell" in cmd:
                    commands.add("powershell_execution")
                if "whoami" in cmd or "net user" in cmd or "ipconfig" in cmd:
                    commands.add("recon_command")

            if ev_type == "file":
                if "write" in cmd or "exe" in cmd or "dll" in cmd:
                    has_payload = True

        return {
            "protocols": sorted(list(protocols)) or ["TCP"],
            "ports": sorted(list(ports)) or [22, 80, 443],
            "authentication": sorted(list(auth_signals)) or ["observed"],
            "commands": sorted(list(commands)) or ["process_spawn"],
            "payload_delivery": has_payload,
            "execution": has_execution
        }

    def evaluate_lifecycle_stages(self, events: List[Dict[str, Any]]) -> List[str]:
        """Determines observed campaign lifecycle stages based strictly on evidence."""
        observed = set()
        for ev in events:
            ev_type = (ev.get("event_type") or "").lower()
            cmd = (ev.get("command") or "").lower()

            if ev_type in ["network", "dns"] or "scan" in cmd or "ping" in cmd:
                observed.add("RECONNAISSANCE")
            if ev_type in ["authentication", "network"] or "ssh" in cmd or "rdp" in cmd:
                observed.add("INITIAL_ACCESS")
            if ev_type in ["process", "powershell"]:
                observed.add("EXECUTION")
            if "run" in cmd or "schtasks" in cmd or "registry" in cmd:
                observed.add("PERSISTENCE")
            if "whoami" in cmd or "net" in cmd or "systeminfo" in cmd:
                observed.add("DISCOVERY")
            if "mimikatz" in cmd or "lsass" in cmd or "pass" in cmd:
                observed.add("CREDENTIAL_ACCESS")
            if "c2" in cmd or "beacon" in cmd:
                observed.add("COMMAND_AND_CONTROL")

        if not observed:
            observed.add("INITIAL_ACCESS")
        
        return [s for s in LIFECYCLE_STAGES if s in observed]

    def calculate_confidence(self, events: List[Dict[str, Any]], src_ips: List[str], techniques: List[str]) -> Tuple[float, List[str]]:
        """Calculates an explainable confidence score with positive & negative factors."""
        score = 0.50
        reasons = []

        if len(events) >= 5:
            score += 0.15
            reasons.append("+ Strong multi-event temporal correlation")
        elif len(events) >= 2:
            score += 0.10
            reasons.append("+ Multiple observed event links")

        if len(src_ips) >= 2:
            score += 0.12
            reasons.append("+ Multi-source IP infrastructure cluster")

        if len(techniques) >= 2:
            score += 0.13
            reasons.append("+ Multi-stage MITRE ATT&CK technique consistency")

        if any(e.get("source") == "ScenarioEngine" for e in events):
            reasons.append("+ Synthetic scenario baseline verification")

        reasons.append("- No external threat actor intelligence attribution")
        
        final_conf = min(0.95, max(0.40, score))
        return round(final_conf, 2), reasons

    def calculate_severity(self, events: List[Dict[str, Any]], stages: List[str]) -> Tuple[str, List[str]]:
        """Calculates severity based on impact indicators rather than confidence."""
        reasons = []
        is_critical = "CREDENTIAL_ACCESS" in stages or "COMMAND_AND_CONTROL" in stages or "EXFILTRATION" in stages
        is_high = "EXECUTION" in stages or "PERSISTENCE" in stages or len(events) >= 4

        for ev in events:
            cmd = (ev.get("command") or "").lower()
            if "lsass" in cmd or "mimikatz" in cmd:
                reasons.append("Credential dumping payload detected")
                is_critical = True
            if "powershell" in cmd and "enc" in cmd:
                reasons.append("Obfuscated PowerShell execution")
                is_high = True

        if is_critical:
            reasons.append("Multi-stage high-impact attack lifecycle reached")
            return "CRITICAL", reasons
        elif is_high:
            reasons.append("Command execution & persistence activity observed")
            return "HIGH", reasons
        else:
            reasons.append("Observed reconnaissance / authentication sequence")
            return "MEDIUM", reasons

    def correlate_telemetry(self, events: List[Dict[str, Any]], source_mode: str = "LIVE") -> List[Campaign]:
        """Correlates telemetry events into Campaign objects via AttackSessions."""
        if not events:
            return []

        attack_sessions = self.build_attack_sessions(events, source_mode=source_mode)
        if not attack_sessions:
            return []

        campaigns = []
        c_idx = 1

        for session in attack_sessions:
            g_events = session.events
            if not g_events:
                continue

            # Check if telemetry contains suspicious / multi-stage activity warranting a Campaign candidate
            suspicious_keywords = {"powershell", "wget", "curl", "mimikatz", "lsass", "schtasks", "nc", "chmod", "brute", "bypass"}
            has_suspicious_cmd = False
            for e in g_events:
                cmd_words = set((e.get("command") or "").lower().replace("-", " ").replace("/", " ").replace("\\", " ").split())
                if cmd_words.intersection(suspicious_keywords):
                    has_suspicious_cmd = True
                    break

            has_multi_events = len(g_events) >= 2 and any(e.get("event_type") in ["network", "authentication", "process"] for e in g_events)
            is_scenario = (source_mode == "SCENARIO") or any(e.get("source") == "ScenarioEngine" for e in g_events)

            # Strict correlation threshold: Only create candidate if suspicious payload/auth sequence, multi-event cluster, or scenario
            if not (has_suspicious_cmd or has_multi_events or is_scenario):
                continue

            ev_ids = [e.get("event_id") for e in g_events if e.get("event_id")]
            src_ips = [session.source_ip] if session.source_ip else []
            dst_ips = sorted(list(set(e.get("dst_ip") for e in g_events if e.get("dst_ip"))))
            target_ports = session.target_ports
            hosts = sorted(list(set(e.get("host_id") for e in g_events if e.get("host_id")))) or [get_stable_host_id()]

            techs = set()
            for e in g_events:
                et = (e.get("event_type") or "").lower()
                cmd = (e.get("command") or "").lower()
                if "powershell" in et or "powershell" in cmd:
                    techs.add("T1059.001")
                if "lsass" in cmd or "mimikatz" in cmd:
                    techs.add("T1003.001")
                if et == "network" or dst_ips:
                    techs.add("T1071.001")

            tech_list = sorted(list(techs)) or ["T1059"]
            stages = session.lifecycle_stages
            fingerprint = self.extract_behavior_fingerprint(g_events)
            confidence, conf_reasons = self.calculate_confidence(g_events, src_ips, tech_list)
            severity, sev_reasons = self.calculate_severity(g_events, stages)

            attribution = Attribution(type="UNKNOWN", name=None, confidence=0.0)

            c_id = f"CMP-2026-{c_idx:04d}"
            c_name = f"UNKNOWN BEHAVIORAL CAMPAIGN {c_id}"

            camp = Campaign(
                campaign_id=c_id,
                campaign_name=c_name,
                campaign_type="BEHAVIORAL",
                status="ACTIVE",
                first_seen=session.first_seen,
                last_seen=session.last_seen,
                source_mode=source_mode,
                confidence=confidence,
                severity=severity,
                attribution=attribution,
                evidence_event_ids=ev_ids,
                attack_session_ids=[session.session_id],
                technique_ids=tech_list,
                source_ips=src_ips,
                destination_ips=dst_ips,
                target_ports=target_ports,
                hosts=hosts,
                behavior_fingerprint=fingerprint,
                campaign_stage=stages[-1] if stages else "INITIAL_ACCESS",
                observed_stages=stages,
                mapping_type="INFERRED",
                analyst_status="UNVALIDATED",
                confidence_reasons=conf_reasons,
                severity_reasons=sev_reasons,
                audit_trail=[{
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "CAMPAIGN_DISCOVERED",
                    "actor": "CampaignEngine",
                    "notes": f"Correlated attack session {session.session_id} containing {len(ev_ids)} events"
                }]
            )
            campaigns.append(camp)
            c_idx += 1

        return campaigns

    def generate_relationship_graph(self, campaign_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Generates node-link graph data for interactive relationship visualization."""
        c_id = campaign_dict.get("campaign_id", "CMP-0001")

        nodes = [
            {"id": c_id, "label": c_id, "type": "campaign", "severity": campaign_dict.get("severity", "HIGH")}
        ]
        edges = []

        for ip in campaign_dict.get("source_ips", []):
            ip_id = f"ip-{ip}"
            nodes.append({"id": ip_id, "label": ip, "type": "ip"})
            edges.append({"source": c_id, "target": ip_id, "label": "OBSERVED_IN"})

        for ip in campaign_dict.get("destination_ips", []):
            ip_id = f"dst-{ip}"
            nodes.append({"id": ip_id, "label": ip, "type": "ip"})
            edges.append({"source": c_id, "target": ip_id, "label": "CONNECTED_TO"})

        for h in campaign_dict.get("hosts", []):
            h_id = f"host-{h}"
            nodes.append({"id": h_id, "label": h, "type": "host"})
            edges.append({"source": c_id, "target": h_id, "label": "TARGETED"})

        for t in campaign_dict.get("technique_ids", []):
            t_id = f"tech-{t}"
            nodes.append({"id": t_id, "label": t, "type": "technique"})
            edges.append({"source": c_id, "target": t_id, "label": "EXECUTED"})

        return {"nodes": nodes, "edges": edges}

    def generate_scenario_campaigns(self, scenario_name: str) -> List[Campaign]:
        """Generates deterministic test scenario campaigns (source_mode = SCENARIO)."""
        now_str = datetime.now(timezone.utc).isoformat()
        name = scenario_name.upper()

        if name in ["BENIGN", "BENIGN_BASELINE"]:
            return []

        if name in ["SSH_BRUTEFORCE", "SUSPICIOUS_POWERSHELL", "POWERSHELL_EXECUTION"]:
            return [
                Campaign(
                    campaign_id="CMP-SCEN-0001",
                    campaign_name="UNKNOWN BEHAVIORAL CAMPAIGN CMP-SCEN-0001",
                    campaign_type="BEHAVIORAL",
                    status="ACTIVE",
                    first_seen=now_str,
                    last_seen=now_str,
                    source_mode="SCENARIO",
                    confidence=0.84,
                    severity="HIGH",
                    attribution=Attribution(type="UNKNOWN", name=None, confidence=0.0),
                    evidence_event_ids=["scen-ps-01", "scen-net-01"],
                    attack_session_ids=["SESS-192.168.1.102-1"],
                    technique_ids=["T1059.001", "T1071.001"],
                    source_ips=["192.168.1.102"],
                    destination_ips=["140.82.121.4"],
                    target_ports=[443, 22],
                    hosts=["WK-902"],
                    behavior_fingerprint={"protocols": ["TCP"], "ports": [22, 443], "commands": ["powershell_execution"], "payload_delivery": True, "execution": True},
                    campaign_stage="EXECUTION",
                    observed_stages=["RECONNAISSANCE", "INITIAL_ACCESS", "EXECUTION"],
                    mapping_type="INFERRED",
                    analyst_status="UNVALIDATED",
                    confidence_reasons=["+ Strong temporal correlation", "+ Multi-stage execution sequence", "- No external attribution"],
                    severity_reasons=["Obfuscated PowerShell execution observed"],
                    audit_trail=[{"timestamp": now_str, "action": "SCENARIO_CREATED", "actor": "ScenarioEngine"}]
                )
            ]

        return [
            Campaign(
                campaign_id="CMP-SCEN-0002",
                campaign_name="UNKNOWN BEHAVIORAL CAMPAIGN CMP-SCEN-0002",
                campaign_type="MULTI_STAGE",
                status="ACTIVE",
                first_seen=now_str,
                last_seen=now_str,
                source_mode="SCENARIO",
                confidence=0.91,
                severity="CRITICAL",
                attribution=Attribution(type="UNKNOWN", name=None, confidence=0.0),
                evidence_event_ids=["scen-file-01", "scen-ps-02"],
                attack_session_ids=["SESS-10.0.0.55-1"],
                technique_ids=["T1059.001", "T1003.001", "T1105"],
                source_ips=["10.0.0.55"],
                destination_ips=["192.168.1.1"],
                target_ports=[445],
                hosts=["WK-902"],
                behavior_fingerprint={"protocols": ["SMB", "TCP"], "ports": [445], "commands": ["lsass_dump"], "payload_delivery": True, "execution": True},
                campaign_stage="CREDENTIAL_ACCESS",
                observed_stages=["INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS"],
                mapping_type="INFERRED",
                analyst_status="UNVALIDATED",
                confidence_reasons=["+ Multi-source IP cluster", "+ Credential access observed"],
                severity_reasons=["Credential dumping payload detected"],
                audit_trail=[{"timestamp": now_str, "action": "SCENARIO_CREATED", "actor": "ScenarioEngine"}]
            )
        ]
