"""
ATLAS Telemetry Schema & Event Normalizer.
Standardizes raw endpoint telemetry events from Windows collectors, Sysmon, and T-Pot
into a unified, evidence-based event model.

Requirement #3 Unified Schema:
- event_id: UUID string
- timestamp: ISO-8601 UTC
- host_id: Stable host identifier (hostname + IP)
- source: "windows", "sysmon", "tpot"
- source_mode: "LIVE" or "SCENARIO"
- event_type: "process", "network", "dns", "authentication", "file", "powershell", "event_log"
- category: "process", "network", "dns", "authentication", "file", "system"
- severity: "info", "low", "medium", "high", "critical"
- process: { pid, ppid, name, path, command_line, user }
- network: { src_ip, src_port, dst_ip, dst_port, protocol, state }
- dns: { query, record_type, response }
- authentication: { user, logon_type, source_ip, result }
- file: { path, operation, hash }
- raw_source: { provider, event_id, channel }
- parent_event_id, correlation_id, confidence
"""

import uuid
import re
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional, List

try:
    from privacy.sanitizer import DataSanitizer
    _sanitizer = DataSanitizer()
except Exception:
    _sanitizer = None

def get_stable_host_id() -> str:
    """Returns a stable host identifier based on local hostname and primary IP."""
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = '127.0.0.1'
    return f"{hostname}_{ip}"

def classify_ip_destination(ip_str: Optional[str]) -> str:
    """Classifies an IP address into LOOPBACK, PRIVATE/LAN, PUBLIC/INTERNET, or UNKNOWN."""
    if not ip_str or str(ip_str).strip() in ["Not available", "None", "0.0.0.0", ""]:
        return "UNKNOWN"
    ip_clean = str(ip_str).strip()
    if ip_clean in ["127.0.0.1", "::1", "localhost"]:
        return "LOOPBACK"
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_clean)
        if ip.is_loopback:
            return "LOOPBACK"
        if ip.is_private or ip.is_link_local:
            return "PRIVATE/LAN"
        return "PUBLIC/INTERNET"
    except Exception:
        return "UNKNOWN"

@dataclass
class TelemetryEvent:
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    host_id: str = field(default_factory=get_stable_host_id)
    source: str = "windows"  # windows / sysmon / tpot
    source_mode: str = "LIVE"  # LIVE vs SCENARIO
    event_type: str = "process"  # process / network / dns / authentication / file / powershell / event_log
    category: str = "process"  # process / network / dns / authentication / file / system
    severity: str = "info"  # info / low / medium / high / critical
    
    process: Optional[Dict[str, Any]] = None
    network: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    authentication: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    raw_source: Optional[Dict[str, Any]] = None
    
    parent_event_id: Optional[str] = None
    correlation_id: Optional[str] = None
    confidence: float = 1.0

    def sanitize(self):
        """Redacts sensitive credentials, tokens, or PII from command lines or file paths."""
        if self.process and self.process.get("command_line"):
            cmd = str(self.process["command_line"])
            # Redact passwords/tokens
            cmd_clean = re.sub(r'(--password|-password|-token|-secret|-p)\s+[^\s]+', r'\1 [REDACTED]', cmd, flags=re.IGNORECASE)
            self.process["command_line"] = cmd_clean

    def validate() -> bool:
        """Validates that event schema fields are strictly sane and valid."""
        if self.source_mode not in ["LIVE", "SCENARIO"]:
            return False
        if self.category not in ["process", "network", "dns", "authentication", "file", "system"]:
            return False
        if self.network:
            for port_key in ["src_port", "dst_port"]:
                val = self.network.get(port_key)
                if val is not None and not (0 <= int(val) <= 65535):
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        self.sanitize()
        d = asdict(self)
        
        # Populate all 17 required canonical keys at top level (null if non-existent, never fabricated)
        proc = d.get("process") or {}
        net = d.get("network") or {}
        auth = d.get("authentication") or {}
        fl = d.get("file") or {}
        dns = d.get("dns") or {}
        raw = d.get("raw_source") or {}

        def _clean_str(v):
            if v is None or str(v).strip() in ["Not available", "unknown", "None", "-", ""]:
                return None
            return str(v).strip()

        pid_val = proc.get("pid") if proc else None
        ppid_val = proc.get("ppid") if proc else None
        user_val = _clean_str(proc.get("user")) or _clean_str(auth.get("user"))
        
        src_ip_val = _clean_str(net.get("src_ip")) or _clean_str(auth.get("source_ip"))
        src_port_val = net.get("src_port") if (net and net.get("src_port") not in [0, None]) else None
        dst_ip_val = _clean_str(net.get("dst_ip"))
        dst_port_val = net.get("dst_port") if (net and net.get("dst_port") not in [0, None]) else None
        proto_val = _clean_str(net.get("protocol"))

        cmd_val = _clean_str(proc.get("command_line"))
        payload_val = cmd_val or _clean_str(fl.get("path")) or _clean_str(dns.get("query"))
        raw_evt_id = _clean_str(raw.get("event_id"))

        d["pid"] = pid_val
        d["parent_pid"] = ppid_val
        d["user"] = user_val
        d["src_ip"] = src_ip_val
        d["src_port"] = src_port_val
        d["dst_ip"] = dst_ip_val
        d["dst_port"] = dst_port_val
        d["protocol"] = proto_val
        d["command"] = cmd_val
        d["payload"] = payload_val
        d["raw_event_id"] = raw_evt_id
        d["ip_classification"] = classify_ip_destination(dst_ip_val)

        return d

def normalize_raw_event(raw: Dict[str, Any], source_mode: str = "LIVE") -> Dict[str, Any]:
    """Helper to convert any raw event payload into canonical TelemetryEvent dictionary."""
    ev_type = raw.get("event_type", "process").lower()
    cat = raw.get("category", ev_type if ev_type in ["process", "network", "dns", "authentication", "file"] else "system")
    
    # Process attributes
    proc_dict = None
    if ev_type in ["process", "powershell"] or "process" in raw or "pid" in raw.get("event_data", {}):
        ed = raw.get("event_data", raw.get("process", {}))
        pid_v = ed.get("pid", ed.get("Id"))
        ppid_v = ed.get("ppid", ed.get("parent_pid"))
        proc_dict = {
            "pid": int(pid_v) if pid_v is not None else None,
            "ppid": int(ppid_v) if ppid_v is not None else None,
            "name": str(ed.get("name", ed.get("ProcessName", ed.get("image", "unknown")))),
            "path": str(ed.get("path", ed.get("Path", ed.get("exe", "Not available")))),
            "command_line": str(ed.get("command_line", ed.get("command", ed.get("cmdline", "Not available")))),
            "user": str(ed.get("user", ed.get("username", "Not available")))
        }

    # Network attributes
    net_dict = None
    if ev_type == "network" or "network" in raw or "src_ip" in raw.get("event_data", {}):
        ed = raw.get("event_data", raw.get("network", {}))
        net_dict = {
            "src_ip": str(ed.get("src_ip", ed.get("source_ip", "Not available"))),
            "src_port": int(ed.get("src_port", ed.get("source_port", 0))),
            "dst_ip": str(ed.get("dst_ip", ed.get("dest_ip", "Not available"))),
            "dst_port": int(ed.get("dst_port", ed.get("dest_port", 0))),
            "protocol": str(ed.get("protocol", "TCP")).upper(),
            "state": str(ed.get("state", "ESTABLISHED")).upper()
        }

    # DNS attributes
    dns_dict = None
    if ev_type == "dns" or "dns" in raw:
        ed = raw.get("event_data", raw.get("dns", {}))
        dns_dict = {
            "query": str(ed.get("query", ed.get("query_name", "Not available"))),
            "record_type": str(ed.get("record_type", ed.get("type", "A"))),
            "response": str(ed.get("response", ed.get("result", "Not available")))
        }

    # Authentication attributes
    auth_dict = None
    if ev_type == "authentication" or "auth" in raw or "logon" in str(raw).lower():
        ed = raw.get("event_data", raw.get("authentication", {}))
        auth_dict = {
            "user": str(ed.get("user", ed.get("username", "Not available"))),
            "logon_type": str(ed.get("logon_type", ed.get("logon_kind", "Interactive"))),
            "source_ip": str(ed.get("source_ip", ed.get("src_ip", "Not available"))),
            "result": str(ed.get("result", ed.get("status", "SUCCESS"))).upper()
        }

    # File attributes
    file_dict = None
    if ev_type == "file" or "file" in raw:
        ed = raw.get("event_data", raw.get("file", {}))
        file_dict = {
            "path": str(ed.get("path", ed.get("file_name", "Not available"))),
            "operation": str(ed.get("operation", ed.get("action", "write"))),
            "hash": str(ed.get("hash", ed.get("sha256", "Not available")))
        }

    raw_src = {
        "provider": raw.get("provider", raw.get("source", "windows")),
        "event_id": str(raw.get("raw_event_id", raw.get("event_id", str(uuid.uuid4())))),
        "channel": str(raw.get("channel", "Security"))
    }

    te = TelemetryEvent(
        event_id=str(raw.get("event_id", f"evt-{uuid.uuid4()}")),
        timestamp=str(raw.get("timestamp", datetime.now(timezone.utc).isoformat())),
        host_id=str(raw.get("host_id", get_stable_host_id())),
        source=str(raw.get("source", "windows")),
        source_mode=source_mode,
        event_type=ev_type,
        category=cat,
        severity=str(raw.get("severity", "info")).lower(),
        process=proc_dict,
        network=net_dict,
        dns=dns_dict,
        authentication=auth_dict,
        file=file_dict,
        raw_source=raw_src,
        parent_event_id=raw.get("parent_event_id"),
        correlation_id=raw.get("correlation_id"),
        confidence=float(raw.get("confidence", 1.0))
    )
    
    return te.to_dict()
