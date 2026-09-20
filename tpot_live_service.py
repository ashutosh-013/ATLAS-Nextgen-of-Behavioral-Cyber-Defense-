"""
ATLAS Live T-Pot Honeypot Ingestion Service
============================================
Provides real-time network ingestion of T-Pot honeypot telemetry over:
1. UDP/TCP Syslog socket (RFC 3164 / RFC 5424, default port 1514 / 514)
2. REST webhook ingestion endpoint (/api/tpot/ingest)

Parses:
- Cowrie (SSH/Telnet brute force, commands, sessions)
- Suricata (Network IDS EVE-JSON alerts)
- Dionaea (SMB/RPC/FTP malware captures)
- Honeytrap (TCP/UDP connection probes)

Persists records with source_mode='LIVE' into SQLite database tables:
tpot_events, tpot_alerts, tpot_sessions, and blocked_ips.
"""

import os
import sys
import time
import json
import socket
import select
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import database

logger = logging.getLogger("TPotLiveService")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


class TPotLiveIngestionEngine:
    """Singleton Live Ingestion Engine and Socket Listener for T-Pot Honeypots."""
    
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TPotLiveIngestionEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, port: int = 1514, bind_host: str = "0.0.0.0"):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.port = port
        self.bind_host = bind_host
        self.is_running = False
        self.udp_sock: Optional[socket.socket] = None
        self.tcp_sock: Optional[socket.socket] = None
        self.listener_thread: Optional[threading.Thread] = None
        
        # Ingestion metrics
        self.total_received = 0
        self.total_parsed = 0
        self.last_event_time: Optional[str] = None
        self.live_sources: Dict[str, int] = {}  # IP -> count
        self.recent_live_events: List[Dict[str, Any]] = []
        self._buffer_lock = threading.Lock()

    def start_listener(self) -> bool:
        """Starts background UDP and TCP syslog listener threads."""
        if self.is_running:
            return True

        try:
            # Bind UDP socket
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.bind_host, self.port))
            self.udp_sock.setblocking(False)

            # Bind TCP socket
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.bind_host, self.port))
            self.tcp_sock.listen(10)
            self.tcp_sock.setblocking(False)

            self.is_running = True
            self.listener_thread = threading.Thread(target=self._listen_loop, daemon=True, name="TPotListenerThread")
            self.listener_thread.start()
            logger.info(f"Live T-Pot Syslog listener started on {self.bind_host}:{self.port} (UDP/TCP)")
            return True
        except Exception as e:
            logger.warning(f"Could not bind T-Pot syslog listener on {self.bind_host}:{self.port}: {e}. (REST /api/tpot/ingest remains available)")
            self.is_running = False
            return False

    def stop_listener(self):
        """Stops live listener sockets."""
        self.is_running = False
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
            self.tcp_sock = None
        logger.info("Live T-Pot Syslog listener stopped.")

    def _listen_loop(self):
        """Main non-blocking select loop for UDP & TCP syslog packets."""
        while self.is_running:
            try:
                readable, _, _ = select.select([self.udp_sock, self.tcp_sock], [], [], 1.0)
                for s in readable:
                    if s is self.udp_sock:
                        try:
                            data, addr = self.udp_sock.recvfrom(65535)
                            self.process_raw_payload(data.decode("utf-8", errors="ignore"), source_ip=addr[0])
                        except Exception as e:
                            logger.debug(f"UDP packet recv error: {e}")
                    elif s is self.tcp_sock:
                        try:
                            client, addr = self.tcp_sock.accept()
                            client.settimeout(2.0)
                            data = client.recv(65535)
                            client.close()
                            if data:
                                self.process_raw_payload(data.decode("utf-8", errors="ignore"), source_ip=addr[0])
                        except Exception as e:
                            logger.debug(f"TCP connection recv error: {e}")
            except Exception as e:
                if self.is_running:
                    logger.debug(f"Select loop notice: {e}")
                    time.sleep(0.5)

    def process_raw_payload(self, text: str, source_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Parses syslog lines or raw JSON objects sent by T-Pot sensors."""
        self.total_received += 1
        if not text or not text.strip():
            return None

        # Clean syslog headers if present (e.g., "<134>1 2026-09-20T... host cowrie: {json}")
        json_str = text.strip()
        brace_idx = json_str.find("{")
        if brace_idx != -1:
            json_str = json_str[brace_idx:]

        parsed_data = None
        try:
            parsed_data = json.loads(json_str)
        except Exception:
            # Not JSON, handle as plain text syslog line
            parsed_data = {
                "raw_log": text.strip(),
                "src_ip": source_ip or "127.0.0.1",
                "type": "syslog",
                "payload": text.strip()
            }

        return self.ingest_event(parsed_data, fallback_source_ip=source_ip)

    def ingest_event(self, raw: Dict[str, Any], fallback_source_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalizes and commits a live T-Pot event into the ATLAS database.
        Strictly marks event with source_mode = 'LIVE'.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        self.last_event_time = now_iso
        self.total_parsed += 1

        # Extract fields
        src_ip = raw.get("src_ip") or raw.get("src_host") or raw.get("peerIP") or fallback_source_ip or "127.0.0.1"
        src_port = int(raw.get("src_port") or raw.get("src_port_num") or 0)
        dst_port = int(raw.get("dest_port") or raw.get("dst_port") or raw.get("destination_port") or 22)
        
        # Determine honeypot service
        sensor_type = str(
            raw.get("honeypot") or 
            raw.get("type") or 
            raw.get("event_type") or 
            raw.get("eventid") or 
            raw.get("app") or 
            ""
        ).lower()

        if "suricata" in sensor_type or "alert" in raw or raw.get("event_type") == "alert":
            honeypot_name = "SURICATA"
        elif "cowrie" in sensor_type or dst_port in [22, 2222]:
            honeypot_name = "COWRIE"
        elif "dionaea" in sensor_type or dst_port in [445, 139, 21]:
            honeypot_name = "DIONAEA"
        else:
            honeypot_name = sensor_type.upper() if sensor_type else "HONEYPOT"

        payload = (
            raw.get("payload") or 
            raw.get("input") or 
            raw.get("command") or 
            raw.get("message") or 
            raw.get("raw_log") or 
            f"Active connection on port {dst_port}"
        )

        alert_id = f"tpot-live-{int(time.time()*1000)}-{self.total_parsed}"
        severity = "HIGH" if dst_port in [22, 445, 3389] or "exploit" in str(payload).lower() else "MEDIUM"

        normalized_record = {
            "id": alert_id,
            "timestamp": now_iso,
            "type": honeypot_name.lower(),
            "honeypot": honeypot_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_port": dst_port,
            "payload": payload,
            "severity": severity,
            "status": "pending_approval",
            "source_mode": "LIVE"
        }

        # 1. Save to SQLite tpot_alerts table
        try:
            database.save_tpot_alert(
                alert_id=alert_id,
                timestamp=now_iso,
                alert_type=honeypot_name.lower(),
                src_ip=src_ip,
                src_port=src_port,
                dest_port=dst_port,
                payload=str(payload),
                status="pending_approval"
            )
        except Exception as e:
            logger.debug(f"save_tpot_alert note: {e}")

        # 2. Add to blocked_ips catalog as pending approval
        if src_ip and src_ip not in ["127.0.0.1", "0.0.0.0", "localhost"]:
            try:
                database.save_blocked_ip(
                    ip=src_ip,
                    timestamp=now_iso,
                    status="pending_approval",
                    service=honeypot_name,
                    payload=str(payload)
                )
            except Exception as e:
                logger.debug(f"save_blocked_ip note: {e}")

        # Update metrics and recent buffer
        with self._buffer_lock:
            self.live_sources[src_ip] = self.live_sources.get(src_ip, 0) + 1
            self.recent_live_events.insert(0, normalized_record)
            if len(self.recent_live_events) > 100:
                self.recent_live_events.pop()

        logger.info(f"[LIVE T-POT EVENT] {honeypot_name} probe from {src_ip}:{src_port} -> port {dst_port} ({payload[:60]})")
        return normalized_record

    def get_status(self) -> Dict[str, Any]:
        """Returns live listener and ingestion health status."""
        is_fresh = False
        if self.last_event_time:
            try:
                dt = datetime.fromisoformat(self.last_event_time)
                is_fresh = (datetime.now(timezone.utc) - dt).total_seconds() < 900  # 15 mins
            except Exception:
                pass

        return {
            "service": "TPotLiveIngestionEngine",
            "listener_running": self.is_running,
            "listen_port": self.port,
            "bind_host": self.bind_host,
            "total_received": self.total_received,
            "total_parsed": self.total_parsed,
            "last_event_time": self.last_event_time,
            "has_recent_live_data": is_fresh,
            "active_live_sources_count": len(self.live_sources),
            "recent_events_cached": len(self.recent_live_events)
        }


# Singleton accessor
_live_engine_instance: Optional[TPotLiveIngestionEngine] = None

def get_tpot_live_engine(port: int = 1514) -> TPotLiveIngestionEngine:
    global _live_engine_instance
    if _live_engine_instance is None:
        _live_engine_instance = TPotLiveIngestionEngine(port=port)
    return _live_engine_instance
