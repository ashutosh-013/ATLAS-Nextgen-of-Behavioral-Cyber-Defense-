"""
Continuous IOC & Signature Monitoring Engine for ATLAS

Monitors incoming events for known malicious file hashes, domain names, IPs, URLs, 
process paths, and registry keys in parallel with behavioral analysis.
"""

import re
import sys
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

try:
    from data_models import SecurityEvent
    from knowledge_base.knowledge_base import KnowledgeBase
    from ingestion.api_clients.clients import MalwareBazaarClient, URLhausClient
    from ingestion.parsers.cisa_kev_parser import create_cisa_kev_parser
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from data_models import SecurityEvent
    from knowledge_base.knowledge_base import KnowledgeBase
    from ingestion.api_clients.clients import MalwareBazaarClient, URLhausClient
    from ingestion.parsers.cisa_kev_parser import create_cisa_kev_parser

logger = logging.getLogger("ioc_monitor")


class IOCMonitorEngine:
    """
    Continuous IOC & Signature Monitoring Engine.
    
    Operates in parallel with the Behavioral Analysis (BADNA) pipeline.
    Maintains a local database of known indicators that is updated via background threads.
    """
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        
        # Threat intelligence client connectors
        self.mb_client = MalwareBazaarClient()
        self.uh_client = URLhausClient()
        
        # Thread-safe lock for runtime database updates
        self.db_lock = threading.Lock()
        
        # Active IOC Databases
        self.file_hashes: Set[str] = set()
        self.file_names: Set[str] = set()
        self.ips: Set[str] = set()
        self.domains: Set[str] = set()
        self.urls: Set[str] = set()
        self.process_names: Set[str] = set()
        self.registry_keys: Set[str] = set()
        self.vulnerabilities: Dict[str, Dict[str, Any]] = {}  # Mapped CVE -> metadata
        
        # Additional metadata repository for matches
        self.ioc_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Initialize default database and load local CISA KEV
        self._initialize_database()
        
        # Background scheduler parameters
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
    def _initialize_database(self) -> None:
        """Load default signatures and local databases on start"""
        # Load local CISA KEV if exists
        kev_path = Path("e:/BADNA/datasets/known_exploited_vulnerabilities.csv")
        if kev_path.exists():
            try:
                parser = create_cisa_kev_parser(kev_path)
                records = parser.parse_and_normalize_to_dict(kev_path)
                with self.db_lock:
                    for cve_id, rec in records.items():
                        self.vulnerabilities[cve_id] = {
                            "vendor": rec.get("vendor", ""),
                            "product": rec.get("product", ""),
                            "ransomware": "Yes" if rec.get("ransomware_usage") else "No",
                            "added_date": rec.get("date_added", "")
                        }
                logger.info(f"IOC Monitor pre-loaded {len(self.vulnerabilities)} CVEs from CISA KEV")
            except Exception as e:
                logger.error(f"Failed to pre-load CISA KEV: {e}")
                
        # Load seed indicators for testing and fallback (offline signatures)
        with self.db_lock:
            # Seed file hashes (e.g. SOREL examples)
            self.file_hashes.add("32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74")
            self.file_hashes.add("0004cec68fdb95507c6161d84e4965db60f997a679ce20786075992f1e5b340c")
            self.file_names.add("malicious_payload.exe")
            self.file_names.add("mock_malware.exe")
            
            # Seed network indicators
            self.ips.add("192.168.1.100")
            self.domains.add("malicious-site.com")
            self.urls.add("http://malicious-site.com/payload.exe")
            
            # Seed process names
            self.process_names.add("mimikatz.exe")
            self.process_names.add("cobaltstrike.exe")
            
            # Seed registry keys
            self.registry_keys.add(r"Software\Microsoft\Windows\CurrentVersion\Run\MaliciousTask")

    def start_scheduler(self) -> None:
        """Start the background scheduler to fetch threat intelligence updates hourly/daily"""
        if self.is_running:
            return
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("ATLAS IOC & Signature update scheduler started.")
        
    def stop_scheduler(self) -> None:
        """Stop background scheduler"""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=2)
            
    def _scheduler_loop(self) -> None:
        """Continuous scheduler loop calling updates hourly and daily"""
        last_hourly = 0.0
        last_daily = 0.0
        
        while self.is_running:
            now = time.time()
            
            # Hourly checks (MalwareBazaar & URLhaus)
            if now - last_hourly >= 3600:
                self._update_hourly_feeds()
                last_hourly = now
                
            # Daily checks (CISA KEV updates)
            if now - last_daily >= 86400:
                self._update_daily_feeds()
                last_daily = now
                
            # Sleep 10 seconds between checks
            time.sleep(10)
            
    def _update_hourly_feeds(self) -> None:
        """Fetch hourly updates from MalwareBazaar and URLhaus"""
        logger.info("Scheduler: Fetching hourly IOC updates...")
        
        # 1. Fetch MalwareBazaar samples
        try:
            samples = self.mb_client.get_recent_samples(hours=1)
            with self.db_lock:
                for sample in samples:
                    sha256 = sample.get("sha256_hash")
                    if sha256:
                        self.file_hashes.add(sha256)
                        # Map metadata
                        self.ioc_metadata[sha256] = {
                            "type": "file_hash",
                            "source": "MalwareBazaar",
                            "malware_family": sample.get("signature") or "Unknown",
                            "confidence": 1.0,
                            "timestamp": datetime.now().isoformat()
                        }
            logger.info(f"Hourly update: Ingested MalwareBazaar samples. Active hashes: {len(self.file_hashes)}")
        except Exception as e:
            logger.warning(f"Failed to fetch MalwareBazaar updates: {e}")
            
        # 2. Fetch URLhaus samples
        try:
            urls = self.uh_client.get_recent_urls(limit=100)
            with self.db_lock:
                for url_info in urls:
                    url = url_info.get("url")
                    if url:
                        self.urls.add(url)
                        self.ioc_metadata[url] = {
                            "type": "url",
                            "source": "URLhaus",
                            "threat_type": url_info.get("threat") or "malware_download",
                            "confidence": 1.0,
                            "timestamp": datetime.now().isoformat()
                        }
            logger.info(f"Hourly update: Ingested URLhaus URLs. Active URLs: {len(self.urls)}")
        except Exception as e:
            logger.warning(f"Failed to fetch URLhaus updates: {e}")

    def _update_daily_feeds(self) -> None:
        """Fetch daily updates (CISA KEV)"""
        logger.info("Scheduler: Fetching daily CISA KEV updates...")
        kev_path = Path("e:/BADNA/datasets/known_exploited_vulnerabilities.csv")
        if kev_path.exists():
            try:
                parser = create_cisa_kev_parser(kev_path)
                records = parser.parse_and_normalize_to_dict(kev_path)
                with self.db_lock:
                    for cve_id, rec in records.items():
                        self.vulnerabilities[cve_id] = {
                            "vendor": rec.get("vendor", ""),
                            "product": rec.get("product", ""),
                            "ransomware": "Yes" if rec.get("ransomware_usage") else "No",
                            "added_date": rec.get("date_added", "")
                        }
                logger.info(f"Daily update: Refreshed {len(self.vulnerabilities)} CISA KEV CVE profiles")
            except Exception as e:
                logger.warning(f"Failed to update CISA KEV: {e}")

    def check_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Continuously monitor incoming raw events for matching IOC indicators.
        
        Args:
            event: A raw event dictionary with structure matching the Unified Schema
            
        Returns:
            Optional[Dict[str, Any]]: Match alert payload if IOC matched, else None
        """
        event_type = event.get("event_type")
        event_data = event.get("event_data", {})
        
        # Check event structure
        if not event_type or not event_data:
            return None
            
        matched_ioc_type = None
        matched_value = None
        malware_family = "Unknown"
        cve_id = None
        confidence = 0.95
        threat_source = "LocalSignature"
        
        with self.db_lock:
            # 1. File Indicators
            if event_type == "file":
                path = event_data.get("path", "")
                file_name = Path(path).name if path else ""
                
                # Check Hashes
                for hash_key in ["md5", "sha1", "sha256"]:
                    hash_val = event_data.get(hash_key)
                    if hash_val and hash_val in self.file_hashes:
                        matched_ioc_type = f"file_{hash_key}"
                        matched_value = hash_val
                        break
                        
                # Check Name and Path
                if not matched_value:
                    if file_name and file_name in self.file_names:
                        matched_ioc_type = "file_name"
                        matched_value = file_name
                    elif path and path in self.file_names:
                        matched_ioc_type = "file_path"
                        matched_value = path
                        
            # 2. Network Indicators
            elif event_type == "network":
                dst_ip = event_data.get("ip") or event_data.get("dest_ip")
                domain = event_data.get("domain")
                url = event_data.get("url")
                dns = event_data.get("dns_query")
                
                if dst_ip and dst_ip in self.ips:
                    matched_ioc_type = "network_ip"
                    matched_value = dst_ip
                elif domain and domain in self.domains:
                    matched_ioc_type = "network_domain"
                    matched_value = domain
                elif url and url in self.urls:
                    matched_ioc_type = "network_url"
                    matched_value = url
                elif dns and dns in self.domains:
                    matched_ioc_type = "network_dns"
                    matched_value = dns
                    
            # 3. Process Indicators
            elif event_type == "process":
                proc_name = event_data.get("name")
                cmd = event_data.get("command") or event_data.get("command_line")
                
                if proc_name and proc_name in self.process_names:
                    matched_ioc_type = "process_name"
                    matched_value = proc_name
                elif cmd:
                    # Check cmd line parameters for malicious process payloads using word boundary regex
                    for name in self.process_names:
                        if len(name) >= 3 and re.search(r'\b' + re.escape(name) + r'\b', cmd, re.IGNORECASE):
                            matched_ioc_type = "process_command"
                            matched_value = cmd
                            break
                            
            # 4. Registry/System Modifications
            elif event_type == "registry":
                key = event_data.get("key_path")
                if key and key in self.registry_keys:
                    matched_ioc_type = "registry_key"
                    matched_value = key
                    
            # 5. Vulnerability Association (CISA KEV lookup)
            vuln_id = event.get("metadata", {}).get("vulnerability") or event_data.get("vulnerability")
            if vuln_id and vuln_id in self.vulnerabilities:
                matched_ioc_type = "vulnerability"
                matched_value = vuln_id
                cve_id = vuln_id
                
        # If matched, compile the alert details
        if matched_value:
            # Pull metadata if exists
            meta = self.ioc_metadata.get(matched_value)
            if meta:
                threat_source = meta.get("source", threat_source)
                malware_family = meta.get("malware_family", malware_family)
                confidence = meta.get("confidence", confidence)
                
            alert = {
                "alert_id": f"ioc_alert_{int(time.time())}_{event.get('event_id')}",
                "timestamp": datetime.now().isoformat(),
                "event_id": event.get("event_id"),
                "ioc_type": matched_ioc_type,
                "ioc_value": matched_value,
                "threat_source": threat_source,
                "threat_confidence": confidence,
                "malware_family": malware_family,
                "cve_id": cve_id,
                "related_mitre_techniques": [],
                "related_campaign_id": None
            }
            
            # Map vulnerability context
            if cve_id and cve_id in self.vulnerabilities:
                v_info = self.vulnerabilities[cve_id]
                if v_info.get("ransomware") == "Yes":
                    alert["malware_family"] = "Ransomware_KEV_Campaign"
                    
            # Persist inside Knowledge Base
            self.kb.store_ioc_match(alert)
            return alert
            
        return None
