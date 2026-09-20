"""
ATLAS IOC Repository Layer.

Strictly separates atomic Indicators of Compromise (Hashes, IPs, Domains, URLs, CVEs)
from the Behavioral Knowledge Base (Behavioral DNA, Campaigns, Feedback, Patterns).

Enforces ATLAS Rule #3:
- IOC Repository: Stores hashes, IPs, URLs, domains, CVEs.
- Behavioral Knowledge Base: Stores Behavioral DNA, campaigns, analyst feedback, threat intelligence, and historical behavior.
Do not mix them.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("ioc_repository")


@dataclass
class IOCRecord:
    """Atomic Indicator of Compromise record."""
    ioc_type: str  # hash, ip, domain, url, cve
    value: str
    threat_class: str = "Malicious"
    source: str = "Internal"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IOCRepository:
    """
    Dedicated thread-safe repository for atomic Indicators of Compromise (IOCs).
    Provides O(1) membership lookups and atomic persistence.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.lock = threading.Lock()
        
        # In-memory indices for O(1) lookups
        self.file_hashes: Dict[str, IOCRecord] = {}
        self.ips: Dict[str, IOCRecord] = {}
        self.domains: Dict[str, IOCRecord] = {}
        self.urls: Dict[str, IOCRecord] = {}
        self.cves: Dict[str, IOCRecord] = {}
        
        # Storage configuration
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path("e:/BADNA/datasets/ioc_repository.json")
            
        self._load_from_disk()
        self._seed_default_indicators()

    def _seed_default_indicators(self) -> None:
        """Seed baseline known-bad indicators if empty."""
        with self.lock:
            # Seed hashes
            seed_hashes = [
                ("32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74", "Ransomware.WannaCry"),
                ("0004cec68fdb95507c6161d84e4965db60f997a679ce20786075992f1e5b340c", "Trojan.SOREL"),
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "HackTool.Mimikatz")
            ]
            for h, fam in seed_hashes:
                if h.lower() not in self.file_hashes:
                    self.file_hashes[h.lower()] = IOCRecord(
                        ioc_type="hash", value=h.lower(), threat_class="Malware", source="Seed",
                        metadata={"family": fam}
                    )

            # Seed IPs
            seed_ips = ["192.168.1.100", "203.0.113.55", "198.51.100.22"]
            for ip in seed_ips:
                if ip not in self.ips:
                    self.ips[ip] = IOCRecord(
                        ioc_type="ip", value=ip, threat_class="C2", source="Seed",
                        metadata={"description": "Simulated Malicious C2"}
                    )

            # Seed Domains
            seed_domains = ["malicious-site.com", "known-bad-c2.example.com", "attacker-c2.net"]
            for d in seed_domains:
                if d.lower() not in self.domains:
                    self.domains[d.lower()] = IOCRecord(
                        ioc_type="domain", value=d.lower(), threat_class="C2", source="Seed",
                        metadata={"description": "Known Bad Domain"}
                    )

            # Seed URLs
            seed_urls = ["http://malicious-site.com/payload.exe", "https://known-bad-c2.example.com/beacon"]
            for u in seed_urls:
                if u not in self.urls:
                    self.urls[u] = IOCRecord(
                        ioc_type="url", value=u, threat_class="Distribution", source="Seed"
                    )

    def add_hash(self, hash_value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a file hash (MD5, SHA1, SHA256)."""
        val = hash_value.strip().lower()
        with self.lock:
            self.file_hashes[val] = IOCRecord(
                ioc_type="hash",
                value=val,
                metadata=metadata or {}
            )

    def add_ip(self, ip_address: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a malicious IP address."""
        val = ip_address.strip()
        with self.lock:
            self.ips[val] = IOCRecord(
                ioc_type="ip",
                value=val,
                metadata=metadata or {}
            )

    def add_domain(self, domain: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a malicious domain / FQDN."""
        val = domain.strip().lower()
        with self.lock:
            self.domains[val] = IOCRecord(
                ioc_type="domain",
                value=val,
                metadata=metadata or {}
            )

    def add_url(self, url: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a malicious URL."""
        val = url.strip()
        with self.lock:
            self.urls[val] = IOCRecord(
                ioc_type="url",
                value=val,
                metadata=metadata or {}
            )

    def add_cve(self, cve_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a CVE record (e.g. from CISA KEV)."""
        val = cve_id.strip().upper()
        with self.lock:
            self.cves[val] = IOCRecord(
                ioc_type="cve",
                value=val,
                metadata=metadata or {}
            )

    def check_hash(self, hash_val: str) -> Optional[Dict[str, Any]]:
        """Check if a file hash is a known IOC."""
        if not hash_val:
            return None
        with self.lock:
            record = self.file_hashes.get(hash_val.strip().lower())
            return record.to_dict() if record else None

    def check_ip(self, ip_val: str) -> Optional[Dict[str, Any]]:
        """Check if an IP address is a known IOC."""
        if not ip_val:
            return None
        with self.lock:
            record = self.ips.get(ip_val.strip())
            return record.to_dict() if record else None

    def check_domain(self, domain_val: str) -> Optional[Dict[str, Any]]:
        """Check if a domain is a known IOC."""
        if not domain_val:
            return None
        with self.lock:
            record = self.domains.get(domain_val.strip().lower())
            return record.to_dict() if record else None

    def check_url(self, url_val: str) -> Optional[Dict[str, Any]]:
        """Check if a URL is a known IOC."""
        if not url_val:
            return None
        with self.lock:
            record = self.urls.get(url_val.strip())
            return record.to_dict() if record else None

    def check_cve(self, cve_val: str) -> Optional[Dict[str, Any]]:
        """Check if a CVE is in the known exploited database."""
        if not cve_val:
            return None
        with self.lock:
            record = self.cves.get(cve_val.strip().upper())
            return record.to_dict() if record else None

    def check_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check an incoming telemetry event dictionary against all IOC categories.
        Returns match dictionary if found, else None.
        """
        data = event.get("event_data", {})
        
        # Check hashes
        for key in ["hash", "sha256", "md5", "file_hash"]:
            val = data.get(key)
            if val:
                hit = self.check_hash(val)
                if hit:
                    return {"indicator_type": "hash", "indicator_value": val, "details": hit}
        
        # Check IPs
        for key in ["ip", "src_ip", "dst_ip", "remote_ip", "destination_ip"]:
            val = data.get(key)
            if val:
                hit = self.check_ip(val)
                if hit:
                    return {"indicator_type": "ip", "indicator_value": val, "details": hit}
        
        # Check Domains
        for key in ["domain", "dns_query", "fqdn", "hostname"]:
            val = data.get(key)
            if val:
                hit = self.check_domain(val)
                if hit:
                    return {"indicator_type": "domain", "indicator_value": val, "details": hit}
        
        # Check URLs
        for key in ["url", "uri", "http_uri"]:
            val = data.get(key)
            if val:
                hit = self.check_url(val)
                if hit:
                    return {"indicator_type": "url", "indicator_value": val, "details": hit}
        
        # Check CVEs
        for key in ["cve", "cve_id", "vulnerability"]:
            val = data.get(key)
            if val:
                hit = self.check_cve(val)
                if hit:
                    return {"indicator_type": "cve", "indicator_value": val, "details": hit}
                    
        return None

    def get_stats(self) -> Dict[str, int]:
        """Return total counts across all IOC categories."""
        with self.lock:
            return {
                "hashes": len(self.file_hashes),
                "ips": len(self.ips),
                "domains": len(self.domains),
                "urls": len(self.urls),
                "cves": len(self.cves),
                "total": (
                    len(self.file_hashes) +
                    len(self.ips) +
                    len(self.domains) +
                    len(self.urls) +
                    len(self.cves)
                )
            }

    def save_to_disk(self) -> None:
        """Persist IOC database to disk atomically."""
        with self.lock:
            try:
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "hashes": [r.to_dict() for r in self.file_hashes.values()],
                    "ips": [r.to_dict() for r in self.ips.values()],
                    "domains": [r.to_dict() for r in self.domains.values()],
                    "urls": [r.to_dict() for r in self.urls.values()],
                    "cves": [r.to_dict() for r in self.cves.values()]
                }
                temp_path = self.storage_path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                temp_path.replace(self.storage_path)
            except Exception as e:
                logger.error(f"Failed to save IOC repository to disk: {e}")

    def _load_from_disk(self) -> None:
        """Load IOC database from disk if available."""
        if not self.storage_path.exists():
            return
        with self.lock:
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data.get("hashes", []):
                    rec = IOCRecord(**item)
                    self.file_hashes[rec.value.lower()] = rec
                for item in data.get("ips", []):
                    rec = IOCRecord(**item)
                    self.ips[rec.value] = rec
                for item in data.get("domains", []):
                    rec = IOCRecord(**item)
                    self.domains[rec.value.lower()] = rec
                for item in data.get("urls", []):
                    rec = IOCRecord(**item)
                    self.urls[rec.value] = rec
                for item in data.get("cves", []):
                    rec = IOCRecord(**item)
                    self.cves[rec.value.upper()] = rec
            except Exception as e:
                logger.warning(f"Could not load IOC repository from {self.storage_path}: {e}")


# Singleton instance accessor
_ioc_repository_instance: Optional[IOCRepository] = None

def get_ioc_repository() -> IOCRepository:
    """Get or create singleton IOCRepository instance."""
    global _ioc_repository_instance
    if _ioc_repository_instance is None:
        _ioc_repository_instance = IOCRepository()
    return _ioc_repository_instance
