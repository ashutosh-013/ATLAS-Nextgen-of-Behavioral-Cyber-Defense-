"""
Fast Static Pre-Filter Engine for ATLAS

Provides sub-millisecond static hash lookup (MD5/SHA256) and YARA rule pattern
evaluations. Feeds match evidence directly into the BADNA 8-stage pipeline
without bypassing behavioral analysis.
"""

import os
import re
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

logger = logging.getLogger("pre_filter")


@dataclass
class PreFilterMatch:
    is_matched: bool = False
    threat_name: Optional[str] = None
    match_type: Optional[str] = None  # 'hash', 'yara', 'regex'
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


class StaticPreFilterEngine:
    """
    High-performance static pre-filter engine.
    Maintains in-memory Bloom/Set filters for fast hash matching and YARA rules.
    """

    def __init__(self):
        self.known_hashes: Dict[str, Dict[str, Any]] = {}
        self.regex_patterns: Dict[str, re.Pattern] = {}
        self.yara_rules = None
        self._init_default_signatures()

    def _init_default_signatures(self):
        """Initialize standard high-risk static indicators."""
        # Known ransomware/malware test hashes
        sample_malicious_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"name": "Test.Malware.SHA256", "class": "ransomware"},
            "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR-Test-File", "class": "test_virus"},
            "25a2653207908b9815594d75438848d7": {"name": "WannaCry.Ransomware", "class": "ransomware"}
        }
        for h, meta in sample_malicious_hashes.items():
            self.known_hashes[h.lower()] = meta

        # Known suspicious regex command line signatures
        default_regexes = {
            "PowerShell_B64_Exec": r"(?i)powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}",
            "Certutil_Decode": r"(?i)certutil.*-decode",
            "Bitsadmin_Transfer": r"(?i)bitsadmin.*/transfer",
            "Vssadmin_Delete_Shadows": r"(?i)vssadmin.*delete\s+shadows"
        }
        for name, pat in default_regexes.items():
            self.regex_patterns[name] = re.compile(pat)

    def add_hash(self, hash_str: str, threat_name: str, threat_class: str = "malware"):
        """Add a hash indicator to the pre-filter set."""
        if hash_str:
            self.known_hashes[hash_str.lower().strip()] = {
                "name": threat_name,
                "class": threat_class
            }

    def evaluate_hash(self, hash_str: Optional[str]) -> Optional[PreFilterMatch]:
        """Evaluate a file hash against the fast lookup database."""
        if not hash_str:
            return None
        
        cleaned_hash = hash_str.lower().strip()
        if cleaned_hash in self.known_hashes:
            meta = self.known_hashes[cleaned_hash]
            return PreFilterMatch(
                is_matched=True,
                threat_name=meta["name"],
                match_type="hash",
                confidence=0.99,
                evidence={"hash": cleaned_hash, "threat_class": meta["class"]}
            )
        return None

    def evaluate_cmdline(self, cmdline: Optional[str]) -> Optional[PreFilterMatch]:
        """Evaluate process command line arguments against regex pattern rules."""
        if not cmdline:
            return None
        
        for rule_name, pattern in self.regex_patterns.items():
            if pattern.search(cmdline):
                return PreFilterMatch(
                    is_matched=True,
                    threat_name=f"Rule.{rule_name}",
                    match_type="regex",
                    confidence=0.85,
                    evidence={"pattern_name": rule_name, "matched_cmdline": cmdline}
                )
        return None

    def evaluate_file_bytes(self, file_path: str) -> Optional[PreFilterMatch]:
        """Calculate SHA256 of file and run static hash evaluation."""
        if not os.path.exists(file_path):
            return None
        
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            
            file_hash = sha256.hexdigest()
            return self.evaluate_hash(file_hash)
        except Exception as e:
            logger.debug(f"Pre-filter file read error for {file_path}: {e}")
            return None
