"""
Policy-Driven Anti-Ransomware Canary Trap Engine for ATLAS

Deploys decoy canary files and evaluates access events using a Policy Engine.
Avoids blind process termination; evaluates process identity, command line,
signature provenance, and BADNA behavioral risk score before policy enforcement.
"""

import os
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

logger = logging.getLogger("canary_engine")


@dataclass
class CanaryEvaluationResult:
    is_canary_event: bool = False
    canary_file: Optional[str] = None
    calling_process: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    action_recommended: str = "PASS"  # "PASS", "LOG_EVENT", "HIGH_ALERT", "KILL_AND_ISOLATE"
    reason: str = ""


class CanaryTrapEngine:
    """
    Decoy file deployment and policy-driven ransomware detection engine.
    """

    def __init__(self, target_directories: Optional[List[str]] = None):
        self.canary_files: Dict[str, str] = {}  # file_path -> expected_hash
        self.known_whitelisted_tools = {
            "searchindexer.exe", "explorer.exe", "vssvc.exe", "wbengine.exe",
            "onedrive.exe", "dropbox.exe", "backup.exe"
        }
        self.target_directories = target_directories or self._get_default_canary_dirs()
        self.deploy_canary_traps()

    def _get_default_canary_dirs(self) -> List[str]:
        """Get standard user directories for decoy placement."""
        dirs = []
        user_home = os.path.expanduser("~")
        for folder in ["Documents", "Desktop"]:
            p = os.path.join(user_home, folder)
            if os.path.exists(p):
                dirs.append(p)
        if not dirs:
            dirs.append(os.getcwd())
        return dirs

    def deploy_canary_traps(self):
        """Deploy hidden decoy canary files into target directories."""
        canary_names = [
            ".atlas_decoy_financial_statement.docx",
            ".atlas_decoy_passwords_backup.xlsx"
        ]
        
        for d in self.target_directories:
            for name in canary_names:
                filepath = os.path.join(d, name)
                try:
                    if not os.path.exists(filepath):
                        content = f"ATLAS CANARY DECOY FILE - DO NOT MODIFY - {name}\n".encode("utf-8") * 50
                        with open(filepath, "wb") as f:
                            f.write(content)
                        # Hide file on Windows
                        if os.name == "nt":
                            os.system(f'attrib +h "{filepath}"')
                    
                    # Store expected hash
                    h = self._calc_hash(filepath)
                    if h:
                        self.canary_files[filepath] = h
                        logger.info(f"Deployed canary trap: {filepath}")
                except Exception as e:
                    logger.debug(f"Could not deploy canary {filepath}: {e}")

    def evaluate_canary_touch(
        self,
        file_path: str,
        calling_process_info: Dict[str, Any],
        behavioral_risk_score: float = 0.0,
        signature_trust_score: float = 0.5
    ) -> CanaryEvaluationResult:
        """
        Policy Engine for Canary File Touch Events:
        Canary modified -> Identify Process -> Check Identity & Signature -> Behavior Risk Score -> Policy Decision
        """
        if file_path not in self.canary_files:
            return CanaryEvaluationResult(is_canary_event=False)

        proc_name = (calling_process_info.get("ProcessName") or calling_process_info.get("name") or "unknown").lower()
        pid = calling_process_info.get("pid") or calling_process_info.get("Id") or 0

        # Check if canary content was altered or deleted
        current_hash = self._calc_hash(file_path)
        expected_hash = self.canary_files[file_path]
        is_modified = (current_hash != expected_hash)

        # 1. Whitelisted System Backup / Indexer Check
        if proc_name in self.known_whitelisted_tools and signature_trust_score >= 0.80:
            return CanaryEvaluationResult(
                is_canary_event=True,
                canary_file=file_path,
                calling_process=calling_process_info,
                risk_score=behavioral_risk_score,
                action_recommended="LOG_EVENT",
                reason=f"Whitelisted system utility '{proc_name}' with verified signature accessed canary file."
            )

        # 2. Elevated Behavioral Risk + Canary Modification = High Threat
        if is_modified and (behavioral_risk_score >= 0.60 or signature_trust_score < 0.40):
            return CanaryEvaluationResult(
                is_canary_event=True,
                canary_file=file_path,
                calling_process=calling_process_info,
                risk_score=max(behavioral_risk_score, 0.95),
                action_recommended="KILL_AND_ISOLATE",
                reason=f"Untrusted/High-risk process '{proc_name}' (PID: {pid}) modified decoy canary file."
            )

        # 3. Read Access / Low Risk Modification = Suspicious Warning
        return CanaryEvaluationResult(
            is_canary_event=True,
            canary_file=file_path,
            calling_process=calling_process_info,
            risk_score=max(behavioral_risk_score, 0.70),
            action_recommended="HIGH_ALERT",
            reason=f"Process '{proc_name}' accessed decoy canary file. Pending behavior evaluation."
        )

    @staticmethod
    def _calc_hash(file_path: str) -> Optional[str]:
        """Calculate SHA256 of file."""
        if not os.path.exists(file_path):
            return "DELETED"
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                sha256.update(f.read())
            return sha256.hexdigest()
        except Exception:
            return None
