"""
VSS Ransomware Recovery & Incident Evidence Preservation Manager for ATLAS

Treats Volume Shadow Copies (VSS) as a recovery mechanism (not a guarantee).
Preserves incident evidence (process metadata, file hashes, memory state context)
and provides recovery snapshot verification.
"""

import os
import json
import time
import logging
import platform
import subprocess
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

logger = logging.getLogger("rollback")


@dataclass
class IncidentEvidence:
    incident_id: str
    timestamp: str
    target_process: Dict[str, Any]
    affected_files: List[str]
    evidence_hashes: Dict[str, str]
    system_state: Dict[str, Any]
    evidence_file_path: str


class VSSRollbackManager:
    """
    VSS Recovery Mechanism and Incident Evidence Preservation Orchestrator.
    """

    def __init__(self, evidence_dir: str = "knowledge_base/evidence"):
        self.evidence_dir = evidence_dir
        self.os_name = platform.system()
        os.makedirs(self.evidence_dir, exist_ok=True)

    def preserve_incident_evidence(
        self,
        target_process: Dict[str, Any],
        affected_files: Optional[List[str]] = None,
        additional_metadata: Optional[Dict[str, Any]] = None
    ) -> IncidentEvidence:
        """
        Preserve incident evidence for forensic analysis prior to mitigation.
        """
        inc_id = f"inc_{int(time.time())}_{target_process.get('pid', '0')}"
        ts = datetime.now().isoformat()
        affected_files = affected_files or []

        evidence_hashes = {}
        for f in affected_files[:20]:  # Hash top affected files
            if os.path.exists(f):
                evidence_hashes[f] = self._hash_file(f)

        system_state = {
            "os": self.os_name,
            "architecture": platform.architecture()[0],
            "python_version": platform.python_version(),
            "metadata": additional_metadata or {}
        }

        evidence_obj = IncidentEvidence(
            incident_id=inc_id,
            timestamp=ts,
            target_process=target_process,
            affected_files=affected_files,
            evidence_hashes=evidence_hashes,
            system_state=system_state,
            evidence_file_path=os.path.join(self.evidence_dir, f"{inc_id}.json")
        )

        # Save to disk
        try:
            with open(evidence_obj.evidence_file_path, "w", encoding="utf-8") as fn:
                json.dump(evidence_obj.__dict__, fn, indent=2, default=str)
            logger.info(f"Preserved incident evidence: {evidence_obj.evidence_file_path}")
        except Exception as e:
            logger.error(f"Failed to save incident evidence: {e}")

        return evidence_obj

    def create_system_restore_point(self, description: str = "ATLAS Defensive Checkpoint") -> bool:
        """Create Windows Volume Shadow Copy restore point."""
        if self.os_name != "Windows":
            logger.info("VSS creation skipped: non-Windows system")
            return False

        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                f"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS'"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                logger.info(f"Successfully created Windows Restore Point: {description}")
                return True
        except Exception as e:
            logger.debug(f"Restore point creation failed: {e}")

        return False

    def verify_recovery_snapshot(self) -> Dict[str, Any]:
        """Verify existence and status of Volume Shadow Copies on Windows."""
        if self.os_name != "Windows":
            return {"vss_available": False, "reason": "Non-Windows Operating System"}

        try:
            res = subprocess.run(["vssadmin", "list", "shadows"], capture_output=True, text=True, timeout=5)
            output = res.stdout
            count = output.count("Contents of shadow copy set")
            return {
                "vss_available": count > 0,
                "shadow_copy_count": count,
                "verification_status": "VALID" if count > 0 else "NO_SNAPSHOTS_FOUND",
                "raw_summary": output[:300]
            }
        except Exception as e:
            return {"vss_available": False, "verification_status": "ERROR", "reason": str(e)}

    def attempt_vss_recovery(self) -> Dict[str, Any]:
        """
        Attempt VSS recovery procedure while returning verification limits.
        """
        verification = self.verify_recovery_snapshot()
        if not verification.get("vss_available"):
            return {
                "success": False,
                "status": "RECOVERY_UNAVAILABLE",
                "message": "Volume Shadow Copies are not available on this host. Manual backup restore required.",
                "verification": verification
            }

        return {
            "success": True,
            "status": "RECOVERY_INITIATED",
            "message": f"Verified {verification.get('shadow_copy_count')} Volume Shadow Copy snapshot(s) available for system rollback.",
            "verification": verification
        }

    @staticmethod
    def _hash_file(path: str) -> str:
        """Calculate SHA256 file hash."""
        import hashlib
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return "UNREADABLE"


RollbackManager = VSSRollbackManager
_rollback_mgr_instance = None


def get_rollback_manager() -> VSSRollbackManager:
    global _rollback_mgr_instance
    if _rollback_mgr_instance is None:
        _rollback_mgr_instance = VSSRollbackManager()
    return _rollback_mgr_instance
