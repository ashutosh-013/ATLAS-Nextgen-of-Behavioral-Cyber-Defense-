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
import re
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

    create_vss_snapshot = create_system_restore_point

    def get_shadow_volumes(self) -> List[Dict[str, str]]:
        """Parse available Volume Shadow Copy device volumes and creation dates."""
        if self.os_name != "Windows":
            return []

        try:
            res = subprocess.run(["vssadmin", "list", "shadows"], capture_output=True, text=True, timeout=8)
            output = res.stdout
            volumes = []
            
            # Extract Shadow Copy Volume device paths and creation times
            vol_matches = re.findall(r"Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)", output, re.IGNORECASE)
            time_matches = re.findall(r"Creation Time:\s*([^\r\n]+)", output, re.IGNORECASE)
            
            for idx, vol in enumerate(vol_matches):
                ctime = time_matches[idx].strip() if idx < len(time_matches) else "Unknown"
                volumes.append({
                    "shadow_volume": vol,
                    "creation_time": ctime,
                    "index": idx + 1
                })
            return volumes
        except Exception as e:
            logger.debug(f"Failed to query shadow volumes: {e}")
            return []

    def verify_recovery_snapshot(self) -> Dict[str, Any]:
        """Verify existence and status of Volume Shadow Copies on Windows."""
        if self.os_name != "Windows":
            return {"vss_available": False, "reason": "Non-Windows Operating System"}

        try:
            volumes = self.get_shadow_volumes()
            count = len(volumes)
            return {
                "vss_available": count > 0,
                "shadow_copy_count": count,
                "volumes": volumes,
                "latest_volume": volumes[-1]["shadow_volume"] if volumes else None,
                "verification_status": "VALID" if count > 0 else "NO_SNAPSHOTS_FOUND"
            }
        except Exception as e:
            return {"vss_available": False, "verification_status": "ERROR", "reason": str(e)}

    def restore_file_from_shadow_copy(self, file_path: str, shadow_volume: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract and restore an uncorrupted copy of a file directly from a Windows Volume Shadow Copy.
        """
        if self.os_name != "Windows":
            return {"success": False, "error": "VSS recovery only supported on Windows"}

        try:
            if not shadow_volume:
                vols = self.get_shadow_volumes()
                if not vols:
                    return {"success": False, "error": "No Volume Shadow Copies available on this host"}
                # Use newest shadow volume
                shadow_volume = vols[-1]["shadow_volume"]

            # Convert drive path (C:\Users\...) to shadow path (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Users\...)
            abs_path = os.path.abspath(file_path)
            drive, rel_path = os.path.splitdrive(abs_path)
            shadow_src = os.path.join(shadow_volume, rel_path.lstrip("\\/"))

            # Execute safe extraction via PowerShell with LiteralPath
            ps_script = (
                f"$src = '{shadow_src}'; "
                f"$dst = '{abs_path}'; "
                "if (Test-Path -LiteralPath $src) { "
                "  Copy-Item -LiteralPath $src -Destination $dst -Force; "
                "  exit 0; "
                "} else { exit 2; }"
            )
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if res.returncode == 0 and os.path.exists(abs_path):
                new_hash = self._hash_file(abs_path)
                logger.info(f"Successfully restored file from VSS snapshot: {abs_path} (Hash: {new_hash})")
                return {
                    "success": True,
                    "status": "RESTORED",
                    "file_path": abs_path,
                    "sha256": new_hash,
                    "shadow_source": shadow_src
                }
            elif res.returncode == 2:
                return {
                    "success": False,
                    "status": "NOT_FOUND_IN_SNAPSHOT",
                    "error": f"File was created after snapshot or not captured in shadow copy: {shadow_src}"
                }
            else:
                return {
                    "success": False,
                    "status": "EXTRACTION_FAILED",
                    "error": res.stderr.strip() or "PowerShell copy command exited with error"
                }

        except Exception as e:
            logger.error(f"Error during VSS file restore for {file_path}: {e}")
            return {"success": False, "error": str(e)}

    def attempt_vss_recovery(self, target_files: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Attempt VSS recovery procedure: verifies shadow copies and restores damaged/quarantined files.
        """
        verification = self.verify_recovery_snapshot()
        if not verification.get("vss_available"):
            return {
                "success": False,
                "status": "RECOVERY_UNAVAILABLE",
                "message": "Volume Shadow Copies are not available on this host. Manual backup restore required.",
                "verification": verification,
                "restored_files": []
            }

        restored_records = []
        if target_files:
            latest_vol = verification.get("latest_volume")
            for fpath in target_files:
                r_res = self.restore_file_from_shadow_copy(fpath, shadow_volume=latest_vol)
                restored_records.append(r_res)

        successful_restores = [r for r in restored_records if r.get("success")]

        return {
            "success": True,
            "status": "RECOVERY_COMPLETED" if (target_files and successful_restores) else "SNAPSHOTS_VERIFIED",
            "message": (
                f"Successfully restored {len(successful_restores)}/{len(target_files)} file(s) from VSS snapshot."
                if target_files else
                f"Verified {verification.get('shadow_copy_count')} Volume Shadow Copy snapshot(s) available for file restoration."
            ),
            "verification": verification,
            "restored_files": restored_records
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
