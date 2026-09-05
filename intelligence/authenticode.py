"""
Authenticode & Digital Signature Provenance Engine for ATLAS

Verifies code-signing certificates and executable provenance to supply
evidence attributes into the CCF Risk Engine. Does NOT bypass behavioral AI analysis.
A valid signature is treated as evidence of provenance, not proof that behavior is safe.
"""

import os
import sys
import logging
import platform
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

logger = logging.getLogger("authenticode")


@dataclass
class AuthenticodeProvenance:
    file_path: str
    is_signed: bool = False
    is_trusted_root: bool = False
    publisher: Optional[str] = None
    trust_score: float = 0.5  # 0.0 (untrusted/revoked) to 1.0 (verified trusted CA)
    status: str = "Unsigned/Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuthenticodeEngine:
    """
    Code-signing certificate and binary provenance analyzer.
    Extracts certificate authority evidence for input into BADNA CCF Risk Engine.
    """

    def __init__(self):
        self.os_name = platform.system()
        self._cache: Dict[str, AuthenticodeProvenance] = {}

    def verify_binary_signature(self, file_path: str) -> AuthenticodeProvenance:
        """
        Verify code-signing signature and return provenance evidence.
        """
        if not file_path or not os.path.exists(file_path):
            return AuthenticodeProvenance(
                file_path=file_path,
                is_signed=False,
                trust_score=0.5,
                status="File Not Found"
            )

        if file_path in self._cache:
            return self._cache[file_path]

        provenance = self._verify_platform_signature(file_path)
        self._cache[file_path] = provenance
        return provenance

    def _verify_platform_signature(self, file_path: str) -> AuthenticodeProvenance:
        """Platform-specific certificate verification."""
        if self.os_name == "Windows":
            return self._verify_windows_authenticode(file_path)
        elif self.os_name in ["Linux", "Darwin"]:
            return self._verify_unix_provenance(file_path)
        else:
            return AuthenticodeProvenance(file_path=file_path, is_signed=False, trust_score=0.5, status="Unsupported OS")

    def _verify_windows_authenticode(self, file_path: str) -> AuthenticodeProvenance:
        """Verify Windows Authenticode digital signature using PowerShell CIM/Get-AuthenticodeSignature."""
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                f"(Get-AuthenticodeSignature -FilePath '{file_path}').Status.ToString(); "
                f"(Get-AuthenticodeSignature -FilePath '{file_path}').SignerCertificate.Subject"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            output_lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]

            if output_lines:
                status_str = output_lines[0]
                signer_subject = output_lines[1] if len(output_lines) > 1 else ""

                if status_str == "Valid":
                    publisher = self._extract_cn(signer_subject) or "Verified Publisher"
                    is_ms = "Microsoft" in signer_subject or "Windows" in signer_subject
                    trust_score = 0.90 if is_ms else 0.80
                    return AuthenticodeProvenance(
                        file_path=file_path,
                        is_signed=True,
                        is_trusted_root=True,
                        publisher=publisher,
                        trust_score=trust_score,
                        status="Valid Signature",
                        metadata={"subject": signer_subject}
                    )
                elif status_str in ["HashMismatch", "NotTrusted", "UnknownError"]:
                    return AuthenticodeProvenance(
                        file_path=file_path,
                        is_signed=True,
                        is_trusted_root=False,
                        trust_score=0.20,  # Invalid/Corrupted Signature = High Risk Indicator!
                        status=f"Invalid Signature ({status_str})"
                    )
        except Exception as e:
            logger.debug(f"Authenticode check error for {file_path}: {e}")

        # Unsigned binary default
        return AuthenticodeProvenance(
            file_path=file_path,
            is_signed=False,
            is_trusted_root=False,
            trust_score=0.50,
            status="Unsigned"
        )

    def _verify_unix_provenance(self, file_path: str) -> AuthenticodeProvenance:
        """Verify Unix/macOS binary system path provenance."""
        system_paths = ["/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/System/Applications/"]
        is_system = any(file_path.startswith(p) for p in system_paths)
        
        if is_system:
            return AuthenticodeProvenance(
                file_path=file_path,
                is_signed=True,
                is_trusted_root=True,
                publisher="System Core OS",
                trust_score=0.85,
                status="System Path Binary"
            )
        
        return AuthenticodeProvenance(
            file_path=file_path,
            is_signed=False,
            trust_score=0.50,
            status="Userland/Third-Party Binary"
        )

    @staticmethod
    def _extract_cn(subject: str) -> Optional[str]:
        """Extract Common Name (CN) from X.509 certificate subject line."""
        if not subject:
            return None
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:].strip('"')
        return None
