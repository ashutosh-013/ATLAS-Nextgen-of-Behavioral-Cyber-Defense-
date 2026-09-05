"""
AMSI In-Memory Inspection Engine for ATLAS

Interfaces with Windows Antimalware Scan Interface (amsi.dll) to inspect
obfuscated scripts (PowerShell, VBScript, C#, JScript) dynamically in RAM before execution.
Includes script entropy analysis and pattern fallback for non-Windows platforms.
"""

import os
import re
import math
import ctypes
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional

logger = logging.getLogger("amsi_scanner")


@dataclass
class AMSIScanResult:
    is_malicious: bool = False
    amsi_result_code: int = 0  # 1 = CLEAN, 32768 = DETECTED
    risk_score: float = 0.0
    threat_name: Optional[str] = None
    details: str = "Clean"


class AMSIScanner:
    """
    Antimalware Scan Interface (AMSI) and RAM Script Analyzer.
    """

    def __init__(self):
        self.os_name = os.name
        self.amsi_handle = None
        self.amsi_session = None
        self._init_amsi()
        
        # High-risk script regex patterns
        self.suspicious_cmdlets = [
            re.compile(r"(?i)Invoke-Expression|iex\s"),
            re.compile(r"(?i)DownloadString|DownloadFile"),
            re.compile(r"(?i)VirtualAlloc|WriteProcessMemory|CreateThread"),
            re.compile(r"(?i)Reflect\.Assembly|System\.Reflection"),
            re.compile(r"(?i)amsiUtils|amsiInitFailed")  # AMSI Bypass attempts!
        ]

    def _init_amsi(self):
        """Initialize Windows amsi.dll handle if running on Windows."""
        if self.os_name == "nt":
            try:
                self.amsi = ctypes.windll.amsi
                # AmsiInitialize(appName, amsiContext)
                ctx = ctypes.c_void_p()
                res = self.amsi.AmsiInitialize("ATLAS_Behavioral_Agent", ctypes.byref(ctx))
                if res == 0:
                    self.amsi_handle = ctx
                    logger.info("Windows AMSI Interface initialized successfully")
            except Exception as e:
                logger.debug(f"AMSI initialization error: {e}")

    def scan_script_content(self, script_content: str, script_name: str = "ScriptPayload") -> AMSIScanResult:
        """
        Scan script content string via Windows AMSI API or pattern fallback.
        """
        if not script_content:
            return AMSIScanResult(is_malicious=False, risk_score=0.0)

        # 1. Try Native Windows AMSI Scan
        if self.amsi_handle:
            native_res = self._scan_native_amsi(script_content, script_name)
            if native_res.is_malicious:
                return native_res

        # 2. Entropy & Heuristic Pattern Fallback Scan
        return self._scan_heuristic_patterns(script_content)

    def _scan_native_amsi(self, content: str, app_name: str) -> AMSIScanResult:
        """Execute ctypes call to AmsiScanString on Windows."""
        try:
            result_code = ctypes.c_int(0)
            res = self.amsi.AmsiScanString(
                self.amsi_handle,
                ctypes.c_wchar_p(content),
                ctypes.c_wchar_p(app_name),
                None,
                ctypes.byref(result_code)
            )
            
            # AMSI_RESULT_DETECTED = 32768
            if res == 0 and result_code.value >= 32768:
                return AMSIScanResult(
                    is_malicious=True,
                    amsi_result_code=result_code.value,
                    risk_score=0.98,
                    threat_name="AMSI.Script.Malicious",
                    details=f"Windows AMSI flagged script payload (Result Code: {result_code.value})"
                )
        except Exception as e:
            logger.debug(f"AmsiScanString call failed: {e}")

        return AMSIScanResult(is_malicious=False, amsi_result_code=1)

    def _scan_heuristic_patterns(self, content: str) -> AMSIScanResult:
        """Analyze script entropy and suspicious cmdlets for obfuscated payloads."""
        matched_patterns = []
        for pat in self.suspicious_cmdlets:
            if pat.search(content):
                matched_patterns.append(pat.pattern)

        entropy = self._calculate_entropy(content)
        
        # High entropy (> 5.8) + dangerous cmdlets = Obfuscated Script Attack
        if len(matched_patterns) >= 2 or (entropy > 5.8 and len(matched_patterns) >= 1):
            return AMSIScanResult(
                is_malicious=True,
                risk_score=0.88,
                threat_name="Heuristic.ObfuscatedScript",
                details=f"High entropy ({entropy:.2f}) script containing suspicious patterns: {matched_patterns}"
            )
        elif len(matched_patterns) == 1:
            return AMSIScanResult(
                is_malicious=False,
                risk_score=0.45,
                threat_name="Heuristic.SuspiciousCmdlet",
                details=f"Script contains cmdlet pattern: {matched_patterns[0]}"
            )

        return AMSIScanResult(is_malicious=False, risk_score=0.10)

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculate Shannon Entropy of string."""
        if not data:
            return 0.0
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        return - sum(p * math.log(p, 2) for p in prob)
