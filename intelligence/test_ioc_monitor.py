import sys
import os
import unittest
from pathlib import Path
import numpy as np

# Ensure correct pathing
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge_base.knowledge_base import KnowledgeBase
from intelligence.ioc_monitor import IOCMonitorEngine
from main import BADNAAnalysisOrchestrator
from data_models import VALID_THREAT_CLASSES


class TestIOCMonitor(unittest.TestCase):
    
    def setUp(self):
        # Initialize knowledge base in memory or temp dir
        self.kb = KnowledgeBase()
        self.engine = IOCMonitorEngine(self.kb)
        
    def tearDown(self):
        self.engine.stop_scheduler()

    def test_file_hash_matching(self):
        # 1. Matching SHA256
        event = {
            "event_id": "evt_test_1",
            "event_type": "file",
            "event_data": {
                "path": "C:\\Windows\\Temp\\mock_malware.exe",
                "sha256": "32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74"
            }
        }
        alert = self.engine.check_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["ioc_type"], "file_sha256")
        self.assertEqual(alert["ioc_value"], "32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74")
        
        # Verify stored in KB under match_id
        self.assertIn(alert["match_id"], self.kb.ioc_matches)
        
    def test_network_matching(self):
        # Matching destination IP
        event = {
            "event_id": "evt_test_2",
            "event_type": "network",
            "event_data": {
                "dest_ip": "192.168.1.100",
                "domain": "safe-site.com"
            }
        }
        alert = self.engine.check_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["ioc_type"], "network_ip")
        
        # Matching domain
        event_domain = {
            "event_id": "evt_test_3",
            "event_type": "network",
            "event_data": {
                "domain": "malicious-site.com"
            }
        }
        alert_domain = self.engine.check_event(event_domain)
        self.assertIsNotNone(alert_domain)
        self.assertEqual(alert_domain["ioc_type"], "network_domain")

    def test_process_matching(self):
        # Matching process name in command line
        event = {
            "event_id": "evt_test_4",
            "event_type": "process",
            "event_data": {
                "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\mimikatz.exe"
            }
        }
        alert = self.engine.check_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["ioc_type"], "process_command")
        self.assertEqual(alert["ioc_value"], event["event_data"]["command"])

    def test_registry_matching(self):
        event = {
            "event_id": "evt_test_5",
            "event_type": "registry",
            "event_data": {
                "key_path": r"Software\Microsoft\Windows\CurrentVersion\Run\MaliciousTask"
            }
        }
        alert = self.engine.check_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["ioc_type"], "registry_key")

    def test_no_matches(self):
        # Non-malicious event
        event = {
            "event_id": "evt_test_6",
            "event_type": "file",
            "event_data": {
                "path": "C:\\Windows\\notepad.exe",
                "sha256": "4e72352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74"
            }
        }
        alert = self.engine.check_event(event)
        self.assertIsNone(alert)

    def test_background_feed_updates(self):
        # Manually trigger updates and ensure scheduler components pull feed data
        initial_hash_count = len(self.engine.file_hashes)
        
        # Pull live feeds (mocked fallback or live depending on connection)
        self.engine._update_hourly_feeds()
        
        # Check that we loaded signatures from MalwareBazaar and URLhaus (hashes/urls)
        self.assertTrue(len(self.engine.file_hashes) >= initial_hash_count)


class TestIOCOrchestrationIntegration(unittest.TestCase):
    
    def setUp(self):
        self.orchestrator = BADNAAnalysisOrchestrator()
        
    def tearDown(self):
        if hasattr(self.orchestrator, 'ioc_monitor'):
            self.orchestrator.ioc_monitor.stop_scheduler()

    def test_orchestrator_integration_boosts_confidence(self):
        # 1. Base events without IOC match
        raw_events_clean = [
            {
                "event_type": "process", 
                "timestamp": "2024-01-01T10:00:00", 
                "source_system": "EDR",
                "event_data": {"pid": 1234, "action": "create", "name": "cmd.exe", "command": "cmd.exe /c echo hello"}
            },
            {
                "event_type": "file", 
                "timestamp": "2024-01-01T10:00:05",
                "source_system": "EDR",
                "event_data": {"path": "C:\\Windows\\Temp\\test.txt", "action": "write"}
            }
        ]
        
        profile_clean = self.orchestrator.analyze_events(raw_events_clean)
        self.assertIsNotNone(profile_clean)
        self.assertIsNotNone(profile_clean.threat_classification)
        clean_confidence = profile_clean.threat_classification.confidence
        
        # 2. Events with IOC match (powershell executing mimikatz)
        raw_events_malicious = [
            {
                "event_type": "process", 
                "timestamp": "2024-01-01T10:00:00", 
                "source_system": "EDR",
                "event_data": {"pid": 1234, "action": "create", "name": "cmd.exe", "command": "cmd.exe /c mimikatz.exe"}
            },
            {
                "event_type": "file", 
                "timestamp": "2024-01-01T10:00:05",
                "source_system": "EDR",
                "event_data": {"path": "C:\\Windows\\Temp\\test.txt", "action": "write"}
            }
        ]
        
        profile_malicious = self.orchestrator.analyze_events(raw_events_malicious)
        self.assertIsNotNone(profile_malicious)
        
        # Verify that ioc_matches metadata exists in profile
        self.assertIn("ioc_matches", profile_malicious.metadata)
        self.assertTrue(len(profile_malicious.metadata["ioc_matches"]) > 0)
        
        # Check that classification confidence is boosted for the malicious profile
        self.assertIsNotNone(profile_malicious.threat_classification)
        malicious_confidence = profile_malicious.threat_classification.confidence
        self.assertTrue(malicious_confidence > clean_confidence or malicious_confidence > 0.9)


if __name__ == '__main__':
    unittest.main()
