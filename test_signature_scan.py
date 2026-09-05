import sys
import os
import json
from pathlib import Path

# Ensure correct PYTHONPATH resolving
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import BADNAAnalysisOrchestrator

def main():
    print("=" * 65)
    print("ATLAS SIGNATURE MONITORING ENGINE - LIVE SCAN TEST RUNNER")
    print("=" * 65)
    print("[+] Initializing ATLAS Orchestrator and Loading Threat Intel Feeds...")
    
    try:
        orchestrator = BADNAAnalysisOrchestrator()
    except Exception as e:
        print(f"[!] Initialization failed: {e}")
        return
        
    print("[+] System initialized successfully.")
    print("-" * 65)
    
    # 1. Scan Benign Event Stream
    print("[*] STEP 1: Scanning Benign Event Stream...")
    benign_events = [
        {
            "event_id": "evt_benign_1",
            "event_type": "process",
            "timestamp": "2026-07-13T10:00:00",
            "source_system": "EDR",
            "event_data": {
                "pid": 4052,
                "name": "chrome.exe",
                "command": "chrome.exe --no-sandbox",
                "action": "create"
            }
        },
        {
            "event_id": "evt_benign_2",
            "event_type": "network",
            "timestamp": "2026-07-13T10:02:00",
            "source_system": "Zeek",
            "event_data": {
                "dest_ip": "140.82.112.3",
                "domain": "github.com",
                "action": "http"
            }
        }
    ]
    
    profile_benign = orchestrator.analyze_events(benign_events)
    print(f"    - Inferred Threat Class: {profile_benign.threat_classification.threat_class}")
    print(f"    - Ensemble Confidence Score: {profile_benign.threat_classification.confidence:.4f}")
    print(f"    - Match IOC Alerts Raised: {len(orchestrator.knowledge_base.ioc_matches)}")
    print("-" * 65)
    
    # 2. Scan Suspicious Event Stream containing matching signatures (mimikatz, Run Key Registry)
    print("[*] STEP 2: Scanning Suspicious Event Stream with Threat Signatures...")
    malicious_events = [
        {
            "event_id": "evt_mal_1",
            "event_type": "process",
            "timestamp": "2026-07-13T10:10:00",
            "source_system": "EDR",
            "event_data": {
                "pid": 2547,
                "name": "powershell.exe",
                "command": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\mimikatz.exe",
                "action": "create"
            }
        },
        {
            "event_id": "evt_mal_2",
            "event_type": "registry",
            "timestamp": "2026-07-13T10:12:00",
            "source_system": "EDR",
            "event_data": {
                "key_path": r"Software\Microsoft\Windows\CurrentVersion\Run\MaliciousTask",
                "action": "modify"
            }
        }
    ]
    
    # Reset matches for clear tracking
    orchestrator.knowledge_base.ioc_matches.clear()
    
    profile_mal = orchestrator.analyze_events(malicious_events)
    
    print("\n[+] SCAN RESULT:")
    print(f"    - Inferred Threat Class: {profile_mal.threat_classification.threat_class}")
    print(f"    - Calibrated Confidence Score: {profile_mal.threat_classification.confidence:.4f}")
    print(f"    - Risk Level: {profile_mal.risk_score.risk_level} (Score: {profile_mal.risk_score.score:.4f})")
    
    print("\n[+] SIGNATURES MATCHED IN PARALLEL:")
    matched_alerts = list(orchestrator.knowledge_base.ioc_matches.values())
    if matched_alerts:
        for idx, alert in enumerate(matched_alerts):
            print(f"    {idx+1}. IOC Type: {alert['ioc_type']} | Matched Value: {alert['ioc_value']}")
    else:
        print("    [!] No signatures matched.")
        
    print("\n[+] EXPLAINABLE EVIDENCE:")
    print(f"    - Rationale: {profile_mal.evidence.natural_language}")
    
    print("=" * 65)

if __name__ == "__main__":
    main()
