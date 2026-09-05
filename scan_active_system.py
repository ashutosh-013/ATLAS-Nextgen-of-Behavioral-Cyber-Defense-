import sys
import os
import json
import subprocess
from datetime import datetime

# Ensure correct PYTHONPATH resolving
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import BADNAAnalysisOrchestrator

import psutil

def fetch_running_processes():
    print("[+] Querying active processes on your laptop using native psutil APIs...")
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            info = proc.info
            exe_path = info.get('exe')
            if exe_path:
                processes.append({
                    "Id": info['pid'],
                    "ProcessName": info['name'] or "unknown",
                    "Path": exe_path
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def main():
    print("=" * 65)
    print("ATLAS ACTIVE LAPTOP PROCESS & SIGNATURE SCANNER")
    print("=" * 65)
    
    processes = fetch_running_processes()
    if not processes:
        print("[!] No running processes with valid executable paths found.")
        return
        
    print(f"[+] Found {len(processes)} active executable paths.")
    print("[+] Loading ATLAS Behavioral Knowledge Base...")
    
    try:
        orchestrator = BADNAAnalysisOrchestrator()
    except Exception as e:
        print(f"[!] Initialization failed: {e}")
        return
        
    print("[+] Normalizing process telemetry into ATLAS event schema...")
    events = []
    for idx, proc in enumerate(processes):
        pid = proc.get("Id", idx)
        name = proc.get("ProcessName", "unknown")
        path = proc.get("Path", "")
        
        event = {
            "event_id": f"real_proc_{pid}_{idx}",
            "event_type": "process",
            "timestamp": datetime.now().isoformat(),
            "source_system": "Local_Laptop_Host",
            "event_data": {
                "pid": pid,
                "name": name,
                "command": path,
                "action": "create"
            }
        }
        events.append(event)
        
    print(f"[+] Processing {len(events)} events through the signature engine and BADNA pipeline...")
    
    # Reset matches for clean tracking
    orchestrator.knowledge_base.ioc_matches.clear()
    
    profile = orchestrator.analyze_events(events)
    
    # Send telemetry to local server so it shows up in dashboard UI
    import urllib.request
    import socket
    import getpass
    
    # Fetch accurate device metadata
    print("[+] Gathering local system identity metadata...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"

    try:
        owner = getpass.getuser()
    except Exception:
        owner = "Local User"

    try:
        mfg = subprocess.check_output(["powershell", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer"]).decode().strip()
        model = subprocess.check_output(["powershell", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"]).decode().strip()
        brand = f"{mfg} {model}"
    except Exception:
        brand = "Windows PC"
        
    print(f"    - IP: {ip_address}")
    print(f"    - Owner: {owner}")
    print(f"    - Brand: {brand}")
    print("[+] Streaming local PC scan telemetry to live ATLAS dashboard...")
    
    try:
        payload = {
            "events": events,
            "device_metadata": {
                "ip": ip_address,
                "owner": owner,
                "brand": brand
            }
        }
        req = urllib.request.Request(
            "http://localhost:5000/api/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            if res_data.get("success"):
                print("[+] Successfully registered PC scan on live dashboard history list!")
    except Exception as e:
        print(f"[!] Could not notify dashboard API (is server running?): {e}")
        
    print("\n" + "=" * 65)
    print("LIVE LAPTOP SCAN REPORT")
    print("=" * 65)
    print(f"    - Threat Classification: {profile.threat_classification.threat_class}")
    print(f"    - Platform Confidence Score: {profile.threat_classification.confidence:.4f}")
    print(f"    - Risk Posture Level: {profile.risk_score.risk_level} (Score: {profile.risk_score.score:.4f})")
    
    print("\n[+] MALICIOUS SIGNATURE MATCHES:")
    matched_alerts = list(orchestrator.knowledge_base.ioc_matches.values())
    if matched_alerts:
        for idx, alert in enumerate(matched_alerts):
            print(f"    [!] Match {idx+1}: IOC Type: {alert['ioc_type']} | Value: {alert['ioc_value']}")
    else:
        print("    [OK] No malware signatures or forbidden executables matched in your running processes.")
        
    print("\n[+] PIPELINE BEHAVIORAL SUMMARY:")
    print(f"    {profile.evidence.natural_language}")
    print("=" * 65)

if __name__ == "__main__":
    main()
