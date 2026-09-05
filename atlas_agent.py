import os
import sys
import json
import time
import socket
import getpass
import threading
import subprocess
import urllib.request
from datetime import datetime

import psutil

API_URL = "http://localhost:5000"

def get_device_metadata():
    """Fetch local system identity metadata."""
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
        
    return {
        "ip": ip_address,
        "owner": owner,
        "brand": brand
    }

def fetch_running_processes():
    """Query active processes on the host machine using highly optimized native psutil APIs."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
        try:
            info = proc.info
            exe_path = info.get('exe')
            if exe_path:
                processes.append({
                    "Id": info['pid'],
                    "ProcessName": info['name'] or "unknown",
                    "Path": exe_path,
                    "ParentId": info.get('ppid', 0)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

# Global Thread-Safe Real-Time Telemetry Event Queue
import queue
TELEMETRY_QUEUE = queue.Queue(maxsize=10000)

def enqueue_telemetry_event(event_type: str, event_data: dict, source_system: str = "Local_Laptop_Host"):
    """Enqueue a real-time telemetry event for async streaming."""
    event = {
        "event_id": f"real_{event_type}_{int(time.time() * 1000)}_{os.urandom(2).hex()}",
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "source_system": source_system,
        "event_data": event_data
    }
    try:
        TELEMETRY_QUEUE.put_nowait(event)
    except queue.Full:
        pass # Drop oldest or skip if buffer full under extreme load

def run_telemetry_dispatcher():
    """Batch-dispatch real-time events from queue to ATLAS server API/WebSocket."""
    print("[+] Starting Real-Time Event Telemetry Dispatcher...")
    meta = get_device_metadata()
    
    while True:
        try:
            batch = []
            # Drain up to 100 events from queue
            while len(batch) < 100:
                try:
                    event = TELEMETRY_QUEUE.get_nowait()
                    batch.append(event)
                except queue.Empty:
                    break
            
            if batch:
                payload = {
                    "events": batch,
                    "device_metadata": meta
                }
                req = urllib.request.Request(
                    f"{API_URL}/api/analyze",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=3) as res:
                        pass
                except Exception:
                    pass # Quietly handle server offline state
            
            time.sleep(0.1) # 100ms dispatch latency for near-instant execution
        except Exception as e:
            time.sleep(1)

def run_continuous_process_scanner():
    """Perform differential process monitoring to catch new creations & terminations in real-time."""
    print("[+] Starting Differential Live Process & Event Streaming Thread...")
    known_pids = set()
    
    while True:
        try:
            current_processes = fetch_running_processes()
            current_pid_map = {proc["Id"]: proc for proc in current_processes}
            current_pids = set(current_pid_map.keys())
            
            # Detect new process launches
            new_pids = current_pids - known_pids
            for pid in new_pids:
                proc = current_pid_map[pid]
                enqueue_telemetry_event("process", {
                    "pid": pid,
                    "ppid": proc.get("ParentId", 0),
                    "name": proc.get("ProcessName", "unknown"),
                    "command": proc.get("Path", ""),
                    "action": "create"
                })
                
            # Detect process terminations
            terminated_pids = known_pids - current_pids
            for pid in terminated_pids:
                enqueue_telemetry_event("process", {
                    "pid": pid,
                    "action": "terminate"
                })
                
            known_pids = current_pids
        except Exception as e:
            print(f"[!] Error in process scanner: {e}")
            
        time.sleep(0.5)  # 500ms fast polling loop for differential process tracking

def handle_honeypot_connection(conn, addr, port):
    """Handle connection attempts to honeypot decoy ports and stream alerts."""
    src_ip, src_port = addr
    print(f"[!] TPOT ALERT: Inbound connection on decoy port {port} from {src_ip}:{src_port}")
    
    payload = "Connection Established"
    try:
        conn.settimeout(2.0)
        data = conn.recv(1024)
        if data:
            payload = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
        
    try:
        conn.sendall(b"ATLAS Secure Access Gateway\nLogin: ")
        time.sleep(0.5)
    except Exception:
        pass
    finally:
        conn.close()
        
    # Map honeypot service name
    service_type = "honeytrap"
    if port == 2222:
        service_type = "cowrie"
    elif port == 4455:
        service_type = "dionaea"
        
    # Post alert to Flask server
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "type": service_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_port": port,
        "payload": payload[:100],  # Keep short
        "status": "pending_approval"
    }
    
    try:
        req = urllib.request.Request(
            f"{API_URL}/api/tpot/alerts",
            data=json.dumps(alert_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as res:
            pass
    except Exception as e:
        print(f"[!] Failed to send T-Pot alert to dashboard: {e}")

def run_honeypot_listener(port):
    """Listen for TCP packets on decoy honeypot ports."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(100)
        print(f"[+] T-Pot Honeypot listening on port {port}...")
    except Exception as e:
        print(f"[!] Failed to bind T-Pot decoy port {port}: {e}")
        return
        
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_honeypot_connection, args=(conn, addr, port), daemon=True)
            t.start()
        except Exception:
            pass

def main():
    print("=" * 70)
    print("ATLAS PARALLEL EDR TELEMETRY & T-POT HONEYPOT AGENT")
    print("=" * 70)
    
    # 0. Run Real-Time Telemetry Dispatcher thread
    dispatcher_thread = threading.Thread(target=run_telemetry_dispatcher, daemon=True)
    dispatcher_thread.start()

    # 1. Run Differential Process Scanner thread
    scanner_thread = threading.Thread(target=run_continuous_process_scanner, daemon=True)
    scanner_thread.start()
    
    # 2. Run T-Pot Honeypot Listeners (decoy SSH/2222, SMB/4455, HTTP-Honeytrap/8080)
    decoy_ports = [2222, 4455, 8080]
    for port in decoy_ports:
        t = threading.Thread(target=run_honeypot_listener, args=(port,), daemon=True)
        t.start()
        
    print("[+] All threads running successfully. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Agent shutting down safely.")

if __name__ == "__main__":
    main()
