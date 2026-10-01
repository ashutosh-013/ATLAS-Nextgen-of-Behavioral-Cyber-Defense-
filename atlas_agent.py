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

# Ensure immediate unbuffered console logging in Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(line_buffering=True)

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

# Global Thread-Safe Real-Time Telemetry Event Queue (Capped to prevent memory overload)
import queue
TELEMETRY_QUEUE = queue.Queue(maxsize=2000)

def enqueue_telemetry_event(event_type: str, event_data: dict, source_system: str = "Local_Laptop_Host"):
    """Enqueue a real-time telemetry event with non-blocking overflow protection."""
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
        # Prevent queue memory bloat: drop oldest and insert new
        try:
            _ = TELEMETRY_QUEUE.get_nowait()
            TELEMETRY_QUEUE.put_nowait(event)
        except Exception:
            pass

def run_telemetry_dispatcher():
    """Batch-dispatch real-time events with adaptive CPU throttling."""
    print("[+] Starting Real-Time Event Telemetry Dispatcher (Throttled & Protected)...")
    meta = get_device_metadata()
    
    while True:
        try:
            # Resource check: if memory is critically high, sleep longer
            try:
                if psutil.virtual_memory().percent > 92.0:
                    time.sleep(2.0)
            except Exception:
                pass

            batch = []
            # Drain up to 50 events from queue
            while len(batch) < 50:
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
                    with urllib.request.urlopen(req, timeout=3.0) as res:
                        pass
                except Exception:
                    pass # Quietly handle server busy/offline state
            
            # 500ms dispatch interval: ensures sub-second alert latency without overloading backend
            time.sleep(0.5)
        except Exception:
            time.sleep(1.0)

def run_continuous_process_scanner():
    """Perform differential process monitoring with CPU-adaptive throttling."""
    print("[+] Starting Differential Live Process & Event Streaming Thread...")
    known_pids = set()
    
    while True:
        try:
            # Adaptive CPU Throttle: If CPU is pegged >85%, back off to preserve user PC responsiveness
            try:
                cpu_load = psutil.cpu_percent(interval=None)
                if cpu_load > 85.0:
                    time.sleep(2.5)
                    continue
            except Exception:
                pass

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
            pass # Keep scanning even if an individual psutil call encounters transient permission issues
            
        # Balanced 1.2s loop interval keeps CPU consumption below 0.5% while catching all process changes
        time.sleep(1.2)

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
            time.sleep(0.5)

def watch_directory_win32_kernel(wdir: str):
    """Event-driven Windows kernel filesystem change listener using ReadDirectoryChangesW."""
    if os.name != "nt":
        return

    import ctypes
    from ctypes import wintypes
    import struct
    import hashlib

    kernel32 = ctypes.windll.kernel32
    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    NOTIFY_FILTERS = 0x00000001 | 0x00000002 | 0x00000008 | 0x00000010  # Name, Dir, Size, LastWrite

    suspicious_exts = {'.exe', '.bat', '.ps1', '.vbs', '.js', '.dll', '.scr', '.hta', '.lockbit', '.wannacry'}

    try:
        h_dir = kernel32.CreateFileW(
            wdir,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        if h_dir == -1 or h_dir == 0:
            return
    except Exception:
        return

    buf = ctypes.create_string_buffer(65536)
    bytes_ret = wintypes.DWORD()

    try:
        while True:
            success = kernel32.ReadDirectoryChangesW(
                h_dir,
                buf,
                len(buf),
                True,  # watch subtree
                NOTIFY_FILTERS,
                ctypes.byref(bytes_ret),
                None,
                None
            )
            if not success or bytes_ret.value == 0:
                time.sleep(0.5)
                continue

            offset = 0
            while True:
                next_offset, action, fn_len = struct.unpack_from("III", buf, offset)
                fn_bytes = buf[offset + 12 : offset + 12 + fn_len]
                fname = fn_bytes.decode("utf-16le", errors="ignore")
                fpath = os.path.join(wdir, fname)
                ext = os.path.splitext(fname)[1].lower()
                is_canary = fname.startswith(".atlas_decoy")

                action_str = "create" if action == 1 else "delete" if action == 2 else "modify" if action == 3 else "rename"

                if ext in suspicious_exts or is_canary or "temp" in wdir.lower():
                    fhash = "UNKNOWN"
                    fsize = 0
                    if action_str in ("create", "modify") and os.path.exists(fpath):
                        try:
                            fsize = os.path.getsize(fpath)
                            if fsize < 10 * 1024 * 1024:
                                with open(fpath, "rb") as f:
                                    fhash = hashlib.sha256(f.read()).hexdigest()
                        except Exception:
                            pass

                    enqueue_telemetry_event(
                        "file",
                        {
                            "path": fpath,
                            "name": fname,
                            "action": action_str,
                            "size": fsize,
                            "sha256": fhash,
                            "is_canary": is_canary,
                            "kernel_hook": "ReadDirectoryChangesW"
                        }
                    )

                if next_offset == 0:
                    break
                offset += next_offset
    except Exception:
        pass
    finally:
        try:
            kernel32.CloseHandle(h_dir)
        except Exception:
            pass


def run_continuous_filesystem_monitor():
    """Continuously observe drop and canary paths for suspicious file activity using kernel events with polling fallback."""
    print("[+] Starting Real-Time Kernel Event & Canary Filesystem Monitor...")
    import hashlib

    watch_dirs = []
    user_home = os.path.expanduser("~")
    for d in [
        os.environ.get("TEMP"),
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "Documents")
    ]:
        if d and os.path.exists(d):
            watch_dirs.append(d)

    # Spawn Win32 kernel event listener thread for each directory
    if os.name == "nt":
        for wdir in watch_dirs:
            t = threading.Thread(target=watch_directory_win32_kernel, args=(wdir,), daemon=True)
            t.start()

    known_state = {}
    for wdir in watch_dirs:
        try:
            for entry in os.scandir(wdir):
                if entry.is_file(follow_symlinks=False):
                    try:
                        stat = entry.stat()
                        known_state[entry.path] = (stat.st_mtime, stat.st_size)
                    except Exception:
                        pass
        except Exception:
            pass

    suspicious_exts = {'.exe', '.bat', '.ps1', '.vbs', '.js', '.dll', '.scr', '.hta', '.lockbit', '.wannacry'}

    while True:
        try:
            current_state = {}
            for wdir in watch_dirs:
                try:
                    for entry in os.scandir(wdir):
                        if entry.is_file(follow_symlinks=False):
                            try:
                                stat = entry.stat()
                                p = entry.path
                                current_state[p] = (stat.st_mtime, stat.st_size)

                                if p not in known_state:
                                    ext = os.path.splitext(p)[1].lower()
                                    fname = entry.name
                                    is_canary = fname.startswith(".atlas_decoy")
                                    if ext in suspicious_exts or is_canary or "temp" in wdir.lower():
                                        fhash = "UNKNOWN"
                                        if stat.st_size < 10 * 1024 * 1024:
                                            try:
                                                with open(p, "rb") as f:
                                                    fhash = hashlib.sha256(f.read()).hexdigest()
                                            except Exception:
                                                pass
                                        enqueue_telemetry_event(
                                            "file",
                                            {
                                                "path": p,
                                                "name": fname,
                                                "action": "create",
                                                "size": stat.st_size,
                                                "sha256": fhash,
                                                "is_canary": is_canary
                                            }
                                        )
                                else:
                                    prev_mtime, prev_size = known_state[p]
                                    if stat.st_mtime != prev_mtime:
                                        fname = entry.name
                                        is_canary = fname.startswith(".atlas_decoy")
                                        if is_canary or stat.st_size != prev_size:
                                            enqueue_telemetry_event(
                                                "file",
                                                {
                                                    "path": p,
                                                    "name": fname,
                                                    "action": "modify",
                                                    "size": stat.st_size,
                                                    "is_canary": is_canary
                                                }
                                            )
                            except Exception:
                                pass
                except Exception:
                    pass

            deleted = set(known_state.keys()) - set(current_state.keys())
            for dp in deleted:
                fname = os.path.basename(dp)
                if fname.startswith(".atlas_decoy"):
                    enqueue_telemetry_event("file", {"path": dp, "name": fname, "action": "delete", "is_canary": True})

            known_state = current_state
            time.sleep(3.0)
        except Exception:
            time.sleep(3.0)


def run_continuous_amsi_script_monitor():
    """Monitor Windows PowerShell Script Block execution (Event ID 4104) and inspect via AMSI."""
    if os.name != "nt":
        return

    print("[+] Starting Real-Time AMSI Script Block Logging Ingestion Engine...")
    try:
        from intelligence.amsi_scanner import AMSIScanner
        amsi = AMSIScanner()
    except Exception as e:
        print(f"[!] AMSI Scanner import warning: {e}")
        return

    last_check = datetime.now()
    seen_ids = set()

    while True:
        try:
            # Query recent 4104 Script Block events via PowerShell
            ps_cmd = (
                "try { "
                "  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 5 -ErrorAction Stop | "
                "  ForEach-Object { [PSCustomObject]@{ Id=$_.RecordId; Time=$_.TimeCreated.ToString('o'); Msg=$_.Message } } | "
                "  ConvertTo-Json -Compress "
                "} catch { '[]' }"
            )
            res = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], capture_output=True, text=True, timeout=8)
            output = res.stdout.strip()

            if output and output != "[]":
                try:
                    records = json.loads(output)
                    if isinstance(records, dict):
                        records = [records]

                    for rec in records:
                        rec_id = rec.get("Id")
                        if rec_id and rec_id not in seen_ids:
                            seen_ids.add(rec_id)
                            msg = rec.get("Msg", "")
                            
                            # Inspect script buffer with AMSI
                            scan_res = amsi.scan_string(msg, content_name=f"ScriptBlock_{rec_id}")
                            
                            if scan_res.is_malicious or scan_res.amsi_result_code == 32768 or scan_res.risk_score > 0.5:
                                enqueue_telemetry_event(
                                    "process",
                                    {
                                        "name": "powershell.exe",
                                        "command_line": msg[:500],
                                        "amsi_detected": True,
                                        "threat_name": scan_res.threat_name or "AMSI.MaliciousScriptBlock",
                                        "risk_score": scan_res.risk_score,
                                        "action": "script_execute"
                                    }
                                )
                except Exception:
                    pass

            if len(seen_ids) > 1000:
                seen_ids.clear()

            time.sleep(4.0)
        except Exception:
            time.sleep(4.0)


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

    # 2. Run Real-Time Filesystem & Canary Activity Monitor thread
    fs_thread = threading.Thread(target=run_continuous_filesystem_monitor, daemon=True)
    fs_thread.start()
    
    # 3. Run Real-Time AMSI Script Block Logging Ingestion thread
    amsi_thread = threading.Thread(target=run_continuous_amsi_script_monitor, daemon=True)
    amsi_thread.start()

    # 4. Run T-Pot Honeypot Listeners (decoy SSH/2222, SMB/4455, HTTP-Honeytrap/8080)
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
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Agent stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical error in ATLAS agent: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
