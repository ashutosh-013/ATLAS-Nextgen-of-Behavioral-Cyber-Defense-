"""
ATLAS Desktop Native Application Launcher
-----------------------------------------
Provides a smooth, zero-latency desktop application experience for ATLAS.
- Runs the local Flask & SSE analytics backend on 127.0.0.1:5000 in a background daemon thread.
- Directs database and telemetry storage to %LOCALAPPDATA%\\ATLAS\\ to prevent write permission crashes.
- Launches a dedicated, frameless desktop window (via pywebview or Edge Application Mode).
"""

import os
import sys
import time
import socket
import threading
import subprocess
import urllib.request
from pathlib import Path

# Configure Desktop Mode environment variable before imports
os.environ["ATLAS_DESKTOP_MODE"] = "1"

# In packaged (frozen) mode, adjust sys.path if necessary
if getattr(sys, 'frozen', False):
    bundle_dir = getattr(sys, '_MEIPASS', Path(sys.executable).parent)
    if str(bundle_dir) not in sys.path:
        sys.path.insert(0, str(bundle_dir))
    os.chdir(bundle_dir)

import database
import config
from web_app import app

PORT = 5000
BASE_URL = f"http://127.0.0.1:{PORT}"
APP_TITLE = "ATLAS - Causal Behavioral Cyber Intelligence Platform"


def is_port_in_use(port: int) -> bool:
    """Check if the local port is already bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0


def wait_for_server(url: str, timeout: float = 15.0) -> bool:
    """Wait for Flask server to respond to HTTP requests."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.2)
    return False


def start_backend_server():
    """Start Flask web server on a background thread."""
    if is_port_in_use(PORT):
        print(f"[ATLAS Desktop] Port {PORT} is already active. Attaching to running backend...")
        return

    print(f"[ATLAS Desktop] Initializing database at: {database.get_database_path()}")
    database.init_db()

    print(f"[ATLAS Desktop] Starting unified engine on {BASE_URL}...")
    # Run Flask application with multithreading enabled for SSE stream concurrency
    app.run(
        host="127.0.0.1",
        port=PORT,
        threaded=True,
        use_reloader=False,
        debug=False
    )


def start_live_host_agent():
    """
    Spawns real-time differential process monitoring, telemetry dispatch,
    and decoy honeypot listeners in protected background daemon threads.
    Protects user's PC with adaptive thresholds to prevent high CPU or memory usage.
    """
    try:
        import atlas_agent
        print("[ATLAS Desktop] Starting real-time host protection daemon...")
        
        # 1. Telemetry dispatcher
        t_dispatch = threading.Thread(target=atlas_agent.run_telemetry_dispatcher, daemon=True, name="TelemetryDispatcher")
        t_dispatch.start()
        
        # 2. Continuous differential process scanner
        t_scanner = threading.Thread(target=atlas_agent.run_continuous_process_scanner, daemon=True, name="LiveProcessScanner")
        t_scanner.start()
        
        # 3. Decoy honeypot listeners on safe ports
        for port in [2222, 4455, 8080]:
            try:
                t_honey = threading.Thread(target=atlas_agent.run_honeypot_listener, args=(port,), daemon=True, name=f"Honeypot-{port}")
                t_honey.start()
            except Exception as e:
                pass
                
        print("[ATLAS Desktop] Real-time host protection active.")
    except Exception as e:
        print(f"[ATLAS Desktop] Could not start live host agent: {e}")


def launch_native_window():
    """
    Launch native desktop application window.
    Priority 1: pywebview (Native Windows WebView2 container)
    Priority 2: Microsoft Edge standalone App Mode (built-in to all Windows 10/11)
    Priority 3: Default system browser fallback
    """
    # Priority 1: pywebview
    try:
        import webview
        print("[ATLAS Desktop] Launching native window via pywebview (WebView2)...")
        candidates = [
            Path(__file__).parent / "frontend" / "atlas_logo.ico",
            Path(__file__).parent / "_internal" / "frontend" / "atlas_logo.ico",
            Path(sys.executable).parent / "frontend" / "atlas_logo.ico",
            Path(sys.executable).parent / "_internal" / "frontend" / "atlas_logo.ico",
        ]
        icon_path = None
        for c in candidates:
            if c.exists():
                icon_path = str(c)
                break
            
        window = webview.create_window(
            title=APP_TITLE,
            url=BASE_URL,
            width=1440,
            height=900,
            min_size=(1024, 700),
            background_color='#040811',
            text_select=True
        )
        webview.start(debug=False)
        return
    except ImportError:
        pass
    except Exception as e:
        print(f"[ATLAS Desktop] pywebview initialization note: {e}")

    # Priority 2: Microsoft Edge Application Mode (zero-install native window on Windows)
    if sys.platform == "win32":
        edge_paths = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe")
        ]
        for ep in edge_paths:
            if os.path.exists(ep):
                print(f"[ATLAS Desktop] Launching standalone App Mode via Microsoft Edge...")
                cmd = [ep, f"--app={BASE_URL}", "--window-size=1440,900"]
                proc = subprocess.Popen(cmd)
                proc.wait()
                return

    # Priority 3: Default web browser
    import webbrowser
    print("[ATLAS Desktop] Launching dashboard in default browser...")
    webbrowser.open(BASE_URL)
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass


def main():
    print("================================================================================")
    print(" ATLAS (Adaptive Threat Learning and Analysis System) Desktop")
    print("================================================================================")
    
    # Verify local AppData storage
    storage_dir = Path(database.get_database_path()).parent
    print(f"[ATLAS Storage] Persistent data path: {storage_dir}")
    storage_dir.mkdir(parents=True, exist_ok=True)

    # Launch server in daemon thread
    server_thread = threading.Thread(target=start_backend_server, daemon=True)
    server_thread.start()

    # Wait until server is accepting requests
    if not wait_for_server(BASE_URL, timeout=15.0):
        print("[ATLAS Desktop] Warning: Backend server took longer than expected to bind.")

    # Start live host protection agent (process scanner, telemetry stream, honeypot)
    agent_thread = threading.Thread(target=start_live_host_agent, daemon=True)
    agent_thread.start()

    # Launch GUI window
    launch_native_window()
    print("[ATLAS Desktop] Application terminated cleanly.")


if __name__ == "__main__":
    main()
