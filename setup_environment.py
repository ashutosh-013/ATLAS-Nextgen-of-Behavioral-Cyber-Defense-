"""
ATLAS Automated Environment Setup & Diagnostic Suite
======================================================
Prepares the complete local runtime environment for the ATLAS Platform:
1. Validates Python version (>=3.10) & OS architecture
2. Checks Windows Administrator / UAC privileges
3. Provisions essential directories & file permissions
4. Installs and verifies Python dependencies
5. Initializes SQLite database & seeds threat knowledge base
6. Runs pre-flight diagnostic check across all 7 defensive layers
"""

import sys
import os
import ctypes
import subprocess
import time
from pathlib import Path

# Ensure UTF-8 output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def print_banner():
    banner = """
=======================================================================
           ATLAS BEHAVIORAL CYBER-INTELLIGENCE PLATFORM
             Turnkey Automated Setup & Environment Suite
=======================================================================
"""
    print(banner)


def check_admin_privileges() -> bool:
    """Checks if current process is elevated as Windows Administrator."""
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def run_stage(title: str, func) -> bool:
    """Executes a setup stage with structured visual feedback."""
    print(f"\n[*] Stage: {title}...")
    try:
        res = func()
        if res is False:
            print(f"[-] FAILED: {title}")
            return False
        print(f"[+] SUCCESS: {title}")
        return True
    except Exception as e:
        print(f"[-] ERROR in {title}: {e}")
        return False


def stage_check_python():
    print(f"    Detected Python version: {sys.version.split()[0]} on {sys.platform}")
    if sys.version_info < (3, 10):
        print("    [!] WARNING: ATLAS requires Python 3.10 or newer for full type support.")
        return False
    return True


def stage_check_permissions():
    is_admin = check_admin_privileges()
    if is_admin:
        print("    Administrator / Elevated Privileges: ACTIVE (Firewall & ETW full access)")
    else:
        print("    Administrator Privileges: PASSIVE")
        print("    [!] Note: Real-time Windows Firewall block rules require Administrator elevation.")
        print("    [!] The dashboard will operate normally, but run start_atlas.bat as Admin for active blocking.")
    return True


def stage_create_directories():
    base_dir = Path(__file__).resolve().parent
    dirs = [
        base_dir / "data",
        base_dir / "logs",
        base_dir / "config",
        base_dir / "intelligence" / "feeds",
        base_dir / "behavior" / "canaries",
        base_dir / "backups",
        base_dir / "scratch"
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"    Provisioned directory: {d.relative_to(base_dir)}")
    return True


def stage_install_dependencies():
    req_file = Path(__file__).resolve().parent / "requirements.txt"
    if not req_file.exists():
        print("    [!] requirements.txt not found. Skipping pip install.")
        return True

    print("    Verifying and installing dependencies from requirements.txt...")
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file), "--quiet", "--no-warn-script-location"]
    res = subprocess.run(cmd)
    return res.returncode == 0


def stage_initialize_database():
    import database
    import config_manager

    print("    Initializing database schema and migrations...")
    database.init_db()

    print("    Seeding configuration schema and default settings...")
    cm = config_manager.get_config_manager()
    stats = cm.get_all()
    total_settings = sum(len(v) for v in stats.values())
    print(f"    Configuration initialized: {total_settings} settings across {len(stats)} modules.")
    return True


def stage_run_preflight_diagnostics():
    import smart_scan_engine

    print("    Executing 7-layer pre-flight diagnostic assessment...")
    scanner = smart_scan_engine.get_smart_scan_engine()
    report = scanner.execute_scan_sync(scan_type="PREFLIGHT", source_mode="LIVE")

    print(f"    Diagnostic scan finished in {report.get('duration_ms', 0)}ms:")
    for mod_key, mod in report.get("modules", {}).items():
        name = mod.get("name", mod_key)
        status = mod.get("status", "UNKNOWN")
        print(f"      - {name:<25}: [{status}]")

    print(f"    System Overall Posture: {report.get('overall_risk', 'CLEAN')} (Analyzed: {report.get('events_analyzed', 0)} baseline items)")
    return True


def main():
    print_banner()
    t0 = time.time()

    stages = [
        ("Python Runtime Verification", stage_check_python),
        ("Permission & Privilege Assessment", stage_check_permissions),
        ("Runtime Directory Provisioning", stage_create_directories),
        ("Python Dependency Resolution", stage_install_dependencies),
        ("Database & Knowledge Base Seeding", stage_initialize_database),
        ("7-Layer Pre-Flight Diagnostic Health Check", stage_run_preflight_diagnostics)
    ]

    all_passed = True
    for title, func in stages:
        if not run_stage(title, func):
            all_passed = False
            break

    elapsed = round(time.time() - t0, 2)
    print("\n=======================================================================")
    if all_passed:
        print(f"[+] ATLAS SETUP COMPLETED SUCCESSFULLY in {elapsed}s!")
        print("    You can now start ATLAS by running:")
        print("      - start_atlas.bat (or python run_frontend.py)")
        print("    Web Dashboard will be live at: http://localhost:5000")
    else:
        print(f"[-] SETUP ENCOUNTERED AN ISSUE (Elapsed: {elapsed}s).")
        print("    Please check the error logs above and retry.")
    print("=======================================================================\n")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
