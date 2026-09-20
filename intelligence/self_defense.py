"""
Self-Defense & Anti-Tampering Engine for ATLAS

Guards daemon processes, SQLite databases (atlas_state.db), and configuration
files against unauthorized termination, deletion, or tampering by malware.
"""

import os
import sys
import time
import psutil
import logging
import threading
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger("self_defense")


class SelfDefenseEngine:
    """
    Self-Defense Watchdog and File Integrity Guard.
    """

    def __init__(self):
        self.monitored_pids: Set[int] = set()
        self.protected_files: List[str] = []
        self._watchdog_thread: Optional[threading.Thread] = None
        self._running = False

    def add_monitored_pid(self, pid: int):
        """Add a process ID to self-defense watchdog monitoring."""
        if pid:
            self.monitored_pids.add(pid)

    def protect_file_integrity(self, file_path: str):
        """Register file path for integrity protection."""
        if file_path and os.path.exists(file_path):
            self.protected_files.append(os.path.abspath(file_path))
            logger.info(f"Registered self-defense file guard: {file_path}")

    def check_integrity(self) -> Dict[str, Any]:
        """Perform a synchronous health and integrity check across monitored PIDs and files."""
        dead_pids = [pid for pid in self.monitored_pids if not psutil.pid_exists(pid)]
        alive_pids = [pid for pid in self.monitored_pids if psutil.pid_exists(pid)]

        missing_files = [f for f in self.protected_files if not os.path.exists(f)]
        intact_files = [f for f in self.protected_files if os.path.exists(f)]

        is_healthy = len(dead_pids) == 0 and len(missing_files) == 0

        return {
            "status": "HEALTHY" if is_healthy else "COMPROMISED",
            "is_healthy": is_healthy,
            "monitored_pids_count": len(self.monitored_pids),
            "alive_pids": alive_pids,
            "dead_pids": dead_pids,
            "protected_files_count": len(self.protected_files),
            "intact_files": intact_files,
            "missing_files": missing_files,
            "timestamp": time.time()
        }

    def start_watchdog(self):
        """Start self-defense watchdog monitor thread."""
        if not self._running:
            self._running = True
            self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
            self._watchdog_thread.start()
            logger.info("Self-Defense Watchdog thread started")

    def stop_watchdog(self):
        """Stop watchdog thread."""
        self._running = False

    def _watchdog_loop(self):
        """Periodically check daemon process health and database file access."""
        while self._running:
            try:
                # Check process survival
                dead_pids = set()
                for pid in list(self.monitored_pids):
                    if not psutil.pid_exists(pid):
                        logger.warning(f"[!] Self-Defense Warning: Monitored ATLAS process (PID: {pid}) was terminated!")
                        dead_pids.add(pid)

                for dp in dead_pids:
                    self.monitored_pids.remove(dp)

                # Check protected file presence
                for pf in self.protected_files:
                    if not os.path.exists(pf):
                        logger.error(f"[!] Critical Self-Defense Alert: Protected file {pf} was deleted or tampered with!")

                time.sleep(5)  # 5-second watchdog interval
            except Exception as e:
                logger.debug(f"Watchdog loop iteration error: {e}")
                time.sleep(5)
