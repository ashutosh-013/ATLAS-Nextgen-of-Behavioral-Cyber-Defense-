"""
Test Suite for ATLAS Autonomous Smart System Scan Engine.
Validates 7-layer empirical diagnostic scan execution, metrics, and REST API endpoints.
"""

import pytest
import time
import database
import smart_scan_engine
import web_app


@pytest.fixture(autouse=True)
def setup_teardown():
    """Initializes DB and SmartScanEngine."""
    database.init_db()
    engine = smart_scan_engine.get_smart_scan_engine()
    yield engine


def test_smart_scan_singleton_initialization():
    """Verify SmartScanEngine is instantiated as a singleton."""
    engine1 = smart_scan_engine.get_smart_scan_engine()
    engine2 = smart_scan_engine.SmartScanEngine()
    assert engine1 is engine2


def test_sync_smart_scan_execution():
    """Verify synchronous full scan executes all 7 layers and calculates valid metrics."""
    engine = smart_scan_engine.get_smart_scan_engine()
    report = engine.execute_scan_sync(scan_type="FULL", source_mode="LIVE")

    assert report is not None
    assert report["status"] == "COMPLETED"
    assert report["progress_percent"] == 100
    assert report["events_analyzed"] >= 2000
    assert report["overall_risk"] in ["CLEAN", "LOW", "MEDIUM", "HIGH"]
    assert report["duration_ms"] > 0

    # Validate all 7 modules
    expected_mods = ["health", "endpoint", "network", "behavior", "intel", "ransomware", "ai"]
    for mod_key in expected_mods:
        assert mod_key in report["modules"], f"Module {mod_key} missing from scan report"
        mod = report["modules"][mod_key]
        assert mod["status"] in ["VERIFIED", "WARNING", "THREAT_DETECTED"]
        assert len(mod["findings"]) > 0
        assert len(mod["metrics"]) > 0

    # Check Layer 1 (Health) metrics
    assert "cpu_percent" in report["modules"]["health"]["metrics"]
    assert "ram_used_mb" in report["modules"]["health"]["metrics"]

    # Check Layer 4 (Behavioral) metrics
    assert report["modules"]["behavior"]["metrics"]["embedding_dimensions"] == 128


def test_async_smart_scan_lifecycle():
    """Verify asynchronous scan start, background thread execution, and polling."""
    engine = smart_scan_engine.get_smart_scan_engine()
    scan_id = engine.start_scan(scan_type="FULL", source_mode="LIVE")
    assert scan_id.startswith("SCAN-")

    # Initial state should be running or completed
    initial_status = engine.get_scan_status(scan_id)
    assert initial_status is not None
    assert initial_status["scan_id"] == scan_id

    # Wait for completion
    max_wait = 5.0
    start_t = time.time()
    completed = False
    while time.time() - start_t < max_wait:
        st = engine.get_scan_status(scan_id)
        if st and st["status"] == "COMPLETED":
            completed = True
            break
        time.sleep(0.05)

    assert completed is True, "Async scan did not complete within timeout"
    latest = engine.get_latest_scan()
    assert latest["scan_id"] == scan_id


def test_smart_scan_rest_endpoints():
    """Verify Flask REST API endpoints for Smart System Scan."""
    client = web_app.app.test_client()

    # POST /api/smart-scan/start
    r_start = client.post("/api/smart-scan/start", json={"scan_type": "FULL", "source_mode": "LIVE"})
    assert r_start.status_code == 200
    d_start = r_start.get_json()
    assert d_start["success"] is True
    scan_id = d_start["scan_id"]
    assert scan_id is not None

    # Wait for completion
    time.sleep(0.5)

    # GET /api/smart-scan/status/<scan_id>
    r_status = client.get(f"/api/smart-scan/status/{scan_id}")
    assert r_status.status_code == 200
    d_status = r_status.get_json()
    assert d_status["success"] is True
    assert d_status["scan"]["scan_id"] == scan_id

    # GET /api/smart-scan/latest
    r_latest = client.get("/api/smart-scan/latest")
    assert r_latest.status_code == 200
    d_latest = r_latest.get_json()
    assert d_latest["success"] is True
    assert d_latest["scan"] is not None
