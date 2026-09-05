"""
Comprehensive Test Suite for ATLAS Central Configuration & Control Plane System.
Validates ConfigManager, schema rules, database persistence, audit logging,
runtime notification dispatch, and all REST API endpoints.
"""

import pytest
import json
import os
import database
import config_manager
import web_app
from playbook_engine import DefenceResponseEngine, Playbook, PlaybookAction


@pytest.fixture(autouse=True)
def setup_teardown():
    """Initializes DB and ConfigManager for clean test state."""
    database.init_db()
    cm = config_manager.get_config_manager()
    yield cm


def test_schema_and_defaults_seeded():
    """Verify all 10 modules have active schema keys seeded in the database."""
    cm = config_manager.get_config_manager()
    all_cfg = cm.get_all()
    
    expected_modules = ["general", "telemetry", "detection", "campaigns", "ai", "defence", "data", "notifications", "rbac", "integrations"]
    for mod in expected_modules:
        assert mod in all_cfg, f"Module {mod} missing from config schema"
        assert len(all_cfg[mod]) > 0, f"Module {mod} has no configured settings"

    # Verify default values
    assert all_cfg["general"]["general.instance_name"]["default"] == "ATLAS-CORE-PROD-01"
    assert all_cfg["telemetry"]["telemetry.collection_interval_ms"]["default"] == 1000
    assert all_cfg["detection"]["detection.min_confidence_threshold"]["default"] == 0.60
    assert all_cfg["defence"]["defence.global_kill_switch"]["default"] is False


def test_setting_validation_rules():
    """Verify input validation, bounds checks, and type coercion."""
    cm = config_manager.get_config_manager()

    # Valid setting update
    res = cm.set("telemetry.collection_interval_ms", 2500, actor="SecAdmin", reason="Performance tuning")
    assert res["value"] == 2500
    assert cm.get("telemetry.collection_interval_ms") == 2500

    # Upper bound violation
    with pytest.raises(ValueError, match="must be <="):
        cm.set("telemetry.collection_interval_ms", 999999)

    # Lower bound violation
    with pytest.raises(ValueError, match="must be >="):
        cm.set("telemetry.collection_interval_ms", 10)

    # Enum constraint violation
    with pytest.raises(ValueError, match="must be one of"):
        cm.set("general.environment", "INVALID_ENV")


def test_database_persistence_and_audit_log():
    """Verify database storage, versioning, and immutable audit logs."""
    cm = config_manager.get_config_manager()
    
    cm.set("general.instance_name", "ATLAS-SOC-TEST-NODE", actor="Lead_Auditor", reason="Renaming cluster", ip_address="192.168.1.50")
    assert database.get_setting("general.instance_name") == "ATLAS-SOC-TEST-NODE"

    # Audit log verification
    logs = database.get_settings_audit_log(limit=10)
    assert len(logs) > 0
    latest_log = logs[0]
    assert latest_log["setting_key"] == "general.instance_name"
    assert latest_log["new_value"] == "ATLAS-SOC-TEST-NODE"
    assert latest_log["actor"] == "Lead_Auditor"
    assert latest_log["reason"] == "Renaming cluster"


def test_defence_emergency_kill_switch():
    """Verify Emergency Kill Switch engages and blocks physical defensive actions."""
    cm = config_manager.get_config_manager()
    engine = DefenceResponseEngine()

    # 1. Engage Kill Switch
    ks_res = cm.toggle_defence_kill_switch(True, actor="SecAdmin", reason="Simulated emergency containment halt")
    assert ks_res["kill_switch_active"] is True
    assert cm.get("defence.global_kill_switch") is True

    # 2. Attempt to execute destructive action in live mode
    action = PlaybookAction(
        action_id="ACT-TEST-01",
        action_type="TERMINATE_PROCESS",
        target="999999",
        category="CONTAINMENT",
        reason="Test kill switch",
        authorization_required=False,
        authorized=True
    )
    pb = Playbook(
        playbook_id="PB-TEST-KS",
        name="Kill Switch Verification Playbook",
        description="Verification of emergency kill switch inhibition",
        threat_classification="CONFIRMED_MALICIOUS",
        risk_score=0.95,
        confidence=0.92,
        actions=[action],
        source_mode="LIVE"
    )

    executed_pb = engine.execute_playbook(pb, source_mode="LIVE")
    # Action MUST be blocked by KillSwitchGuard
    assert executed_pb.actions[0].status == "ACTION_BLOCKED"
    assert "Kill Switch is ENGAGED" in executed_pb.actions[0].actual_result

    # 3. Disengage Kill Switch
    cm.toggle_defence_kill_switch(False, actor="SecAdmin", reason="Emergency resolved")
    assert cm.get("defence.global_kill_switch") is False


def test_rest_api_endpoints():
    """Verify Flask REST API endpoints for Settings control plane."""
    client = web_app.app.test_client()

    # GET /api/settings
    r_get = client.get("/api/settings")
    assert r_get.status_code == 200
    d_get = r_get.get_json()
    assert d_get["success"] is True
    assert "telemetry" in d_get["settings"]

    # POST /api/settings
    r_post = client.post("/api/settings", json={
        "settings": {
            "general.instance_name": "ATLAS-REST-API-NODE",
            "telemetry.collection_interval_ms": 1200
        },
        "actor": "API_Client",
        "reason": "REST API validation test"
    })
    assert r_post.status_code == 200
    d_post = r_post.get_json()
    assert d_post["success"] is True
    assert d_post["updated_count"] == 2

    # GET /api/settings/system-health
    r_health = client.get("/api/settings/system-health")
    assert r_health.status_code == 200
    d_health = r_health.get_json()
    assert d_health["success"] is True
    assert "cpu" in d_health["health"]
    assert "memory" in d_health["health"]
    assert "database" in d_health["health"]

    # POST /api/settings/export
    r_export = client.post("/api/settings/export")
    assert r_export.status_code == 200
    d_export = r_export.get_json()
    assert d_export["success"] is True
    assert "configuration" in d_export["bundle"]

    # GET /api/settings/audit-log
    r_audit = client.get("/api/settings/audit-log?limit=5")
    assert r_audit.status_code == 200
    d_audit = r_audit.get_json()
    assert d_audit["success"] is True
    assert d_audit["count"] > 0
