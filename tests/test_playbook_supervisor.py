"""
ATLAS Phase 4 Supervisor Test Suite — Response Playbooks, Verification & Autonomous Defense.

Validates:
1. System protected process safety guardrails (PID 0, 4, current PID, explorer.exe).
2. Authorization gate enforcement (unauthorized actions must never execute).
3. Dry-run blast radius calculation without mutating host state.
4. Host state verification realism (zero-fabrication: running processes and existing files fail verification).
5. File quarantine and rollback restoration lifecycle.
6. Global defence emergency kill-switch enforcement.
7. Immutable SQLite audit trail logging and retrieval.
8. Incident evidence preservation and SHA256 integrity hashing.
9. Anti-tampering self-defense watchdog and health integrity checks.
10. Adaptive defense intelligence recommendation synthesis.
"""

import os
import sys
import time
import json
import hashlib
import tempfile
import platform
import pytest
from datetime import datetime, timezone

from playbook_engine import (
    DefenceResponseEngine,
    Playbook,
    PlaybookAction,
    PROTECTED_PROCESS_NAMES,
    PROTECTED_PIDS
)
import database
import config_manager
from intelligence.rollback import VSSRollbackManager
from intelligence.self_defense import SelfDefenseEngine
from intelligence.adaptive_defense import AdaptiveDefenseIntelligence
from data_models import (
    BADNAProfile,
    ThreatClassification,
    RiskScore
)


@pytest.fixture(autouse=True)
def init_test_env():
    """Initialize database and reset config state before each test."""
    database.init_db()
    cm = config_manager.get_config_manager()
    cm.set("defence.global_kill_switch", False)
    yield
    cm.set("defence.global_kill_switch", False)


@pytest.fixture
def defense_engine():
    return DefenceResponseEngine()


# ---------------------------------------------------------------------------
# Test 1: Protected Process Safety Guardrails
# ---------------------------------------------------------------------------
def test_protected_process_guardrails(defense_engine):
    """PID 0, PID 4, current agent PID, and system binaries must be blocked."""
    # Test PID 0
    is_prot, msg0 = defense_engine.is_protected_process(0)
    assert is_prot is True
    assert "critical" in msg0.lower() or "system" in msg0.lower()

    # Test PID 4
    is_prot_4, _ = defense_engine.is_protected_process(4)
    assert is_prot_4 is True

    # Test current process PID
    cur_pid = os.getpid()
    is_prot_self, msg_self = defense_engine.is_protected_process(cur_pid)
    assert is_prot_self is True
    assert "current" in msg_self.lower() or "atlas" in msg_self.lower()

    # Test system binary names
    for name in ["explorer.exe", "svchost.exe", "lsass.exe", "python.exe"]:
        is_prot_name, _ = defense_engine.is_protected_process(99999, process_name=name)
        assert is_prot_name is True

    # Test execution attempt on protected process
    act = PlaybookAction(
        action_id="act-prot-test",
        action_type="TERMINATE_PROCESS",
        category="REMEDIATION",
        target=str(cur_pid),
        reason="Malicious attempt to terminate self",
        authorization_required=False,
        authorized=True,
        status="AUTHORIZED"
    )
    pb = Playbook(
        playbook_id="PB-PROT-TEST",
        name="Protected Process Test",
        description="Verify blocked execution",
        source_mode="LIVE",
        actions=[act]
    )

    executed = defense_engine.execute_playbook(pb, source_mode="LIVE")
    res_act = executed.actions[0]
    assert res_act.status == "ACTION_BLOCKED"
    assert res_act.verification_status == "NOT_APPLICABLE"
    assert "ACTION BLOCKED" in res_act.actual_result


# ---------------------------------------------------------------------------
# Test 2: Authorization Gate Enforcement
# ---------------------------------------------------------------------------
def test_unauthorized_action_enforcement(defense_engine):
    """Actions requiring authorization must NOT execute if unauthorized."""
    act = PlaybookAction(
        action_id="act-unauth-test",
        action_type="TERMINATE_PROCESS",
        category="REMEDIATION",
        target="99998",
        reason="Termination requiring approval",
        authorization_required=True,
        authorized=False,
        status="AWAITING_AUTHORIZATION"
    )
    pb = Playbook(
        playbook_id="PB-UNAUTH-TEST",
        name="Unauthorized Playbook Test",
        description="Verify unauthorized action halted",
        source_mode="LIVE",
        actions=[act]
    )

    executed = defense_engine.execute_playbook(pb, source_mode="LIVE")
    res_act = executed.actions[0]
    assert res_act.status == "AWAITING_AUTHORIZATION"
    assert res_act.verification_status == "NOT_APPLICABLE"
    assert "requires explicit authorization" in res_act.actual_result
    assert executed.status == "AWAITING_AUTHORIZATION"


# ---------------------------------------------------------------------------
# Test 3: Dry-Run Blast Radius Simulation
# ---------------------------------------------------------------------------
def test_dry_run_blast_radius_simulation(defense_engine):
    """Dry run preview must compute blast radius and never modify host state."""
    scratch_dir = os.path.join(os.getcwd(), "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    test_file = os.path.join(scratch_dir, "dry_run_sample.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("dry run test data")

    act1 = PlaybookAction(
        action_id="act-dry-1",
        action_type="QUARANTINE_FILE",
        category="CONTAINMENT",
        target=test_file,
        reason="Quarantine dry run test"
    )
    act2 = PlaybookAction(
        action_id="act-dry-2",
        action_type="BLOCK_IP",
        category="CONTAINMENT",
        target="203.0.113.50",
        reason="Block C2 IP dry run test"
    )
    pb = Playbook(
        playbook_id="PB-DRY-TEST",
        name="Dry Run Test Playbook",
        description="Verify blast radius preview",
        source_mode="LIVE",
        affected_asset="WK-902",
        actions=[act1, act2]
    )

    dry_res = defense_engine.dry_run_playbook(pb)
    assert dry_res["status"] == "DRY_RUN_COMPLETED"
    assert dry_res["actual_execution"] is False
    assert test_file in dry_res["blast_radius"]["affected_files"]
    assert "203.0.113.50" in dry_res["blast_radius"]["affected_ips"]
    assert "WK-902" in dry_res["blast_radius"]["affected_hosts"]

    # Assert test file still exists on disk
    assert os.path.exists(test_file)
    os.remove(test_file)


# ---------------------------------------------------------------------------
# Test 4: Host State Verification Realism (Zero Fabrication)
# ---------------------------------------------------------------------------
def test_host_verification_realism(defense_engine):
    """Host verification checks actual OS state; false claims must fail."""
    # Check 1: Currently running process should NOT be verified as terminated
    cur_pid = os.getpid()
    verified_proc, msg_proc = defense_engine.verify_action_execution("TERMINATE_PROCESS", str(cur_pid))
    assert verified_proc is False
    assert "Verification Failed" in msg_proc

    # Check 2: Existing file should NOT be verified as quarantined
    scratch_dir = os.path.join(os.getcwd(), "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    existing_file = os.path.join(scratch_dir, "existing_file.txt")
    with open(existing_file, "w", encoding="utf-8") as f:
        f.write("still exists")

    verified_file, msg_file = defense_engine.verify_action_execution("QUARANTINE_FILE", existing_file)
    assert verified_file is False
    assert "Verification Failed" in msg_file

    # Clean up
    os.remove(existing_file)


# ---------------------------------------------------------------------------
# Test 5: Live File Quarantine and Rollback Lifecycle
# ---------------------------------------------------------------------------
def test_live_quarantine_and_rollback(defense_engine):
    """File quarantine moves file to vault, rollback restores it to original path."""
    scratch_dir = os.path.join(os.getcwd(), "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    target_file = os.path.join(scratch_dir, f"quar_target_{int(time.time())}.exe")
    payload_content = "malicious_payload_binary_content"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(payload_content)

    assert os.path.exists(target_file)

    act = PlaybookAction(
        action_id="act-live-quar",
        action_type="QUARANTINE_FILE",
        category="CONTAINMENT",
        target=target_file,
        reason="Quarantine live test",
        authorization_required=True,
        authorized=True,
        status="AUTHORIZED"
    )
    pb = Playbook(
        playbook_id="PB-LIVE-QUAR",
        name="Quarantine Lifecycle Test",
        description="Verify quarantine and rollback",
        source_mode="LIVE",
        actions=[act]
    )

    # 1. Execute quarantine
    executed = defense_engine.execute_playbook(pb, source_mode="LIVE")
    res_act = executed.actions[0]
    assert res_act.status == "VERIFIED"
    assert res_act.verification_status == "VERIFIED"
    assert not os.path.exists(target_file)
    assert res_act.rollback_data is not None

    # 2. Execute rollback
    rollback_res = defense_engine.rollback_action(executed, "act-live-quar", actor="SupervisorTest")
    assert rollback_res["status"] == "SUCCESS"
    assert res_act.status == "ROLLED_BACK"
    assert os.path.exists(target_file)

    # Verify content restored intact
    with open(target_file, "r", encoding="utf-8") as f:
        assert f.read() == payload_content

    os.remove(target_file)


# ---------------------------------------------------------------------------
# Test 6: Global Defence Emergency Kill-Switch
# ---------------------------------------------------------------------------
def test_emergency_kill_switch_enforcement(defense_engine):
    """When kill switch is engaged, all live destructive executions are blocked."""
    cm = config_manager.get_config_manager()
    cm.set("defence.global_kill_switch", True)

    act = PlaybookAction(
        action_id="act-killswitch-test",
        action_type="TERMINATE_PROCESS",
        category="REMEDIATION",
        target="12345",
        reason="Attempt termination during emergency freeze",
        authorization_required=True,
        authorized=True,
        status="AUTHORIZED"
    )
    pb = Playbook(
        playbook_id="PB-KILLSWITCH-TEST",
        name="Emergency Kill Switch Test",
        description="Verify execution blocked by kill switch",
        source_mode="LIVE",
        actions=[act]
    )

    executed = defense_engine.execute_playbook(pb, source_mode="LIVE")
    res_act = executed.actions[0]

    assert res_act.status == "ACTION_BLOCKED"
    assert res_act.verification_status == "NOT_APPLICABLE"
    assert "Kill Switch is ENGAGED" in res_act.actual_result

    audit_types = [a.get("action") for a in res_act.audit_trail]
    assert "KILL_SWITCH_ENFORCED" in audit_types


# ---------------------------------------------------------------------------
# Test 7: SQLite Audit Trail Logging & Retrieval
# ---------------------------------------------------------------------------
def test_sqlite_audit_trail_logging():
    """Playbook executions and rollbacks must persist to SQLite audit store."""
    audit_id = f"aud-supervisor-{int(time.time())}"
    audit_entry = {
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": "SupervisorAgent",
        "action": "QUARANTINE_FILE",
        "target": "C:\\temp\\malware.exe",
        "reason": "Test audit record creation",
        "evidence_event_ids": ["ev-sup-01", "ev-sup-02"],
        "risk": 0.85,
        "confidence": 0.90,
        "policy": "APPROVAL_REQUIRED",
        "authorization": "AUTHORIZED",
        "execution_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "result": "File successfully moved to quarantine vault.",
        "error": None
    }

    database.save_playbook_audit(audit_entry)
    logs = database.get_playbook_audit_logs(limit=50)

    found = [l for l in logs if l.get("audit_id") == audit_id]
    assert len(found) == 1
    assert found[0]["actor"] == "SupervisorAgent"
    assert found[0]["execution_status"] == "VERIFIED"
    assert found[0]["action"] == "QUARANTINE_FILE"


# ---------------------------------------------------------------------------
# Test 8: Incident Evidence Preservation & Full Hashing
# ---------------------------------------------------------------------------
def test_incident_evidence_preservation():
    """VSSRollbackManager must capture process context and SHA256 hashes of affected files."""
    scratch_dir = os.path.join(os.getcwd(), "scratch", "evidence_test")
    os.makedirs(scratch_dir, exist_ok=True)
    sample_file = os.path.join(scratch_dir, "ransom_sample.dat")
    content = b"CRITICAL_USER_DATA_CONTENT_PRESERVATION"
    with open(sample_file, "wb") as f:
        f.write(content)

    expected_hash = hashlib.sha256(content).hexdigest()

    mgr = VSSRollbackManager(evidence_dir=scratch_dir)
    evidence = mgr.preserve_incident_evidence(
        target_process={"pid": 4040, "name": "ransomware.exe", "command": "ransomware.exe -encrypt"},
        affected_files=[sample_file],
        additional_metadata={"investigator": "SupervisorTest"}
    )

    assert os.path.exists(evidence.evidence_file_path)
    assert evidence.evidence_hashes[sample_file] == expected_hash

    # Verify JSON content on disk
    with open(evidence.evidence_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["incident_id"] == evidence.incident_id
        assert data["target_process"]["name"] == "ransomware.exe"
        assert data["evidence_hashes"][sample_file] == expected_hash

    # Clean up
    if os.path.exists(sample_file):
        os.remove(sample_file)
    if os.path.exists(evidence.evidence_file_path):
        os.remove(evidence.evidence_file_path)


# ---------------------------------------------------------------------------
# Test 9: Self-Defense Anti-Tampering Engine
# ---------------------------------------------------------------------------
def test_self_defense_engine():
    """SelfDefenseEngine monitors daemon processes and detects missing protected files."""
    engine = SelfDefenseEngine()
    cur_pid = os.getpid()
    engine.add_monitored_pid(cur_pid)

    scratch_dir = os.path.join(os.getcwd(), "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    guard_file = os.path.join(scratch_dir, "atlas_guard_file.db")
    with open(guard_file, "w") as f:
        f.write("db_state")

    engine.protect_file_integrity(guard_file)

    # 1. Check healthy state
    health_initial = engine.check_integrity()
    assert health_initial["status"] == "HEALTHY"
    assert health_initial["is_healthy"] is True
    assert cur_pid in health_initial["alive_pids"]
    assert len(health_initial["dead_pids"]) == 0
    assert os.path.abspath(guard_file) in health_initial["intact_files"]

    # 2. Simulate compromised state (deleted protected file)
    os.remove(guard_file)
    health_compromised = engine.check_integrity()
    assert health_compromised["status"] == "COMPROMISED"
    assert health_compromised["is_healthy"] is False
    assert os.path.abspath(guard_file) in health_compromised["missing_files"]


# ---------------------------------------------------------------------------
# Test 10: Adaptive Defense Intelligence Recommendation Synthesis
# ---------------------------------------------------------------------------
def test_adaptive_defense_intelligence():
    """AdaptiveDefenseIntelligence generates threat-specific recommendations from BADNA profile."""
    adaptive_engine = AdaptiveDefenseIntelligence()

    # Construct high-risk Ransomware profile
    profile = BADNAProfile(
        profile_id="prof-ransomware-01",
        threat_classification=ThreatClassification(
            profile_id="prof-ransomware-01",
            threat_class="Ransomware",
            confidence=0.92,
            probability_distribution={"Ransomware": 0.92, "Malware": 0.08},
            uncertainty_flag=False,
            classification_method="ensemble_supervised"
        ),
        risk_score=RiskScore(
            profile_id="prof-ransomware-01",
            score=0.95,
            risk_level="Critical",
            contributing_factors={"lateral_movement": 0.4, "encryption": 0.55},
            rationale="High volume mass file modifications and ransom note dropped."
        )
    )

    suite = adaptive_engine.recommend_actions(profile)
    assert suite.threat_class == "Ransomware"
    assert suite.risk_level == "Critical"
    assert len(suite.recommendations) > 0
    assert any("isolation" in r.title.lower() or r.category == "Isolation" for r in suite.recommendations)
    assert len(suite.immediate_actions) > 0
    assert any("isolate" in act.lower() for act in suite.immediate_actions)

    # Summary metrics
    summary = adaptive_engine.get_recommendation_summary(suite)
    assert summary["profile_id"] == "prof-ransomware-01"
    assert summary["total_recommendations"] >= 1
    assert summary["high_priority_recommendations"] >= 1
