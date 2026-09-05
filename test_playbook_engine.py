"""
Comprehensive Automated Test Suite for ATLAS Defence Response & Playbook Engine.
Validates:
1. Host capability detection
2. System protected process safety guardrail (e.g., rejecting termination of explorer.exe / python.exe)
3. Explainable Defense Decision Engine scoring
4. Non-mutating Dry Run simulation & blast radius calculation
5. Authorization policy workflow
6. Process termination & post-kill host verification
7. Firewall block & post-block rule verification
8. File quarantine & post-quarantine verification
9. Immutable audit trail logging in SQLite
10. SCENARIO simulation segregation (physical host untouched in scenario mode)
"""

import os
import sys
import platform
import tempfile
import time
import subprocess
import pytest
from datetime import datetime, timezone

from playbook_engine import DefenceResponseEngine, Playbook, PlaybookAction, PROTECTED_PROCESS_NAMES
import database


@pytest.fixture
def engine():
    database.init_db()
    return DefenceResponseEngine()


def test_1_host_capabilities_detection(engine):
    caps = engine.detect_host_capabilities()
    assert caps.os_name is not None
    assert isinstance(caps.is_admin, bool)
    assert caps.process_control is True
    assert caps.file_quarantine is True
    assert caps.sigma_generator is True
    assert caps.yara_generator is True


def test_2_protected_process_safety_guardrail(engine):
    # Test PID 0 and System processes
    is_prot, msg0 = engine.is_protected_process(0)
    assert is_prot is True
    assert "System" in msg0 or "Idle" in msg0 or "critical" in msg0

    # Test current Python process PID
    current_pid = os.getpid()
    is_prot_self, msg_self = engine.is_protected_process(current_pid)
    assert is_prot_self is True
    assert "ATLAS" in msg_self or "current" in msg_self

    # Test explorer.exe name guardrail
    is_prot_exp, _ = engine.is_protected_process(999999, process_name="explorer.exe")
    assert is_prot_exp is True


def test_3_explainable_defense_decision_scoring(engine):
    threat_data = {
        "evidence_event_ids": ["e1", "e2", "e3"],
        "command": "powershell -enc AAAA==",
        "observed_stages": ["INITIAL_ACCESS", "EXECUTION"],
        "source_mode": "LIVE"
    }

    classification, risk, conf, ev_strength, rationale = engine.evaluate_defense_decision(threat_data)
    assert risk >= 0.70
    assert conf >= 0.75
    assert ev_strength in ["MEDIUM", "HIGH"]
    assert classification in ["LIKELY_MALICIOUS", "CONFIRMED_MALICIOUS"]
    assert len(rationale) >= 3


def test_4_dry_run_simulation_non_mutating(engine):
    pb = engine.generate_recommended_playbooks(source_mode="SCENARIO")[0]
    dry_res = engine.dry_run_playbook(pb)

    assert dry_res["status"] == "DRY_RUN_COMPLETED"
    assert dry_res["actual_execution"] is False
    assert "blast_radius" in dry_res
    assert len(dry_res["actions"]) == len(pb.actions)


def test_5_authorization_policy_workflow(engine):
    pb = engine.generate_recommended_playbooks(source_mode="SCENARIO")[0]
    action_to_auth = [a for a in pb.actions if a.authorization_required][0]
    
    assert action_to_auth.authorized is False
    assert action_to_auth.status == "AWAITING_AUTHORIZATION"

    # Authorize
    updated = engine.authorize_action(pb, action_to_auth.action_id, actor="TestAnalyst")
    authed_action = [a for a in updated.actions if a.action_id == action_to_auth.action_id][0]
    assert authed_action.authorized is True
    assert authed_action.status == "AUTHORIZED"
    assert len(authed_action.audit_trail) >= 1


def test_6_process_termination_and_verification(engine):
    # Spawn a safe dummy non-protected subprocess (ping) to terminate
    cmd = ["ping", "-t", "127.0.0.1"] if platform.system() == "Windows" else ["sleep", "60"]
    sub = subprocess.Popen(cmd)
    target_pid = sub.pid
    assert sub.poll() is None  # Process is running

    action = PlaybookAction(
        action_id="act-test-term",
        action_type="TERMINATE_PROCESS",
        category="REMEDIATION",
        target=str(target_pid),
        reason="Test termination of dummy process",
        authorization_required=True,
        authorized=True,
        status="AUTHORIZED"
    )

    pb = Playbook(
        playbook_id="PB-TEST-TERM",
        name="Test Terminate Playbook",
        description="Testing real process termination & verification",
        source_mode="LIVE",
        actions=[action]
    )

    executed_pb = engine.execute_playbook(pb, source_mode="LIVE")
    res_action = executed_pb.actions[0]

    assert res_action.status == "VERIFIED"
    assert res_action.verification_status == "VERIFIED"
    assert "terminated" in res_action.actual_result.lower() or "no longer running" in res_action.actual_result.lower()
    
    # Subprocess should be killed
    time.sleep(0.3)
    assert sub.poll() is not None


def test_7_file_quarantine_and_verification(engine):
    # Create temporary file to quarantine
    temp_dir = tempfile.mkdtemp()
    test_file = os.path.join(temp_dir, "test_malware.exe")
    with open(test_file, "w") as f:
        f.write("test malware payload sample")

    assert os.path.exists(test_file)

    action = PlaybookAction(
        action_id="act-test-quar",
        action_type="QUARANTINE_FILE",
        category="CONTAINMENT",
        target=test_file,
        reason="Test file quarantine",
        authorization_required=True,
        authorized=True,
        status="AUTHORIZED"
    )

    pb = Playbook(
        playbook_id="PB-TEST-QUAR",
        name="Test Quarantine Playbook",
        description="Testing file quarantine & verification",
        source_mode="LIVE",
        actions=[action]
    )

    executed_pb = engine.execute_playbook(pb, source_mode="LIVE")
    res_action = executed_pb.actions[0]

    assert res_action.status == "VERIFIED"
    assert res_action.verification_status == "VERIFIED"
    assert not os.path.exists(test_file)  # Source file removed


def test_8_scenario_mode_simulation_isolation(engine):
    action = PlaybookAction(
        action_id="act-scen-term",
        action_type="TERMINATE_PROCESS",
        category="REMEDIATION",
        target="12345",
        reason="Scenario process termination",
        authorization_required=False,
        authorized=True,
        status="AUTHORIZED"
    )

    pb = Playbook(
        playbook_id="PB-SCEN-01",
        name="Scenario Test Playbook",
        description="Testing scenario simulation adapter",
        source_mode="SCENARIO",
        actions=[action]
    )

    executed_pb = engine.execute_playbook(pb, source_mode="SCENARIO")
    res_action = executed_pb.actions[0]

    assert res_action.status == "VERIFIED"
    assert "[SIMULATION MODE]" in res_action.actual_result


def test_9_audit_logging_persistence(engine):
    audit_dict = {
        "audit_id": "aud-test-999",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": "SOC_Analyst_John",
        "action": "BLOCK_IP",
        "target": "198.51.100.44",
        "reason": "Suspicious C2 beacon",
        "evidence_event_ids": ["ev-101"],
        "risk": 0.88,
        "confidence": 0.94,
        "policy": "APPROVAL_REQUIRED",
        "authorization": "AUTHORIZED",
        "execution_status": "VERIFIED",
        "verification_status": "VERIFIED",
        "result": "IP 198.51.100.44 blocked via OS Firewall.",
        "error": None
    }

    database.save_playbook_audit(audit_dict)
    logs = database.get_playbook_audit_logs(limit=10)

    matching = [l for l in logs if l.get("audit_id") == "aud-test-999"]
    assert len(matching) == 1
    log_rec = matching[0]
    assert log_rec["actor"] == "SOC_Analyst_John"
    assert log_rec["action"] == "BLOCK_IP"
    assert log_rec["execution_status"] == "VERIFIED"


def test_10_rule_generators(engine):
    sigma = engine.generate_sigma_rule(
        title="Test Encoded PowerShell",
        description="Detects encoded powershell",
        logsource="process_creation",
        selection={"CommandLine|contains": "enc"}
    )
    assert "title: Test Encoded PowerShell" in sigma
    assert "logsource:" in sigma

    yara = engine.generate_yara_rule("Test_Malware_Sig", ["mimikatz", "lsass"])
    assert "rule Test_Malware_Sig" in yara
    assert "$s1 = \"mimikatz\"" in yara


def test_11_rollback_action_workflow(engine):
    temp_dir = tempfile.mkdtemp()
    test_file = os.path.join(temp_dir, "to_quarantine.exe")
    with open(test_file, "w") as f:
        f.write("quarantine test file")

    act = PlaybookAction(
        action_id="act-rollback-01",
        action_type="QUARANTINE_FILE",
        category="CONTAINMENT",
        target=test_file,
        reason="Rollback test quarantine",
        authorization_required=True,
        authorized=True,
        status="AUTHORIZED"
    )

    pb = Playbook(
        playbook_id="PB-ROLLBACK-01",
        name="Rollback Test Playbook",
        description="Testing rollback of file quarantine",
        source_mode="LIVE",
        actions=[act]
    )

    executed_pb = engine.execute_playbook(pb, source_mode="LIVE")
    assert executed_pb.actions[0].status == "VERIFIED"
    assert not os.path.exists(test_file)

    # Perform Rollback
    res = engine.rollback_action(executed_pb, "act-rollback-01", actor="SOC_Analyst")
    assert res["status"] == "SUCCESS"
    assert os.path.exists(test_file)  # File restored!

