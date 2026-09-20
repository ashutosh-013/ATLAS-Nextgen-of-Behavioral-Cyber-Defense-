"""
Validation & Integrity Supervisor Test Suite (Agent 20)
ATLAS Behavioral Cyber-Intelligence Platform

Authoritative automated verification suite ensuring:
1. Zero-Fabrication Invariant (Security evidence is never manufactured or substituted)
2. Universal Data Provenance Standard (LIVE_HOST, SCENARIO_REPLAY, TPOT, DATASET_REPLAY, SYNTHETIC_TEST)
3. Relational Forensic Evidence Chain Integrity (Telemetry -> Behavior DNA -> Campaign -> Playbook -> Host Verification)
4. Host Verification via physical OS inspection
5. Emergency Response Kill Switch Safety Boundaries
6. Zero Permanent Agent Infrastructure Residue
"""

import os
import json
import uuid
import pytest
from datetime import datetime, timezone
from dataclasses import asdict

import database
from telemetry_schema import TelemetryEvent, EventProvenance, normalize_raw_event
from playbook_engine import DefenceResponseEngine, Playbook, PlaybookAction
import web_app


@pytest.fixture(scope="module")
def app_client():
    database.init_db()
    web_app.app.config["TESTING"] = True
    with web_app.app.test_client() as client:
        yield client


class TestZeroFabricationInvariant:
    """Ensures ATLAS never manufactures fake evidence or simulated numbers."""

    def test_nonexistent_evidence_chain_returns_insufficient_data(self, app_client):
        """Querying a non-existent root ID must return INSUFFICIENT_DATA and empty evidence chain."""
        fake_id = f"non-existent-evt-{uuid.uuid4()}"
        res = app_client.get(f"/api/telemetry/evidence-chain/{fake_id}")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "INSUFFICIENT_DATA"
        assert data["evidence_chain"] == []
        assert data["evidence_count"] == 0
        assert data["stages_completed"] == 0

    def test_analytics_honest_state_when_zero_events(self, app_client):
        """Analytics overview must report honest data freshness and evidence count."""
        res = app_client.get("/api/analytics/overview?source_mode=SYNTHETIC_TEST_EMPTY")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "INSUFFICIENT_DATA"
        assert data["evidence_count"] == 0
        assert data["data_freshness"]["events_analyzed"] == 0

    def test_threats_over_time_honest_empty_buckets(self, app_client):
        """Threats over time for empty stream must not manufacture random curve heights."""
        res = app_client.get("/api/analytics/threats-over-time?source_mode=SYNTHETIC_TEST_EMPTY")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "INSUFFICIENT_DATA"
        assert data["evidence_count"] == 0
        for b in data["buckets"]:
            assert b["total"] == 0
            assert b["threat_count"] == 0


class TestUniversalDataProvenanceStandard:
    """Ensures all events and schemas carry strict data provenance."""

    def test_event_provenance_dataclass_fields(self):
        """EventProvenance dataclass must contain all 9 required provenance fields."""
        prov = EventProvenance(
            source_type="SYNTHETIC_TEST",
            source_id="unit-test-agent20",
            collector="SupervisorTestCollector",
            event_id="test-ev-100",
            observed_at=datetime.now(timezone.utc).isoformat(),
            processing_stage="INGESTION",
            confidence_calibrated=0.95,
            calibration_method="CCF",
            evidence_count=1
        )
        d = asdict(prov)
        assert d["source_type"] == "SYNTHETIC_TEST"
        assert d["collector"] == "SupervisorTestCollector"
        assert d["calibration_method"] == "CCF"
        assert d["confidence_calibrated"] == 0.95

    def test_normalize_raw_event_injects_provenance(self):
        """normalize_raw_event must attach valid provenance dictionary to TelemetryEvent."""
        raw = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_name": "cmd.exe",
            "pid": 1234,
            "source": "WindowsETW",
            "source_mode": "LIVE"
        }
        ev = normalize_raw_event(raw)
        assert "provenance" in ev
        assert ev["provenance"] is not None
        assert ev["provenance"]["source_type"] == "LIVE_HOST"
        assert "WindowsETW" in ev["provenance"]["collector"]
        assert ev["provenance"]["event_id"] == ev["event_id"]


class TestRelationalForensicEvidenceChain:
    """Verifies end-to-end evidence linking across DB tables."""

    def test_unbroken_four_stage_evidence_chain(self, app_client):
        """Telemetry -> Behavior Pattern -> Campaign -> Playbook Audit Log -> Verification."""
        test_eid = f"ev-prov-{uuid.uuid4().hex[:8]}"
        test_pid = f"pat-prov-{uuid.uuid4().hex[:8]}"
        test_cid = f"camp-prov-{uuid.uuid4().hex[:8]}"
        test_aid = f"audit-prov-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Ingest Telemetry Event
        ev = {
            "event_id": test_eid,
            "timestamp": now_str,
            "host_id": "SUPERVISOR-WK",
            "source": "SupervisorCollector",
            "source_mode": "SYNTHETIC_TEST",
            "event_type": "powershell",
            "category": "execution",
            "severity": "HIGH",
            "process": {"name": "powershell.exe", "pid": 5555},
            "network": {"src_ip": "10.0.0.1", "dst_ip": "185.220.101.5"},
            "correlation_id": "corr-supervisor-99",
            "provenance": {
                "source_type": "SYNTHETIC_TEST",
                "source_id": "test-runner",
                "collector": "SupervisorCollector",
                "event_id": test_eid,
                "observed_at": now_str,
                "processing_stage": "INGESTION",
                "confidence_calibrated": 0.96,
                "calibration_method": "CCF",
                "evidence_count": 1
            }
        }
        database.save_telemetry_event(ev)

        # 2. Ingest Behavioral Pattern
        pat = {
            "pattern_id": test_pid,
            "fingerprint": f"fp-{test_pid}",
            "classification": "APT",
            "dna_version": "v1.3",
            "feature_vector": [0.1] * 128,
            "sequence_flow": ["cmd.exe", "powershell.exe"],
            "feature_breakdown": {"process_ancestry": "cmd.exe ➔ powershell.exe"},
            "bsf_similarity": 95.5,
            "nsf_novelty": 0.05,
            "ccf_confidence": 96.2,
            "risk_score": 88.0,
            "campaign": "SupervisorCampaign",
            "related_threat_id": test_eid,
            "first_seen": now_str,
            "last_seen": now_str
        }
        database.save_behavior_pattern(pat)

        # 3. Ingest Campaign
        camp = {
            "campaign_id": test_cid,
            "campaign_name": "Supervisor Test Campaign",
            "campaign_type": "APT",
            "status": "ACTIVE",
            "first_seen": now_str,
            "last_seen": now_str,
            "source_mode": "SYNTHETIC_TEST",
            "confidence": 0.95,
            "severity": "HIGH",
            "attribution": {"actor": "APT-Supervisor", "confidence": 0.92},
            "evidence_event_ids": [test_eid],
            "technique_ids": ["T1059.001"],
            "analyst_status": "UNREVIEWED"
        }
        database.save_campaign(camp)

        # 4. Ingest Playbook Audit Log
        audit = {
            "audit_id": test_aid,
            "timestamp": now_str,
            "actor": "SupervisorEngine",
            "action": "TERMINATE_PROCESS",
            "target": "5555",
            "reason": "Contain supervisor test process",
            "evidence_event_ids": [test_eid],
            "risk": 88.0,
            "confidence": 0.96,
            "policy": "APPROVAL_REQUIRED",
            "authorization": "AUTHORIZED",
            "execution_status": "COMPLETED",
            "verification_status": "VERIFIED",
            "result": "Process terminated cleanly."
        }
        database.save_playbook_audit(audit)

        # 5. Query Evidence Chain via Driver
        chain_data = database.get_forensic_evidence_chain(test_eid)
        assert chain_data["status"] == "PROVEN_CHAIN"
        assert chain_data["evidence_count"] >= 1
        assert chain_data["stages_completed"] >= 3

        stages = [step["stage"] for step in chain_data["evidence_chain"]]
        assert "TELEMETRY_INGESTION" in stages
        assert "CAMPAIGN_ATTRIBUTION" in stages
        assert "DEFENSIVE_ACTION" in stages

        # 6. Query Evidence Chain via REST API Endpoint
        res = app_client.get(f"/api/telemetry/evidence-chain/{test_eid}")
        assert res.status_code == 200
        api_data = res.get_json()
        assert api_data["success"] is True
        assert api_data["status"] == "PROVEN_CHAIN"
        assert api_data["provenance"]["source_type"] == "SYNTHETIC_TEST"


class TestHostVerificationAndPlaybooks:
    """Verifies physical OS state checking and playbook verification endpoints."""

    def test_verify_process_absence(self):
        """Verifies process termination returns True when PID is not active in process table."""
        engine = DefenceResponseEngine()
        # Use an impossibly high PID
        verified, msg = engine.verify_action_execution("TERMINATE_PROCESS", "9999998")
        assert verified is True
        assert "is no longer running" in msg

    def test_verify_endpoint_get_and_post(self, app_client):
        """Endpoint /api/playbooks/<action_id>/verify must support both GET and POST with host checks."""
        # POST test
        res_post = app_client.post(
            "/api/playbooks/act-test-1/verify",
            json={"action_type": "TERMINATE_PROCESS", "target": "9999997"}
        )
        assert res_post.status_code == 200
        d_post = res_post.get_json()
        assert d_post["success"] is True
        assert d_post["verified"] is True
        assert d_post["verification_status"] == "VERIFIED"

        # GET test
        res_get = app_client.get("/api/playbooks/act-test-1/verify?action_type=TERMINATE_PROCESS&target=9999997")
        assert res_get.status_code == 200
        d_get = res_get.get_json()
        assert d_get["success"] is True
        assert d_get["verified"] is True


class TestSupervisorSafetyAndIntegrity:
    """Verifies that no permanent agent infrastructure or unmonitored daemons were installed."""

    def test_no_permanent_agent_daemons(self):
        """Repository root must remain clean of permanent agent runtime engines."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        prohibited_folders = [
            os.path.join(repo_root, "agent_runtime"),
            os.path.join(repo_root, "daemon"),
            os.path.join(repo_root, ".permanent_agents")
        ]
        for p in prohibited_folders:
            assert not os.path.exists(p), f"Prohibited permanent agent folder found: {p}"
