"""
Test Threat Intelligence, Knowledge Base, & Campaign Supervisor - Batch 3 Verification Suite

Verifies ATLAS Rules:
- Rule #1: Keep ATLAS Behavior-First
- Rule #2: Never Let Any Module Bypass BADNA (Every telemetry event must pass through the behavioral pipeline even on IOC hit)
- Rule #3: Separate Responsibilities (IOC Repository vs. Behavioral Knowledge Base)
- Rule #7: Build for Real Data (Parser quality and honest evidence chains)
"""

import pytest
import numpy as np
from datetime import datetime, timezone
import sys
import os
from pathlib import Path

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_models import (
    BehaviorGraph, BehaviorNode, BehaviorEdge, BADNAProfile,
    BADNAEmbedding, IntentPrediction, Evidence, NoveltyResult,
    BehaviorPattern, CampaignProfile
)
from intelligence.ioc_repository import IOCRepository, IOCRecord, get_ioc_repository
from knowledge_base.knowledge_base import KnowledgeBase, get_knowledge_base
from intelligence.ioc_monitor import IOCMonitorEngine
from intelligence.threat_intel_fusion import ThreatIntelFusion, EnrichedProfile
from campaign_engine import CampaignEngine, Campaign, AttackSession
from main import BADNAAnalysisOrchestrator


def test_strict_ioc_vs_behavioral_separation():
    """
    Test 1: Rule #3 - Separate Responsibilities.
    IOC Repository stores hashes, IPs, URLs, domains, CVEs.
    Behavioral Knowledge Base stores Behavioral DNA, campaigns, feedback, and historical behavior.
    They must remain strictly decoupled.
    """
    ioc_repo = IOCRepository()
    kb = KnowledgeBase()
    
    # Add IOC indicators to IOCRepository
    test_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
    test_ip = "198.51.100.99"
    test_domain = "evil-c2-domain.test"
    test_url = "https://evil-c2-domain.test/dropper.exe"
    test_cve = "CVE-2026-99999"
    
    ioc_repo.add_hash(test_hash, {"threat": "Trojan"})
    ioc_repo.add_ip(test_ip, {"threat": "C2"})
    ioc_repo.add_domain(test_domain, {"threat": "Phishing"})
    ioc_repo.add_url(test_url, {"threat": "MalwareDownload"})
    ioc_repo.add_cve(test_cve, {"vendor": "TestVendor", "product": "TestProduct"})
    
    # 1. Verify IOC Repository stores them
    assert ioc_repo.check_hash(test_hash) is not None
    assert ioc_repo.check_ip(test_ip) is not None
    assert ioc_repo.check_domain(test_domain) is not None
    assert ioc_repo.check_url(test_url) is not None
    assert ioc_repo.check_cve(test_cve) is not None
    
    # 2. Verify Knowledge Base patterns and campaigns are not polluted by raw atomic IOC strings
    assert test_hash not in kb.patterns
    assert test_ip not in kb.patterns
    assert test_domain not in kb.patterns
    assert test_cve not in kb.patterns
    
    # 3. Verify Knowledge Base exclusively stores behavioral entities
    for pattern_id, pat in kb.patterns.items():
        assert isinstance(pat, BehaviorPattern)
        assert pat.embedding is not None
        assert len(pat.embedding) == 128
        
    for camp_id, camp in kb.campaigns.items():
        assert isinstance(camp, CampaignProfile)
        assert camp.signature_embedding is not None
        assert len(camp.signature_embedding) == 128


def test_ioc_repository_crud_and_lookup():
    """
    Test 2: IOC Repository provides fast, thread-safe O(1) lookups across all 5 indicator categories.
    """
    repo = IOCRepository()
    
    # Hashes
    repo.add_hash("44d88612fea8a8f36de82e1278abb02f", {"type": "md5"})
    assert repo.check_hash("44d88612fea8a8f36de82e1278abb02f")["ioc_type"] == "hash"
    assert repo.check_hash("44D88612FEA8A8F36DE82E1278ABB02F") is not None  # Case-insensitivity
    
    # IPs
    repo.add_ip("203.0.113.123", {"geo": "Unknown"})
    assert repo.check_ip("203.0.113.123")["value"] == "203.0.113.123"
    
    # Domains
    repo.add_domain("Phish-Target.com", {"registrar": "BadRegistrar"})
    assert repo.check_domain("phish-target.com") is not None
    
    # URLs
    repo.add_url("http://phish-target.com/login.php")
    assert repo.check_url("http://phish-target.com/login.php") is not None
    
    # CVEs
    repo.add_cve("CVE-2026-12345", {"severity": "Critical"})
    assert repo.check_cve("CVE-2026-12345")["value"] == "CVE-2026-12345"
    assert repo.check_cve("cve-2026-12345") is not None  # Normalized uppercase
    
    # Event matching
    event = {
        "event_id": "evt-lookup-1",
        "event_type": "network",
        "event_data": {
            "dest_ip": "203.0.113.123",
            "domain": "phish-target.com"
        }
    }
    match = repo.check_event(event)
    assert match is not None
    assert match["indicator_type"] in ["ip", "domain"]


def test_cisa_kev_ioc_integration():
    """
    Test 3: Rule #7 - Real Data Ingestion.
    Verify CISA KEV parser normalization integrates with the IOC Repository as valid CVE indicators.
    """
    repo = IOCRepository()
    
    # Ingest CISA KEV entries
    sample_kev_records = {
        "CVE-2021-44228": {
            "vendor": "Apache",
            "product": "Log4j2",
            "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
            "date_added": "2021-12-10",
            "ransomware_usage": "Known"
        },
        "CVE-2023-34362": {
            "vendor": "Progress",
            "product": "MOVEit Transfer",
            "vulnerability_name": "Progress MOVEit Transfer SQL Injection Vulnerability",
            "date_added": "2023-06-02",
            "ransomware_usage": "Known"
        }
    }
    
    for cve_id, data in sample_kev_records.items():
        repo.add_cve(cve_id, metadata=data)
        
    res = repo.check_cve("CVE-2021-44228")
    assert res is not None
    assert res["metadata"]["product"] == "Log4j2"
    assert res["metadata"]["ransomware_usage"] == "Known"
    
    res2 = repo.check_cve("CVE-2023-34362")
    assert res2 is not None
    assert res2["metadata"]["vendor"] == "Progress"


def test_threat_intel_fusion_enrichment():
    """
    Test 4: Threat Intelligence Fusion properly enriches behavioral profiles
    with MITRE ATT&CK, CAPEC, and CISA KEV without modifying behavioral embeddings.
    """
    kb = KnowledgeBase()
    fusion = ThreatIntelFusion(kb)
    
    intent = IntentPrediction(
        profile_id="test-fusion-profile",
        primary_intent="execution",
        intent_ranking=[("execution", 0.85)],
        attack_stage="intermediate",
        mitre_techniques=["T1059", "T1059.001"],
        natural_language_explanation="PowerShell script execution detected."
    )
    
    evidence = Evidence(
        profile_id="test-fusion-profile",
        top_features=[("powershell.exe", 0.9)],
        critical_path=["powershell.exe -enc"],
        mitre_mappings={"T1059.001": "PowerShell"},
        campaign_reference=None,
        novelty_explanation={},
        structured_json={},
        natural_language="Observed execution of encoded command"
    )
    
    # 128D unit embedding
    v = np.ones(128) / np.sqrt(128)
    embedding = BADNAEmbedding(embedding_id="emb-test-fusion", vector=v, source_graph_id="g-1")
    
    profile = BADNAProfile(
        profile_id="test-fusion-profile",
        embedding=embedding,
        intent_prediction=intent,
        evidence=evidence,
        metadata={"vulnerability": "CVE-2021-44228"}
    )
    
    enriched = fusion.enrich_profile(profile)
    assert isinstance(enriched, EnrichedProfile)
    assert enriched.base_profile.profile_id == "test-fusion-profile"
    
    # Embedding must not be altered by threat intelligence fusion (Rule #1: behavior first)
    np.testing.assert_allclose(enriched.base_profile.embedding.vector, v)
    
    # Threat intel context must be present
    ctx = enriched.threat_intel_context
    assert "mitre_techniques" in ctx
    assert "capec_patterns" in ctx
    assert "related_vulnerabilities" in ctx


def test_no_bypass_on_ioc_hit():
    """
    Test 5: Rule #2 - Never Let Any Module Bypass BADNA.
    An event matching a known IOC must STILL execute the complete BADNA behavioral pipeline:
    d-BEF feature/embedding extraction, BSF similarity, NSF novelty, and CCF calibrated risk.
    """
    orchestrator = BADNAAnalysisOrchestrator()
    
    # Known malicious seed hash
    known_hash = "32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74"
    
    events = [
        {
            "event_id": "evt-bypass-check-1",
            "event_type": "process",
            "timestamp": "2026-09-01T14:00:00",
            "source_system": "Endpoint-Alpha",
            "event_data": {
                "name": "wannacry.exe",
                "hash": known_hash,
                "command": "wannacry.exe -m",
                "action": "create"
            }
        },
        {
            "event_id": "evt-bypass-check-2",
            "event_type": "file",
            "timestamp": "2026-09-01T14:00:05",
            "source_system": "Endpoint-Alpha",
            "event_data": {
                "path": "C:\\Windows\\Temp\\wannacry.exe",
                "sha256": known_hash,
                "action": "write"
            }
        }
    ]
    
    profile = orchestrator.analyze_events(events)
    
    # 1. IOC Match was caught
    assert "ioc_matches" in profile.metadata
    assert len(profile.metadata["ioc_matches"]) > 0
    
    # 2. Behavioral Pipeline was NOT bypassed (Rule #2)
    assert profile.embedding is not None, "d-BEF embedding MUST be computed despite IOC match"
    assert len(profile.embedding.vector) == 128
    assert abs(np.linalg.norm(profile.embedding.vector) - 1.0) < 1e-5
    
    assert profile.novelty_result is not None, "NSF novelty MUST be calculated despite IOC match"
    assert profile.confidence_result is not None, "CCF confidence MUST be calibrated despite IOC match"
    assert profile.risk_score is not None, "RiskScorer MUST assess unified risk despite IOC match"
    assert 0.0 <= profile.risk_score.score <= 1.0


def test_campaign_correlation_with_provenance():
    """
    Test 6: CampaignEngine groups multi-source telemetry while preserving
    concrete event traceability and attack session lifecycles.
    """
    engine = CampaignEngine()
    
    multi_source_events = [
        {
            "event_id": "ev-net-01",
            "event_type": "network",
            "timestamp": "2026-09-01T15:00:00Z",
            "src_ip": "198.51.100.44",
            "dst_port": 445,
            "command": "port_scan",
            "source_mode": "LIVE"
        },
        {
            "event_id": "ev-auth-02",
            "event_type": "authentication",
            "timestamp": "2026-09-01T15:00:05Z",
            "src_ip": "198.51.100.44",
            "command": "ssh brute force login",
            "source_mode": "LIVE"
        },
        {
            "event_id": "ev-proc-03",
            "event_type": "process",
            "timestamp": "2026-09-01T15:00:10Z",
            "src_ip": "198.51.100.44",
            "command": "powershell.exe -enc JABjAG0AZA...",
            "source_mode": "LIVE"
        },
        {
            "event_id": "ev-cred-04",
            "event_type": "process",
            "timestamp": "2026-09-01T15:00:15Z",
            "src_ip": "198.51.100.44",
            "command": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "source_mode": "LIVE"
        }
    ]
    
    campaigns = engine.correlate_telemetry(multi_source_events, source_mode="LIVE")
    assert len(campaigns) > 0
    
    camp = campaigns[0]
    assert isinstance(camp, Campaign)
    assert camp.source_mode == "LIVE"
    assert "198.51.100.44" in camp.source_ips
    
    # Traceability check: evidence event IDs must point to real events
    assert len(camp.evidence_event_ids) >= 4
    assert "ev-net-01" in camp.evidence_event_ids
    assert "ev-cred-04" in camp.evidence_event_ids
    
    # Lifecycle progression
    assert "INITIAL_ACCESS" in camp.observed_stages or "EXECUTION" in camp.observed_stages
    assert "CREDENTIAL_ACCESS" in camp.observed_stages
    assert camp.severity in ["HIGH", "CRITICAL"]


def test_zero_fabrication_in_threat_intel():
    """
    Test 7: Zero-Fabrication Invariant.
    Queries for unobserved indicators return clean None / empty results.
    """
    repo = IOCRepository()
    
    # Non-existent hash
    assert repo.check_hash("0000000000000000000000000000000000000000000000000000000000000000") is None
    
    # Non-existent IP
    assert repo.check_ip("192.0.2.1") is None
    
    # Non-existent domain
    assert repo.check_domain("innocent-domain-definitely-clean-12345.org") is None
    
    # Non-existent URL
    assert repo.check_url("https://innocent-domain.org/clean.html") is None
    
    # Non-existent CVE
    assert repo.check_cve("CVE-1990-00001") is None
