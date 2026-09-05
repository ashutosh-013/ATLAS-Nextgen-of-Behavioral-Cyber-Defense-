"""
Unit tests for Threat Intelligence Fusion Module
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

from knowledge_base.knowledge_base import KnowledgeBase
from intelligence.threat_intel_fusion import ThreatIntelFusion, EnrichedProfile
from data_models import BADNAProfile, IntentPrediction, Evidence, NoveltyResult


@pytest.fixture
def kb():
    """Create simulated KnowledgeBase"""
    return KnowledgeBase()


@pytest.fixture
def fusion_engine(kb):
    """Create ThreatIntelFusion engine"""
    return ThreatIntelFusion(kb)


@pytest.fixture
def sample_profile():
    """Create a sample BADNA profile with mock intent, evidence, and novelty results"""
    intent = IntentPrediction(
        profile_id="test_profile_123",
        primary_intent="defense_evasion",
        intent_ranking=[("defense_evasion", 0.9), ("persistence", 0.3)],
        attack_stage="initial",
        mitre_techniques=["T1055.011", "T1055"],
        natural_language_explanation="Process injection detected.",
        computation_time=datetime.now()
    )
    
    evidence = Evidence(
        profile_id="test_profile_123",
        top_features=[("buffer overflow", 0.8), ("32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74", 0.9)],
        critical_path=[".text", "CopyFileW"],
        mitre_mappings={"T1055.011": "Extra Window Memory Injection"},
        campaign_reference=None,
        novelty_explanation={"features": 0.5},
        structured_json={},
        natural_language="Evidence details"
    )
    
    novelty = NoveltyResult(
        embedding_id="test_profile_123",
        novelty_score=0.95,
        novelty_category="highly_novel",
        nearest_neighbors=[],
        local_outlier_factor=1.5,
        explanation={"feature": 0.5}
    )
    
    profile = BADNAProfile(
        profile_id="test_profile_123",
        timestamp=datetime.now(),
        intent_prediction=intent,
        evidence=evidence,
        novelty_result=novelty,
        metadata={
            "hash": "32c37c352802fb20004fa14053ac13134f31aff747dc0a2962da2ea1ea894d74",
            "dest_ip": "192.168.1.100",
            "vulnerability": "CVE-2026-48908"
        }
    )
    return profile


def test_fusion_initialization(fusion_engine):
    """Test that threat intel local databases are loaded"""
    # Verify that techniques and KEV are loaded (if files exist, they should be populated)
    assert isinstance(fusion_engine.mitre_techniques, dict)
    assert isinstance(fusion_engine.capec_patterns, dict)
    assert isinstance(fusion_engine.cve_database, dict)


def test_enrich_profile(fusion_engine, sample_profile):
    """Test full enrichment pipeline on sample profile"""
    enriched = fusion_engine.enrich_profile(sample_profile)
    
    assert isinstance(enriched, EnrichedProfile)
    assert enriched.base_profile.profile_id == "test_profile_123"
    
    context = enriched.threat_intel_context
    assert "mitre_techniques" in context
    assert "capec_patterns" in context
    assert "malware_correlation" in context
    assert "related_vulnerabilities" in context
    
    # 1. Verify MITRE techniques enrichment
    techs = context["mitre_techniques"]
    assert len(techs) > 0
    # The first technique in the intent was T1055.011, check if matched
    tech_ids = [t["technique_id"] for t in techs]
    assert "T1055.011" in tech_ids or "T1055" in tech_ids
    
    # 2. Verify CAPEC patterns matching (buffer overflow keyword)
    capecs = context["capec_patterns"]
    assert len(capecs) > 0
    
    # 3. Verify MalwareBazaar correlation (using mock fallback for hash lookup)
    correlations = context["malware_correlation"]
    assert len(correlations) > 0
    assert correlations[0]["feed"] == "MalwareBazaar"
    
    # 4. Verify CVE/KEV lookup
    vulns = context["related_vulnerabilities"]
    assert len(vulns) > 0
    cve_ids = [v["cve_id"] for v in vulns]
    assert "CVE-2026-48908" in cve_ids


if __name__ == "__main__":
    import sys
    pytest.main([__file__, "-v"])
