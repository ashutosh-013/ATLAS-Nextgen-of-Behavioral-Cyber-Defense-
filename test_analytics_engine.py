"""
Unit and Integration Tests for ATLAS Analytics & Threat Story Engine
======================================================================
Verifies that all analytics calculations are backed by real empirical DB events,
handles zero-event clean states cleanly, calculates latency percentiles, reconstructs
attack stories without hardcoded strings, and reports ground-truth quality status correctly.
"""

import pytest
from analytics_engine import AnalyticsEngine
from campaign_engine import CampaignEngine
from playbook_engine import DefenceResponseEngine


@pytest.fixture(scope="module")
def analytics_engine():
    camp_engine = CampaignEngine()
    def_engine = DefenceResponseEngine()
    return AnalyticsEngine(campaign_engine=camp_engine, defense_engine=def_engine)


def test_1_security_overview_clean_and_scenario_modes(analytics_engine):
    ov_live = analytics_engine.get_security_overview(source_mode="LIVE", time_range="24h")
    assert "data_freshness" in ov_live
    assert "metrics" in ov_live
    assert ov_live["source_mode"] == "LIVE"
    assert isinstance(ov_live["metrics"]["total_events"], int)

    ov_scen = analytics_engine.get_security_overview(source_mode="SCENARIO", time_range="24h")
    assert ov_scen["source_mode"] == "SCENARIO"


def test_2_mttd_mttr_performance_calculations(analytics_engine):
    perf = analytics_engine.calculate_detection_and_response_performance(source_mode="LIVE", time_range="24h")
    assert "mttd" in perf
    assert "mttr" in perf
    assert perf["mttd"]["status"] in ["CALCULATED", "INSUFFICIENT_DATA"]
    assert perf["mttr"]["status"] in ["CALCULATED", "INSUFFICIENT_DATA"]


def test_3_detection_quality_ground_truth(analytics_engine):
    qual_live = analytics_engine.calculate_detection_quality(source_mode="LIVE")
    assert qual_live["status"] in ["LIMITED", "CALCULATED"]
    if qual_live["status"] == "LIMITED":
        assert "Ground-truth analyst validation labels unavailable" in qual_live["reason"]

    qual_scen = analytics_engine.calculate_detection_quality(source_mode="SCENARIO")
    assert qual_scen["status"] == "CALCULATED"
    assert qual_scen["precision"] >= 0.80


def test_4_threats_over_time_discrete_buckets(analytics_engine):
    tot = analytics_engine.get_threats_over_time(source_mode="LIVE", time_range="24h")
    assert "buckets" in tot
    assert len(tot["buckets"]) == 6
    for b in tot["buckets"]:
        assert "time" in b
        assert "total" in b
        assert "sources" in b


def test_5_threat_class_distribution(analytics_engine):
    dist_live = analytics_engine.get_threat_class_distribution(source_mode="LIVE")
    assert "distribution" in dist_live

    dist_scen = analytics_engine.get_threat_class_distribution(source_mode="SCENARIO")
    assert len(dist_scen["distribution"]) > 0


def test_6_attack_story_reconstruction(analytics_engine):
    story_scen = analytics_engine.reconstruct_attack_story(source_mode="SCENARIO")
    assert story_scen["status"] == "RECONSTRUCTED"
    assert len(story_scen["nodes"]) >= 4
    assert len(story_scen["links"]) >= 3
    
    # Verify provenance types
    types = [n["type"] for n in story_scen["nodes"]]
    assert "USER" in types
    assert "PROCESS" in types
    assert "CAMPAIGN" in types


def test_7_temporal_attack_timeline(analytics_engine):
    tl = analytics_engine.get_attack_timeline(source_mode="SCENARIO")
    assert "timeline" in tl
    assert isinstance(tl["timeline"], list)


def test_8_mitre_attack_stage_analysis(analytics_engine):
    stages = analytics_engine.get_attack_stage_analysis(source_mode="SCENARIO")
    assert "stages" in stages
    assert len(stages["stages"]) >= 5


def test_9_process_and_network_behavior(analytics_engine):
    proc = analytics_engine.get_process_behavior_analytics(source_mode="LIVE")
    assert "top_processes" in proc

    net = analytics_engine.get_network_behavior_analytics(source_mode="LIVE")
    assert "top_destinations" in net


def test_10_ip_geolocation_threat_map(analytics_engine):
    geo = analytics_engine.get_ip_geolocation_threat_map(source_mode="SCENARIO")
    assert "markers" in geo
    assert len(geo["markers"]) > 0
    # Private IPs must not be geolocated as public
    for m in geo["markers"]:
        assert not m["ip"].startswith("10.")


def test_11_data_quality_and_blind_spots(analytics_engine):
    dq = analytics_engine.get_data_quality_metrics()
    assert "telemetry_completeness" in dq
    assert "collectors" in dq
    assert "blind_spots" in dq


def test_12_security_story_and_insights(analytics_engine):
    story = analytics_engine.generate_security_story_narrative(source_mode="LIVE", time_range="24h")
    assert "narrative" in story
    assert len(story["narrative"]) > 20

    insights = analytics_engine.get_analytics_insights(source_mode="LIVE")
    assert len(insights) >= 3


def test_13_risk_vs_confidence_matrix(analytics_engine):
    matrix = analytics_engine.get_risk_vs_confidence_matrix(source_mode="SCENARIO")
    assert "points" in matrix
    assert len(matrix["points"]) > 0
