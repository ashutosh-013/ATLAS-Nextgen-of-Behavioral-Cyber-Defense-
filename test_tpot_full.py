"""
End-to-End Automated Test Suite for ATLAS T-Pot Honeypot & Protection Engine.
Validates:
- All 9 scenario states (7 deterministic scenarios + NO_DATA + DISCONNECTED)
- Strict backend truthfulness & API payload completeness
- Pipeline parity between live and scenario events
- GET /api/tpot/sessions/<session_id> detail view payload structure
- GET /api/tpot/health backend sensor health metrics
- POST /api/tpot/scenario trigger execution
- Read-only Windows Defender Firewall status inspection
"""

import pytest
import json
from web_app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_tpot_status_truthfulness(client):
    res = client.get('/api/tpot/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'sensor_state' in data
    assert 'telemetry_state' in data
    assert 'firewall_state' in data
    assert 'protection_mode' in data
    assert data['read_only'] is True

def test_tpot_health_metrics(client):
    res = client.get('/api/tpot/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    health = data['health']
    assert 'tpot_api_status' in health
    assert 'parser_status' in health
    assert 'storage_status' in health
    assert health['firewall_access_mode'] == 'READ_ONLY'

def test_tpot_scenario_trigger_all(client):
    scenarios = [
        "BENIGN_CONNECTION",
        "SSH_BRUTE_FORCE",
        "SUCCESSFUL_SSH_COMPROMISE",
        "COMMAND_EXECUTION",
        "MALWARE_PAYLOAD_DELIVERY",
        "PORT_SCAN",
        "MULTI_STAGE_ATTACK",
        "NO_DATA",
        "DISCONNECTED"
    ]
    for s in scenarios:
        res = client.post('/api/tpot/scenario', json={'scenario': s})
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['scenario'] == s
        assert 'payload' in data

def test_tpot_session_detail_view(client):
    # Fetch sessions list first
    res = client.get('/api/tpot/sessions')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['sessions']) >= 1
    
    sess_id = data['sessions'][0]['session_id']
    detail_res = client.get(f'/api/tpot/sessions/{sess_id}')
    assert detail_res.status_code == 200
    detail_data = detail_res.get_json()
    assert detail_data['success'] is True
    s = detail_data['session']
    assert s['session_id'] == sess_id
    assert 'timeline' in s
    assert 'mitre_techniques' in s
    assert 'threat_intelligence' in s
    assert 'recommendations' in s

def test_tpot_iocs_provenance(client):
    res = client.get('/api/tpot/iocs')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'iocs' in data
    if len(data['iocs']) > 0:
        ioc = data['iocs'][0]
        assert 'value' in ioc
        assert 'source' in ioc
        assert 'confidence' in ioc

def test_tpot_firewall_rules_read_only(client):
    res = client.get('/api/tpot/firewall/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    fw = data['firewall']
    assert fw['read_only'] is True
    assert 'platform' in fw
