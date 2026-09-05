"""
Automated Pytest Test Suite for ATLAS T-Pot Honeypot & Protection Engine.
Validates:
- 4-state status detection (T-Pot Sensor, Telemetry Ingestion, Host Firewall, Protection Mode)
- Dynamic multi-honeypot sensor list
- Normalized T-Pot event feed & source_mode separation (LIVE vs SCENARIO)
- Correlated attack sessions engine
- Read-only Windows Defender Firewall health check
- Security coverage metrics
"""

import pytest
import json
from web_app import app
from firewall_manager import CrossPlatformFirewallManager

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_tpot_status_endpoint(client):
    res = client.get('/api/tpot/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'sensor_state' in data
    assert 'telemetry_state' in data
    assert 'firewall_state' in data
    assert 'protection_mode' in data
    assert data['read_only'] is True

def test_tpot_sensors_endpoint(client):
    res = client.get('/api/tpot/sensors')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['sensors']) >= 4
    sensor_names = [s['name'] for s in data['sensors']]
    assert "Cowrie SSH" in sensor_names
    assert "Dionaea SMB" in sensor_names

def test_tpot_events_endpoint(client):
    res = client.get('/api/tpot/events')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'events' in data
    if len(data['events']) > 0:
        evt = data['events'][0]
        assert 'source_mode' in evt
        assert 'honeypot' in evt
        assert 'src_ip' in evt

def test_tpot_sessions_endpoint(client):
    res = client.get('/api/tpot/sessions')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['sessions']) >= 1
    sess = data['sessions'][0]
    assert 'session_id' in sess
    assert 'timeline' in sess
    assert 'mitre_techniques' in sess

def test_tpot_firewall_status_endpoint(client):
    res = client.get('/api/tpot/firewall/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    fw = data['firewall']
    assert 'platform' in fw
    assert fw['read_only'] is True

def test_tpot_coverage_endpoint(client):
    res = client.get('/api/tpot/coverage')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    cov = data['coverage']
    assert 'tpot_sensor' in cov
    assert 'protection_mode' in cov

def test_firewall_manager_read_only_status():
    fm = CrossPlatformFirewallManager()
    status = fm.get_firewall_status()
    assert isinstance(status, dict)
    assert status['read_only'] is True
    assert status['available'] is True
