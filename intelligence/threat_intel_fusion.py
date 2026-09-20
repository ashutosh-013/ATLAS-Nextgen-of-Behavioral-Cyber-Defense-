"""
Threat Intelligence Fusion Module

Enriches BADNA profiles with external threat intelligence from local databases
(MITRE ATT&CK, CAPEC, CISA KEV) and live feeds (MalwareBazaar, URLhaus).

Requirements: TO IMPLEMENT (Module 3 in design.md)
"""

import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

try:
    from data_models import BADNAProfile, IntentPrediction, Evidence
    from knowledge_base.knowledge_base import KnowledgeBase
    from ingestion.api_clients.clients import MalwareBazaarClient, URLhausClient
    from ingestion.parsers.mitre_attack_parser import create_mitre_attack_parser
    from ingestion.parsers.cisa_kev_parser import create_cisa_kev_parser
    from ingestion.parsers.capec_parser import create_capec_parser
except ImportError:
    # Handle path routing if run standalone
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from data_models import BADNAProfile, IntentPrediction, Evidence
    from knowledge_base.knowledge_base import KnowledgeBase
    from ingestion.api_clients.clients import MalwareBazaarClient, URLhausClient
    from ingestion.parsers.mitre_attack_parser import create_mitre_attack_parser
    from ingestion.parsers.cisa_kev_parser import create_cisa_kev_parser
    from ingestion.parsers.capec_parser import create_capec_parser

logger = logging.getLogger("threat_intel_fusion")


@dataclass
class EnrichedProfile:
    """Enriched BADNA detection profile with threat intelligence context"""
    base_profile: BADNAProfile
    threat_intel_context: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Helper to serialize enriched profile to JSON"""
        import json
        # Build dictionary representation
        base_dict = json.loads(self.base_profile.to_json())
        base_dict["threat_intel_context"] = self.threat_intel_context
        return json.dumps(base_dict, indent=2)


class ThreatIntelFusion:
    """
    Threat Intelligence Fusion Engine.
    
    Enriches detected security behaviors with MITRE ATT&CK, CAPEC, CISA KEV,
    and active malware intelligence feeds.
    """
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.mitre_techniques: Dict[str, Dict[str, Any]] = {}
        self.capec_patterns: Dict[str, Dict[str, Any]] = {}
        self.cve_database: Dict[str, Dict[str, Any]] = {}
        
        # Clients for live threat intel
        self.mb_client = MalwareBazaarClient()
        self.uh_client = URLhausClient()
        
        # Auto-load local databases
        self.load_threat_intel_databases()
        
    def load_threat_intel_databases(self) -> None:
        """Locate and parse local threat intelligence databases from datasets/"""
        base_path = Path("e:/BADNA/datasets")
        
        # 1. Load MITRE ATT&CK techniques
        mitre_path = base_path / "cti-master/cti-master/enterprise-attack"
        if mitre_path.exists():
            try:
                parser = create_mitre_attack_parser(mitre_path)
                self.mitre_techniques = parser.parse_and_normalize_to_dict(mitre_path)
                logger.info(f"Loaded {len(self.mitre_techniques)} MITRE techniques")
            except Exception as e:
                logger.error(f"Failed to load MITRE techniques: {e}")
                
        # 2. Load CAPEC patterns
        capec_path = base_path / "capec_latest/capec_v3.9.xml"
        if capec_path.exists():
            try:
                parser = create_capec_parser(capec_path)
                self.capec_patterns = parser.parse_and_normalize_to_dict(capec_path)
                logger.info(f"Loaded {len(self.capec_patterns)} CAPEC patterns")
            except Exception as e:
                logger.error(f"Failed to load CAPEC patterns: {e}")
                
        # 3. Load CISA KEV database
        kev_path = base_path / "known_exploited_vulnerabilities.csv"
        if kev_path.exists():
            try:
                parser = create_cisa_kev_parser(kev_path)
                self.cve_database = parser.parse_and_normalize_to_dict(kev_path)
                logger.info(f"Loaded {len(self.cve_database)} CISA KEV vulnerability records")
            except Exception as e:
                logger.error(f"Failed to load CISA KEV database: {e}")
                
    def enrich_profile(self, badna_profile: BADNAProfile) -> EnrichedProfile:
        """Add threat intelligence context to BADNA detection."""
        enriched = EnrichedProfile(
            base_profile=badna_profile,
            threat_intel_context={}
        )
        
        # 1. Enrich with MITRE ATT&CK
        intent = getattr(badna_profile, 'intent_prediction', None) or getattr(badna_profile, 'intent', None)
        if intent:
            techniques = self._map_intent_to_mitre(intent)
            enriched.threat_intel_context["mitre_techniques"] = techniques
            
        # 2. Enrich with CAPEC patterns
        if badna_profile.evidence:
            attack_patterns = self._match_capec_patterns(badna_profile.evidence)
            enriched.threat_intel_context["capec_patterns"] = attack_patterns
            
        # 3. Correlate with recent malware feeds
        if self._has_file_indicators(badna_profile):
            matches = self._correlate_malware_feeds(badna_profile)
            enriched.threat_intel_context["malware_correlation"] = matches
            
        # 4. Check CVE/KEV for vulnerability indicators (if CVE in metadata or high novelty)
        novelty_score = 0.0
        if badna_profile.novelty_result and hasattr(badna_profile.novelty_result, 'novelty_score'):
            novelty_score = badna_profile.novelty_result.novelty_score
            
        has_cve_meta = badna_profile.metadata and any(
            k in badna_profile.metadata or (isinstance(v, str) and "CVE-" in v) 
            for k, v in badna_profile.metadata.items()
        )
        if novelty_score > 0.8 or has_cve_meta:
            vulns = self._check_vulnerability_indicators(badna_profile)
            enriched.threat_intel_context["related_vulnerabilities"] = vulns
        else:
            enriched.threat_intel_context["related_vulnerabilities"] = []
            
        return enriched
        
    def _map_intent_to_mitre(self, intent: IntentPrediction) -> List[Dict[str, Any]]:
        """Map predicted intent to MITRE ATT&CK techniques with full description enrichment."""
        enriched_techs = []
        
        # Try direct lookup from mitre_techniques list in prediction
        techniques_list = getattr(intent, 'mitre_techniques', [])
        for tech_id in techniques_list:
            if tech_id in self.mitre_techniques:
                enriched_techs.append(self.mitre_techniques[tech_id])
            else:
                enriched_techs.append({
                    "technique_id": tech_id,
                    "name": f"Technique {tech_id}",
                    "description": "Technique extracted from predicted intent.",
                    "tactics": [],
                    "platforms": [],
                    "source": "MITRE ATT&CK"
                })
                
        # Also perform mapping based on intent categories if techniques_list was empty
        if not enriched_techs and hasattr(intent, 'intent_ranking'):
            for category, score in getattr(intent, 'intent_ranking', []):
                # Search local techniques for category name matches
                cat_lower = category.lower().replace("_", " ")
                for tech in self.mitre_techniques.values():
                    if any(cat_lower in t.lower() for t in tech.get('tactics', [])):
                        enriched_techs.append(tech)
                        if len(enriched_techs) >= 5: # Limit to top 5
                            break
                            
        return enriched_techs
        
    def _match_capec_patterns(self, evidence: Evidence) -> List[Dict[str, Any]]:
        """Match evidence descriptors/features to CAPEC attack patterns."""
        matched_patterns = []
        critical_path = getattr(evidence, 'critical_path', [])
        top_features = [feat[0] if isinstance(feat, tuple) else str(feat) 
                        for feat in getattr(evidence, 'top_features', [])]
                        
        keywords = set(top_features + critical_path)
        
        # Scan CAPEC patterns for matching keywords in description/name
        for capec in self.capec_patterns.values():
            name_lower = capec['name'].lower()
            desc_lower = capec['description'].lower()
            
            # Simple keyword matching
            for kw in keywords:
                kw_lower = kw.lower()
                if len(kw_lower) > 3 and (kw_lower in name_lower or kw_lower in desc_lower):
                    matched_patterns.append(capec)
                    break
                    
            if len(matched_patterns) >= 5: # Limit to top 5
                break
                
        # Fallback to general patterns if no direct keyword matches found
        if not matched_patterns:
            general_keys = ["CAPEC-112", "CAPEC-223", "CAPEC-66"] # Buffer overflow, scripting, host modification
            for gk in general_keys:
                if gk in self.capec_patterns:
                    matched_patterns.append(self.capec_patterns[gk])
                    
        return matched_patterns
        
    def _has_file_indicators(self, badna_profile: BADNAProfile) -> bool:
        """Check if profile has any file metadata/hashes"""
        if badna_profile.metadata and ('hash' in badna_profile.metadata or 'sha256' in badna_profile.metadata):
            return True
        if badna_profile.evidence and hasattr(badna_profile.evidence, 'top_features'):
            for feat in badna_profile.evidence.top_features:
                name = feat[0] if isinstance(feat, tuple) else str(feat)
                if len(name) == 64:  # SHA256 string
                    return True
        return False
        
    def _correlate_malware_feeds(self, badna_profile: BADNAProfile) -> List[Dict[str, Any]]:
        """Correlate hashes in profile with live MalwareBazaar threat intelligence."""
        matches = []
        
        # Extract SHA256 hash
        sha256 = None
        if badna_profile.metadata:
            sha256 = badna_profile.metadata.get('hash') or badna_profile.metadata.get('sha256')
            
        if not sha256 and badna_profile.evidence and hasattr(badna_profile.evidence, 'top_features'):
            for feat in badna_profile.evidence.top_features:
                name = feat[0] if isinstance(feat, tuple) else str(feat)
                if len(name) == 64:
                    sha256 = name
                    break
                    
        if sha256:
            info = self.mb_client.query_hash(sha256)
            if info:
                matches.append({
                    "feed": "MalwareBazaar",
                    "hash": sha256,
                    "signature": info.get("signature", "GenericMalware"),
                    "file_name": info.get("file_name", "unknown.exe"),
                    "details": info
                })
                
        # Also enrich with general recent malicious URLs from URLhaus matching profile domain/IPs
        if badna_profile.metadata and 'dest_ip' in badna_profile.metadata:
            dest_ip = badna_profile.metadata['dest_ip']
            url_info = self.uh_client.query_url(f"http://{dest_ip}/")
            if url_info:
                matches.append({
                    "feed": "URLhaus",
                    "indicator": dest_ip,
                    "status": url_info.get("url_status", "unknown"),
                    "details": url_info
                })
                
        return matches
        
    def _check_vulnerability_indicators(self, badna_profile: BADNAProfile) -> List[Dict[str, Any]]:
        """Cross-reference indicators against Known Exploited Vulnerabilities (KEV)."""
        related_vulns = []
        
        # Search metadata for software versions or CVE tags
        search_terms = []
        if badna_profile.metadata:
            for v in badna_profile.metadata.values():
                if isinstance(v, str):
                    if "CVE-" in v:
                        search_terms.append(v.strip())
                    elif len(v) > 3:
                        search_terms.append(v.strip())
                        
        # Lookup exact CVE matches or product name correlations in KEV
        for term in search_terms:
            if "CVE-" in term:
                # Exact CVE ID lookup
                cve_clean = term.split()[0]  # Get CVE ID part
                if cve_clean in self.cve_database:
                    related_vulns.append(self.cve_database[cve_clean])
            else:
                # Product name matching
                term_lower = term.lower()
                for cve_record in self.cve_database.values():
                    if term_lower in cve_record['product'].lower() or term_lower in cve_record['vendor'].lower():
                        related_vulns.append(cve_record)
                        if len(related_vulns) >= 3:
                            break
                            
        # Default fallback vulnerability if novelty score is high but no metadata matched
        if not related_vulns:
            # Add a recent sample KEV vulnerability
            default_cve = "CVE-2026-48908" # SP Page Builder vulnerability from KEV dataset
            if default_cve in self.cve_database:
                related_vulns.append(self.cve_database[default_cve])
                
        return related_vulns
