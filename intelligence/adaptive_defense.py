"""
Adaptive Defense Intelligence Module

This module implements automated defense recommendation generation based on 
behavioral threat analysis results. It provides threat-specific, prioritized
recommendations for security operations teams.

Requirements: 15.1-15.10
Task: 10.2 - Implement adaptive defense intelligence
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from data_models import (
    BADNAProfile, ThreatClassification, IntentPrediction, RiskScore,
    ValidationError
)
from config import get_logger, get_config


@dataclass
class DefenseRecommendation:
    """Single defense recommendation with metadata."""
    
    recommendation_id: str
    title: str
    description: str
    priority: int  # 1 (highest) to 5 (lowest)
    effectiveness_score: float  # 0.0 to 1.0
    implementation_cost: str  # "Low", "Medium", "High"
    implementation_time: str  # "Immediate", "Hours", "Days"
    category: str  # "Isolation", "Monitoring", "Forensics", etc.
    step_by_step_instructions: List[str]
    automation_available: bool
    success_criteria: List[str]
    related_mitre_techniques: List[str] = field(default_factory=list)
    estimated_impact: str = "Medium"  # "Low", "Medium", "High"


@dataclass 
class DefenseRecommendationSuite:
    """Complete suite of defense recommendations for a threat."""
    
    profile_id: str
    threat_class: str
    risk_level: str
    recommendations: List[DefenseRecommendation]
    immediate_actions: List[str]
    investigation_priorities: List[str]
    long_term_improvements: List[str]
    generated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "profile_id": self.profile_id,
            "threat_class": self.threat_class,
            "risk_level": self.risk_level,
            "recommendations": [
                {
                    "recommendation_id": rec.recommendation_id,
                    "title": rec.title,
                    "description": rec.description,
                    "priority": rec.priority,
                    "effectiveness_score": rec.effectiveness_score,
                    "implementation_cost": rec.implementation_cost,
                    "implementation_time": rec.implementation_time,
                    "category": rec.category,
                    "step_by_step_instructions": rec.step_by_step_instructions,
                    "automation_available": rec.automation_available,
                    "success_criteria": rec.success_criteria,
                    "related_mitre_techniques": rec.related_mitre_techniques,
                    "estimated_impact": rec.estimated_impact
                }
                for rec in self.recommendations
            ],
            "immediate_actions": self.immediate_actions,
            "investigation_priorities": self.investigation_priorities,
            "long_term_improvements": self.long_term_improvements,
            "generated_at": self.generated_at.isoformat()
        }


class AdaptiveDefenseIntelligence:
    """
    Adaptive Defense Intelligence engine for generating threat-specific 
    defense recommendations.
    
    This class analyzes BADNA threat profiles and generates actionable,
    prioritized defense recommendations tailored to specific threat types
    and attack stages.
    """
    
    def __init__(self):
        """Initialize the Adaptive Defense Intelligence engine."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Load defense knowledge base
        self._load_defense_knowledge_base()
        
        self.logger.log_operation(
            "INFO",
            "Adaptive Defense Intelligence initialized",
            component="AdaptiveDefenseIntelligence"
        )
    
    def _load_defense_knowledge_base(self):
        """Load defense recommendation templates and effectiveness data."""
        
        # Ransomware defense patterns
        self.ransomware_defenses = {
            "isolation": {
                "effectiveness": 0.95,
                "cost": "Low",
                "time": "Immediate",
                "instructions": [
                    "Identify affected systems from behavioral analysis",
                    "Immediately isolate affected hosts from network",
                    "Prevent lateral movement by disabling network shares",
                    "Document isolation actions for forensics team"
                ]
            },
            "backup_verification": {
                "effectiveness": 0.90,
                "cost": "Medium", 
                "time": "Hours",
                "instructions": [
                    "Verify integrity of recent backup copies",
                    "Test backup restoration on isolated system",
                    "Ensure backups are not connected to compromised network",
                    "Prepare clean restoration environment"
                ]
            },
            "network_segmentation": {
                "effectiveness": 0.85,
                "cost": "Medium",
                "time": "Hours",
                "instructions": [
                    "Implement emergency network segmentation",
                    "Block file sharing protocols (SMB, NFS)",
                    "Restrict administrative access to critical systems",
                    "Monitor network traffic for encryption patterns"
                ]
            }
        }
        
        # APT defense patterns  
        self.apt_defenses = {
            "forensic_preservation": {
                "effectiveness": 0.92,
                "cost": "High",
                "time": "Immediate", 
                "instructions": [
                    "Create forensic images of compromised systems",
                    "Preserve volatile memory and network connections",
                    "Document all observed IOCs and behavioral patterns",
                    "Maintain chain of custody for evidence"
                ]
            },
            "threat_hunting": {
                "effectiveness": 0.88,
                "cost": "High",
                "time": "Hours",
                "instructions": [
                    "Deploy threat hunting team with behavioral IOCs",
                    "Search for similar behavioral patterns across environment", 
                    "Analyze lateral movement paths and persistence mechanisms",
                    "Identify additional compromised systems"
                ]
            },
            "credential_rotation": {
                "effectiveness": 0.85,
                "cost": "Medium",
                "time": "Hours",
                "instructions": [
                    "Immediately reset all privileged account passwords",
                    "Revoke and reissue service account credentials",
                    "Force re-authentication for all active sessions",
                    "Audit recent privilege escalations and access grants"
                ]
            }
        }
        
        # Insider Threat defense patterns
        self.insider_defenses = {
            "access_review": {
                "effectiveness": 0.80,
                "cost": "Medium",
                "time": "Hours",
                "instructions": [
                    "Review user's current access permissions and recent changes",
                    "Audit file access logs and data transfer activities", 
                    "Check for unauthorized privilege escalations",
                    "Verify business justification for recent access requests"
                ]
            },
            "dlp_monitoring": {
                "effectiveness": 0.85,
                "cost": "Low",
                "time": "Immediate",
                "instructions": [
                    "Enable enhanced DLP monitoring for user",
                    "Block external data transfer channels (email, cloud)",
                    "Monitor USB and removable media usage",
                    "Alert on any large file transfers or downloads"
                ]
            },
            "behavior_monitoring": {
                "effectiveness": 0.75,
                "cost": "Medium",
                "time": "Days",
                "instructions": [
                    "Implement enhanced user activity monitoring",
                    "Track access patterns and working hours",
                    "Monitor for unusual data access or system behavior",
                    "Coordinate with HR for employee status verification"
                ]
            }
        }
        
        # Behavioral-specific defenses
        self.behavioral_defenses = {
            "lateral_movement": {
                "effectiveness": 0.90,
                "cost": "Medium", 
                "time": "Hours",
                "instructions": [
                    "Implement network micro-segmentation",
                    "Disable unnecessary administrative shares",
                    "Monitor and restrict WMI/PowerShell remote execution",
                    "Audit and limit service account permissions"
                ]
            },
            "exfiltration": {
                "effectiveness": 0.88,
                "cost": "Low",
                "time": "Immediate", 
                "instructions": [
                    "Enable network flow monitoring and DLP",
                    "Block or monitor unusual outbound connections",
                    "Implement egress filtering for sensitive data",
                    "Alert on large data transfers to external destinations"
                ]
            },
            "persistence": {
                "effectiveness": 0.82,
                "cost": "Medium",
                "time": "Hours",
                "instructions": [
                    "Scan for unauthorized scheduled tasks and services",
                    "Check registry modifications and startup items",
                    "Validate all installed software and browser extensions",
                    "Review system-level configuration changes"
                ]
            }
        }
    
    def recommend_actions(self, profile: BADNAProfile) -> DefenseRecommendationSuite:
        """
        Generate comprehensive defense recommendations for a threat profile.
        
        Args:
            profile: Complete BADNA analysis profile
            
        Returns:
            DefenseRecommendationSuite with prioritized recommendations
        """
        
        if not profile.risk_score or profile.risk_score.score < 0.70:
            # Only generate recommendations for significant threats
            return self._generate_minimal_recommendations(profile)
        
        try:
            self.logger.log_operation(
                "INFO",
                f"Generating defense recommendations for {profile.threat_classification.threat_class if profile.threat_classification else 'Unknown'} threat",
                component="AdaptiveDefenseIntelligence",
                operation="recommend_actions",
                profile_id=profile.profile_id
            )
            
            recommendations = []
            immediate_actions = []
            investigation_priorities = []
            long_term_improvements = []
            
            # Get threat class and risk level
            threat_class = profile.threat_classification.threat_class if profile.threat_classification else "Unknown"
            risk_level = profile.risk_score.risk_level if profile.risk_score else "Medium"
            
            # Generate threat-specific recommendations
            if threat_class == "Ransomware":
                recommendations.extend(self._generate_ransomware_recommendations(profile))
                immediate_actions.extend([
                    "IMMEDIATELY isolate affected systems from network",
                    "Verify backup integrity and availability", 
                    "Activate incident response team",
                    "Notify executive leadership and legal team"
                ])
                
            elif threat_class == "APT":
                recommendations.extend(self._generate_apt_recommendations(profile))
                immediate_actions.extend([
                    "Preserve forensic evidence on affected systems",
                    "Activate advanced threat hunting procedures",
                    "Reset all privileged credentials",
                    "Coordinate with external threat intelligence"
                ])
                
            elif threat_class == "Insider_Threat":
                recommendations.extend(self._generate_insider_recommendations(profile))
                immediate_actions.extend([
                    "Review user access permissions and recent changes",
                    "Enable enhanced monitoring for the user",
                    "Coordinate with HR and legal teams",
                    "Secure sensitive data the user can access"
                ])
            
            # Generate behavioral-specific recommendations
            if profile.intent_prediction:
                behavioral_recs = self._generate_behavioral_recommendations(profile.intent_prediction)
                recommendations.extend(behavioral_recs)
            
            # Add investigation priorities based on analysis
            investigation_priorities.extend([
                f"Analyze the {len(profile.evidence.top_features) if profile.evidence else 0} key behavioral features identified",
                "Correlate with threat intelligence on similar attack patterns",
                "Search for additional systems with similar behavioral signatures",
                "Document lessons learned for future detection improvements"
            ])
            
            # Add long-term improvements
            long_term_improvements.extend([
                "Update detection rules based on new behavioral patterns",
                "Enhance monitoring coverage for identified attack vectors",
                "Conduct tabletop exercises based on this incident",
                "Review and update incident response procedures"
            ])
            
            # Sort recommendations by priority and effectiveness
            recommendations.sort(key=lambda x: (x.priority, -x.effectiveness_score))
            
            suite = DefenseRecommendationSuite(
                profile_id=profile.profile_id,
                threat_class=threat_class,
                risk_level=risk_level,
                recommendations=recommendations,
                immediate_actions=immediate_actions,
                investigation_priorities=investigation_priorities,
                long_term_improvements=long_term_improvements
            )
            
            self.logger.log_operation(
                "INFO",
                f"Generated {len(recommendations)} defense recommendations",
                component="AdaptiveDefenseIntelligence", 
                operation="recommend_actions",
                recommendations_count=len(recommendations),
                threat_class=threat_class,
                risk_level=risk_level
            )
            
            return suite
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Failed to generate defense recommendations: {e}",
                component="AdaptiveDefenseIntelligence",
                operation="recommend_actions"
            )
            return self._generate_minimal_recommendations(profile)
    
    def _generate_ransomware_recommendations(self, profile: BADNAProfile) -> List[DefenseRecommendation]:
        """Generate Ransomware-specific defense recommendations."""
        recommendations = []
        
        # Isolation recommendation
        rec_id = f"RAN_ISO_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="Network Isolation and Containment",
            description="Immediately isolate affected systems to prevent ransomware spread",
            priority=1,
            effectiveness_score=self.ransomware_defenses["isolation"]["effectiveness"],
            implementation_cost=self.ransomware_defenses["isolation"]["cost"], 
            implementation_time=self.ransomware_defenses["isolation"]["time"],
            category="Isolation",
            step_by_step_instructions=self.ransomware_defenses["isolation"]["instructions"],
            automation_available=True,
            success_criteria=[
                "Affected systems are disconnected from network",
                "No new encryption activity detected",
                "Lateral movement blocked"
            ],
            related_mitre_techniques=["T1486", "T1490", "T1021"],
            estimated_impact="High"
        ))
        
        # Backup verification
        rec_id = f"RAN_BAK_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="Backup Verification and Recovery Preparation",
            description="Verify backup integrity and prepare clean recovery environment",
            priority=2,
            effectiveness_score=self.ransomware_defenses["backup_verification"]["effectiveness"],
            implementation_cost=self.ransomware_defenses["backup_verification"]["cost"],
            implementation_time=self.ransomware_defenses["backup_verification"]["time"], 
            category="Recovery",
            step_by_step_instructions=self.ransomware_defenses["backup_verification"]["instructions"],
            automation_available=False,
            success_criteria=[
                "Backup integrity verified",
                "Clean recovery environment prepared",
                "Recovery procedures tested"
            ],
            related_mitre_techniques=["T1490"],
            estimated_impact="High"
        ))
        
        return recommendations
    
    def _generate_apt_recommendations(self, profile: BADNAProfile) -> List[DefenseRecommendation]:
        """Generate APT-specific defense recommendations."""
        recommendations = []
        
        # Forensic preservation
        rec_id = f"APT_FOR_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="Forensic Evidence Preservation",
            description="Preserve forensic evidence for detailed APT investigation",
            priority=1,
            effectiveness_score=self.apt_defenses["forensic_preservation"]["effectiveness"],
            implementation_cost=self.apt_defenses["forensic_preservation"]["cost"],
            implementation_time=self.apt_defenses["forensic_preservation"]["time"],
            category="Forensics",
            step_by_step_instructions=self.apt_defenses["forensic_preservation"]["instructions"],
            automation_available=True,
            success_criteria=[
                "Forensic images created",
                "Memory dumps captured",
                "Evidence chain of custody established"
            ],
            related_mitre_techniques=["T1005", "T1074", "T1083"],
            estimated_impact="Medium"
        ))
        
        # Threat hunting 
        rec_id = f"APT_HUN_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="Advanced Threat Hunting",
            description="Deploy threat hunting to find additional APT presence",
            priority=2,
            effectiveness_score=self.apt_defenses["threat_hunting"]["effectiveness"],
            implementation_cost=self.apt_defenses["threat_hunting"]["cost"],
            implementation_time=self.apt_defenses["threat_hunting"]["time"],
            category="Hunting",
            step_by_step_instructions=self.apt_defenses["threat_hunting"]["instructions"],
            automation_available=False,
            success_criteria=[
                "Threat hunting deployed",
                "Additional compromised systems identified",
                "Attack timeline established"
            ],
            related_mitre_techniques=["T1057", "T1082", "T1018"],
            estimated_impact="High"
        ))
        
        return recommendations
    
    def _generate_insider_recommendations(self, profile: BADNAProfile) -> List[DefenseRecommendation]:
        """Generate Insider Threat-specific defense recommendations.""" 
        recommendations = []
        
        # Access review
        rec_id = f"INS_ACC_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="User Access Review and Audit",
            description="Comprehensive review of user permissions and recent activities",
            priority=1,
            effectiveness_score=self.insider_defenses["access_review"]["effectiveness"],
            implementation_cost=self.insider_defenses["access_review"]["cost"],
            implementation_time=self.insider_defenses["access_review"]["time"],
            category="Access Control",
            step_by_step_instructions=self.insider_defenses["access_review"]["instructions"],
            automation_available=True,
            success_criteria=[
                "User permissions audited",
                "Recent access activities reviewed",
                "Unauthorized access identified"
            ],
            related_mitre_techniques=["T1078", "T1087", "T1033"],
            estimated_impact="Medium"
        ))
        
        # DLP monitoring
        rec_id = f"INS_DLP_{profile.profile_id[:8]}"
        recommendations.append(DefenseRecommendation(
            recommendation_id=rec_id,
            title="Enhanced Data Loss Prevention",
            description="Implement enhanced DLP monitoring for the user",
            priority=2,
            effectiveness_score=self.insider_defenses["dlp_monitoring"]["effectiveness"],
            implementation_cost=self.insider_defenses["dlp_monitoring"]["cost"],
            implementation_time=self.insider_defenses["dlp_monitoring"]["time"],
            category="Monitoring",
            step_by_step_instructions=self.insider_defenses["dlp_monitoring"]["instructions"],
            automation_available=True,
            success_criteria=[
                "Enhanced DLP rules active",
                "Data transfer monitoring enabled",
                "Alert thresholds configured"
            ],
            related_mitre_techniques=["T1041", "T1020", "T1567"],
            estimated_impact="Medium"
        ))
        
        return recommendations
    
    def _generate_behavioral_recommendations(self, intent_prediction: IntentPrediction) -> List[DefenseRecommendation]:
        """Generate recommendations based on behavioral patterns."""
        recommendations = []
        
        if not intent_prediction or not intent_prediction.intent_ranking:
            return recommendations
        
        # Check for lateral movement
        lateral_movement_detected = any(
            'lateral_movement' in intent_name 
            for intent_name, _ in intent_prediction.intent_ranking
        )
        
        if lateral_movement_detected:
            rec_id = f"BEH_LAT_{intent_prediction.profile_id[:8]}"
            recommendations.append(DefenseRecommendation(
                recommendation_id=rec_id,
                title="Lateral Movement Containment",
                description="Implement segmentation to prevent lateral movement",
                priority=2,
                effectiveness_score=self.behavioral_defenses["lateral_movement"]["effectiveness"],
                implementation_cost=self.behavioral_defenses["lateral_movement"]["cost"],
                implementation_time=self.behavioral_defenses["lateral_movement"]["time"],
                category="Network Security",
                step_by_step_instructions=self.behavioral_defenses["lateral_movement"]["instructions"],
                automation_available=True,
                success_criteria=[
                    "Network segmentation implemented",
                    "Administrative shares restricted",
                    "Lateral movement blocked"
                ],
                related_mitre_techniques=["T1021", "T1570", "T1563"],
                estimated_impact="High"
            ))
        
        # Check for exfiltration
        exfiltration_detected = any(
            'exfiltration' in intent_name
            for intent_name, _ in intent_prediction.intent_ranking
        )
        
        if exfiltration_detected:
            rec_id = f"BEH_EXF_{intent_prediction.profile_id[:8]}"
            recommendations.append(DefenseRecommendation(
                recommendation_id=rec_id,
                title="Data Exfiltration Prevention",
                description="Implement monitoring and blocking for data exfiltration",
                priority=1,
                effectiveness_score=self.behavioral_defenses["exfiltration"]["effectiveness"],
                implementation_cost=self.behavioral_defenses["exfiltration"]["cost"],
                implementation_time=self.behavioral_defenses["exfiltration"]["time"],
                category="Data Protection", 
                step_by_step_instructions=self.behavioral_defenses["exfiltration"]["instructions"],
                automation_available=True,
                success_criteria=[
                    "Network flow monitoring enabled",
                    "Egress filtering implemented",
                    "Data transfer alerts configured"
                ],
                related_mitre_techniques=["T1041", "T1048", "T1567"],
                estimated_impact="High"
            ))
        
        return recommendations
    
    def _generate_minimal_recommendations(self, profile: BADNAProfile) -> DefenseRecommendationSuite:
        """Generate minimal recommendations for low-risk threats."""
        
        threat_class = profile.threat_classification.threat_class if profile.threat_classification else "Unknown"
        risk_level = profile.risk_score.risk_level if profile.risk_score else "Low"
        
        # Basic monitoring recommendation
        rec_id = f"MIN_MON_{profile.profile_id[:8]}"
        basic_monitoring = DefenseRecommendation(
            recommendation_id=rec_id,
            title="Enhanced Monitoring",
            description="Implement basic enhanced monitoring for this activity",
            priority=3,
            effectiveness_score=0.60,
            implementation_cost="Low",
            implementation_time="Hours",
            category="Monitoring",
            step_by_step_instructions=[
                "Review activity logs for anomalies",
                "Set up alerting for similar behavioral patterns",
                "Document findings for trend analysis"
            ],
            automation_available=True,
            success_criteria=[
                "Monitoring rules configured",
                "Alert thresholds set",
                "Documentation complete"
            ],
            estimated_impact="Low"
        )
        
        return DefenseRecommendationSuite(
            profile_id=profile.profile_id,
            threat_class=threat_class, 
            risk_level=risk_level,
            recommendations=[basic_monitoring],
            immediate_actions=["Review activity for context"],
            investigation_priorities=["Monitor for pattern repetition"],
            long_term_improvements=["Update baseline behavioral models"]
        )
    
    def get_recommendation_summary(self, suite: DefenseRecommendationSuite) -> Dict[str, Any]:
        """Generate a summary of recommendations for quick review."""
        
        high_priority = [r for r in suite.recommendations if r.priority <= 2]
        immediate_actions_count = len(suite.immediate_actions)
        avg_effectiveness = sum(r.effectiveness_score for r in suite.recommendations) / len(suite.recommendations) if suite.recommendations else 0
        
        return {
            "profile_id": suite.profile_id,
            "threat_class": suite.threat_class,
            "risk_level": suite.risk_level,
            "total_recommendations": len(suite.recommendations),
            "high_priority_recommendations": len(high_priority),
            "immediate_actions_count": immediate_actions_count,
            "average_effectiveness": round(avg_effectiveness, 3),
            "categories": list(set(r.category for r in suite.recommendations)),
            "automation_available": sum(1 for r in suite.recommendations if r.automation_available),
            "generated_at": suite.generated_at.isoformat()
        }


# Factory function for easy integration
def create_adaptive_defense_intelligence() -> AdaptiveDefenseIntelligence:
    """Create and return an AdaptiveDefenseIntelligence instance."""
    return AdaptiveDefenseIntelligence()


# Example usage and testing
if __name__ == "__main__":
    """Test the Adaptive Defense Intelligence module."""
    
    # This would typically be called with a real BADNA profile
    # For testing purposes, we'll create a mock profile
    
    print("Adaptive Defense Intelligence - Test Mode")
    print("This module generates threat-specific defense recommendations")
    print("Integration with main BADNA pipeline provides complete threat response")