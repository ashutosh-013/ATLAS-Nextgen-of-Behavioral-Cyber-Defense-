"""
BADNA Knowledge Update Integration Module

This module provides integration functions for updating the knowledge base with
feedback and triggering model evolution. It orchestrates the interaction between
FeedbackLoop, ModelEvolution, and KnowledgeBase components.

Requirements: 12.1-12.3, 13.4-13.10, 14.1-14.10
Task: 9.2 - Implement feedback loop and model evolution integration
"""

import json
import time
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
import logging

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_models import (
    Feedback, BehaviorPattern, BADNAProfile, 
    ValidationError, create_badna_profile
)
from config import get_config, get_logger, handle_processing_error
from knowledge_base.knowledge_base import get_knowledge_base
from learning.feedback import get_feedback_loop, FeedbackResult
from learning.evolution import get_model_evolution, RetrainingResult


@dataclass
class KnowledgeUpdateResult:
    """Result of knowledge base update operation."""
    feedback_processed: bool
    patterns_added: int
    retraining_triggered: bool
    retraining_result: Optional[RetrainingResult]
    updated_statistics: Dict[str, Any]
    message: str
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'feedback_processed': self.feedback_processed,
            'patterns_added': self.patterns_added,
            'retraining_triggered': self.retraining_triggered,
            'updated_statistics': self.updated_statistics,
            'message': self.message
        }
        
        if self.retraining_result:
            result['retraining_result'] = self.retraining_result.to_dict()
        
        return result


class KnowledgeUpdater:
    """
    Knowledge Update orchestrator for BADNA learning system.
    
    Coordinates feedback processing, knowledge base updates, and model evolution
    to ensure continuous learning and improvement of the BADNA system.
    """
    
    def __init__(self):
        """Initialize KnowledgeUpdater."""
        self.config = get_config()
        self.logger = get_logger()
        
        # Get component instances
        self.knowledge_base = get_knowledge_base()
        self.feedback_loop = get_feedback_loop()
        self.model_evolution = get_model_evolution()
        
        # Configuration
        self.auto_retrain_enabled = True
        self.min_feedback_for_retraining = 50
        self.performance_check_interval_hours = 24
        
        self.logger.log_operation(
            "INFO",
            "KnowledgeUpdater initialized",
            component="KnowledgeUpdater"
        )
    
    def process_analyst_feedback(self, feedback: Feedback, 
                               behavioral_data: Optional[Dict[str, Any]] = None) -> KnowledgeUpdateResult:
        """
        Process analyst feedback and update knowledge base accordingly.
        
        Args:
            feedback: Analyst feedback object
            behavioral_data: Optional behavioral data for false negatives
            
        Returns:
            KnowledgeUpdateResult with processing results
        """
        start_time = time.time()
        
        try:
            # Process feedback through feedback loop
            feedback_result = self.feedback_loop.accept_feedback(feedback)
            
            if not feedback_result.success:
                return KnowledgeUpdateResult(
                    feedback_processed=False,
                    patterns_added=0,
                    retraining_triggered=False,
                    retraining_result=None,
                    updated_statistics={},
                    message=f"Feedback processing failed: {feedback_result.message}"
                )
            
            patterns_added = 0
            retraining_result = None
            
            # Handle false negative feedback by adding missed pattern to training
            if feedback.feedback_type == 'false_negative' and behavioral_data:
                patterns_added = self._add_false_negative_to_training(feedback, behavioral_data)
            
            # Check if retraining should be triggered
            retraining_triggered = False
            if self.auto_retrain_enabled:
                trigger_status = self.model_evolution.check_retraining_triggers()
                
                if trigger_status.get('retraining_recommended', False):
                    retraining_result = self._trigger_automatic_retraining()
                    retraining_triggered = retraining_result.success if retraining_result else False
            
            # Get updated statistics
            updated_stats = feedback_result.aggregated_stats
            
            duration_ms = (time.time() - start_time) * 1000
            
            result = KnowledgeUpdateResult(
                feedback_processed=True,
                patterns_added=patterns_added,
                retraining_triggered=retraining_triggered,
                retraining_result=retraining_result,
                updated_statistics=updated_stats,
                message="Analyst feedback processed successfully"
            )
            
            self.logger.log_operation(
                "INFO",
                f"Processed analyst feedback: {feedback.feedback_type}",
                component="KnowledgeUpdater",
                operation="process_analyst_feedback",
                duration_ms=duration_ms,
                feedback_type=feedback.feedback_type,
                patterns_added=patterns_added,
                retraining_triggered=retraining_triggered
            )
            
            return result
            
        except Exception as e:
            return handle_processing_error(
                e, "KnowledgeUpdater", "process_analyst_feedback",
                KnowledgeUpdateResult(
                    feedback_processed=False,
                    patterns_added=0,
                    retraining_triggered=False,
                    retraining_result=None,
                    updated_statistics={},
                    message=f"Failed to process feedback: {str(e)}"
                )
            )
    
    def bulk_update_knowledge_base(self, new_patterns: List[BehaviorPattern]) -> KnowledgeUpdateResult:
        """
        Bulk update knowledge base with new behavioral patterns.
        
        Args:
            new_patterns: List of new behavioral patterns to add
            
        Returns:
            KnowledgeUpdateResult with update results
        """
        start_time = time.time()
        
        try:
            if not new_patterns:
                return KnowledgeUpdateResult(
                    feedback_processed=False,
                    patterns_added=0,
                    retraining_triggered=False,
                    retraining_result=None,
                    updated_statistics={},
                    message="No patterns provided for bulk update"
                )
            
            # Add patterns to knowledge base
            patterns_added = 0
            for pattern in new_patterns:
                try:
                    pattern_id = self.knowledge_base.store_pattern(pattern)
                    if pattern_id:
                        patterns_added += 1
                except Exception as e:
                    self.logger.log_operation(
                        "WARNING",
                        f"Failed to add pattern {pattern.pattern_id}: {e}",
                        component="KnowledgeUpdater"
                    )
            
            # Update embeddings incrementally
            incremental_success = self.model_evolution.incremental_embedding_update(new_patterns)
            
            # Check for retraining triggers
            retraining_result = None
            retraining_triggered = False
            
            if self.auto_retrain_enabled:
                trigger_status = self.model_evolution.check_retraining_triggers()
                
                if trigger_status.get('retraining_recommended', False):
                    retraining_result = self._trigger_automatic_retraining()
                    retraining_triggered = retraining_result.success if retraining_result else False
            
            # Get knowledge base statistics
            kb_stats = self.knowledge_base.get_statistics()
            
            duration_ms = (time.time() - start_time) * 1000
            
            result = KnowledgeUpdateResult(
                feedback_processed=False,  # This was a bulk update, not feedback
                patterns_added=patterns_added,
                retraining_triggered=retraining_triggered,
                retraining_result=retraining_result,
                updated_statistics=kb_stats,
                message=f"Bulk update completed: {patterns_added} patterns added"
            )
            
            self.logger.log_operation(
                "INFO",
                f"Bulk knowledge base update completed",
                component="KnowledgeUpdater",
                operation="bulk_update_knowledge_base",
                duration_ms=duration_ms,
                patterns_added=patterns_added,
                incremental_update_success=incremental_success,
                retraining_triggered=retraining_triggered
            )
            
            return result
            
        except Exception as e:
            return handle_processing_error(
                e, "KnowledgeUpdater", "bulk_update_knowledge_base",
                KnowledgeUpdateResult(
                    feedback_processed=False,
                    patterns_added=0,
                    retraining_triggered=False,
                    retraining_result=None,
                    updated_statistics={},
                    message=f"Bulk update failed: {str(e)}"
                )
            )
    
    def check_and_trigger_maintenance(self) -> Dict[str, Any]:
        """
        Check system health and trigger maintenance operations if needed.
        
        Returns:
            Dictionary with maintenance results and recommendations
        """
        try:
            maintenance_results = {
                'timestamp': datetime.now().isoformat(),
                'operations_performed': [],
                'recommendations': [],
                'system_health': {}
            }
            
            # Check knowledge base retention policy
            kb_stats = self.knowledge_base.get_statistics()
            if kb_stats['total_patterns'] > 10000:
                removed_count = self.knowledge_base.apply_retention_policy(10000)
                maintenance_results['operations_performed'].append(
                    f"Applied retention policy: removed {removed_count} patterns"
                )
            
            # Check model version retention
            version_history = self.model_evolution.get_version_history()
            if len(version_history) > 10:
                maintenance_results['recommendations'].append(
                    "Consider cleaning up old model versions"
                )
            
            # Check retraining triggers
            trigger_status = self.model_evolution.check_retraining_triggers()
            if trigger_status.get('retraining_recommended', False):
                maintenance_results['recommendations'].append(
                    "Model retraining is recommended based on trigger conditions"
                )
            
            # System health assessment
            feedback_summary = self.feedback_loop.get_recent_feedback_summary(days=7)
            maintenance_results['system_health'] = {
                'knowledge_base_size': kb_stats['total_patterns'],
                'recent_feedback_volume': feedback_summary['total_feedback'],
                'model_versions': len(version_history),
                'active_version': version_history[0]['version_id'] if version_history else None,
                'last_retraining': trigger_status.get('last_training'),
                'trigger_status': {name: t['triggered'] for name, t in trigger_status.get('triggers', {}).items()}
            }
            
            self.logger.log_operation(
                "INFO",
                f"Maintenance check completed: {len(maintenance_results['operations_performed'])} operations performed",
                component="KnowledgeUpdater",
                operation="check_and_trigger_maintenance"
            )
            
            return maintenance_results
            
        except Exception as e:
            return handle_processing_error(
                e, "KnowledgeUpdater", "check_and_trigger_maintenance", 
                fallback_value={
                    'timestamp': datetime.now().isoformat(),
                    'operations_performed': [],
                    'recommendations': ['System maintenance check failed'],
                    'system_health': {},
                    'error': str(e)
                }
            )
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive learning system statistics.
        
        Returns:
            Dictionary with learning system metrics
        """
        try:
            # Get feedback statistics
            feedback_stats = self.feedback_loop.aggregate_statistics()
            
            # Get knowledge base statistics
            kb_stats = self.knowledge_base.get_statistics()
            
            # Get model evolution statistics
            version_history = self.model_evolution.get_version_history()
            trigger_status = self.model_evolution.check_retraining_triggers()
            
            # Get recent activity summary
            recent_feedback = self.feedback_loop.get_recent_feedback_summary(days=30)
            
            learning_stats = {
                'knowledge_base': kb_stats,
                'feedback_system': feedback_stats.to_dict() if feedback_stats else {},
                'recent_activity': recent_feedback,
                'model_evolution': {
                    'total_versions': len(version_history),
                    'active_version': version_history[0] if version_history else None,
                    'trigger_status': trigger_status,
                    'last_retraining': trigger_status.get('last_training')
                },
                'system_metrics': {
                    'auto_retrain_enabled': self.auto_retrain_enabled,
                    'min_feedback_for_retraining': self.min_feedback_for_retraining,
                    'performance_check_interval_hours': self.performance_check_interval_hours
                },
                'generated_at': datetime.now().isoformat()
            }
            
            return learning_stats
            
        except Exception as e:
            return handle_processing_error(
                e, "KnowledgeUpdater", "get_learning_statistics", 
                fallback_value={
                    'error': str(e),
                    'generated_at': datetime.now().isoformat()
                }
            )
    
    def _add_false_negative_to_training(self, feedback: Feedback, 
                                      behavioral_data: Dict[str, Any]) -> int:
        """Add false negative behavioral data to training set."""
        try:
            if 'embedding' not in behavioral_data:
                self.logger.log_operation(
                    "WARNING",
                    "Cannot add false negative: no embedding provided",
                    component="KnowledgeUpdater"
                )
                return 0
            
            # Create pattern from behavioral data
            pattern = BehaviorPattern(
                embedding=np.array(behavioral_data['embedding']),
                threat_class=feedback.corrected_label or "Unknown",
                confidence_score=0.8,  # Medium confidence for analyst-provided data
                source="feedback_false_negative",
                metadata={
                    'feedback_id': feedback.feedback_id,
                    'analyst_id': feedback.analyst_id,
                    'analyst_notes': feedback.analyst_notes,
                    'original_profile_id': feedback.profile_id
                }
            )
            
            # Store pattern in knowledge base
            pattern_id = self.knowledge_base.store_pattern(pattern)
            
            if pattern_id:
                self.logger.log_operation(
                    "INFO",
                    f"Added false negative pattern to training: {pattern_id}",
                    component="KnowledgeUpdater",
                    operation="add_false_negative_to_training",
                    pattern_id=pattern_id,
                    threat_class=pattern.threat_class
                )
                return 1
            
            return 0
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Failed to add false negative to training: {e}",
                component="KnowledgeUpdater",
                operation="add_false_negative_to_training"
            )
            return 0
    
    def _trigger_automatic_retraining(self) -> Optional[RetrainingResult]:
        """Trigger automatic model retraining."""
        try:
            # Check if we have sufficient feedback for reliable retraining
            recent_feedback = self.feedback_loop.get_recent_feedback_summary(days=30)
            
            if recent_feedback['total_feedback'] < self.min_feedback_for_retraining:
                self.logger.log_operation(
                    "INFO",
                    f"Skipping automatic retraining: insufficient feedback ({recent_feedback['total_feedback']} < {self.min_feedback_for_retraining})",
                    component="KnowledgeUpdater"
                )
                return None
            
            # Determine trigger type based on trigger status
            trigger_status = self.model_evolution.check_retraining_triggers()
            trigger_types = [
                name for name, trigger in trigger_status.get('triggers', {}).items()
                if trigger.get('triggered', False)
            ]
            
            primary_trigger = trigger_types[0] if trigger_types else "kb_growth"
            
            # Trigger retraining
            result = self.model_evolution.trigger_retraining(trigger_type=primary_trigger)
            
            if result.success:
                self.logger.log_operation(
                    "INFO",
                    f"Automatic retraining completed: {result.new_version_id}",
                    component="KnowledgeUpdater",
                    operation="trigger_automatic_retraining",
                    trigger_type=primary_trigger,
                    new_version=result.new_version_id,
                    training_duration=result.training_duration_minutes
                )
            else:
                self.logger.log_operation(
                    "WARNING",
                    f"Automatic retraining failed: {result.message}",
                    component="KnowledgeUpdater",
                    operation="trigger_automatic_retraining"
                )
            
            return result
            
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Failed to trigger automatic retraining: {e}",
                component="KnowledgeUpdater",
                operation="trigger_automatic_retraining"
            )
            return None


# Global knowledge updater instance
_global_knowledge_updater: Optional[KnowledgeUpdater] = None

def get_knowledge_updater() -> KnowledgeUpdater:
    """Get global knowledge updater instance."""
    global _global_knowledge_updater
    if _global_knowledge_updater is None:
        _global_knowledge_updater = KnowledgeUpdater()
    return _global_knowledge_updater

def initialize_knowledge_updater() -> KnowledgeUpdater:
    """Initialize global knowledge updater."""
    global _global_knowledge_updater
    _global_knowledge_updater = KnowledgeUpdater()
    return _global_knowledge_updater


# Convenience functions for common operations
def process_feedback(feedback: Feedback, 
                    behavioral_data: Optional[Dict[str, Any]] = None) -> KnowledgeUpdateResult:
    """Process analyst feedback through the learning system."""
    updater = get_knowledge_updater()
    return updater.process_analyst_feedback(feedback, behavioral_data)


def add_new_patterns(patterns: List[BehaviorPattern]) -> KnowledgeUpdateResult:
    """Add new behavioral patterns to the knowledge base."""
    updater = get_knowledge_updater()
    return updater.bulk_update_knowledge_base(patterns)


def get_system_health() -> Dict[str, Any]:
    """Get current system health and learning statistics."""
    updater = get_knowledge_updater()
    return updater.get_learning_statistics()


def run_maintenance() -> Dict[str, Any]:
    """Run system maintenance checks and operations."""
    updater = get_knowledge_updater()
    return updater.check_and_trigger_maintenance()


if __name__ == "__main__":
    # Test KnowledgeUpdater integration
    print("Testing KnowledgeUpdater integration...")
    
    from data_models import Feedback
    
    # Test feedback processing
    feedback = Feedback(
        profile_id="test-integration-123",
        feedback_type="true_positive",
        analyst_id="test-analyst",
        analyst_notes="Testing knowledge update integration"
    )
    
    result = process_feedback(feedback)
    print(f"Feedback processing result: {result.feedback_processed}")
    
    # Test system health
    health = get_system_health()
    print(f"System health check: {len(health.keys())} metrics")
    
    # Test maintenance
    maintenance = run_maintenance()
    print(f"Maintenance check: {len(maintenance['operations_performed'])} operations")
    
    print("KnowledgeUpdater integration complete!")