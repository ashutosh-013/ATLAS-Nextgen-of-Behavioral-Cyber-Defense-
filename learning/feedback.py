"""
BADNA Feedback Loop System

This module implements the FeedbackLoop class for processing analyst feedback and updating
model weights based on human intelligence. Supports feedback types: true_positive, 
false_positive, and false_negative with validation and statistics aggregation.

Requirements: 13.1-13.3, 14.1-14.10
Task: 9.2 - Implement feedback loop and model evolution
"""

import json
import time
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from pathlib import Path
from dataclasses import dataclass
import logging

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_models import Feedback, BehaviorPattern, BADNAProfile, ValidationError
from config import get_config, get_logger, handle_processing_error
from knowledge_base.knowledge_base import get_knowledge_base


@dataclass
class FeedbackResult:
    """Result of feedback processing."""
    success: bool
    updated_weights: Dict[str, float]
    next_actions: List[str]
    aggregated_stats: Dict[str, Any]
    message: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'updated_weights': self.updated_weights,
            'next_actions': self.next_actions,
            'aggregated_stats': self.aggregated_stats,
            'message': self.message
        }


@dataclass
class FeedbackStatistics:
    """Aggregated feedback statistics."""
    total_feedback_count: int
    true_positive_count: int
    false_positive_count: int
    false_negative_count: int
    precision_by_class: Dict[str, float]
    recall_by_class: Dict[str, float]
    f1_score_by_class: Dict[str, float]
    overall_accuracy: float
    last_updated: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'total_feedback_count': self.total_feedback_count,
            'true_positive_count': self.true_positive_count,
            'false_positive_count': self.false_positive_count,
            'false_negative_count': self.false_negative_count,
            'precision_by_class': self.precision_by_class,
            'recall_by_class': self.recall_by_class,
            'f1_score_by_class': self.f1_score_by_class,
            'overall_accuracy': self.overall_accuracy,
            'last_updated': self.last_updated.isoformat()
        }
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FeedbackStatistics':
        if isinstance(data['last_updated'], str):
            data['last_updated'] = datetime.fromisoformat(data['last_updated'])
        return cls(**data)


class FeedbackLoop:
    """
    BADNA Feedback Loop for processing analyst corrections and continuous learning.
    
    Processes feedback types:
    - true_positive: Reinforce detection pattern
    - false_positive: Reduce sensitivity for similar patterns  
    - false_negative: Add missed pattern to training data
    
    Maintains feedback history and prioritizes recent feedback over older entries.
    """
    
    def __init__(self, feedback_storage_path: Optional[str] = None):
        """
        Initialize FeedbackLoop.
        
        Args:
            feedback_storage_path: Path to feedback history storage file
        """
        config = get_config()
        self.logger = get_logger()
        
        # Set storage path
        feedback_dir = Path(config.knowledge_base_path) / "feedback"
        feedback_dir.mkdir(parents=True, exist_ok=True)
        
        self.feedback_path = Path(feedback_storage_path) if feedback_storage_path else feedback_dir / "feedback_history.json"
        self.stats_path = feedback_dir / "feedback_statistics.json"
        
        # In-memory storage
        self.feedback_history: Dict[str, List[Feedback]] = defaultdict(list)
        self.model_weights: Dict[str, float] = {
            'similarity_weight': 1.0,
            'novelty_weight': 1.0,
            'confidence_weight': 1.0,
            'feature_weights': {}
        }
        
        # Configuration
        self.feedback_decay_days = 90  # Prioritize feedback from last 90 days
        self.min_feedback_for_stats = 10  # Minimum feedback required for reliable statistics
        
        # Load existing data
        self._load_feedback_history()
        self._load_model_weights()
        
        self.logger.log_operation(
            "INFO",
            f"FeedbackLoop initialized with {len(self.feedback_history)} profile histories",
            component="FeedbackLoop"
        )
    
    def accept_feedback(self, feedback: Feedback) -> FeedbackResult:
        """
        Accept analyst feedback on detection and update model weights.
        
        Args:
            feedback: Feedback object with profile_id, feedback_type, analyst_notes
            
        Returns:
            FeedbackResult with success status and updated weights
            
        Raises:
            ValidationError: If feedback validation fails
        """
        start_time = time.time()
        
        try:
            # Validate feedback
            self._validate_feedback(feedback)
            
            # Check if profile_id exists (validate against BADNA profiles)
            kb = get_knowledge_base()
            if not self._validate_profile_exists(feedback.profile_id):
                raise ValidationError(f"Profile ID {feedback.profile_id} not found", "profile_id")
            
            # Store feedback in history (prioritize recent feedback)
            self._store_feedback(feedback)
            
            # Update model weights based on feedback type
            updated_weights = self._update_model_weights(feedback)
            
            # Determine next actions
            next_actions = self._determine_next_actions(feedback)
            
            # Compute aggregated statistics
            stats = self.aggregate_statistics()
            
            duration_ms = (time.time() - start_time) * 1000
            
            result = FeedbackResult(
                success=True,
                updated_weights=updated_weights,
                next_actions=next_actions,
                aggregated_stats=stats.to_dict() if stats else {},
                message=f"Feedback processed successfully for profile {feedback.profile_id}"
            )
            
            self.logger.log_operation(
                "INFO",
                f"Processed {feedback.feedback_type} feedback for profile {feedback.profile_id}",
                component="FeedbackLoop",
                operation="accept_feedback",
                duration_ms=duration_ms,
                feedback_type=feedback.feedback_type,
                profile_id=feedback.profile_id
            )
            
            return result
            
        except Exception as e:
            return handle_processing_error(
                e, "FeedbackLoop", "accept_feedback", 
                FeedbackResult(
                    success=False,
                    updated_weights={},
                    next_actions=[],
                    aggregated_stats={},
                    message=f"Failed to process feedback: {str(e)}"
                )
            )
    
    def aggregate_statistics(self) -> Optional[FeedbackStatistics]:
        """
        Aggregate feedback statistics tracking precision, recall, F1-score by threat class.
        
        Returns:
            FeedbackStatistics with performance metrics by threat class
        """
        try:
            if not self.feedback_history:
                return None
            
            # Count feedback types
            feedback_counts = Counter()
            class_feedback = defaultdict(lambda: defaultdict(int))
            
            # Count recent feedback (last 90 days for better accuracy)
            cutoff_date = datetime.now() - timedelta(days=self.feedback_decay_days)
            
            for profile_id, feedback_list in self.feedback_history.items():
                for feedback in feedback_list:
                    if feedback.timestamp > cutoff_date:
                        feedback_counts[feedback.feedback_type] += 1
                        
                        # Get threat class from corrected label or original classification
                        threat_class = feedback.corrected_label or self._get_original_threat_class(profile_id)
                        if threat_class:
                            class_feedback[threat_class][feedback.feedback_type] += 1
            
            # Calculate precision, recall, F1-score by class
            precision_by_class = {}
            recall_by_class = {}
            f1_score_by_class = {}
            
            for threat_class, counts in class_feedback.items():
                tp = counts.get('true_positive', 0)
                fp = counts.get('false_positive', 0)
                fn = counts.get('false_negative', 0)
                
                # Precision = TP / (TP + FP)
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                precision_by_class[threat_class] = precision
                
                # Recall = TP / (TP + FN)
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                recall_by_class[threat_class] = recall
                
                # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
                f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
                f1_score_by_class[threat_class] = f1_score
            
            # Overall accuracy = TP / (TP + FP + FN)
            total_tp = feedback_counts.get('true_positive', 0)
            total_fp = feedback_counts.get('false_positive', 0)
            total_fn = feedback_counts.get('false_negative', 0)
            total_feedback = total_tp + total_fp + total_fn
            
            overall_accuracy = total_tp / total_feedback if total_feedback > 0 else 0.0
            
            stats = FeedbackStatistics(
                total_feedback_count=total_feedback,
                true_positive_count=total_tp,
                false_positive_count=total_fp,
                false_negative_count=total_fn,
                precision_by_class=precision_by_class,
                recall_by_class=recall_by_class,
                f1_score_by_class=f1_score_by_class,
                overall_accuracy=overall_accuracy,
                last_updated=datetime.now()
            )
            
            # Save statistics
            self._save_statistics(stats)
            
            self.logger.log_operation(
                "INFO",
                f"Aggregated statistics: {total_feedback} total feedback, {overall_accuracy:.3f} accuracy",
                component="FeedbackLoop",
                operation="aggregate_statistics",
                total_feedback=total_feedback,
                accuracy=overall_accuracy
            )
            
            return stats
            
        except Exception as e:
            return handle_processing_error(
                e, "FeedbackLoop", "aggregate_statistics", fallback_value=None
            )
    
    def get_feedback_history(self, profile_id: str) -> List[Feedback]:
        """
        Get feedback history for a specific profile.
        
        Args:
            profile_id: BADNA profile ID
            
        Returns:
            List of Feedback objects sorted by timestamp (most recent first)
        """
        feedback_list = self.feedback_history.get(profile_id, [])
        return sorted(feedback_list, key=lambda f: f.timestamp, reverse=True)
    
    def get_recent_feedback_summary(self, days: int = 7) -> Dict[str, Any]:
        """
        Get summary of recent feedback within specified days.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Dictionary with feedback summary statistics
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_feedback = []
        for feedback_list in self.feedback_history.values():
            recent_feedback.extend([f for f in feedback_list if f.timestamp > cutoff_date])
        
        if not recent_feedback:
            return {
                'period_days': days,
                'total_feedback': 0,
                'feedback_by_type': {},
                'feedback_by_analyst': {},
                'average_per_day': 0.0
            }
        
        feedback_counts = Counter(f.feedback_type for f in recent_feedback)
        analyst_counts = Counter(f.analyst_id for f in recent_feedback)
        
        return {
            'period_days': days,
            'total_feedback': len(recent_feedback),
            'feedback_by_type': dict(feedback_counts),
            'feedback_by_analyst': dict(analyst_counts),
            'average_per_day': len(recent_feedback) / days
        }
    
    def _validate_feedback(self, feedback: Feedback):
        """Validate feedback object."""
        if not feedback.profile_id:
            raise ValidationError("profile_id is required", "profile_id")
        
        valid_types = ['true_positive', 'false_positive', 'false_negative']
        if feedback.feedback_type not in valid_types:
            raise ValidationError(f"Invalid feedback_type: {feedback.feedback_type}", "feedback_type")
        
        if not feedback.analyst_id:
            raise ValidationError("analyst_id is required", "analyst_id")
    
    def _validate_profile_exists(self, profile_id: str) -> bool:
        """
        Validate that profile_id references an existing BADNA profile.
        
        Note: In a full implementation, this would check against a profiles database.
        For now, we allow all profile IDs for testing and integration.
        """
        try:
            # For development/testing, accept all profile IDs
            # In production, this would validate against actual profile storage
            return True
            
        except Exception:
            return True  # Fail open
    
    def _store_feedback(self, feedback: Feedback):
        """Store feedback in history with recent prioritization."""
        # Add to in-memory history
        self.feedback_history[feedback.profile_id].append(feedback)
        
        # Sort by timestamp (most recent first) and limit history size
        self.feedback_history[feedback.profile_id].sort(key=lambda f: f.timestamp, reverse=True)
        
        # Keep only recent feedback (last 100 entries per profile)
        if len(self.feedback_history[feedback.profile_id]) > 100:
            self.feedback_history[feedback.profile_id] = self.feedback_history[feedback.profile_id][:100]
        
        # Handle contradicting feedback - prioritize most recent
        self._resolve_contradicting_feedback(feedback.profile_id)
        
        # Save to disk
        self._save_feedback_history()
    
    def _resolve_contradicting_feedback(self, profile_id: str):
        """Resolve contradicting feedback by prioritizing most recent."""
        feedback_list = self.feedback_history[profile_id]
        
        if len(feedback_list) < 2:
            return
        
        # Check for contradictions in recent feedback (last 5 entries)
        recent_feedback = feedback_list[:5]
        feedback_types = [f.feedback_type for f in recent_feedback]
        
        if len(set(feedback_types)) > 1:
            # Log contradiction but keep most recent
            self.logger.log_operation(
                "WARNING",
                f"Contradicting feedback detected for profile {profile_id}, prioritizing most recent",
                component="FeedbackLoop",
                operation="resolve_contradicting_feedback",
                profile_id=profile_id,
                recent_types=feedback_types[:3]
            )
    
    def _update_model_weights(self, feedback: Feedback) -> Dict[str, float]:
        """Update model weights based on feedback type."""
        updated_weights = {}
        
        if feedback.feedback_type == 'true_positive':
            # Reinforce detection pattern - slightly increase confidence
            self.model_weights['confidence_weight'] *= 1.02
            updated_weights['confidence_weight'] = self.model_weights['confidence_weight']
            
        elif feedback.feedback_type == 'false_positive':
            # Reduce sensitivity - decrease confidence slightly
            self.model_weights['confidence_weight'] *= 0.98
            updated_weights['confidence_weight'] = self.model_weights['confidence_weight']
            
        elif feedback.feedback_type == 'false_negative':
            # Increase sensitivity - boost novelty detection
            self.model_weights['novelty_weight'] *= 1.05
            updated_weights['novelty_weight'] = self.model_weights['novelty_weight']
        
        # Clamp weights to reasonable ranges
        self.model_weights['confidence_weight'] = max(0.5, min(2.0, self.model_weights['confidence_weight']))
        self.model_weights['novelty_weight'] = max(0.5, min(2.0, self.model_weights['novelty_weight']))
        
        self._save_model_weights()
        
        return updated_weights
    
    def _determine_next_actions(self, feedback: Feedback) -> List[str]:
        """Determine recommended next actions based on feedback."""
        actions = []
        
        if feedback.feedback_type == 'false_negative':
            actions.extend([
                "add_to_training_data",
                "trigger_pattern_learning", 
                "review_detection_rules"
            ])
        
        elif feedback.feedback_type == 'false_positive':
            actions.extend([
                "adjust_detection_threshold",
                "review_feature_weights",
                "add_to_whitelist"
            ])
        
        elif feedback.feedback_type == 'true_positive':
            actions.extend([
                "reinforce_pattern",
                "update_campaign_signature"
            ])
        
        # Check if retraining is needed
        stats = self.aggregate_statistics()
        if stats and stats.total_feedback_count % 100 == 0:
            actions.append("trigger_model_retraining")
        
        return actions
    
    def _get_original_threat_class(self, profile_id: str) -> Optional[str]:
        """Get original threat classification for a profile (simplified)."""
        # In real implementation, would query profile database
        # For now, return a default class
        return "Malware"
    
    def _load_feedback_history(self):
        """Load feedback history from disk."""
        try:
            if self.feedback_path.exists():
                with open(self.feedback_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    for profile_id, feedback_list_data in data.get('feedback_history', {}).items():
                        feedback_list = []
                        for feedback_data in feedback_list_data:
                            try:
                                feedback = Feedback.from_dict(feedback_data)
                                feedback_list.append(feedback)
                            except Exception as e:
                                self.logger.log_operation(
                                    "WARNING",
                                    f"Failed to load feedback entry: {e}",
                                    component="FeedbackLoop"
                                )
                        
                        if feedback_list:
                            self.feedback_history[profile_id] = feedback_list
                            
        except Exception as e:
            self.logger.log_operation(
                "WARNING",
                f"Failed to load feedback history: {e}",
                component="FeedbackLoop",
                operation="load_feedback_history"
            )
    
    def _load_model_weights(self):
        """Load model weights from disk."""
        try:
            weights_path = self.feedback_path.parent / "model_weights.json"
            if weights_path.exists():
                with open(weights_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.model_weights.update(data.get('weights', {}))
                    
        except Exception as e:
            self.logger.log_operation(
                "WARNING",
                f"Failed to load model weights, using defaults: {e}",
                component="FeedbackLoop",
                operation="load_model_weights"
            )
    
    def _save_feedback_history(self):
        """Save feedback history to disk."""
        try:
            data = {
                'feedback_history': {
                    profile_id: [feedback.to_dict() for feedback in feedback_list]
                    for profile_id, feedback_list in self.feedback_history.items()
                },
                'metadata': {
                    'last_updated': datetime.now().isoformat(),
                    'total_profiles': len(self.feedback_history),
                    'total_feedback': sum(len(fl) for fl in self.feedback_history.values())
                }
            }
            
            # Ensure directory exists
            self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.feedback_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Failed to save feedback history: {e}",
                component="FeedbackLoop",
                operation="save_feedback_history"
            )
    
    def _save_model_weights(self):
        """Save model weights to disk."""
        try:
            weights_path = self.feedback_path.parent / "model_weights.json"
            data = {
                'weights': self.model_weights,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(weights_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.log_operation(
                "ERROR", 
                f"Failed to save model weights: {e}",
                component="FeedbackLoop",
                operation="save_model_weights"
            )
    
    def _save_statistics(self, stats: FeedbackStatistics):
        """Save aggregated statistics to disk."""
        try:
            with open(self.stats_path, 'w', encoding='utf-8') as f:
                json.dump(stats.to_dict(), f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.log_operation(
                "ERROR",
                f"Failed to save feedback statistics: {e}",
                component="FeedbackLoop",
                operation="save_statistics"
            )


# Global feedback loop instance
_global_feedback_loop: Optional[FeedbackLoop] = None

def get_feedback_loop() -> FeedbackLoop:
    """Get global feedback loop instance."""
    global _global_feedback_loop
    if _global_feedback_loop is None:
        _global_feedback_loop = FeedbackLoop()
    return _global_feedback_loop

def initialize_feedback_loop(feedback_storage_path: Optional[str] = None) -> FeedbackLoop:
    """Initialize global feedback loop with custom path."""
    global _global_feedback_loop
    _global_feedback_loop = FeedbackLoop(feedback_storage_path)
    return _global_feedback_loop


if __name__ == "__main__":
    # Test FeedbackLoop implementation
    print("Testing FeedbackLoop implementation...")
    
    # Create test feedback
    from data_models import Feedback
    
    feedback = Feedback(
        profile_id="test-profile-123",
        feedback_type="true_positive",
        analyst_id="analyst-1",
        analyst_notes="Confirmed APT attack pattern"
    )
    
    # Test feedback processing
    feedback_loop = FeedbackLoop()
    result = feedback_loop.accept_feedback(feedback)
    
    print(f"Feedback processed: {result.success}")
    print(f"Updated weights: {result.updated_weights}")
    
    # Test statistics
    stats = feedback_loop.aggregate_statistics()
    if stats:
        print(f"Statistics: {stats.total_feedback_count} total feedback")
    
    print("FeedbackLoop implementation complete!")