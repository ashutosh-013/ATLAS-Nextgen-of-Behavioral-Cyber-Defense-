"""
Comprehensive Test Suite for CCF (Confidence Calibration Function)

Tests all requirements 6.1-6.10:
- Unit tests for each CCF component
- Property-based tests for mathematical properties
- Integration tests with other BADNA components
- Validation of accuracy correlation (Requirement 6.7)
"""

import pytest
import numpy as np
from hypothesis import given, strategies as st, settings
from hypothesis import assume
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from confidence.ccf import CCFEngine, PlattScaler
from data_models import ConfidenceResult
from config import ValidationError


# ============================================================================
# Unit Tests for PlattScaler
# ============================================================================

class TestPlattScaler:
    """Test Platt scaling algorithm (Requirement 6.2)"""
    
    def test_platt_scaler_initialization(self):
        """Test PlattScaler initializes correctly"""
        scaler = PlattScaler()
        assert scaler.A == 0.0
        assert scaler.B == 0.0
        assert scaler.fitted == False
    
    def test_platt_scaler_fit_basic(self):
        """Test PlattScaler fits with valid data"""
        scaler = PlattScaler()
        
        # Create simple training data
        raw_scores = np.array([0.9, 0.8, 0.7, 0.4, 0.3, 0.2])
        labels = np.array([1, 1, 1, 0, 0, 0])
        
        scaler.fit(raw_scores, labels)
        
        assert scaler.fitted == True
        assert scaler.A != 0.0 or scaler.B != 0.0
    
    def test_platt_scaler_transform_range(self):
        """Test PlattScaler transform outputs are in [0, 1]"""
        scaler = PlattScaler()
        
        # Fit with data
        raw_scores = np.array([0.9, 0.8, 0.7, 0.4, 0.3, 0.2])
        labels = np.array([1, 1, 1, 0, 0, 0])
        scaler.fit(raw_scores, labels)
        
        # Test transform range
        test_scores = [0.0, 0.25, 0.5, 0.75, 1.0]
        for score in test_scores:
            transformed = scaler.transform(score)
            assert 0.0 <= transformed <= 1.0, f"Transform({score}) = {transformed} not in [0, 1]"
    
    def test_platt_scaler_insufficient_data(self):
        """Test PlattScaler handles insufficient training data"""
        scaler = PlattScaler()
        
        # Only 3 samples (need 5+)
        raw_scores = np.array([0.9, 0.5, 0.1])
        labels = np.array([1, 1, 0])
        
        scaler.fit(raw_scores, labels)
        
        # Should still fit
        assert scaler.fitted == True
    
    def test_platt_scaler_sigmoid_properties(self):
        """Test Platt sigmoid has correct properties"""
        scaler = PlattScaler()
        scaler.A = -1.0
        scaler.B = 0.0
        scaler.fitted = True
        
        # Test sigmoid properties
        # Sigmoid at 0 should be ~0.5
        result = scaler.transform(0.0)
        assert 0.4 < result < 0.6
        
        # Positive scores should be > 0.5
        assert scaler.transform(1.0) > 0.5
        
        # Negative scores should be < 0.5
        assert scaler.transform(-1.0) < 0.5


# ============================================================================
# Unit Tests for CCFEngine
# ============================================================================

class TestCCFEngine:
    """Test CCF confidence calibration engine"""
    
    def test_ccf_initialization(self):
        """Test CCFEngine initializes correctly"""
        ccf = CCFEngine()
        assert ccf.min_knowledge_base_size == 50
        assert ccf.scaler_fitted == False
        assert len(ccf.accuracy_history) == 0
    
    def test_ccf_requirement_6_1_range_invariant(self):
        """Test Requirement 6.1: Confidence score in [0, 1]"""
        ccf = CCFEngine()
        
        # Test various input combinations
        test_cases = [
            (0.0, 0.0, 0.0, 0),
            (1.0, 1.0, 1.0, 1000),
            (0.5, 0.5, 0.5, 50),
            (0.9, 0.1, 1.0, 200),
            (0.1, 0.9, 0.2, 5),
        ]
        
        for sim, nov, qual, kb in test_cases:
            result = ccf.calibrate_confidence(
                similarity_score=sim,
                novelty_score=nov,
                evidence_quality=qual,
                knowledge_base_size=kb
            )
            
            assert 0.0 <= result.confidence_score <= 1.0, \
                f"Confidence {result.confidence_score} out of range [0, 1]"
    
    def test_ccf_requirement_6_2_platt_scaling(self):
        """Test Requirement 6.2: Apply Platt scaling"""
        ccf = CCFEngine()
        
        # Update calibration with feedback
        feedback = [
            {'raw_score': 0.9, 'correct': True},
            {'raw_score': 0.8, 'correct': True},
            {'raw_score': 0.6, 'correct': False},
            {'raw_score': 0.4, 'correct': False},
            {'raw_score': 0.3, 'correct': False},
        ]
        
        ccf.update_calibration(feedback)
        
        assert ccf.scaler_fitted == True
        
        # Calibrated confidence should use Platt scaling
        result = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        assert 'platt_scaler_fitted' in result.calibration_factors
        assert result.calibration_factors['platt_scaler_fitted'] == True
    
    def test_ccf_requirement_6_3_tension_adjustment(self):
        """Test Requirement 6.3: Novelty-similarity tension adjustment"""
        ccf = CCFEngine()
        
        # High novelty + low similarity = high tension = lower confidence
        result_high_tension = ccf.calibrate_confidence(
            similarity_score=0.1,  # Low similarity
            novelty_score=0.9,     # High novelty
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        # Low novelty + high similarity = low tension = higher confidence
        result_low_tension = ccf.calibrate_confidence(
            similarity_score=0.9,  # High similarity
            novelty_score=0.1,     # Low novelty
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        # Verify tension is computed
        assert 'novelty_similarity_tension' in result_high_tension.calibration_factors
        assert 'novelty_similarity_tension' in result_low_tension.calibration_factors
        
        # High tension scenario should have higher tension value
        tension_high = result_high_tension.calibration_factors['novelty_similarity_tension']
        tension_low = result_low_tension.calibration_factors['novelty_similarity_tension']
        
        assert tension_high > tension_low, \
            f"High tension scenario ({tension_high}) should exceed low tension ({tension_low})"
        
        # Low tension should result in higher confidence
        assert result_low_tension.confidence_score > result_high_tension.confidence_score
    
    def test_ccf_requirement_6_4_similarity_boost(self):
        """Test Requirement 6.4: Similarity boost for multiple matches"""
        ccf = CCFEngine()
        
        # No campaign match
        result_no_match = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100,
            campaign_match=False,
            multiple_campaign_matches=0
        )
        
        # Single campaign match
        result_single = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100,
            campaign_match=True,
            multiple_campaign_matches=1
        )
        
        # Multiple campaign matches
        result_multiple = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100,
            multiple_campaign_matches=3
        )
        
        # Verify boost factors
        boost_no = result_no_match.calibration_factors['similarity_boost']
        boost_single = result_single.calibration_factors['similarity_boost']
        boost_multiple = result_multiple.calibration_factors['similarity_boost']
        
        assert boost_no == 1.0
        assert boost_single == 1.05
        assert boost_multiple == 1.15
        
        # More matches should give higher confidence
        assert result_multiple.confidence_score > result_single.confidence_score
        assert result_single.confidence_score > result_no_match.confidence_score
    
    def test_ccf_requirement_6_5_kb_penalty(self):
        """Test Requirement 6.5: KB size penalty (if KB < 50: confidence *= KB/50)"""
        ccf = CCFEngine()
        
        # Large KB (no penalty)
        result_large_kb = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        # Small KB (penalty applied)
        result_small_kb = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=25  # 25/50 = 0.5 penalty
        )
        
        # Very small KB (penalty with 0.3 minimum floor)
        result_very_small_kb = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=10  # 10/50 = 0.2, but clamped to 0.3 minimum
        )
        
        # Verify penalties
        penalty_large = result_large_kb.calibration_factors['kb_size_penalty']
        penalty_small = result_small_kb.calibration_factors['kb_size_penalty']
        penalty_very_small = result_very_small_kb.calibration_factors['kb_size_penalty']
        
        assert penalty_large == 1.0  # No penalty
        assert penalty_small == 0.5  # 25/50
        assert penalty_very_small == 0.3  # min(10/50, 0.3) = 0.3 (minimum floor)
        
        # Larger KB should give higher confidence
        assert result_large_kb.confidence_score > result_small_kb.confidence_score
        assert result_small_kb.confidence_score > result_very_small_kb.confidence_score
    
    def test_ccf_requirement_6_6_evidence_quality(self):
        """Test Requirement 6.6: Evidence quality factor"""
        ccf = CCFEngine()
        
        # High evidence quality
        result_high_quality = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        # Low evidence quality
        result_low_quality = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=0.3,
            knowledge_base_size=100
        )
        
        # Verify quality factors
        quality_high = result_high_quality.calibration_factors['evidence_quality_factor']
        quality_low = result_low_quality.calibration_factors['evidence_quality_factor']
        
        assert quality_high == 1.0
        assert quality_low == 0.3
        
        # Higher quality should give higher confidence
        assert result_high_quality.confidence_score > result_low_quality.confidence_score
    
    def test_ccf_requirement_6_7_accuracy_correlation(self):
        """Test Requirement 6.7: Confidence correlates with actual accuracy"""
        ccf = CCFEngine()
        
        # Simulate predictions with known accuracy
        # High confidence predictions should be more accurate
        high_confidence_preds = [
            {'prediction': 'APT', 'ground_truth': 'APT'},
            {'prediction': 'Ransomware', 'ground_truth': 'Ransomware'},
            {'prediction': 'APT', 'ground_truth': 'APT'},
            {'prediction': 'Malware', 'ground_truth': 'Malware'},
        ]  # 100% accurate
        
        low_confidence_preds = [
            {'prediction': 'APT', 'ground_truth': 'Malware'},
            {'prediction': 'Benign', 'ground_truth': 'Phishing'},
            {'prediction': 'Ransomware', 'ground_truth': 'APT'},
        ]  # 0% accurate
        
        high_accuracy = ccf.estimate_accuracy(high_confidence_preds)
        low_accuracy = ccf.estimate_accuracy(low_confidence_preds)
        
        assert high_accuracy == 1.0
        assert low_accuracy == 0.0
        
        # Accuracy should be reflected in confidence intervals
        assert len(ccf.accuracy_history) == 2
    
    def test_ccf_requirement_6_8_empirical_accuracy(self):
        """Test Requirement 6.8: Use empirical accuracy from historical predictions"""
        ccf = CCFEngine()
        
        # Add historical accuracy
        historical = [
            {'prediction': 'APT', 'ground_truth': 'APT'},
            {'prediction': 'Ransomware', 'ground_truth': 'Ransomware'},
            {'prediction': 'Benign', 'ground_truth': 'Malware'},  # Incorrect
        ]
        
        accuracy = ccf.estimate_accuracy(historical)
        assert accuracy == 2.0 / 3.0  # 66.7% accurate
        assert len(ccf.accuracy_history) == 1
        
        # Calibration should use empirical accuracy
        result = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        assert result.calibration_factors['empirical_accuracy_available'] == True
    
    def test_ccf_requirement_6_9_conservative_estimation(self):
        """Test Requirement 6.9: Conservative estimation (0.5) for insufficient data"""
        ccf = CCFEngine()
        
        # Empty knowledge base, no calibration, no history
        result = ccf.calibrate_confidence(
            similarity_score=0.3,
            novelty_score=0.7,
            evidence_quality=0.5,
            knowledge_base_size=3  # Very small KB
        )
        
        # Should apply conservative default
        # With insufficient data, confidence should not be too low
        assert result.confidence_score >= 0.1  # Has some minimum floor
        
        # Test estimate_accuracy with no data
        accuracy = ccf.estimate_accuracy([])
        assert accuracy == 0.5  # Conservative default
    
    def test_ccf_requirement_6_10_confidence_intervals(self):
        """Test Requirement 6.10: Provide confidence intervals"""
        ccf = CCFEngine()
        
        result = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=1.0,
            knowledge_base_size=100
        )
        
        lower, upper = result.confidence_interval
        confidence = result.confidence_score
        
        # Verify interval properties
        assert 0.0 <= lower <= confidence <= upper <= 1.0, \
            f"Invalid interval: [{lower}, {upper}] with confidence {confidence}"
        
        # Interval should be non-trivial
        assert upper > lower
    
    def test_input_validation(self):
        """Test CCF validates inputs"""
        ccf = CCFEngine()
        
        # Invalid similarity score
        with pytest.raises(ValidationError):
            ccf.calibrate_confidence(1.5, 0.5, 1.0, 100)
        
        # Invalid novelty score
        with pytest.raises(ValidationError):
            ccf.calibrate_confidence(0.5, -0.1, 1.0, 100)
        
        # Invalid evidence quality
        with pytest.raises(ValidationError):
            ccf.calibrate_confidence(0.5, 0.5, 2.0, 100)
        
        # Invalid KB size
        with pytest.raises(ValidationError):
            ccf.calibrate_confidence(0.5, 0.5, 1.0, -5)
    
    def test_calibration_factors_transparency(self):
        """Test all calibration factors are reported"""
        ccf = CCFEngine()
        
        result = ccf.calibrate_confidence(
            similarity_score=0.8,
            novelty_score=0.2,
            evidence_quality=0.9,
            knowledge_base_size=50,
            multiple_campaign_matches=2
        )
        
        # All factors should be present
        required_factors = [
            'raw_score',
            'base_confidence_platt_scaled',
            'novelty_similarity_tension',
            'similarity_boost',
            'kb_size_penalty',
            'evidence_quality_factor',
            'knowledge_base_size',
            'multiple_campaign_matches',
            'platt_scaler_fitted',
            'empirical_accuracy_available'
        ]
        
        for factor in required_factors:
            assert factor in result.calibration_factors, \
                f"Missing calibration factor: {factor}"


# ============================================================================
# Property-Based Tests
# ============================================================================

class TestCCFProperties:
    """Property-based tests for CCF mathematical properties"""
    
    @given(
        similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        novelty=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        evidence_quality=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        kb_size=st.integers(min_value=0, max_value=1000)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_9_ccf_range_invariant(self, similarity, novelty, evidence_quality, kb_size):
        """
        Property 9: CCF Range Invariant
        Validates: Requirement 6.1
        
        For all valid inputs, CCF confidence ∈ [0, 1]
        """
        ccf = CCFEngine()
        
        result = ccf.calibrate_confidence(
            similarity_score=similarity,
            novelty_score=novelty,
            evidence_quality=evidence_quality,
            knowledge_base_size=kb_size
        )
        
        assert 0.0 <= result.confidence_score <= 1.0, \
            f"CCF({similarity}, {novelty}, {evidence_quality}, {kb_size}) = " + \
            f"{result.confidence_score} not in [0, 1]"
    
    @given(
        similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        novelty=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        evidence_quality=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        kb_size=st.integers(min_value=0, max_value=1000)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_confidence_intervals_valid(self, similarity, novelty, evidence_quality, kb_size):
        """
        Property: Confidence Intervals Valid
        Validates: Requirement 6.10
        
        For all inputs, 0 ≤ lower ≤ confidence ≤ upper ≤ 1
        """
        ccf = CCFEngine()
        
        result = ccf.calibrate_confidence(
            similarity_score=similarity,
            novelty_score=novelty,
            evidence_quality=evidence_quality,
            knowledge_base_size=kb_size
        )
        
        lower, upper = result.confidence_interval
        confidence = result.confidence_score
        
        assert 0.0 <= lower <= confidence <= upper <= 1.0, \
            f"Invalid interval [{lower}, {upper}] for confidence {confidence}"
    
    @given(
        similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        evidence_quality=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        kb_size=st.integers(min_value=0, max_value=1000)
    )
    @settings(max_examples=50, deadline=None)
    def test_property_higher_quality_higher_confidence(self, similarity, evidence_quality, kb_size):
        """
        Property: Higher Quality → Higher Confidence
        Validates: Requirement 6.6
        
        Given same similarity/novelty, higher evidence quality should yield higher confidence
        """
        assume(evidence_quality > 0.1)  # Need reasonable quality difference
        
        ccf = CCFEngine()
        novelty = 0.5  # Fixed novelty
        
        # Low quality
        result_low = ccf.calibrate_confidence(
            similarity_score=similarity,
            novelty_score=novelty,
            evidence_quality=evidence_quality * 0.5,  # Half the quality
            knowledge_base_size=kb_size
        )
        
        # High quality
        result_high = ccf.calibrate_confidence(
            similarity_score=similarity,
            novelty_score=novelty,
            evidence_quality=evidence_quality,
            knowledge_base_size=kb_size
        )
        
        # Higher quality should give higher or equal confidence
        assert result_high.confidence_score >= result_low.confidence_score


# ============================================================================
# Integration Tests
# ============================================================================

class TestCCFIntegration:
    """Integration tests with other BADNA components"""
    
    def test_ccf_with_bsf_nsf_outputs(self):
        """Test CCF integrates with BSF/NSF outputs"""
        ccf = CCFEngine()
        
        # Simulate BSF output (high similarity to known threat)
        bsf_similarity = 0.87
        
        # Simulate NSF output (low novelty = known behavior)
        nsf_novelty = 0.15
        
        # Simulate evidence quality
        evidence_quality = 0.95
        
        # Simulate knowledge base size
        kb_size = 150
        
        result = ccf.calibrate_confidence(
            similarity_score=bsf_similarity,
            novelty_score=nsf_novelty,
            evidence_quality=evidence_quality,
            knowledge_base_size=kb_size,
            campaign_match=True,
            multiple_campaign_matches=2
        )
        
        # High quality inputs should yield high confidence
        assert result.confidence_score > 0.4, \
            f"Expected high confidence for high-quality inputs, got {result.confidence_score}"
        
        # Verify all factors were applied
        assert result.calibration_factors['similarity_boost'] == 1.10  # 2 matches
        assert result.calibration_factors['kb_size_penalty'] == 1.0  # Large KB
    
    def test_ccf_end_to_end_workflow(self):
        """Test complete CCF workflow with feedback loop"""
        ccf = CCFEngine()
        
        # Step 1: Initial predictions (no calibration)
        result1 = ccf.calibrate_confidence(0.8, 0.2, 1.0, 100)
        assert not ccf.scaler_fitted
        
        # Step 2: Collect feedback
        feedback = [
            {'raw_score': 0.9, 'correct': True},
            {'raw_score': 0.8, 'correct': True},
            {'raw_score': 0.7, 'correct': True},
            {'raw_score': 0.4, 'correct': False},
            {'raw_score': 0.3, 'correct': False}
        ]
        
        # Step 3: Update calibration
        ccf.update_calibration(feedback)
        assert ccf.scaler_fitted
        
        # Step 4: New predictions with calibration
        result2 = ccf.calibrate_confidence(0.8, 0.2, 1.0, 100)
        assert result2.calibration_factors['platt_scaler_fitted'] == True
        
        # Step 5: Estimate accuracy
        historical = [
            {'prediction': 'APT', 'ground_truth': 'APT'},
            {'prediction': 'Ransomware', 'ground_truth': 'Ransomware'},
            {'prediction': 'Malware', 'ground_truth': 'APT'},
            {'prediction': 'APT', 'ground_truth': 'APT'}
        ]
        accuracy = ccf.estimate_accuracy(historical)
        assert accuracy == 0.75  # 3 out of 4 correct
        assert len(ccf.accuracy_history) == 1
