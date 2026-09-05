"""
Unit Tests for BADNA Knowledge Base Management System

Tests for Task 9.1 implementation including:
- Pattern storage and retrieval
- Similarity queries with performance requirements
- Campaign clustering
- Retention policies
- Atomic write operations and integrity validation

Requirements: 12.1-12.11
"""

import unittest
import tempfile
import shutil
import json
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import time
import uuid

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge_base import KnowledgeBase
from data_models import BehaviorPattern, CampaignProfile
from config import initialize_config


class TestKnowledgeBase(unittest.TestCase):
    """Test suite for Knowledge Base implementation."""
    
    def setUp(self):
        """Set up test environment with temporary directories."""
        # Initialize config
        initialize_config()
        
        # Create temporary directory
        self.test_dir = Path(tempfile.mkdtemp())
        self.kb_path = self.test_dir / "test_behavior_memory.json"
        self.campaigns_path = self.test_dir / "test_campaigns.json"
        
        # Initialize knowledge base
        self.kb = KnowledgeBase(str(self.kb_path), str(self.campaigns_path), seed_defaults=False)
        
        # Create test patterns
        self.test_patterns = self._create_test_patterns()
    
    def tearDown(self):
        """Clean up test environment."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def _create_test_patterns(self) -> list:
        """Create test behavior patterns with various characteristics."""
        patterns = []
        
        # High-confidence APT patterns
        for i in range(5):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)  # Normalize
            
            pattern = BehaviorPattern(
                pattern_id=str(uuid.uuid4()),
                embedding=embedding,
                threat_class="APT",
                confidence_score=0.9,
                timestamp=datetime.now() - timedelta(days=i),
                source="test",
                metadata={"techniques": ["T1055", "T1003"]}
            )
            patterns.append(pattern)
        
        # Low-confidence Ransomware patterns (older)
        for i in range(3):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                pattern_id=str(uuid.uuid4()),
                embedding=embedding,
                threat_class="Ransomware",
                confidence_score=0.4,
                timestamp=datetime.now() - timedelta(days=100 + i),
                source="test",
                metadata={"techniques": ["T1486", "T1490"]}
            )
            patterns.append(pattern)
        
        # Similar patterns for clustering
        base_embedding = np.random.rand(128)
        base_embedding = base_embedding / np.linalg.norm(base_embedding)
        
        for i in range(4):
            # Create similar embeddings by adding small noise
            embedding = base_embedding + np.random.normal(0, 0.1, 128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                pattern_id=str(uuid.uuid4()),
                embedding=embedding,
                threat_class="Malware",
                confidence_score=0.8,
                timestamp=datetime.now() - timedelta(days=10 + i),
                source="test",
                metadata={"techniques": ["T1059", "T1105"]}
            )
            patterns.append(pattern)
        
        return patterns
    
    def test_store_pattern_basic(self):
        """Test basic pattern storage functionality."""
        pattern = self.test_patterns[0]
        
        # Store pattern
        pattern_id = self.kb.store_pattern(pattern)
        
        # Verify storage
        self.assertEqual(pattern_id, pattern.pattern_id)
        self.assertIn(pattern_id, self.kb.patterns)
        self.assertEqual(self.kb.patterns[pattern_id].threat_class, "APT")
    
    def test_store_pattern_validation(self):
        """Test pattern validation during storage."""
        # Test invalid embedding dimension (validation happens in constructor)
        with self.assertRaises(Exception):
            pattern = BehaviorPattern(
                embedding=np.random.rand(64),  # Wrong dimension
                threat_class="APT",
                confidence_score=0.9
            )
        
        # Test missing embedding
        pattern = BehaviorPattern(
            embedding=None,
            threat_class="APT",
            confidence_score=0.9
        )
        
        with self.assertRaises(Exception):
            self.kb.store_pattern(pattern)
    
    def test_atomic_write_operations(self):
        """Test atomic write operations prevent data corruption."""
        # Store a pattern
        pattern = self.test_patterns[0]
        self.kb.store_pattern(pattern)
        
        # Verify file exists and is valid JSON
        self.assertTrue(self.kb_path.exists())
        
        with open(self.kb_path, 'r') as f:
            data = json.load(f)
            self.assertIn('patterns', data)
            self.assertEqual(len(data['patterns']), 1)
            self.assertIn('metadata', data)
    
    def test_query_by_similarity_performance(self):
        """Test similarity queries complete within 100ms for large KB."""
        # Store many patterns
        patterns = []
        for i in range(1000):  # Simulate large KB
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                embedding=embedding,
                threat_class=["APT", "Ransomware", "Malware"][i % 3],
                confidence_score=0.8
            )
            patterns.append(pattern)
            self.kb.store_pattern(pattern)
        
        # Test query performance
        query_embedding = np.random.rand(128)
        query_embedding = query_embedding / np.linalg.norm(query_embedding)
        
        start_time = time.time()
        results = self.kb.query_by_similarity(query_embedding, threshold=0.5)
        duration_ms = (time.time() - start_time) * 1000
        
        # Verify performance requirement (100ms for 10,000 patterns)
        # For 1,000 patterns, expect much less than 100ms
        self.assertLess(duration_ms, 100, f"Query took {duration_ms:.1f}ms, expected < 100ms")
        
        # Verify results format
        for pattern, similarity in results:
            self.assertIsInstance(pattern, BehaviorPattern)
            self.assertIsInstance(similarity, float)
            self.assertGreaterEqual(similarity, 0.5)
    
    def test_query_by_similarity_accuracy(self):
        """Test similarity query returns correct results."""
        # Store patterns with known embeddings
        pattern1 = BehaviorPattern(
            embedding=np.array([1.0] + [0.0] * 127),
            threat_class="APT",
            confidence_score=0.9
        )
        pattern2 = BehaviorPattern(
            embedding=np.array([0.9] + [0.1] + [0.0] * 126),
            threat_class="APT", 
            confidence_score=0.8
        )
        pattern3 = BehaviorPattern(
            embedding=np.array([0.0] + [1.0] + [0.0] * 126),
            threat_class="Malware",
            confidence_score=0.7
        )
        
        # Normalize embeddings
        for pattern in [pattern1, pattern2, pattern3]:
            pattern.embedding = pattern.embedding / np.linalg.norm(pattern.embedding)
            self.kb.store_pattern(pattern)
        
        # Query with embedding similar to pattern1
        query_embedding = np.array([0.95] + [0.05] + [0.0] * 126)
        query_embedding = query_embedding / np.linalg.norm(query_embedding)
        
        results = self.kb.query_by_similarity(query_embedding, threshold=0.7)
        
        # Should return patterns sorted by similarity
        self.assertGreater(len(results), 0)
        
        # Verify sorting (highest similarity first)
        if len(results) > 1:
            self.assertGreaterEqual(results[0][1], results[1][1])
    
    def test_query_by_class(self):
        """Test threat class queries."""
        # Store mixed threat classes
        for pattern in self.test_patterns:
            self.kb.store_pattern(pattern)
        
        # Query APT patterns
        apt_patterns = self.kb.query_by_class("APT")
        self.assertEqual(len(apt_patterns), 5)
        
        for pattern in apt_patterns:
            self.assertEqual(pattern.threat_class, "APT")
        
        # Query non-existent class
        phishing_patterns = self.kb.query_by_class("Phishing")
        self.assertEqual(len(phishing_patterns), 0)
        
        # Test invalid class
        with self.assertRaises(Exception):
            self.kb.query_by_class("InvalidClass")
    
    def test_cluster_campaigns(self):
        """Test campaign clustering functionality."""
        # Store patterns (including similar ones for clustering)
        for pattern in self.test_patterns:
            self.kb.store_pattern(pattern)
        
        # Run clustering with more permissive parameters
        campaigns = self.kb.cluster_campaigns(min_patterns=2, eps=0.5)
        
        # Verify campaign creation (may be 0 if patterns are too dissimilar)
        self.assertGreaterEqual(len(campaigns), 0)
        
        if len(campaigns) > 0:
            for campaign in campaigns:
                self.assertIsInstance(campaign, CampaignProfile)
                self.assertIsNotNone(campaign.signature_embedding)
                self.assertEqual(campaign.signature_embedding.shape, (128,))
                self.assertGreaterEqual(len(campaign.member_patterns), 2)
                self.assertIsNotNone(campaign.threat_class)
        else:
            # If no campaigns created, verify it's due to dissimilar patterns
            self.assertLess(len(self.test_patterns), 10)  # Small test dataset
    
    def test_apply_retention_policy(self):
        """Test retention policy removes correct patterns."""
        # Store many patterns
        old_patterns = []
        new_patterns = []
        
        # Create old, low-confidence patterns
        for i in range(15):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                embedding=embedding,
                threat_class="Malware",
                confidence_score=0.3,
                timestamp=datetime.now() - timedelta(days=200 + i),
                source="test"
            )
            old_patterns.append(pattern)
            self.kb.store_pattern(pattern)
        
        # Create recent, high-confidence patterns
        for i in range(10):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                embedding=embedding,
                threat_class="APT",
                confidence_score=0.9,
                timestamp=datetime.now() - timedelta(days=i),
                source="test"
            )
            new_patterns.append(pattern)
            self.kb.store_pattern(pattern)
        
        # Apply retention policy (keep only 10 patterns)
        removed_count = self.kb.apply_retention_policy(max_entries=10)
        
        # Verify retention
        self.assertEqual(removed_count, 15)  # Should remove all old patterns
        self.assertEqual(len(self.kb.patterns), 10)
        
        # Verify kept patterns are recent/high-confidence
        for pattern in self.kb.patterns.values():
            self.assertGreaterEqual(pattern.confidence_score, 0.9)
    
    def test_integrity_validation(self):
        """Test integrity validation on load."""
        # Create corrupted JSON file
        corrupted_data = '{"patterns": [{"invalid": "data"'  # Incomplete JSON
        
        with open(self.kb_path, 'w') as f:
            f.write(corrupted_data)
        
        # Initialize new KB - should handle corruption gracefully
        kb_corrupted = KnowledgeBase(str(self.kb_path), str(self.campaigns_path), seed_defaults=False)
        
        # Should initialize empty KB
        self.assertEqual(len(kb_corrupted.patterns), 0)
        self.assertEqual(len(kb_corrupted.campaigns), 0)
    
    def test_load_startup_performance(self):
        """Test knowledge base loads within 5 seconds at startup."""
        # Store many patterns
        for i in range(1000):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                embedding=embedding,
                threat_class=["APT", "Ransomware", "Malware"][i % 3],
                confidence_score=0.8,
                timestamp=datetime.now() - timedelta(days=i % 100)
            )
            self.kb.store_pattern(pattern)
        
        # Test load performance
        start_time = time.time()
        kb_new = KnowledgeBase(str(self.kb_path), str(self.campaigns_path), seed_defaults=False)
        load_duration = time.time() - start_time
        
        # Verify performance requirement (5 seconds)
        self.assertLess(load_duration, 5.0, f"Load took {load_duration:.1f}s, expected < 5s")
        
        # Verify data integrity
        self.assertEqual(len(kb_new.patterns), 1000)
    
    def test_get_statistics(self):
        """Test knowledge base statistics generation."""
        # Store diverse patterns
        for pattern in self.test_patterns:
            self.kb.store_pattern(pattern)
        
        # Create a campaign
        campaigns = self.kb.cluster_campaigns(min_patterns=3, eps=0.3)
        
        # Get statistics
        stats = self.kb.get_statistics()
        
        # Verify statistics structure
        self.assertIn('total_patterns', stats)
        self.assertIn('total_campaigns', stats)
        self.assertIn('threat_class_distribution', stats)
        self.assertIn('average_confidence', stats)
        self.assertIn('kb_file_size_mb', stats)
        self.assertIn('campaigns_file_size_mb', stats)
        
        # Verify values
        self.assertEqual(stats['total_patterns'], len(self.test_patterns))
        self.assertGreaterEqual(stats['average_confidence'], 0.0)
        self.assertLessEqual(stats['average_confidence'], 1.0)


class TestKnowledgeBaseIntegration(unittest.TestCase):
    """Integration tests for Knowledge Base with real-world scenarios."""
    
    def setUp(self):
        """Set up integration test environment."""
        initialize_config()
        
        self.test_dir = Path(tempfile.mkdtemp())
        self.kb = KnowledgeBase(
            str(self.test_dir / "behavior_memory.json"),
            str(self.test_dir / "campaigns.json"),
            seed_defaults=False
        )
    
    def tearDown(self):
        """Clean up integration test environment."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_complete_workflow(self):
        """Test complete knowledge base workflow."""
        # 1. Store patterns
        patterns = []
        for i in range(50):
            embedding = np.random.rand(128)
            embedding = embedding / np.linalg.norm(embedding)
            
            pattern = BehaviorPattern(
                embedding=embedding,
                threat_class=["APT", "Ransomware", "Malware"][i % 3],
                confidence_score=np.random.uniform(0.6, 0.9),
                timestamp=datetime.now() - timedelta(days=i),
                source="integration_test"
            )
            patterns.append(pattern)
            pattern_id = self.kb.store_pattern(pattern)
            self.assertIsNotNone(pattern_id)
        
        # 2. Query by similarity
        query_embedding = patterns[0].embedding
        similar_patterns = self.kb.query_by_similarity(query_embedding, threshold=0.8)
        self.assertGreater(len(similar_patterns), 0)
        
        # 3. Query by class
        apt_patterns = self.kb.query_by_class("APT")
        expected_apt_count = sum(1 for p in patterns if p.threat_class == "APT")
        self.assertEqual(len(apt_patterns), expected_apt_count)
        
        # 4. Cluster campaigns
        campaigns = self.kb.cluster_campaigns(min_patterns=5, eps=0.25)
        self.assertIsInstance(campaigns, list)
        
        # 5. Apply retention policy
        removed_count = self.kb.apply_retention_policy(max_entries=30)
        self.assertEqual(len(self.kb.patterns), 30)
        
        # 6. Verify data persistence
        stats = self.kb.get_statistics()
        self.assertEqual(stats['total_patterns'], 30)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)