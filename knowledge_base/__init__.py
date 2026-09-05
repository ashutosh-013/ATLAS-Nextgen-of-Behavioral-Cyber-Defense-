"""
BADNA Knowledge Base Module

This module provides persistent storage and querying capabilities for the
BADNA behavioral analysis framework.

Key Components:
- KnowledgeBase: Main class for pattern storage and retrieval
- Atomic write operations for data integrity
- Similarity-based pattern queries
- Campaign clustering functionality
- Retention policy management

Requirements: 12.1-12.11
Task: 9.1 - Implement knowledge base storage and querying
"""

from .knowledge_base import KnowledgeBase, get_knowledge_base, initialize_knowledge_base

__all__ = [
    'KnowledgeBase',
    'get_knowledge_base', 
    'initialize_knowledge_base'
]

__version__ = '1.0.0'