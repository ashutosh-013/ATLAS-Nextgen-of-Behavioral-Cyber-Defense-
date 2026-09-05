"""
Privacy Layer & Sensitive Data Sanitization Engine for ATLAS

Provides automated redaction of sensitive user data (passwords, auth tokens, API keys,
credit cards, SSNs, and PII) from telemetry events, command lines, logs, and database records
before persistence or web dashboard SSE streaming.
"""

import re
import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger("privacy_sanitizer")


@dataclass
class SanitizationReport:
    original_text: str
    sanitized_text: str
    redactions_made: int = 0
    categories_redacted: List[str] = field(default_factory=list)


class PrivacyLayerEngine:
    """
    Enterprise Data Privacy and Sanitization Engine.
    """

    def __init__(self, enable_anonymization: bool = True):
        self.enable_anonymization = enable_anonymization
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex redaction rules for passwords, keys, and PII."""
        self.rules = [
            # 1. Bearer Tokens and API Keys
            ("BEARER_TOKEN", re.compile(r"(?i)Bearer\s+[A-Za-z0-9_\-\.]{15,}")),
            ("API_KEY_OPENAI", re.compile(r"(?i)sk-proj-[A-Za-z0-9_-]{20,}")),
            ("API_KEY_AWS", re.compile(r"(?i)AKIA[0-9A-Z]{16}")),
            ("GENERIC_SECRET_KEY", re.compile(r"(?i)(api[_-]?key|secret|token|auth_header)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{12,}['\"]?")),

            # 2. Command Line Passwords
            ("CLI_PASSWORD_PARAM", re.compile(r"(?i)(--password[= ]|-pass[= ]|password[= ]|pass[= ]|-p\s*['\"]?)([^\s'\"]{3,})")),
            ("NET_USE_PASSWORD", re.compile(r"(?i)net\s+use.*?\s+([^\s]{3,})$")),

            # 3. PII (Credit Cards & SSNs)
            ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
            ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"))
        ]

        # User home path anonymization regex
        self.user_path_regex = re.compile(r"(?i)(C:\\Users\\|/home/|/Users/)([^\\/]+)")

    def sanitize_text(self, text: str) -> SanitizationReport:
        """
        Sanitize string content by redacting sensitive tokens and PII.
        """
        if not text or not isinstance(text, str):
            return SanitizationReport(original_text="", sanitized_text="")

        sanitized = text
        redactions = 0
        categories = []

        for category, pattern in self.rules:
            if pattern.search(sanitized):
                if category == "CLI_PASSWORD_PARAM":
                    sanitized = pattern.sub(r"\1 [REDACTED_PASSWORD]", sanitized)
                elif category == "BEARER_TOKEN":
                    sanitized = pattern.sub("Bearer [REDACTED_TOKEN]", sanitized)
                elif category == "EMAIL_ADDRESS":
                    sanitized = pattern.sub("[REDACTED_EMAIL]", sanitized)
                elif category == "CREDIT_CARD":
                    sanitized = pattern.sub("[REDACTED_CC]", sanitized)
                elif category == "SSN":
                    sanitized = pattern.sub("[REDACTED_SSN]", sanitized)
                else:
                    sanitized = pattern.sub(f"[{category}_REDACTED]", sanitized)
                
                redactions += 1
                categories.append(category)

        # Anonymize user home directory paths if enabled
        if self.enable_anonymization and self.user_path_regex.search(sanitized):
            sanitized = self.user_path_regex.sub(r"\1[REDACTED_USER]", sanitized)

        return SanitizationReport(
            original_text=text,
            sanitized_text=sanitized,
            redactions_made=redactions,
            categories_redacted=categories
        )

    def sanitize_event_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary attributes (command lines, paths, payloads).
        """
        if not isinstance(data, dict):
            return data

        sanitized_dict = {}
        for key, val in data.items():
            if isinstance(val, str):
                sanitized_dict[key] = self.sanitize_text(val).sanitized_text
            elif isinstance(val, dict):
                sanitized_dict[key] = self.sanitize_event_dict(val)
            elif isinstance(val, list):
                sanitized_dict[key] = [
                    self.sanitize_event_dict(item) if isinstance(item, dict)
                    else (self.sanitize_text(item).sanitized_text if isinstance(item, str) else item)
                    for item in val
                ]
            else:
                sanitized_dict[key] = val

        return sanitized_dict


# Global Singleton Privacy Engine Instance
_GLOBAL_PRIVACY_ENGINE: Optional[PrivacyLayerEngine] = None


def get_privacy_engine() -> PrivacyLayerEngine:
    """Get global Privacy Layer Engine singleton instance."""
    global _GLOBAL_PRIVACY_ENGINE
    if _GLOBAL_PRIVACY_ENGINE is None:
        _GLOBAL_PRIVACY_ENGINE = PrivacyLayerEngine()
    return _GLOBAL_PRIVACY_ENGINE
