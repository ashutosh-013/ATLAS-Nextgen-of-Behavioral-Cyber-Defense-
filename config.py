"""
BADNA Configuration Management and Error Handling Framework

This module provides:
1. Configuration loading from JSON/YAML files with validation
2. Custom exception classes for different error types
3. Structured logging infrastructure with JSON format
4. Graceful degradation strategies for non-critical failures

Requirements: 18.1-18.12, 17.1-17.10, 19.1-19.8
"""

import json
import yaml
import logging
import logging.handlers
import os
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path


# =============================================================================
# Custom Exception Classes
# =============================================================================

class BADNAError(Exception):
    """Base exception class for all BADNA errors."""
    def __init__(self, message: str, error_code: str = "BADNA_ERROR", context: Optional[Dict] = None):
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context
        }


class ValidationError(BADNAError):
    """Raised when input validation fails."""
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        context = {}
        if field:
            context["field"] = field
        if value is not None:
            context["invalid_value"] = str(value)
        super().__init__(message, "VALIDATION_ERROR", context)


class ProcessingError(BADNAError):
    """Raised when core processing operations fail."""
    def __init__(self, message: str, component: Optional[str] = None, operation: Optional[str] = None):
        context = {}
        if component:
            context["component"] = component
        if operation:
            context["operation"] = operation
        super().__init__(message, "PROCESSING_ERROR", context)


class ResourceError(BADNAError):
    """Raised when resource operations fail (memory, disk, etc.)."""
    def __init__(self, message: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None):
        context = {}
        if resource_type:
            context["resource_type"] = resource_type
        if resource_id:
            context["resource_id"] = resource_id
        super().__init__(message, "RESOURCE_ERROR", context)


class IntegrationError(BADNAError):
    """Raised when external system integration fails."""
    def __init__(self, message: str, system: Optional[str] = None, endpoint: Optional[str] = None):
        context = {}
        if system:
            context["system"] = system
        if endpoint:
            context["endpoint"] = endpoint
        super().__init__(message, "INTEGRATION_ERROR", context)


# =============================================================================
# Configuration Data Classes
# =============================================================================

@dataclass
class RiskThresholds:
    """Risk level threshold configuration."""
    critical: float = 0.85
    high: float = 0.70
    medium: float = 0.50
    low: float = 0.30

    def __post_init__(self):
        """Validate threshold ordering."""
        thresholds = [self.critical, self.high, self.medium, self.low]
        if thresholds != sorted(thresholds, reverse=True):
            raise ValidationError("Risk thresholds must be in descending order: critical >= high >= medium >= low")
        if any(t < 0.0 or t > 1.0 for t in thresholds):
            raise ValidationError("Risk thresholds must be between 0.0 and 1.0")


@dataclass
class BADNAConfig:
    """Main BADNA system configuration."""
    
    # Core algorithm parameters
    embedding_dimensions: int = 128
    similarity_threshold: float = 0.70
    novelty_threshold: float = 0.80
    confidence_threshold: float = 0.60
    
    # Risk scoring thresholds
    risk_thresholds: RiskThresholds = None
    
    # Storage and processing limits
    knowledge_base_path: str = "knowledge_base/"
    max_graph_size: int = 1000
    batch_size: int = 20
    
    # Performance tuning
    max_memory_mb: int = 4096
    query_timeout_ms: int = 100
    processing_timeout_s: int = 30
    
    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = "logs/badna.log"
    max_log_size_mb: int = 100
    log_backup_count: int = 5
    
    # API settings
    api_port: int = 8080
    api_host: str = "localhost"
    rate_limit_requests_per_minute: int = 60
    
    def __post_init__(self):
        """Post-initialization validation and setup."""
        if self.risk_thresholds is None:
            self.risk_thresholds = RiskThresholds()
            
        self._validate_configuration()
    
    def _validate_configuration(self):
        """Validate all configuration parameters."""
        # Validate dimensions
        if self.embedding_dimensions != 128:
            raise ValidationError("embedding_dimensions must be 128", "embedding_dimensions", self.embedding_dimensions)
        
        # Validate thresholds
        thresholds = {
            "similarity_threshold": self.similarity_threshold,
            "novelty_threshold": self.novelty_threshold,
            "confidence_threshold": self.confidence_threshold
        }
        
        for name, value in thresholds.items():
            if not 0.0 <= value <= 1.0:
                raise ValidationError(f"{name} must be between 0.0 and 1.0", name, value)
        
        # Validate positive integers
        positive_ints = {
            "max_graph_size": self.max_graph_size,
            "batch_size": self.batch_size,
            "max_memory_mb": self.max_memory_mb,
            "query_timeout_ms": self.query_timeout_ms,
            "processing_timeout_s": self.processing_timeout_s,
            "api_port": self.api_port,
            "max_log_size_mb": self.max_log_size_mb,
            "log_backup_count": self.log_backup_count,
            "rate_limit_requests_per_minute": self.rate_limit_requests_per_minute
        }
        
        for name, value in positive_ints.items():
            if not isinstance(value, int) or value <= 0:
                raise ValidationError(f"{name} must be a positive integer", name, value)
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            raise ValidationError(f"log_level must be one of {valid_log_levels}", "log_level", self.log_level)
        
        # Validate log format
        if self.log_format not in ["json", "text"]:
            raise ValidationError("log_format must be 'json' or 'text'", "log_format", self.log_format)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = asdict(self)
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BADNAConfig':
        """Create configuration from dictionary."""
        # Handle nested RiskThresholds
        if 'risk_thresholds' in data and isinstance(data['risk_thresholds'], dict):
            data['risk_thresholds'] = RiskThresholds(**data['risk_thresholds'])
        
        return cls(**data)


# =============================================================================
# Configuration Manager
# =============================================================================

class ConfigurationManager:
    """Manages BADNA system configuration loading and validation."""
    
    DEFAULT_CONFIG_PATHS = [
        "config.json",
        "config.yaml",
        "config.yml",
        "badna_config.json",
        "badna_config.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: Optional[BADNAConfig] = None
        self._logger = logging.getLogger(__name__)
    
    def load_configuration(self, config_path: Optional[str] = None) -> BADNAConfig:
        """
        Load configuration from file with fallback to defaults.
        
        Args:
            config_path: Optional specific path to config file
            
        Returns:
            BADNAConfig instance
            
        Raises:
            ValidationError: If configuration validation fails
            ResourceError: If config file cannot be read
        """
        if config_path:
            self.config_path = config_path
        
        # Try to load from specified or default paths
        config_data = self._load_config_file()
        
        if config_data is None:
            # No config file found, use defaults
            self._logger.warning("No configuration file found, using defaults")
            self.config = BADNAConfig()
            self._save_default_config()
        else:
            # Load from file data
            try:
                self.config = BADNAConfig.from_dict(config_data)
                self._logger.info(f"Configuration loaded from {self.config_path}")
            except Exception as e:
                self._logger.error(f"Failed to parse configuration: {e}")
                raise ValidationError(f"Invalid configuration format: {e}")
        
        return self.config
    
    def _load_config_file(self) -> Optional[Dict[str, Any]]:
        """Load configuration data from file."""
        paths_to_try = []
        
        if self.config_path:
            paths_to_try.append(self.config_path)
        else:
            paths_to_try.extend(self.DEFAULT_CONFIG_PATHS)
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    return self._read_config_file(path)
                except Exception as e:
                    self._logger.error(f"Failed to read config file {path}: {e}")
                    raise ResourceError(f"Cannot read configuration file: {e}", "file", path)
        
        return None
    
    def _read_config_file(self, path: str) -> Dict[str, Any]:
        """Read and parse configuration file."""
        with open(path, 'r', encoding='utf-8') as f:
            if path.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f) or {}
            else:
                return json.load(f)
    
    def _save_default_config(self):
        """Save default configuration to file."""
        if not self.config_path:
            self.config_path = self.DEFAULT_CONFIG_PATHS[0]
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path) or '.', exist_ok=True)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith(('.yaml', '.yml')):
                    yaml.dump(self.config.to_dict(), f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config.to_dict(), f, indent=2)
            
            self._logger.info(f"Default configuration saved to {self.config_path}")
        except Exception as e:
            self._logger.warning(f"Could not save default configuration: {e}")
    
    def get_config(self) -> BADNAConfig:
        """Get current configuration, loading if necessary."""
        if self.config is None:
            return self.load_configuration()
        return self.config
    
    def validate_runtime_config(self) -> bool:
        """Validate configuration against runtime constraints."""
        try:
            if not self.config:
                return False
            
            # Check if knowledge base path is accessible
            kb_path = Path(self.config.knowledge_base_path)
            if not kb_path.exists():
                kb_path.mkdir(parents=True, exist_ok=True)
            
            # Check if log directory is writable
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            return True
            
        except Exception as e:
            self._logger.error(f"Runtime configuration validation failed: {e}")
            return False


# =============================================================================
# Structured Logging Infrastructure
# =============================================================================

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add custom fields from extra
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        # Add error code if this is a BADNA error
        if hasattr(record, 'error_code'):
            log_entry["error_code"] = record.error_code
        
        return json.dumps(log_entry, ensure_ascii=False)


class BADNALogger:
    """BADNA-specific logger with structured output and error codes."""
    
    def __init__(self, config: BADNAConfig):
        self.config = config
        self.logger = logging.getLogger("BADNA")
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure logger based on configuration."""
        # Set level
        level = getattr(logging, self.config.log_level.upper())
        self.logger.setLevel(level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        # File handler with rotation
        try:
            # Ensure log directory exists
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.log_file,
                maxBytes=self.config.max_log_size_mb * 1024 * 1024,
                backupCount=self.config.log_backup_count
            )
            file_handler.setLevel(level)
        except Exception as e:
            print(f"Warning: Could not create file handler: {e}")
            file_handler = None
        
        # Set formatters
        if self.config.log_format == "json":
            formatter = JSONFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(formatter)
        if file_handler:
            file_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        if file_handler:
            self.logger.addHandler(file_handler)
    
    def log_operation(self, level: str, message: str, component: str = None, 
                     operation: str = None, duration_ms: float = None, **kwargs):
        """Log an operation with structured data."""
        extra_fields = {
            "operation_type": "system_operation"
        }
        
        if component:
            extra_fields["component"] = component
        if operation:
            extra_fields["operation"] = operation
        if duration_ms is not None:
            extra_fields["duration_ms"] = duration_ms
        
        extra_fields.update(kwargs)
        
        log_level = getattr(logging, level.upper())
        self.logger.log(log_level, message, extra={"extra_fields": extra_fields})
    
    def log_error(self, error: BADNAError, context: Dict[str, Any] = None):
        """Log a BADNA error with structured information."""
        extra_fields = {
            "operation_type": "error",
            "error_code": error.error_code,
            "error_context": error.context
        }
        
        if context:
            extra_fields["additional_context"] = context
        
        self.logger.error(
            error.message,
            extra={"extra_fields": extra_fields, "error_code": error.error_code},
            exc_info=True
        )
    
    def log_threat_detection(self, profile_id: str, threat_class: str, 
                           risk_score: float, confidence: float, **kwargs):
        """Log threat detection with security-specific fields."""
        extra_fields = {
            "operation_type": "threat_detection",
            "profile_id": profile_id,
            "threat_class": threat_class,
            "risk_score": risk_score,
            "confidence": confidence
        }
        extra_fields.update(kwargs)
        
        self.logger.info(
            f"Threat detected: {threat_class} (Risk: {risk_score:.2f}, Confidence: {confidence:.2f})",
            extra={"extra_fields": extra_fields}
        )
    
    def log_analysis_operation(self, operation: str, duration_ms: float, 
                             events_processed: int = None, status: str = "success", **kwargs):
        """Log analysis operations with performance metrics."""
        extra_fields = {
            "operation_type": "analysis",
            "operation": operation,
            "duration_ms": duration_ms,
            "status": status
        }
        
        if events_processed is not None:
            extra_fields["events_processed"] = events_processed
        
        extra_fields.update(kwargs)
        
        level = logging.INFO if status == "success" else logging.WARNING
        self.logger.log(
            level,
            f"Analysis operation '{operation}' completed in {duration_ms:.1f}ms",
            extra={"extra_fields": extra_fields}
        )


# =============================================================================
# Graceful Degradation Strategies
# =============================================================================

class GracefulDegradation:
    """Implements graceful degradation strategies for non-critical failures."""
    
    def __init__(self, config: BADNAConfig, logger: BADNALogger):
        self.config = config
        self.logger = logger
        self.degraded_components = set()
        self.fallback_strategies = {
            "knowledge_base": self._fallback_empty_kb,
            "embedding": self._fallback_zero_embedding,
            "similarity": self._fallback_low_similarity,
            "novelty": self._fallback_high_novelty,
            "classification": self._fallback_unknown_class,
            "confidence": self._fallback_conservative_confidence,
            "FeedbackLoop": self._fallback_feedback_error,
            "ModelEvolution": self._fallback_model_error,
            "KnowledgeUpdater": self._fallback_update_error,
            "d-BEF": self._fallback_zero_embedding,
            "BSF": self._fallback_low_similarity,
            "NSF": self._fallback_high_novelty,
            "CCF": self._fallback_conservative_confidence,
            "AIInvestigator": self._fallback_unknown_class,
            "RiskScorer": self._fallback_conservative_risk,
            "AdaptiveDefenseIntelligence": self._fallback_minimal_defense,
            "BehaviorCaptureEngine": self._fallback_minimal_graph
        }
    
    def handle_component_failure(self, component: str, error: Exception, 
                               fallback_data: Any = None) -> Any:
        """
        Handle component failure with graceful degradation.
        
        Args:
            component: Name of failed component
            error: The exception that occurred
            fallback_data: Optional fallback data
            
        Returns:
            Fallback result for the component
        """
        if component not in self.fallback_strategies:
            raise ProcessingError(f"No fallback strategy for component: {component}")
        
        self.degraded_components.add(component)
        
        # Log the degradation
        self.logger.log_operation(
            "WARNING",
            f"Component '{component}' failed, using fallback strategy",
            component=component,
            error_type=type(error).__name__,
            error_message=str(error)
        )
        
        # Apply fallback strategy
        return self.fallback_strategies[component](fallback_data)
    
    def is_degraded(self, component: str = None) -> bool:
        """Check if system or specific component is in degraded mode."""
        if component:
            return component in self.degraded_components
        return bool(self.degraded_components)
    
    def get_degraded_components(self) -> set:
        """Get set of currently degraded components."""
        return self.degraded_components.copy()
    
    def _fallback_empty_kb(self, data: Any) -> Dict:
        """Fallback for knowledge base failures."""
        return {"patterns": [], "campaigns": []}
    
    def _fallback_zero_embedding(self, data: Any) -> 'np.ndarray':
        """Fallback for embedding generation failures."""
        import numpy as np
        return np.zeros(self.config.embedding_dimensions)
    
    def _fallback_low_similarity(self, data: Any) -> float:
        """Fallback for similarity computation failures."""
        return 0.0
    
    def _fallback_high_novelty(self, data: Any) -> float:
        """Fallback for novelty detection failures."""
        return 1.0  # Assume highly novel if detection fails
    
    def _fallback_unknown_class(self, data: Any) -> str:
        """Fallback for classification failures."""
        return "Unknown"
    
    def _fallback_conservative_confidence(self, data: Any) -> float:
        """Fallback for confidence calibration failures."""
        return 0.5  # Conservative confidence
    
    def _fallback_feedback_error(self, data: Any) -> Any:
        """Fallback for feedback processing failures."""
        from learning.feedback import FeedbackResult
        return FeedbackResult(
            success=False,
            updated_weights={},
            next_actions=[],
            aggregated_stats={},
            message="Feedback processing failed, using fallback"
        )
    
    def _fallback_model_error(self, data: Any) -> Any:
        """Fallback for model evolution failures."""
        return {"success": False, "message": "Model operation failed, using fallback"}
    
    def _fallback_update_error(self, data: Any) -> Any:
        """Fallback for knowledge update failures."""
        return {"success": False, "message": "Knowledge update failed, using fallback"}
    
    def _fallback_conservative_risk(self, data: Any) -> Any:
        """Fallback for risk scoring failures."""
        from data_models import RiskScore
        return RiskScore(
            profile_id=str(uuid.uuid4()),
            score=0.7,  # Conservative high risk
            risk_level="High",
            contributing_factors={"fallback": "Risk scoring failed, using conservative estimate"},
            rationale="Risk scoring component failed - using conservative high-risk estimate for safety"
        )
    
    def _fallback_minimal_defense(self, data: Any) -> Any:
        """Fallback for adaptive defense intelligence failures."""
        from intelligence.adaptive_defense import DefenseRecommendations
        return DefenseRecommendations(
            profile_id=str(uuid.uuid4()),
            threat_class="Unknown",
            risk_level="High",
            recommendations=[{
                "priority": "High",
                "category": "Incident_Response", 
                "action": "Manual investigation required due to system degradation",
                "rationale": "Defense intelligence component failed - manual review needed"
            }],
            immediate_actions=["Initiate manual threat investigation"],
            generated_at=datetime.now()
        )
    
    def _fallback_minimal_graph(self, data: Any) -> Any:
        """Fallback for behavior capture engine failures."""
        from data_models import BehaviorGraph, BehaviorNode, BehaviorEdge
        # Create minimal graph with single node
        node = BehaviorNode(
            node_id="fallback_node",
            action_type="unknown",
            attributes={"fallback": True, "reason": "Behavior capture failed"}
        )
        graph = BehaviorGraph(
            graph_id=str(uuid.uuid4()),
            nodes=[node],
            edges=[],
            metadata={"degraded": True, "reason": "Behavior capture engine failure"}
        )
        return graph


# =============================================================================
# Global Configuration Instance
# =============================================================================

# Global configuration manager instance
_config_manager: Optional[ConfigurationManager] = None
_logger: Optional[BADNALogger] = None
_degradation: Optional[GracefulDegradation] = None


def initialize_config(config_path: Optional[str] = None) -> BADNAConfig:
    """
    Initialize global configuration and logging.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Loaded BADNAConfig instance
    """
    global _config_manager, _logger, _degradation
    
    _config_manager = ConfigurationManager(config_path)
    config = _config_manager.load_configuration()
    
    # Initialize logger
    _logger = BADNALogger(config)
    
    # Initialize graceful degradation
    _degradation = GracefulDegradation(config, _logger)
    
    _logger.log_operation("INFO", "BADNA configuration initialized successfully")
    
    return config


def get_config() -> BADNAConfig:
    """Get global configuration instance."""
    if _config_manager is None:
        return initialize_config()
    return _config_manager.get_config()


def get_logger() -> BADNALogger:
    """Get global logger instance."""
    if _logger is None:
        initialize_config()
    return _logger


def get_degradation() -> GracefulDegradation:
    """Get global graceful degradation handler."""
    if _degradation is None:
        initialize_config()
    return _degradation


# =============================================================================
# Utility Functions
# =============================================================================

def validate_input_data(data: Any, schema: Dict[str, Any], context: str = "input") -> None:
    """
    Validate input data against schema.
    
    Args:
        data: Data to validate
        schema: Validation schema
        context: Context for error messages
        
    Raises:
        ValidationError: If validation fails
    """
    # Basic type checking
    if "type" in schema:
        expected_type = schema["type"]
        if expected_type == "dict" and not isinstance(data, dict):
            raise ValidationError(f"{context} must be a dictionary")
        elif expected_type == "list" and not isinstance(data, list):
            raise ValidationError(f"{context} must be a list")
        elif expected_type == "str" and not isinstance(data, str):
            raise ValidationError(f"{context} must be a string")
        elif expected_type == "int" and not isinstance(data, int):
            raise ValidationError(f"{context} must be an integer")
        elif expected_type == "float" and not isinstance(data, (int, float)):
            raise ValidationError(f"{context} must be a number")
    
    # Required fields checking
    if isinstance(data, dict) and "required" in schema:
        for field in schema["required"]:
            if field not in data:
                raise ValidationError(f"Required field '{field}' missing in {context}", field)
    
    # Range checking for numbers
    if isinstance(data, (int, float)) and "range" in schema:
        min_val, max_val = schema["range"]
        if not (min_val <= data <= max_val):
            raise ValidationError(f"{context} must be between {min_val} and {max_val}", value=data)


def handle_processing_error(error: Exception, component: str, operation: str, 
                          fallback_value: Any = None, critical: bool = False) -> Any:
    """
    Handle processing errors with optional fallback.
    
    Args:
        error: The exception that occurred
        component: Component where error occurred
        operation: Operation being performed
        fallback_value: Value to return if not critical
        critical: Whether this is a critical error
        
    Returns:
        Fallback value or raises error if critical
        
    Raises:
        ProcessingError: If error is critical
    """
    logger = get_logger()
    
    if isinstance(error, BADNAError):
        logger.log_error(error)
    else:
        processing_error = ProcessingError(str(error), component, operation)
        logger.log_error(processing_error)
    
    if critical:
        raise ProcessingError(f"Critical failure in {component}.{operation}: {error}")
    
    # Use graceful degradation
    degradation = get_degradation()
    return degradation.handle_component_failure(component, error, fallback_value)


if __name__ == "__main__":
    # Demo/test the configuration system
    try:
        print("Initializing BADNA configuration...")
        config = initialize_config()
        
        print(f"Configuration loaded:")
        print(f"  Embedding dimensions: {config.embedding_dimensions}")
        print(f"  Similarity threshold: {config.similarity_threshold}")
        print(f"  Knowledge base path: {config.knowledge_base_path}")
        print(f"  Log level: {config.log_level}")
        
        logger = get_logger()
        logger.log_operation("INFO", "Configuration demo completed successfully")
        
    except Exception as e:
        print(f"Configuration failed: {e}")