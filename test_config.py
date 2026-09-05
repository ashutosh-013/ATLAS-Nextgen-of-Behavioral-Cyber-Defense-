"""
Comprehensive tests for BADNA configuration management and error handling framework.

Tests coverage for Requirements:
- 18.1-18.12: Configuration Management  
- 17.1-17.10: Data Input Validation and Error Handling
- 19.1-19.8: Logging and Monitoring
"""

import pytest
import json
import yaml
import tempfile
import os
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock
import numpy as np

from config import (
    BADNAConfig, ConfigurationManager, BADNALogger, GracefulDegradation,
    ValidationError, ProcessingError, ResourceError, IntegrationError,
    RiskThresholds, initialize_config, get_config, get_logger, get_degradation,
    validate_input_data, handle_processing_error, JSONFormatter
)


class TestCustomExceptions:
    """Test custom exception classes - Requirements 17.1-17.10"""
    
    def test_validation_error_creation(self):
        """Test ValidationError with field and value context"""
        error = ValidationError("Invalid threshold", field="similarity_threshold", value=1.5)
        assert error.message == "Invalid threshold"
        assert error.error_code == "VALIDATION_ERROR"
        assert error.context["field"] == "similarity_threshold"
        assert error.context["invalid_value"] == "1.5"
        
        error_dict = error.to_dict()
        assert error_dict["error_type"] == "ValidationError"
        assert error_dict["error_code"] == "VALIDATION_ERROR"
    
    def test_processing_error_creation(self):
        """Test ProcessingError with component and operation context"""
        error = ProcessingError("Feature extraction failed", component="d-BEF", operation="compute_embedding")
        assert error.message == "Feature extraction failed"
        assert error.error_code == "PROCESSING_ERROR"
        assert error.context["component"] == "d-BEF"
        assert error.context["operation"] == "compute_embedding"
    
    def test_resource_error_creation(self):
        """Test ResourceError with resource type and ID"""
        error = ResourceError("Memory allocation failed", resource_type="memory", resource_id="embedding_cache")
        assert error.error_code == "RESOURCE_ERROR"
        assert error.context["resource_type"] == "memory"
        assert error.context["resource_id"] == "embedding_cache"
    
    def test_integration_error_creation(self):
        """Test IntegrationError with system and endpoint"""
        error = IntegrationError("API call failed", system="SIEM", endpoint="/api/events")
        assert error.error_code == "INTEGRATION_ERROR"
        assert error.context["system"] == "SIEM"
        assert error.context["endpoint"] == "/api/events"


class TestRiskThresholds:
    """Test RiskThresholds validation - Requirements 18.6"""
    
    def test_valid_risk_thresholds(self):
        """Test valid descending risk threshold configuration"""
        thresholds = RiskThresholds(critical=0.9, high=0.7, medium=0.5, low=0.3)
        assert thresholds.critical == 0.9
        assert thresholds.high == 0.7
        assert thresholds.medium == 0.5
        assert thresholds.low == 0.3
    
    def test_default_risk_thresholds(self):
        """Test default risk threshold values"""
        thresholds = RiskThresholds()
        assert thresholds.critical == 0.85
        assert thresholds.high == 0.70
        assert thresholds.medium == 0.50
        assert thresholds.low == 0.30
    
    def test_invalid_threshold_order(self):
        """Test validation error for incorrect threshold ordering"""
        with pytest.raises(ValidationError, match="Risk thresholds must be in descending order"):
            RiskThresholds(critical=0.5, high=0.7, medium=0.8, low=0.9)
    
    def test_threshold_out_of_range(self):
        """Test validation error for thresholds outside [0.0, 1.0] range"""
        with pytest.raises(ValidationError, match="Risk thresholds must be between 0.0 and 1.0"):
            RiskThresholds(critical=1.2, high=0.7, medium=0.5, low=0.3)
        
        with pytest.raises(ValidationError, match="Risk thresholds must be between 0.0 and 1.0"):
            RiskThresholds(critical=0.9, high=0.7, medium=0.5, low=-0.1)


class TestBADNAConfig:
    """Test BADNAConfig validation - Requirements 18.1-18.12"""
    
    def test_default_configuration_values(self):
        """Test default configuration parameters - Requirements 18.2-18.9"""
        config = BADNAConfig()
        
        # Core algorithm parameters
        assert config.embedding_dimensions == 128  # 18.2
        assert config.similarity_threshold == 0.70  # 18.3
        assert config.novelty_threshold == 0.80  # 18.4
        assert config.confidence_threshold == 0.60  # 18.5
        assert config.max_graph_size == 1000  # 18.8
        assert config.batch_size == 20  # 18.9
        
        # Risk thresholds - 18.6
        assert config.risk_thresholds.critical == 0.85
        assert config.risk_thresholds.high == 0.70
        
        # Knowledge base path - 18.7
        assert config.knowledge_base_path == "knowledge_base/"
    
    def test_embedding_dimensions_validation(self):
        """Test embedding_dimensions must be 128 - Requirement 18.2"""
        with pytest.raises(ValidationError, match="embedding_dimensions must be 128"):
            BADNAConfig(embedding_dimensions=256)
    
    def test_threshold_range_validation(self):
        """Test threshold values must be in [0.0, 1.0] range"""
        with pytest.raises(ValidationError, match="similarity_threshold must be between 0.0 and 1.0"):
            BADNAConfig(similarity_threshold=1.5)
        
        with pytest.raises(ValidationError, match="novelty_threshold must be between 0.0 and 1.0"):
            BADNAConfig(novelty_threshold=-0.1)
        
        with pytest.raises(ValidationError, match="confidence_threshold must be between 0.0 and 1.0"):
            BADNAConfig(confidence_threshold=1.2)
    
    def test_positive_integer_validation(self):
        """Test positive integer parameters validation"""
        with pytest.raises(ValidationError, match="max_graph_size must be a positive integer"):
            BADNAConfig(max_graph_size=0)
        
        with pytest.raises(ValidationError, match="batch_size must be a positive integer"):
            BADNAConfig(batch_size=-5)
        
        with pytest.raises(ValidationError, match="api_port must be a positive integer"):
            BADNAConfig(api_port=0)
    
    def test_log_level_validation(self):
        """Test log level validation - Requirement 19.7"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        
        for level in valid_levels:
            config = BADNAConfig(log_level=level)
            assert config.log_level == level
        
        with pytest.raises(ValidationError, match="log_level must be one of"):
            BADNAConfig(log_level="INVALID")
    
    def test_log_format_validation(self):
        """Test log format validation"""
        config = BADNAConfig(log_format="json")
        assert config.log_format == "json"
        
        config = BADNAConfig(log_format="text")
        assert config.log_format == "text"
        
        with pytest.raises(ValidationError, match="log_format must be 'json' or 'text'"):
            BADNAConfig(log_format="xml")
    
    def test_config_serialization(self):
        """Test configuration to_dict and from_dict methods"""
        config = BADNAConfig(
            embedding_dimensions=128,
            similarity_threshold=0.75,
            log_level="DEBUG"
        )
        
        config_dict = config.to_dict()
        assert config_dict["embedding_dimensions"] == 128
        assert config_dict["similarity_threshold"] == 0.75
        assert config_dict["log_level"] == "DEBUG"
        
        # Test round-trip
        restored_config = BADNAConfig.from_dict(config_dict)
        assert restored_config.embedding_dimensions == config.embedding_dimensions
        assert restored_config.similarity_threshold == config.similarity_threshold
        assert restored_config.log_level == config.log_level


class TestConfigurationManager:
    """Test configuration file loading and management - Requirements 18.10-18.12"""
    
    def test_load_configuration_from_json(self):
        """Test loading configuration from JSON file - Requirement 18.1"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {
                "embedding_dimensions": 128,
                "similarity_threshold": 0.75,
                "log_level": "DEBUG"
            }
            json.dump(config_data, f)
            f.flush()
            
        try:
            manager = ConfigurationManager(f.name)
            config = manager.load_configuration()
            
            assert config.embedding_dimensions == 128
            assert config.similarity_threshold == 0.75
            assert config.log_level == "DEBUG"
        finally:
            try:
                os.unlink(f.name)
            except PermissionError:
                pass  # Windows file permission issue
    
    def test_load_configuration_from_yaml(self):
        """Test loading configuration from YAML file - Requirement 18.1"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_data = {
                "embedding_dimensions": 128,
                "novelty_threshold": 0.85,
                "risk_thresholds": {
                    "critical": 0.90,
                    "high": 0.75,
                    "medium": 0.55,
                    "low": 0.35
                }
            }
            yaml.dump(config_data, f)
            f.flush()
            
        try:
            manager = ConfigurationManager(f.name)
            config = manager.load_configuration()
            
            assert config.embedding_dimensions == 128
            assert config.novelty_threshold == 0.85
            assert config.risk_thresholds.critical == 0.90
        finally:
            try:
                os.unlink(f.name)
            except PermissionError:
                pass  # Windows file permission issue
    
    def test_missing_config_file_uses_defaults(self):
        """Test default values when config file is missing - Requirement 18.10"""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ConfigurationManager(os.path.join(temp_dir, "nonexistent.json"))
            config = manager.load_configuration()
            
            # Should use default values
            assert config.embedding_dimensions == 128
            assert config.similarity_threshold == 0.70
            assert config.novelty_threshold == 0.80
    
    def test_invalid_config_file_raises_error(self):
        """Test error handling for invalid configuration files - Requirement 18.11, 17.3"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            f.flush()
            
        try:
            manager = ConfigurationManager(f.name)
            
            with pytest.raises(ResourceError):
                manager.load_configuration()
        finally:
            try:
                os.unlink(f.name)
            except PermissionError:
                pass  # Windows file permission issue
    
    def test_invalid_config_parameters(self):
        """Test validation error for invalid configuration parameters - Requirement 18.12"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {
                "embedding_dimensions": 256,  # Invalid - must be 128
                "similarity_threshold": 1.5   # Invalid - must be <= 1.0
            }
            json.dump(config_data, f)
            f.flush()
            
        try:
            manager = ConfigurationManager(f.name)
            
            with pytest.raises(ValidationError):
                manager.load_configuration()
        finally:
            try:
                os.unlink(f.name)
            except PermissionError:
                pass  # Windows file permission issue
    
    def test_runtime_config_validation(self):
        """Test runtime configuration validation"""
        manager = ConfigurationManager()
        config = manager.load_configuration()
        
        # Should create directories and validate paths
        assert manager.validate_runtime_config()
        
        # Check that knowledge base directory was created
        kb_path = Path(config.knowledge_base_path)
        assert kb_path.exists()


class TestJSONFormatter:
    """Test structured logging JSON formatter - Requirements 19.1-19.8"""
    
    def test_json_log_formatting(self):
        """Test JSON log format structure - Requirement 19.8"""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.module = "test_module"
        record.funcName = "test_function"
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert log_data["level"] == "INFO"
        assert log_data["component"] == "test_logger"
        assert log_data["message"] == "Test message"
        assert log_data["module"] == "test_module"
        assert log_data["function"] == "test_function"
        assert log_data["line"] == 42
        assert "timestamp" in log_data
    
    def test_json_formatter_with_extra_fields(self):
        """Test JSON formatter with custom extra fields"""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="badna",
            level=logging.WARNING,
            pathname="/test/path.py", 
            lineno=10,
            msg="Processing warning",
            args=(),
            exc_info=None
        )
        record.extra_fields = {
            "operation_type": "threat_detection",
            "profile_id": "test-uuid",
            "risk_score": 0.85
        }
        record.error_code = "PROC_WARN_001"
        
        formatted = formatter.format(record)
        log_data = json.loads(formatted)
        
        assert log_data["operation_type"] == "threat_detection"
        assert log_data["profile_id"] == "test-uuid"
        assert log_data["risk_score"] == 0.85
        assert log_data["error_code"] == "PROC_WARN_001"


class TestBADNALogger:
    """Test BADNA logger functionality - Requirements 19.1-19.8"""
    
    def test_logger_initialization(self):
        """Test logger setup with configuration"""
        config = BADNAConfig(
            log_level="DEBUG",
            log_format="json",
            log_file="test_logs/test.log",
            max_log_size_mb=50,
            log_backup_count=3
        )
        
        logger = BADNALogger(config)
        assert logger.config.log_level == "DEBUG"
        assert logger.logger.name == "BADNA"
    
    def test_log_operation(self):
        """Test operation logging with structured data - Requirement 19.1"""
        config = BADNAConfig(log_format="json")
        logger = BADNALogger(config)
        
        with patch.object(logger.logger, 'log') as mock_log:
            logger.log_operation(
                "INFO",
                "Analysis completed",
                component="d-BEF",
                operation="compute_embedding",
                duration_ms=150.5
            )
            
            mock_log.assert_called_once()
            call_args = mock_log.call_args
            
            assert call_args[0][0] == logging.INFO  # log level
            assert call_args[0][1] == "Analysis completed"  # message
            
            extra = call_args[1]["extra"]["extra_fields"]
            assert extra["operation_type"] == "system_operation"
            assert extra["component"] == "d-BEF"
            assert extra["operation"] == "compute_embedding"
            assert extra["duration_ms"] == 150.5
    
    def test_log_error(self):
        """Test error logging with BADNA error objects - Requirement 19.3"""
        config = BADNAConfig(log_format="json")
        logger = BADNALogger(config)
        
        error = ProcessingError("Test processing error", component="BSF", operation="similarity")
        
        with patch.object(logger.logger, 'error') as mock_error:
            logger.log_error(error, context={"input_size": 1000})
            
            mock_error.assert_called_once()
            call_args = mock_error.call_args
            
            assert call_args[0][0] == error.message
            
            extra = call_args[1]["extra"]
            assert extra["error_code"] == "PROCESSING_ERROR"
            
            extra_fields = extra["extra_fields"]
            assert extra_fields["operation_type"] == "error"
            assert extra_fields["error_code"] == "PROCESSING_ERROR"
            assert extra_fields["additional_context"]["input_size"] == 1000
    
    def test_log_threat_detection(self):
        """Test threat detection logging - Requirement 19.2"""
        config = BADNAConfig(log_format="json")
        logger = BADNALogger(config)
        
        with patch.object(logger.logger, 'info') as mock_info:
            logger.log_threat_detection(
                profile_id="uuid-123",
                threat_class="APT",
                risk_score=0.85,
                confidence=0.92
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args
            
            extra_fields = call_args[1]["extra"]["extra_fields"]
            assert extra_fields["operation_type"] == "threat_detection"
            assert extra_fields["profile_id"] == "uuid-123"
            assert extra_fields["threat_class"] == "APT"
            assert extra_fields["risk_score"] == 0.85
            assert extra_fields["confidence"] == 0.92
    
    def test_log_analysis_operation(self):
        """Test analysis operation logging with performance metrics - Requirement 19.10"""
        config = BADNAConfig(log_format="json")
        logger = BADNALogger(config)
        
        with patch.object(logger.logger, 'log') as mock_log:
            logger.log_analysis_operation(
                operation="embedding_generation",
                duration_ms=245.7,
                events_processed=1500,
                status="success"
            )
            
            mock_log.assert_called_once()
            call_args = mock_log.call_args
            
            assert call_args[0][0] == logging.INFO  # success -> INFO level
            
            extra_fields = call_args[1]["extra"]["extra_fields"]
            assert extra_fields["operation_type"] == "analysis"
            assert extra_fields["operation"] == "embedding_generation"
            assert extra_fields["duration_ms"] == 245.7
            assert extra_fields["events_processed"] == 1500
            assert extra_fields["status"] == "success"


class TestGracefulDegradation:
    """Test graceful degradation strategies - Requirements 17.8-17.10"""
    
    def setup_method(self):
        """Setup for each test"""
        config = BADNAConfig()
        logger = BADNALogger(config)
        self.degradation = GracefulDegradation(config, logger)
    
    def test_component_failure_fallback(self):
        """Test graceful degradation for component failures"""
        error = ProcessingError("Test failure")
        
        # Test knowledge base fallback
        result = self.degradation.handle_component_failure("knowledge_base", error)
        assert result == {"patterns": [], "campaigns": []}
        assert "knowledge_base" in self.degradation.degraded_components
    
    def test_embedding_fallback(self):
        """Test embedding generation fallback"""
        error = ResourceError("Memory allocation failed")
        
        result = self.degradation.handle_component_failure("embedding", error)
        assert isinstance(result, np.ndarray)
        assert result.shape == (128,)
        assert np.all(result == 0.0)
    
    def test_similarity_fallback(self):
        """Test similarity computation fallback"""
        error = ProcessingError("Similarity calculation failed")
        
        result = self.degradation.handle_component_failure("similarity", error)
        assert result == 0.0
    
    def test_novelty_fallback(self):
        """Test novelty detection fallback"""
        error = ProcessingError("Novelty detection failed")
        
        result = self.degradation.handle_component_failure("novelty", error)
        assert result == 1.0  # Assume highly novel
    
    def test_confidence_fallback(self):
        """Test confidence calibration fallback"""
        error = ProcessingError("Confidence calibration failed")
        
        result = self.degradation.handle_component_failure("confidence", error)
        assert result == 0.5  # Conservative confidence
    
    def test_degradation_status(self):
        """Test degradation status tracking"""
        assert not self.degradation.is_degraded()
        assert not self.degradation.is_degraded("knowledge_base")
        
        error = ProcessingError("Test failure")
        self.degradation.handle_component_failure("knowledge_base", error)
        
        assert self.degradation.is_degraded()
        assert self.degradation.is_degraded("knowledge_base")
        assert not self.degradation.is_degraded("similarity")
        
        degraded = self.degradation.get_degraded_components()
        assert "knowledge_base" in degraded


class TestInputValidation:
    """Test input validation functions - Requirements 17.1-17.7"""
    
    def test_validate_input_data_dict(self):
        """Test dictionary validation"""
        schema = {"type": "dict", "required": ["event_type", "timestamp"]}
        
        # Valid data
        valid_data = {"event_type": "process", "timestamp": "2024-01-01T12:00:00Z", "extra": "data"}
        validate_input_data(valid_data, schema)  # Should not raise
        
        # Invalid type
        with pytest.raises(ValidationError, match="input must be a dictionary"):
            validate_input_data("not a dict", schema)
        
        # Missing required field
        with pytest.raises(ValidationError, match="Required field 'event_type' missing"):
            validate_input_data({"timestamp": "2024-01-01T12:00:00Z"}, schema)
    
    def test_validate_input_data_list(self):
        """Test list validation"""
        schema = {"type": "list"}
        
        validate_input_data([1, 2, 3], schema)  # Should not raise
        
        with pytest.raises(ValidationError, match="input must be a list"):
            validate_input_data({"not": "a list"}, schema)
    
    def test_validate_input_data_types(self):
        """Test type validation for different data types"""
        # String validation
        validate_input_data("test string", {"type": "str"})
        with pytest.raises(ValidationError, match="input must be a string"):
            validate_input_data(123, {"type": "str"})
        
        # Integer validation  
        validate_input_data(42, {"type": "int"})
        with pytest.raises(ValidationError, match="input must be an integer"):
            validate_input_data("not int", {"type": "int"})
        
        # Float validation
        validate_input_data(3.14, {"type": "float"})
        validate_input_data(42, {"type": "float"})  # int should be valid for float
        with pytest.raises(ValidationError, match="input must be a number"):
            validate_input_data("not float", {"type": "float"})
    
    def test_validate_input_data_range(self):
        """Test range validation for numeric data"""
        schema = {"type": "float", "range": [0.0, 1.0]}
        
        validate_input_data(0.5, schema)  # Should not raise
        validate_input_data(0.0, schema)  # Boundary
        validate_input_data(1.0, schema)  # Boundary
        
        with pytest.raises(ValidationError, match="input must be between 0.0 and 1.0"):
            validate_input_data(1.5, schema)
        
        with pytest.raises(ValidationError, match="input must be between 0.0 and 1.0"):
            validate_input_data(-0.1, schema)


class TestErrorHandling:
    """Test error handling utilities - Requirements 17.8-17.10"""
    
    def test_handle_processing_error_critical(self):
        """Test critical error handling"""
        error = ProcessingError("Critical failure")
        
        with pytest.raises(ProcessingError, match="Critical failure in test.operation"):
            handle_processing_error(error, "test", "operation", critical=True)
    
    def test_handle_processing_error_non_critical(self):
        """Test non-critical error handling with fallback"""
        error = ProcessingError("Non-critical failure")
        
        # Test with a component that has a fallback strategy
        result = handle_processing_error(error, "similarity", "operation", fallback_value="fallback", critical=False)
        assert result == 0.0  # similarity fallback returns 0.0
    
    def test_handle_processing_error_badna_error(self):
        """Test handling of BADNA-specific errors"""
        error = ValidationError("Validation failed")
        
        # Test with a component that has a fallback strategy
        result = handle_processing_error(error, "novelty", "check", fallback_value=None, critical=False)
        assert result == 1.0  # novelty fallback returns 1.0


class TestGlobalConfiguration:
    """Test global configuration functions - Requirements 18.1, 18.10"""
    
    def test_initialize_config(self):
        """Test global configuration initialization"""
        config = initialize_config()
        assert isinstance(config, BADNAConfig)
        assert config.embedding_dimensions == 128
    
    def test_get_config(self):
        """Test get_config function"""
        config = get_config()
        assert isinstance(config, BADNAConfig)
    
    def test_get_logger(self):
        """Test get_logger function"""
        logger = get_logger()
        assert isinstance(logger, BADNALogger)
    
    def test_get_degradation(self):
        """Test get_degradation function"""
        degradation = get_degradation()
        assert isinstance(degradation, GracefulDegradation)


# Integration tests
class TestConfigurationIntegration:
    """Integration tests for complete configuration system"""
    
    def test_full_configuration_lifecycle(self):
        """Test complete configuration loading, validation, and usage"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                config_data = {
                    "embedding_dimensions": 128,
                    "similarity_threshold": 0.75,
                    "novelty_threshold": 0.85,
                    "confidence_threshold": 0.65,
                    "risk_thresholds": {
                        "critical": 0.90,
                        "high": 0.75,
                        "medium": 0.55,
                        "low": 0.35
                    },
                    "knowledge_base_path": "test_kb/",
                    "max_graph_size": 1500,
                    "batch_size": 25,
                    "log_level": "DEBUG",
                    "log_format": "json"
                }
                json.dump(config_data, f)
                f.flush()
                
                # Load configuration
                config = initialize_config(f.name)
                
                # Verify all parameters loaded correctly
                assert config.embedding_dimensions == 128
                assert config.similarity_threshold == 0.75
                assert config.novelty_threshold == 0.85
                assert config.confidence_threshold == 0.65
                assert config.risk_thresholds.critical == 0.90
                assert config.knowledge_base_path == "test_kb/"
                assert config.max_graph_size == 1500
                assert config.batch_size == 25
                assert config.log_level == "DEBUG"
                assert config.log_format == "json"
                
                # Test logger initialization
                logger = get_logger()
                assert logger.config == config
                
                # Test graceful degradation
                degradation = get_degradation()
                assert degradation.config == config
        finally:
            try:
                os.unlink(f.name)
            except (NameError, AttributeError, PermissionError):
                pass  # Windows file permission issue
    
    def test_error_handling_with_logging(self):
        """Test error handling integrates properly with logging"""
        config = BADNAConfig(log_format="json")
        logger = BADNALogger(config)
        degradation = GracefulDegradation(config, logger)
        
        error = ProcessingError("Test processing error", component="test", operation="operation")
        
        # Don't mock the logger since graceful degradation uses its own logging
        result = degradation.handle_component_failure("similarity", error)
        
        # Should return fallback value
        assert result == 0.0
        assert degradation.is_degraded("similarity")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])