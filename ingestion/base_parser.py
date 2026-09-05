"""
Base Parser Interface - Abstract base class for all dataset parsers

This module defines the interface that all dataset-specific parsers must implement.
Provides common functionality for parsing, validation, and normalization.

Task: 1.3 - Base Parser Interface
Integration: Inherited by all dataset parsers (Task 2.x)
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
from datetime import datetime
import logging

from .unified_schema import UnifiedEvent, EventType
from .dataset_registry import DatasetMetadata


class ParserError(Exception):
    """Base exception for parser errors"""
    pass


class ValidationError(ParserError):
    """Exception raised when record validation fails"""
    pass


class ParseError(ParserError):
    """Exception raised when parsing fails"""
    pass


class BaseDatasetParser(ABC):
    """
    Abstract base class for all dataset parsers.
    
    All dataset-specific parsers must inherit from this class and implement:
    - parse_file(): Parse raw dataset file into raw records
    - normalize_to_schema(): Convert raw record to UnifiedEvent format
    
    The base class provides:
    - Common logging infrastructure
    - Validation framework
    - Batch processing utilities
    - Error handling patterns
    - Statistics tracking
    
    Design Pattern:
    ---------------
    1. Subclass inherits BaseDatasetParser
    2. Implement parse_file() to read dataset-specific format
    3. Implement normalize_to_schema() to map fields to UnifiedEvent
    4. Use validate_record() for quality checks
    5. Call base class methods for logging/stats
    
    Example Subclass:
    -----------------
    class DARPAOpTCParser(BaseDatasetParser):
        def parse_file(self, filepath: Path) -> List[Dict]:
            # Read CDM JSON format
            with open(filepath) as f:
                return json.load(f)
        
        def normalize_to_schema(self, raw_record: Dict) -> UnifiedEvent:
            # Map CDM fields to UnifiedEvent
            return UnifiedEvent(
                event_id=raw_record['uuid'],
                event_type='process',
                timestamp=raw_record['timestampNanos'],
                event_data={'pid': raw_record['pid'], ...}
            )
    """
    
    def __init__(self, dataset_metadata: DatasetMetadata):
        """
        Initialize parser with dataset metadata.
        
        Args:
            dataset_metadata: Metadata from DatasetRegistry
        """
        self.metadata = dataset_metadata
        self.logger = self._setup_logger()
        self.stats = {
            'total_records': 0,
            'valid_records': 0,
            'invalid_records': 0,
            'parse_errors': 0,
            'validation_errors': 0
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup parser-specific logger"""
        logger = logging.getLogger(f"parser.{self.metadata.dataset_id}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'[%(asctime)s] {self.metadata.dataset_id} - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    @abstractmethod
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """
        Parse raw dataset file into list of raw records.
        
        This method handles dataset-specific file formats (JSON, CSV, XML, etc.)
        and returns raw records as dictionaries. No schema normalization yet.
        
        Args:
            filepath: Path to dataset file
            
        Returns:
            List of raw record dictionaries
            
        Raises:
            ParseError: If file cannot be parsed
            
        Implementation Notes:
        - Handle file format (JSON, CSV, XML, binary, etc.)
        - Extract individual records/events
        - Preserve all original fields
        - Return as list of dicts (even for streaming formats)
        - Log parsing progress for large files
        """
        pass
    
    @abstractmethod
    def normalize_to_schema(self, raw_record: Dict[str, Any]) -> UnifiedEvent:
        """
        Convert raw dataset record to UnifiedEvent format.
        
        This is the core transformation that maps dataset-specific fields
        to the UnifiedEvent schema required by BehaviorCaptureEngine.
        
        Args:
            raw_record: Raw record dictionary from parse_file()
            
        Returns:
            UnifiedEvent instance
            
        Raises:
            ValidationError: If record cannot be normalized
            
        Implementation Guide:
        --------------------
        1. Map event_type (process, file, network, auth, registry, user)
        2. Extract timestamp (handle dataset-specific formats)
        3. Generate unique event_id (or use existing ID)
        4. Map dataset fields to event_data structure
        5. Handle missing/optional fields gracefully
        6. Preserve important metadata in event_data
        
        Example:
        --------
        def normalize_to_schema(self, raw_record: Dict) -> UnifiedEvent:
            # Determine event type
            if 'process' in raw_record:
                event_type = 'process'
                event_data = {
                    'pid': raw_record['process']['pid'],
                    'action': 'create',
                    'name': raw_record['process']['name']
                }
            
            return UnifiedEvent(
                event_id=raw_record['id'],
                event_type=event_type,
                timestamp=raw_record['timestamp'],
                source_system=self.metadata.dataset_id,
                event_data=event_data
            )
        """
        pass
    
    def validate_record(self, event: UnifiedEvent) -> bool:
        """
        Validate that UnifiedEvent meets quality standards.
        
        Args:
            event: UnifiedEvent to validate
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            # Check required fields in UnifiedEvent
            if not event.event_id:
                raise ValidationError("Missing event_id")
            
            if not event.event_type:
                raise ValidationError("Missing event_type")
            
            if not event.timestamp:
                raise ValidationError("Missing timestamp")
            
            # Validate event-type-specific required fields
            event.validate_required_fields()
            
            return True
            
        except (ValueError, ValidationError) as e:
            self.stats['validation_errors'] += 1
            raise ValidationError(f"Validation failed: {e}")
    
    def parse_and_normalize(self, filepath: Path, 
                           validate: bool = True,
                           max_records: Optional[int] = None) -> List[UnifiedEvent]:
        """
        Complete parsing pipeline: parse file → normalize → validate.
        
        Args:
            filepath: Path to dataset file
            validate: Whether to validate each record (default: True)
            max_records: Maximum records to process (for testing, default: all)
            
        Returns:
            List of validated UnifiedEvent instances
        """
        self.logger.info(f"Starting parse for {filepath.name}")
        start_time = datetime.now()
        
        events = []
        
        try:
            # Step 1: Parse raw file
            self.logger.info("Parsing raw file...")
            raw_records = self.parse_file(filepath)
            total_raw = len(raw_records)
            self.logger.info(f"Parsed {total_raw} raw records")
            
            # Apply max_records limit if specified
            if max_records:
                raw_records = raw_records[:max_records]
                self.logger.info(f"Limited to {max_records} records for processing")
            
            # Step 2: Normalize each record
            self.logger.info("Normalizing records to UnifiedEvent format...")
            for i, raw_record in enumerate(raw_records):
                self.stats['total_records'] += 1
                
                try:
                    # Normalize to schema
                    event = self.normalize_to_schema(raw_record)
                    
                    # Validate if requested
                    if validate:
                        self.validate_record(event)
                    
                    events.append(event)
                    self.stats['valid_records'] += 1
                    
                    # Log progress for large files
                    if (i + 1) % 10000 == 0:
                        self.logger.info(f"Processed {i + 1}/{len(raw_records)} records...")
                
                except ValidationError as e:
                    self.stats['invalid_records'] += 1
                    self.logger.warning(f"Validation error at record {i}: {e}")
                    continue
                
                except Exception as e:
                    self.stats['parse_errors'] += 1
                    self.logger.error(f"Parse error at record {i}: {e}")
                    continue
            
            # Log completion
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"Parsing complete: {len(events)} valid events in {duration:.2f}s")
            self.logger.info(f"Stats: {self.stats}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Fatal parsing error: {e}")
            raise ParseError(f"Failed to parse {filepath}: {e}")
    
    def parse_and_normalize_streaming(self, filepath: Path,
                                     validate: bool = True,
                                     batch_size: int = 1000) -> Iterator[List[UnifiedEvent]]:
        """
        Stream-based parsing for large files (yields batches).
        
        Args:
            filepath: Path to dataset file
            validate: Whether to validate records
            batch_size: Number of events per batch
            
        Yields:
            Batches of UnifiedEvent instances
        """
        self.logger.info(f"Starting streaming parse for {filepath.name}")
        
        try:
            raw_records = self.parse_file(filepath)
            batch = []
            
            for i, raw_record in enumerate(raw_records):
                self.stats['total_records'] += 1
                
                try:
                    event = self.normalize_to_schema(raw_record)
                    
                    if validate:
                        self.validate_record(event)
                    
                    batch.append(event)
                    self.stats['valid_records'] += 1
                    
                    # Yield batch when full
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
                        
                except (ValidationError, Exception) as e:
                    self.stats['invalid_records'] += 1
                    self.logger.warning(f"Error at record {i}: {e}")
                    continue
            
            # Yield remaining records
            if batch:
                yield batch
                
        except Exception as e:
            self.logger.error(f"Fatal streaming error: {e}")
            raise ParseError(f"Failed to stream {filepath}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get parsing statistics.
        
        Returns:
            Dictionary with counts and metrics
        """
        stats = self.stats.copy()
        
        if stats['total_records'] > 0:
            stats['success_rate'] = stats['valid_records'] / stats['total_records']
            stats['error_rate'] = (stats['invalid_records'] + stats['parse_errors']) / stats['total_records']
        else:
            stats['success_rate'] = 0.0
            stats['error_rate'] = 0.0
        
        return stats
    
    def reset_statistics(self):
        """Reset statistics counters"""
        self.stats = {
            'total_records': 0,
            'valid_records': 0,
            'invalid_records': 0,
            'parse_errors': 0,
            'validation_errors': 0
        }


class JSONParser(BaseDatasetParser):
    """Base parser for JSON-based datasets"""
    
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse JSON file"""
        import json
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both single dict and list of dicts
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        else:
            raise ParseError(f"Unexpected JSON structure: {type(data)}")


class CSVParser(BaseDatasetParser):
    """Base parser for CSV-based datasets"""
    
    def parse_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Parse CSV file"""
        import csv
        
        records = []
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))
        
        return records


if __name__ == "__main__":
    print("BaseDatasetParser - Abstract base class for dataset parsers")
    print("\nThis module defines the interface that all parsers must implement:")
    print("  - parse_file(): Read dataset-specific format")
    print("  - normalize_to_schema(): Convert to UnifiedEvent")
    print("  - validate_record(): Quality checks")
    print("\nSubclasses should inherit from BaseDatasetParser or JSONParser/CSVParser")
    print("\nExample subclasses to be implemented:")
    print("  - DARPAOpTCParser")
    print("  - CTU13Parser")
    print("  - EMBERParser")
    print("  - MITREAttackParser")
    print("  - etc.")
