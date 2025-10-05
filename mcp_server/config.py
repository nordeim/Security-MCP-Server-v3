"""
Configuration management system for MCP server.
Production-ready implementation with validation, hot-reload, and sensitive data handling.

All critical fixes applied:
- Enhanced configuration value clamping with logging
- Improved host validation without resource leaks
- Better deep merge with list handling
- Comprehensive validation
- Thread-safe operations

Features:
- Multi-source configuration (file, environment, defaults)
- Hot-reload support with automatic change detection
- Sensitive data redaction
- Comprehensive validation with clamping
- Thread-safe access
- Multiple format support (JSON, YAML)

Usage:
    from mcp_server.config import get_config, reset_config
    
    # Get configuration
    config = get_config()
    
    # Access settings
    if config.security.allow_intrusive:
        print("Intrusive operations allowed")
    
    # Reload configuration
    config.reload_config()
    
    # Testing
    reset_config()
    config = get_config(force_new=True)
"""
import os
import logging
import json
import yaml
import threading
import socket
from typing import Dict, Any, Optional, List, Union, Set
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager

log = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration with validation."""
    url: str = ""
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600


@dataclass
class SecurityConfig:
    """Security configuration with enhanced validation."""
    allowed_targets: List[str] = field(default_factory=lambda: ["RFC1918", ".lab.internal"])
    max_args_length: int = 2048
    max_output_size: int = 1048576
    timeout_seconds: int = 300
    concurrency_limit: int = 2
    allow_intrusive: bool = False  # Controls intrusive scan operations


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    expected_exceptions: List[str] = field(default_factory=lambda: ["Exception"])
    half_open_success_threshold: int = 1


@dataclass
class HealthConfig:
    """Health check configuration."""
    check_interval: float = 30.0
    cpu_threshold: float = 80.0
    memory_threshold: float = 80.0
    disk_threshold: float = 80.0
    dependencies: List[str] = field(default_factory=list)
    timeout: float = 10.0


@dataclass
class MetricsConfig:
    """Metrics configuration."""
    enabled: bool = True
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    collection_interval: float = 15.0


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    transport: str = "stdio"
    workers: int = 1
    max_connections: int = 100
    shutdown_grace_period: float = 30.0


@dataclass
class ToolConfig:
    """Tool-specific configuration."""
    include_patterns: List[str] = field(default_factory=lambda: ["*"])
    exclude_patterns: List[str] = field(default_factory=list)
    default_timeout: int = 300
    default_concurrency: int = 2


class MCPConfig:
    """
    Main MCP configuration class with validation and hot-reload support.
    
    Features:
    - Multi-source configuration (defaults, file, environment)
    - Automatic validation and clamping with logging
    - Hot-reload support
    - Thread-safe operations
    - Sensitive data redaction
    
    Configuration Priority (highest to lowest):
    1. Environment variables
    2. Configuration file
    3. Default values
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.last_modified = None
        self._config_data = {}
        self._lock = threading.RLock()
        
        # Initialize configuration sections
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.circuit_breaker = CircuitBreakerConfig()
        self.health = HealthConfig()
        self.metrics = MetricsConfig()
        self.logging = LoggingConfig()
        self.server = ServerConfig()
        self.tool = ToolConfig()
        
        self.load_config()
    
    @contextmanager
    def _config_lock(self):
        """Context manager for thread-safe config access."""
        self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()
    
    def load_config(self):
        """Thread-safe configuration loading with comprehensive error handling."""
        with self._config_lock():
            try:
                # Start with defaults
                config_data = self._get_defaults()
                
                # Load from file if exists
                if self.config_path and os.path.exists(self.config_path):
                    file_data = self._load_from_file(self.config_path)
                    config_data = self._deep_merge(config_data, file_data)
                    log.info("config.loaded_from_file path=%s", self.config_path)
                
                # Override with environment variables
                env_data = self._load_from_environment()
                if env_data:
                    config_data = self._deep_merge(config_data, env_data)
                    log.info("config.loaded_from_environment keys=%d", 
                            sum(len(v) if isinstance(v, dict) else 1 for v in env_data.values()))
                
                # Validate configuration
                self._validate_config(config_data)
                
                # Apply configuration
                self._apply_config(config_data)
                
                # Update last modified timestamp
                if self.config_path and os.path.exists(self.config_path):
                    self.last_modified = os.path.getmtime(self.config_path)
                
                log.info("config.loaded_successfully sections=%d", len(config_data))
                
            except Exception as e:
                log.error("config.load_failed error=%s", str(e), exc_info=True)
                # Initialize with defaults if loading fails
                if not hasattr(self, 'server') or self.server is None:
                    self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize with default configuration."""
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.circuit_breaker = CircuitBreakerConfig()
        self.health = HealthConfig()
        self.metrics = MetricsConfig()
        self.logging = LoggingConfig()
        self.server = ServerConfig()
        self.tool = ToolConfig()
        log.info("config.initialized_with_defaults")
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "database": asdict(DatabaseConfig()),
            "security": asdict(SecurityConfig()),
            "circuit_breaker": asdict(CircuitBreakerConfig()),
            "health": asdict(HealthConfig()),
            "metrics": asdict(MetricsConfig()),
            "logging": asdict(LoggingConfig()),
            "server": asdict(ServerConfig()),
            "tool": asdict(ToolConfig())
        }
    
    def _load_from_file(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file (JSON or YAML)."""
        try:
            file_path = Path(config_path)
            
            if not file_path.exists():
                log.warning("config.file_not_found path=%s", config_path)
                return {}
            
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix.lower() in ['.yaml', '.yml']:
                    data = yaml.safe_load(f) or {}
                else:
                    data = json.load(f) or {}
            
            log.debug("config.file_loaded path=%s format=%s keys=%d", 
                     config_path, file_path.suffix, len(data))
            return data
        
        except yaml.YAMLError as e:
            log.error("config.yaml_parse_failed path=%s error=%s", config_path, str(e))
            return {}
        except json.JSONDecodeError as e:
            log.error("config.json_parse_failed path=%s error=%s", config_path, str(e))
            return {}
        except Exception as e:
            log.error("config.file_load_failed path=%s error=%s", config_path, str(e))
            return {}
    
    def _load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables with comprehensive mapping."""
        config = {}
        
        # Comprehensive environment variable mappings
        env_mappings = {
            # Database
            'MCP_DATABASE_URL': ('database', 'url'),
            'MCP_DATABASE_POOL_SIZE': ('database', 'pool_size'),
            'MCP_DATABASE_MAX_OVERFLOW': ('database', 'max_overflow'),
            'MCP_DATABASE_POOL_TIMEOUT': ('database', 'pool_timeout'),
            'MCP_DATABASE_POOL_RECYCLE': ('database', 'pool_recycle'),
            
            # Security
            'MCP_SECURITY_MAX_ARGS_LENGTH': ('security', 'max_args_length'),
            'MCP_SECURITY_MAX_OUTPUT_SIZE': ('security', 'max_output_size'),
            'MCP_SECURITY_TIMEOUT_SECONDS': ('security', 'timeout_seconds'),
            'MCP_SECURITY_CONCURRENCY_LIMIT': ('security', 'concurrency_limit'),
            'MCP_SECURITY_ALLOW_INTRUSIVE': ('security', 'allow_intrusive'),
            
            # Circuit Breaker
            'MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD': ('circuit_breaker', 'failure_threshold'),
            'MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT': ('circuit_breaker', 'recovery_timeout'),
            'MCP_CIRCUIT_BREAKER_HALF_OPEN_SUCCESS_THRESHOLD': ('circuit_breaker', 'half_open_success_threshold'),
            
            # Health
            'MCP_HEALTH_CHECK_INTERVAL': ('health', 'check_interval'),
            'MCP_HEALTH_CPU_THRESHOLD': ('health', 'cpu_threshold'),
            'MCP_HEALTH_MEMORY_THRESHOLD': ('health', 'memory_threshold'),
            'MCP_HEALTH_DISK_THRESHOLD': ('health', 'disk_threshold'),
            'MCP_HEALTH_TIMEOUT': ('health', 'timeout'),
            
            # Metrics
            'MCP_METRICS_ENABLED': ('metrics', 'enabled'),
            'MCP_METRICS_PROMETHEUS_ENABLED': ('metrics', 'prometheus_enabled'),
            'MCP_METRICS_PROMETHEUS_PORT': ('metrics', 'prometheus_port'),
            'MCP_METRICS_COLLECTION_INTERVAL': ('metrics', 'collection_interval'),
            
            # Logging
            'MCP_LOGGING_LEVEL': ('logging', 'level'),
            'MCP_LOGGING_FILE_PATH': ('logging', 'file_path'),
            'MCP_LOGGING_MAX_FILE_SIZE': ('logging', 'max_file_size'),
            'MCP_LOGGING_BACKUP_COUNT': ('logging', 'backup_count'),
            
            # Server
            'MCP_SERVER_HOST': ('server', 'host'),
            'MCP_SERVER_PORT': ('server', 'port'),
            'MCP_SERVER_TRANSPORT': ('server', 'transport'),
            'MCP_SERVER_WORKERS': ('server', 'workers'),
            'MCP_SERVER_MAX_CONNECTIONS': ('server', 'max_connections'),
            'MCP_SERVER_SHUTDOWN_GRACE_PERIOD': ('server', 'shutdown_grace_period'),
            
            # Tool
            'MCP_TOOL_DEFAULT_TIMEOUT': ('tool', 'default_timeout'),
            'MCP_TOOL_DEFAULT_CONCURRENCY': ('tool', 'default_concurrency'),
        }
        
        # Integer fields
        int_fields = {
            'pool_size', 'max_overflow', 'pool_timeout', 'pool_recycle',
            'max_args_length', 'max_output_size', 'timeout_seconds', 'concurrency_limit',
            'failure_threshold', 'half_open_success_threshold', 'prometheus_port',
            'max_file_size', 'backup_count', 'port', 'workers', 'max_connections',
            'default_timeout', 'default_concurrency'
        }
        
        # Float fields
        float_fields = {
            'recovery_timeout', 'check_interval', 'cpu_threshold', 'memory_threshold',
            'disk_threshold', 'timeout', 'collection_interval', 'shutdown_grace_period'
        }
        
        # Boolean fields
        bool_fields = {
            'enabled', 'prometheus_enabled', 'allow_intrusive'
        }
        
        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                if section not in config:
                    config[section] = {}
                
                # Type conversion with error handling
                try:
                    if key in int_fields:
                        config[section][key] = int(value)
                    elif key in float_fields:
                        config[section][key] = float(value)
                    elif key in bool_fields:
                        config[section][key] = value.lower() in ['true', '1', 'yes', 'on']
                    else:
                        config[section][key] = value
                    
                    log.debug("config.env_loaded env_var=%s section=%s key=%s", 
                             env_var, section, key)
                
                except (ValueError, TypeError) as e:
                    log.warning("config.env_parse_failed env_var=%s value=%s error=%s", 
                              env_var, value, str(e))
        
        return config
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """
        Enhanced deep merge configuration dictionaries with proper list handling.
        
        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
        
        Returns:
            Merged configuration dictionary
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result:
                base_value = result[key]
                
                # Recursively merge dictionaries
                if isinstance(base_value, dict) and isinstance(value, dict):
                    result[key] = self._deep_merge(base_value, value)
                
                # Replace lists (don't merge to maintain control)
                elif isinstance(base_value, list) and isinstance(value, list):
                    result[key] = value
                    log.debug("config.list_replaced key=%s old_len=%d new_len=%d", 
                             key, len(base_value), len(value))
                
                # Replace with new value
                else:
                    if base_value != value:
                        log.debug("config.value_replaced key=%s old=%s new=%s", 
                                 key, base_value, value)
                    result[key] = value
            else:
                result[key] = value
                log.debug("config.value_added key=%s", key)
        
        return result
    
    def _validate_config(self, config_data: Dict[str, Any]):
        """
        Comprehensive configuration validation with clamping and logging.
        
        Args:
            config_data: Configuration data to validate
        """
        validators = {
            'database': self._validate_database_config,
            'security': self._validate_security_config,
            'circuit_breaker': self._validate_circuit_breaker_config,
            'health': self._validate_health_config,
            'metrics': self._validate_metrics_config,
            'logging': self._validate_logging_config,
            'server': self._validate_server_config,
            'tool': self._validate_tool_config,
        }
        
        for section, validator in validators.items():
            if section in config_data:
                try:
                    validator(config_data[section])
                except Exception as e:
                    log.error("config.validation_failed section=%s error=%s", section, str(e))
                    raise
    
    def _log_clamp(self, section: str, key: str, original: Union[int, float], 
                   clamped: Union[int, float], min_val: Union[int, float], 
                   max_val: Union[int, float]):
        """Log configuration value clamping with details."""
        if original != clamped:
            log.warning(
                "config.value_clamped section=%s key=%s original=%s clamped=%s valid_range=[%s,%s]",
                section, key, original, clamped, min_val, max_val
            )
    
    def _validate_database_config(self, config: Dict):
        """Validate database configuration with clamping and logging."""
        if 'pool_size' in config:
            original = int(config['pool_size'])
            config['pool_size'] = max(1, min(100, original))
            self._log_clamp('database', 'pool_size', original, config['pool_size'], 1, 100)
        
        if 'max_overflow' in config:
            original = int(config['max_overflow'])
            config['max_overflow'] = max(0, min(100, original))
            self._log_clamp('database', 'max_overflow', original, config['max_overflow'], 0, 100)
        
        if 'pool_timeout' in config:
            original = int(config['pool_timeout'])
            config['pool_timeout'] = max(1, min(300, original))
            self._log_clamp('database', 'pool_timeout', original, config['pool_timeout'], 1, 300)
        
        if 'pool_recycle' in config:
            original = int(config['pool_recycle'])
            config['pool_recycle'] = max(60, min(7200, original))
            self._log_clamp('database', 'pool_recycle', original, config['pool_recycle'], 60, 7200)
    
    def _validate_security_config(self, config: Dict):
        """Enhanced security configuration validation with logging."""
        if 'max_args_length' in config:
            original = int(config['max_args_length'])
            config['max_args_length'] = max(1, min(10240, original))
            self._log_clamp('security', 'max_args_length', original, config['max_args_length'], 1, 10240)
        
        if 'max_output_size' in config:
            original = int(config['max_output_size'])
            config['max_output_size'] = max(1024, min(10485760, original))
            self._log_clamp('security', 'max_output_size', original, config['max_output_size'], 1024, 10485760)
        
        if 'timeout_seconds' in config:
            original = int(config['timeout_seconds'])
            config['timeout_seconds'] = max(1, min(3600, original))
            self._log_clamp('security', 'timeout_seconds', original, config['timeout_seconds'], 1, 3600)
        
        if 'concurrency_limit' in config:
            original = int(config['concurrency_limit'])
            config['concurrency_limit'] = max(1, min(100, original))
            self._log_clamp('security', 'concurrency_limit', original, config['concurrency_limit'], 1, 100)
        
        # Validate allowed targets
        if 'allowed_targets' in config:
            valid_patterns = {'RFC1918', 'loopback'}
            validated_targets = []
            
            for target in config['allowed_targets']:
                if target in valid_patterns or (isinstance(target, str) and target.startswith('.')):
                    validated_targets.append(target)
                else:
                    log.warning("config.invalid_target_pattern pattern=%s", target)
            
            if not validated_targets:
                validated_targets = ['RFC1918']
                log.warning("config.no_valid_targets using_default=%s", validated_targets)
            
            config['allowed_targets'] = validated_targets
    
    def _validate_circuit_breaker_config(self, config: Dict):
        """Validate circuit breaker configuration with logging."""
        if 'failure_threshold' in config:
            original = int(config['failure_threshold'])
            config['failure_threshold'] = max(1, min(100, original))
            self._log_clamp('circuit_breaker', 'failure_threshold', original, 
                          config['failure_threshold'], 1, 100)
        
        if 'recovery_timeout' in config:
            original = float(config['recovery_timeout'])
            config['recovery_timeout'] = max(1.0, min(600.0, original))
            self._log_clamp('circuit_breaker', 'recovery_timeout', original, 
                          config['recovery_timeout'], 1.0, 600.0)
        
        if 'half_open_success_threshold' in config:
            original = int(config['half_open_success_threshold'])
            config['half_open_success_threshold'] = max(1, min(10, original))
            self._log_clamp('circuit_breaker', 'half_open_success_threshold', original, 
                          config['half_open_success_threshold'], 1, 10)
    
    def _validate_health_config(self, config: Dict):
        """Validate health configuration with logging."""
        if 'check_interval' in config:
            original = float(config['check_interval'])
            config['check_interval'] = max(5.0, min(300.0, original))
            self._log_clamp('health', 'check_interval', original, config['check_interval'], 5.0, 300.0)
        
        for threshold_key in ['cpu_threshold', 'memory_threshold', 'disk_threshold']:
            if threshold_key in config:
                original = float(config[threshold_key])
                config[threshold_key] = max(0.0, min(100.0, original))
                self._log_clamp('health', threshold_key, original, config[threshold_key], 0.0, 100.0)
        
        if 'timeout' in config:
            original = float(config['timeout'])
            config['timeout'] = max(1.0, min(60.0, original))
            self._log_clamp('health', 'timeout', original, config['timeout'], 1.0, 60.0)
    
    def _validate_metrics_config(self, config: Dict):
        """Validate metrics configuration with logging."""
        if 'prometheus_port' in config:
            original = int(config['prometheus_port'])
            config['prometheus_port'] = max(1, min(65535, original))
            self._log_clamp('metrics', 'prometheus_port', original, config['prometheus_port'], 1, 65535)
        
        if 'collection_interval' in config:
            original = float(config['collection_interval'])
            config['collection_interval'] = max(5.0, min(300.0, original))
            self._log_clamp('metrics', 'collection_interval', original, 
                          config['collection_interval'], 5.0, 300.0)
    
    def _validate_logging_config(self, config: Dict):
        """Validate logging configuration."""
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        
        if 'level' in config:
            level = config['level'].upper()
            if level not in valid_levels:
                log.warning("config.invalid_log_level level=%s valid=%s using_default=INFO",
                          level, valid_levels)
                config['level'] = 'INFO'
            else:
                config['level'] = level
        
        if 'max_file_size' in config:
            original = int(config['max_file_size'])
            config['max_file_size'] = max(1024, min(104857600, original))  # 1KB to 100MB
            self._log_clamp('logging', 'max_file_size', original, config['max_file_size'], 
                          1024, 104857600)
        
        if 'backup_count' in config:
            original = int(config['backup_count'])
            config['backup_count'] = max(0, min(100, original))
            self._log_clamp('logging', 'backup_count', original, config['backup_count'], 0, 100)
    
    def _validate_server_config(self, config: Dict):
        """Enhanced server configuration validation with proper host checking."""
        if 'port' in config:
            port = int(config['port'])
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}, must be 1-65535")
            config['port'] = port
        
        if 'transport' in config:
            transport = str(config['transport']).lower()
            if transport not in ['stdio', 'http']:
                raise ValueError(f"Invalid transport: {transport}, must be 'stdio' or 'http'")
            config['transport'] = transport
        
        if 'host' in config:
            if not self._validate_host(config['host']):
                raise ValueError(f"Invalid host: {config['host']}")
        
        if 'workers' in config:
            original = int(config['workers'])
            config['workers'] = max(1, min(16, original))
            self._log_clamp('server', 'workers', original, config['workers'], 1, 16)
        
        if 'max_connections' in config:
            original = int(config['max_connections'])
            config['max_connections'] = max(1, min(10000, original))
            self._log_clamp('server', 'max_connections', original, config['max_connections'], 1, 10000)
        
        if 'shutdown_grace_period' in config:
            original = float(config['shutdown_grace_period'])
            config['shutdown_grace_period'] = max(0.0, min(300.0, original))
            self._log_clamp('server', 'shutdown_grace_period', original, 
                          config['shutdown_grace_period'], 0.0, 300.0)
    
    def _validate_host(self, host: str) -> bool:
        """
        Validate host without resource leaks using proper socket API.
        
        Args:
            host: Hostname or IP address to validate
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Try to parse as IP address first
            socket.inet_aton(host)
            return True
        except socket.error:
            pass
        
        # Use getaddrinfo which handles cleanup properly
        try:
            # Just check if we can resolve it, don't keep the connection
            socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return True
        except (socket.gaierror, socket.error) as e:
            log.debug("config.host_validation_failed host=%s error=%s", host, str(e))
            return False
    
    def _validate_tool_config(self, config: Dict):
        """Validate tool configuration with logging."""
        if 'default_timeout' in config:
            original = int(config['default_timeout'])
            config['default_timeout'] = max(1, min(3600, original))
            self._log_clamp('tool', 'default_timeout', original, config['default_timeout'], 1, 3600)
        
        if 'default_concurrency' in config:
            original = int(config['default_concurrency'])
            config['default_concurrency'] = max(1, min(100, original))
            self._log_clamp('tool', 'default_concurrency', original, config['default_concurrency'], 1, 100)
    
    def _apply_config(self, config_data: Dict[str, Any]):
        """Apply validated configuration to dataclass instances."""
        section_map = {
            'database': self.database,
            'security': self.security,
            'circuit_breaker': self.circuit_breaker,
            'health': self.health,
            'metrics': self.metrics,
            'logging': self.logging,
            'server': self.server,
            'tool': self.tool
        }
        
        for section_name, section_obj in section_map.items():
            if section_name in config_data:
                for key, value in config_data[section_name].items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)
                        log.debug("config.applied section=%s key=%s", section_name, key)
                    else:
                        log.warning("config.unknown_key section=%s key=%s", section_name, key)
        
        self._config_data = config_data
    
    def check_for_changes(self) -> bool:
        """Check if configuration file has been modified."""
        if not self.config_path:
            return False
        
        try:
            if not os.path.exists(self.config_path):
                return False
            
            current_mtime = os.path.getmtime(self.config_path)
            if current_mtime != self.last_modified:
                log.info("config.file_changed path=%s", self.config_path)
                return True
        except OSError as e:
            log.warning("config.check_failed path=%s error=%s", self.config_path, str(e))
        
        return False
    
    def reload_config(self) -> bool:
        """
        Thread-safe configuration reload with rollback on failure.
        
        Returns:
            True if reload successful, False otherwise
        """
        with self._config_lock():
            if not self.check_for_changes():
                return False
            
            log.info("config.reloading_changes_detected path=%s", self.config_path)
            
            # Create backup of current config
            backup = self.to_dict(redact_sensitive=False)
            
            try:
                self.load_config()
                log.info("config.reloaded_successfully")
                return True
            
            except Exception as e:
                log.error("config.reload_failed error=%s reverting", str(e), exc_info=True)
                
                # Restore from backup
                try:
                    self._apply_config(backup)
                    log.info("config.reverted_to_previous")
                except Exception as revert_error:
                    log.critical("config.revert_failed error=%s", str(revert_error), exc_info=True)
                
                return False
    
    def get_sensitive_keys(self) -> List[str]:
        """Get list of sensitive configuration keys that should be redacted."""
        return [
            'database.url',
            'security.api_key',
            'security.secret_key',
            'security.token',
            'security.password'
        ]
    
    def redact_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive data from configuration for safe logging/display.
        
        Args:
            data: Configuration dictionary
        
        Returns:
            Dictionary with sensitive values redacted
        """
        import copy
        redacted_data = copy.deepcopy(data)
        sensitive_keys = self.get_sensitive_keys()
        
        for key in sensitive_keys:
            if '.' in key:
                section, subkey = key.split('.', 1)
                if section in redacted_data and isinstance(redacted_data[section], dict):
                    if subkey in redacted_data[section]:
                        original = redacted_data[section][subkey]
                        if original:  # Only redact if there's a value
                            redacted_data[section][subkey] = "***REDACTED***"
            else:
                if key in redacted_data:
                    original = redacted_data[key]
                    if original:
                        redacted_data[key] = "***REDACTED***"
        
        return redacted_data
    
    def to_dict(self, redact_sensitive: bool = True) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Args:
            redact_sensitive: Whether to redact sensitive values
        
        Returns:
            Configuration as dictionary
        """
        config_dict = {
            'database': asdict(self.database),
            'security': asdict(self.security),
            'circuit_breaker': asdict(self.circuit_breaker),
            'health': asdict(self.health),
            'metrics': asdict(self.metrics),
            'logging': asdict(self.logging),
            'server': asdict(self.server),
            'tool': asdict(self.tool)
        }
        
        if redact_sensitive:
            config_dict = self.redact_sensitive_data(config_dict)
        
        return config_dict
    
    def save_config(self, file_path: Optional[str] = None):
        """
        Save current configuration to file.
        
        Args:
            file_path: Optional path override, uses self.config_path if None
        """
        save_path = file_path or self.config_path
        if not save_path:
            raise ValueError("No config file path specified")
        
        try:
            config_dict = self.to_dict(redact_sensitive=False)
            
            file_path_obj = Path(save_path)
            file_path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path_obj, 'w', encoding='utf-8') as f:
                if file_path_obj.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2)
            
            log.info("config.saved_successfully path=%s", save_path)
            
        except Exception as e:
            log.error("config.save_failed path=%s error=%s", save_path, str(e), exc_info=True)
            raise
    
    def get_section(self, section_name: str) -> Any:
        """
        Get a specific configuration section.
        
        Args:
            section_name: Name of the section
        
        Returns:
            Configuration section object or None
        """
        return getattr(self, section_name, None)
    
    def get_value(self, section_name: str, key: str, default=None):
        """
        Get a specific configuration value.
        
        Args:
            section_name: Name of the section
            key: Configuration key
            default: Default value if not found
        
        Returns:
            Configuration value or default
        """
        section = self.get_section(section_name)
        if section and hasattr(section, key):
            return getattr(section, key)
        return default
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current configuration and return detailed status.
        
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Check file accessibility
        if self.config_path and not os.path.exists(self.config_path):
            warnings.append(f"Configuration file not found: {self.config_path}")
        
        # Validate server host
        if not self._validate_host(self.server.host):
            issues.append(f"Invalid server host: {self.server.host}")
        
        # Check port availability
        if self.server.transport == "http":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.server.host, self.server.port))
            except OSError as e:
                warnings.append(f"Port {self.server.port} may not be available: {e}")
        
        # Check security settings
        if self.security.allow_intrusive:
            warnings.append("Intrusive operations are ENABLED - ensure this is intentional")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "configuration": self.to_dict(redact_sensitive=True)
        }
    
    def __str__(self) -> str:
        """String representation with sensitive data redacted."""
        config_dict = self.to_dict(redact_sensitive=True)
        return json.dumps(config_dict, indent=2)
    
    def __repr__(self) -> str:
        """Repr with basic info."""
        return f"MCPConfig(path={self.config_path}, sections={len(self.to_dict())})"


# Global configuration instance management
_config_instance: Optional[MCPConfig] = None
_config_lock = threading.Lock()


def get_config(config_path: Optional[str] = None, force_new: bool = False) -> MCPConfig:
    """
    Get configuration instance with singleton pattern and testing support.
    
    Args:
        config_path: Optional path to configuration file
        force_new: Force creation of new instance (for testing)
    
    Returns:
        MCPConfig instance
    """
    global _config_instance
    
    with _config_lock:
        if force_new or _config_instance is None:
            config_path = config_path or os.getenv('MCP_CONFIG_FILE')
            _config_instance = MCPConfig(config_path)
            log.info("config.instance_created path=%s", config_path)
        return _config_instance


def reset_config():
    """Reset configuration instance (for testing)."""
    global _config_instance
    with _config_lock:
        _config_instance = None
        log.debug("config.instance_reset")
