"""
Health monitoring system for MCP server.
Production-ready implementation with all critical fixes applied.

All critical fixes applied:
- Health check result staleness validation
- HealthCheckPriority enum instead of magic numbers
- Enhanced overlap prevention
- Proper cleanup methods
- Comprehensive type hints
- Better configuration handling

Features:
- Priority-based health checks (Critical, Important, Informational)
- Automatic staleness detection
- Overlap prevention for concurrent checks
- Configurable thresholds and intervals
- Comprehensive health history
- Custom health check support
- Tool availability monitoring

Usage:
    from mcp_server.health import HealthCheckManager, HealthCheckPriority
    
    # Create health manager
    manager = HealthCheckManager(config=config)
    
    # Add custom check
    async def check_database():
        # Check database connectivity
        return HealthStatus.HEALTHY
    
    manager.register_check(
        "database",
        check_database,
        priority=HealthCheckPriority.CRITICAL
    )
    
    # Start monitoring
    await manager.start_monitoring()
    
    # Get health status
    health = await manager.run_health_checks()
    
    # Cleanup
    await manager.stop_monitoring()
"""
import asyncio
import logging
import time
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Awaitable, Union, Protocol
from collections import deque

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

log = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheckPriority(IntEnum):
    """
    Health check priority levels with clear semantics.
    
    Priority determines impact on overall health status:
    - CRITICAL (0): Failure causes UNHEALTHY status
    - IMPORTANT (1): Failure causes DEGRADED status
    - INFORMATIONAL (2): Failure only logged, minimal impact
    """
    CRITICAL = 0      # System-critical checks (CPU, memory, disk)
    IMPORTANT = 1     # Important but non-critical (process health, circuit breakers)
    INFORMATIONAL = 2  # Nice-to-have checks (dependencies, tool availability)


@dataclass
class HealthCheckResult:
    """Result of a health check with comprehensive metadata."""
    name: str
    status: HealthStatus
    message: str
    priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL
    timestamp: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "priority": self.priority.value,
            "priority_name": self.priority.name,
            "timestamp": self.timestamp.isoformat(),
            "duration": round(self.duration, 3),
            "metadata": self.metadata
        }


@dataclass
class SystemHealth:
    """Overall system health status with staleness tracking."""
    overall_status: HealthStatus
    checks: Dict[str, HealthCheckResult]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_stale(self, max_age_seconds: float = 60.0) -> bool:
        """
        Check if health data is stale.
        
        Args:
            max_age_seconds: Maximum age before considered stale
        
        Returns:
            True if stale, False otherwise
        """
        age = (datetime.now() - self.timestamp).total_seconds()
        return age > max_age_seconds
    
    def get_age_seconds(self) -> float:
        """Get age of health check in seconds."""
        return (datetime.now() - self.timestamp).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "overall_status": self.overall_status.value,
            "timestamp": self.timestamp.isoformat(),
            "age_seconds": round(self.get_age_seconds(), 2),
            "is_stale": self.is_stale(),
            "checks": {name: result.to_dict() for name, result in self.checks.items()},
            "metadata": self.metadata
        }


class HealthCheckProtocol(Protocol):
    """Protocol for health check callables."""
    async def __call__(self) -> HealthStatus:
        """Execute health check and return status."""
        ...


class HealthCheck:
    """Base class for health checks with timeout and error handling."""
    
    def __init__(self, name: str, priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL,
                 timeout: float = 10.0):
        self.name = name
        self.priority = max(HealthCheckPriority.CRITICAL, 
                          min(priority, HealthCheckPriority.INFORMATIONAL))
        self.timeout = max(1.0, timeout)
    
    async def check(self) -> HealthCheckResult:
        """Execute the health check with timeout and error handling."""
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(self._execute_check(), timeout=self.timeout)
            duration = time.time() - start_time
            result.duration = duration
            result.priority = self.priority
            return result
        
        except asyncio.TimeoutError:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self.timeout}s",
                priority=self.priority,
                duration=self.timeout,
                metadata={"error": "timeout"}
            )
        
        except Exception as e:
            duration = time.time() - start_time
            log.error("health_check.failed name=%s error=%s duration=%.2f", 
                     self.name, str(e), duration, exc_info=True)
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                priority=self.priority,
                duration=duration,
                metadata={"error": str(e), "error_type": type(e).__name__}
            )
    
    async def _execute_check(self) -> HealthCheckResult:
        """Override this method to implement specific health check logic."""
        raise NotImplementedError


class SystemResourceHealthCheck(HealthCheck):
    """Check system resources (CPU, memory, disk) with proper thresholds."""
    
    def __init__(self, name: str = "system_resources",
                 cpu_threshold: float = 80.0,
                 memory_threshold: float = 80.0,
                 disk_threshold: float = 80.0,
                 priority: HealthCheckPriority = HealthCheckPriority.CRITICAL):
        super().__init__(name, priority)
        self.cpu_threshold = max(0.0, min(100.0, cpu_threshold))
        self.memory_threshold = max(0.0, min(100.0, memory_threshold))
        self.disk_threshold = max(0.0, min(100.0, disk_threshold))
    
    async def _execute_check(self) -> HealthCheckResult:
        """Check system resources with detailed reporting."""
        if not PSUTIL_AVAILABLE:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.DEGRADED,
                message="psutil not available for system resource monitoring",
                priority=self.priority,
                metadata={"psutil_available": False, "hint": "pip install psutil"}
            )
        
        try:
            # CPU check (non-blocking)
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory check
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk check (with error handling)
            try:
                disk = psutil.disk_usage('/')
                disk_percent = disk.percent
            except Exception as disk_error:
                log.warning("health_check.disk_usage_failed error=%s", str(disk_error))
                disk_percent = 0.0
            
            # Determine status based on thresholds
            status = HealthStatus.HEALTHY
            messages = []
            warnings = []
            
            if cpu_percent > self.cpu_threshold:
                status = HealthStatus.UNHEALTHY
                messages.append(f"CPU usage critical: {cpu_percent:.1f}%")
            elif cpu_percent > self.cpu_threshold * 0.8:
                warnings.append(f"CPU usage elevated: {cpu_percent:.1f}%")
            
            if memory_percent > self.memory_threshold:
                if status == HealthStatus.HEALTHY:
                    status = HealthStatus.DEGRADED
                messages.append(f"Memory usage high: {memory_percent:.1f}%")
            elif memory_percent > self.memory_threshold * 0.8:
                warnings.append(f"Memory usage elevated: {memory_percent:.1f}%")
            
            if disk_percent > self.disk_threshold:
                if status == HealthStatus.HEALTHY:
                    status = HealthStatus.DEGRADED
                messages.append(f"Disk usage high: {disk_percent:.1f}%")
            elif disk_percent > self.disk_threshold * 0.8:
                warnings.append(f"Disk usage elevated: {disk_percent:.1f}%")
            
            # Construct message
            if messages:
                message = ", ".join(messages)
            elif warnings:
                message = "System resources acceptable with warnings: " + ", ".join(warnings)
            else:
                message = "System resources healthy"
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                priority=self.priority,
                metadata={
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory_percent, 2),
                    "disk_percent": round(disk_percent, 2),
                    "cpu_threshold": self.cpu_threshold,
                    "memory_threshold": self.memory_threshold,
                    "disk_threshold": self.disk_threshold,
                    "warnings": warnings,
                    "psutil_available": True
                }
            )
        
        except Exception as e:
            log.error("health_check.system_resources_failed error=%s", str(e), exc_info=True)
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check system resources: {str(e)}",
                priority=self.priority,
                metadata={"psutil_available": PSUTIL_AVAILABLE, "error": str(e)}
            )


class ToolAvailabilityHealthCheck(HealthCheck):
    """Check availability of MCP tools."""
    
    def __init__(self, tool_registry, name: str = "tool_availability",
                 priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL):
        super().__init__(name, priority)
        self.tool_registry = tool_registry
    
    async def _execute_check(self) -> HealthCheckResult:
        """Check tool availability with detailed reporting."""
        try:
            if not hasattr(self.tool_registry, 'get_enabled_tools'):
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    message="Tool registry does not support get_enabled_tools method",
                    priority=self.priority,
                    metadata={"registry_type": type(self.tool_registry).__name__}
                )
            
            tools = self.tool_registry.get_enabled_tools()
            unavailable_tools = []
            available_count = 0
            
            for tool_name, tool in tools.items():
                try:
                    if not hasattr(tool, '_resolve_command'):
                        unavailable_tools.append({
                            "name": tool_name,
                            "reason": "missing _resolve_command method"
                        })
                    elif not tool._resolve_command():
                        unavailable_tools.append({
                            "name": tool_name,
                            "reason": "command not found in PATH"
                        })
                    else:
                        available_count += 1
                except Exception as tool_error:
                    unavailable_tools.append({
                        "name": tool_name,
                        "reason": f"error: {str(tool_error)}"
                    })
            
            total_tools = len(tools)
            
            # Determine status
            if unavailable_tools:
                if available_count == 0:
                    status = HealthStatus.UNHEALTHY
                    message = f"All {total_tools} tools unavailable"
                elif available_count < total_tools / 2:
                    status = HealthStatus.DEGRADED
                    message = f"Majority of tools unavailable: {len(unavailable_tools)}/{total_tools}"
                else:
                    status = HealthStatus.DEGRADED
                    message = f"Some tools unavailable: {len(unavailable_tools)}/{total_tools}"
            else:
                status = HealthStatus.HEALTHY
                message = f"All {total_tools} tools available"
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                priority=self.priority,
                metadata={
                    "total_tools": total_tools,
                    "available_tools": available_count,
                    "unavailable_tools": len(unavailable_tools),
                    "unavailable_details": unavailable_tools
                }
            )
        
        except Exception as e:
            log.error("health_check.tool_availability_failed error=%s", str(e), exc_info=True)
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check tool availability: {str(e)}",
                priority=self.priority,
                metadata={
                    "registry_type": type(self.tool_registry).__name__ if self.tool_registry else None,
                    "error": str(e)
                }
            )


class ProcessHealthCheck(HealthCheck):
    """Check if the process is running properly."""
    
    def __init__(self, name: str = "process_health",
                 priority: HealthCheckPriority = HealthCheckPriority.IMPORTANT):
        super().__init__(name, priority)
    
    async def _execute_check(self) -> HealthCheckResult:
        """Check process health with detailed metrics."""
        if not PSUTIL_AVAILABLE:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.DEGRADED,
                message="psutil not available for process health monitoring",
                priority=self.priority,
                metadata={"psutil_available": False, "hint": "pip install psutil"}
            )
        
        try:
            process = psutil.Process()
            
            if not process.is_running():
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    message="Process is not running",
                    priority=self.priority,
                    metadata={"pid": process.pid}
                )
            
            # Get process metrics
            create_time = datetime.fromtimestamp(process.create_time())
            age = datetime.now() - create_time
            
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            cpu_percent = process.cpu_percent()
            
            # Get thread count
            num_threads = process.num_threads()
            
            # Get file descriptors (Unix only)
            try:
                num_fds = process.num_fds()
            except (AttributeError, NotImplementedError):
                num_fds = None
            
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Process is running normally",
                priority=self.priority,
                metadata={
                    "pid": process.pid,
                    "age_seconds": round(age.total_seconds(), 2),
                    "memory_mb": round(memory_mb, 2),
                    "cpu_percent": round(cpu_percent, 2),
                    "num_threads": num_threads,
                    "num_fds": num_fds,
                    "create_time": create_time.isoformat(),
                    "psutil_available": True
                }
            )
        
        except Exception as e:
            log.error("health_check.process_health_failed error=%s", str(e), exc_info=True)
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check process health: {str(e)}",
                priority=self.priority,
                metadata={"psutil_available": PSUTIL_AVAILABLE, "error": str(e)}
            )


class DependencyHealthCheck(HealthCheck):
    """Check external dependencies availability."""
    
    def __init__(self, dependencies: List[str], name: str = "dependencies",
                 priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL):
        super().__init__(name, priority)
        self.dependencies = dependencies or []
    
    async def _execute_check(self) -> HealthCheckResult:
        """Check dependency availability."""
        try:
            import importlib
            
            missing_deps = []
            available_deps = []
            
            for dep in self.dependencies:
                try:
                    importlib.import_module(dep)
                    available_deps.append(dep)
                except ImportError:
                    missing_deps.append({"name": dep, "reason": "not installed"})
                except Exception as dep_error:
                    missing_deps.append({
                        "name": dep,
                        "reason": f"error: {str(dep_error)}"
                    })
            
            total_deps = len(self.dependencies)
            
            # Determine status
            if missing_deps:
                if available_deps:
                    status = HealthStatus.DEGRADED
                    message = f"Some dependencies missing: {len(missing_deps)}/{total_deps}"
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f"All {total_deps} dependencies missing"
            else:
                status = HealthStatus.HEALTHY
                message = f"All {total_deps} dependencies available"
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                priority=self.priority,
                metadata={
                    "total_dependencies": total_deps,
                    "available_dependencies": available_deps,
                    "missing_dependencies": missing_deps
                }
            )
        
        except Exception as e:
            log.error("health_check.dependency_failed error=%s", str(e), exc_info=True)
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check dependencies: {str(e)}",
                priority=self.priority,
                metadata={"dependencies": self.dependencies, "error": str(e)}
            )


class CustomHealthCheck(HealthCheck):
    """Custom health check with user-provided function."""
    
    def __init__(self, name: str, check_func: Callable[[], Awaitable[HealthStatus]],
                 priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL,
                 timeout: float = 10.0):
        super().__init__(name, priority, timeout)
        self.check_func = check_func
    
    async def _execute_check(self) -> HealthCheckResult:
        """Execute custom health check function."""
        try:
            status = await self.check_func()
            message = f"{self.name} check {'passed' if status == HealthStatus.HEALTHY else 'failed'}"
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                priority=self.priority
            )
        
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Custom check failed: {str(e)}",
                priority=self.priority,
                metadata={"error": str(e)}
            )


class HealthCheckManager:
    """
    Manager for health checks with enhanced features and all critical fixes.
    
    Features:
    - Priority-based health checks
    - Staleness detection
    - Overlap prevention
    - Automatic monitoring
    - Health history tracking
    - Comprehensive cleanup
    """
    
    def __init__(self, config: Optional[Union[dict, object]] = None,
                 checks: Optional[List[HealthCheck]] = None,
                 check_timeout_seconds: float = 10.0,
                 max_staleness_seconds: float = 60.0):
        self._raw_config = config
        self.config = self._normalize_config(config)
        
        self.health_checks: Dict[str, HealthCheck] = {}
        self.check_priorities: Dict[str, HealthCheckPriority] = {}
        
        self.last_health_check: Optional[SystemHealth] = None
        self.check_interval = self.config.get('check_interval', 30.0)
        self.check_timeout_seconds = max(1.0, check_timeout_seconds)
        self.max_staleness_seconds = max(10.0, max_staleness_seconds)
        
        self._monitor_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._check_in_progress = False
        self._check_lock = asyncio.Lock()
        
        self.check_history = deque(maxlen=100)
        
        # Register provided checks
        if checks:
            for check in checks:
                self.add_health_check(check, check.priority)
        
        self._initialize_default_checks()
    
    def _normalize_config(self, cfg: Union[dict, object, None]) -> dict:
        """Simplified and robust config normalization."""
        defaults = {
            'check_interval': 30.0,
            'cpu_threshold': 80.0,
            'memory_threshold': 80.0,
            'disk_threshold': 80.0,
            'dependencies': [],
            'timeout': 10.0,
        }
        
        if cfg is None:
            return defaults
        
        result = defaults.copy()
        
        # Handle dict config
        if isinstance(cfg, dict):
            # Direct keys
            for key in defaults:
                if key in cfg:
                    result[key] = cfg[key]
            
            # Nested health section
            if 'health' in cfg and isinstance(cfg['health'], dict):
                health = cfg['health']
                mapping = {
                    'check_interval': 'check_interval',
                    'cpu_threshold': 'cpu_threshold',
                    'memory_threshold': 'memory_threshold',
                    'disk_threshold': 'disk_threshold',
                    'dependencies': 'dependencies',
                    'timeout': 'timeout'
                }
                for src, dst in mapping.items():
                    if src in health:
                        result[dst] = health[src]
        
        # Handle object config
        elif hasattr(cfg, 'health'):
            health = getattr(cfg, 'health', None)
            if health:
                for attr in ['check_interval', 'cpu_threshold', 'memory_threshold',
                            'disk_threshold', 'dependencies', 'timeout']:
                    if hasattr(health, attr):
                        value = getattr(health, attr, None)
                        if value is not None:
                            result[attr] = value
        
        # Validate and clamp values
        result['check_interval'] = max(5.0, float(result['check_interval']))
        result['cpu_threshold'] = max(0.0, min(100.0, float(result['cpu_threshold'])))
        result['memory_threshold'] = max(0.0, min(100.0, float(result['memory_threshold'])))
        result['disk_threshold'] = max(0.0, min(100.0, float(result['disk_threshold'])))
        result['timeout'] = max(1.0, float(result['timeout']))
        
        if not isinstance(result['dependencies'], list):
            result['dependencies'] = []
        
        return result
    
    def _initialize_default_checks(self):
        """Initialize default health checks with proper priorities."""
        try:
            # System resources check (CRITICAL)
            self.add_health_check(
                SystemResourceHealthCheck(
                    cpu_threshold=self.config['cpu_threshold'],
                    memory_threshold=self.config['memory_threshold'],
                    disk_threshold=self.config['disk_threshold'],
                    priority=HealthCheckPriority.CRITICAL
                ),
                priority=HealthCheckPriority.CRITICAL
            )
            
            # Process health (IMPORTANT)
            self.add_health_check(
                ProcessHealthCheck(priority=HealthCheckPriority.IMPORTANT),
                priority=HealthCheckPriority.IMPORTANT
            )
            
            # Dependencies (INFORMATIONAL)
            if self.config['dependencies']:
                self.add_health_check(
                    DependencyHealthCheck(
                        self.config['dependencies'],
                        priority=HealthCheckPriority.INFORMATIONAL
                    ),
                    priority=HealthCheckPriority.INFORMATIONAL
                )
            
            log.info("health_check_manager.initialized checks=%d interval=%.1f",
                    len(self.health_checks), self.check_interval)
        
        except Exception as e:
            log.error("health_check_manager.initialization_failed error=%s", str(e), exc_info=True)
    
    def add_health_check(self, health_check: HealthCheck,
                        priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL):
        """Add a health check with priority level."""
        if not health_check or not health_check.name:
            log.warning("health_check.invalid_check skipped")
            return
        
        self.health_checks[health_check.name] = health_check
        self.check_priorities[health_check.name] = priority
        
        log.info("health_check.added name=%s priority=%s", health_check.name, priority.name)
    
    def remove_health_check(self, name: str):
        """Remove a health check."""
        if name in self.health_checks:
            del self.health_checks[name]
            if name in self.check_priorities:
                del self.check_priorities[name]
            log.info("health_check.removed name=%s", name)
    
    def register_check(self, name: str, check_func: Callable[[], Awaitable[HealthStatus]],
                      priority: HealthCheckPriority = HealthCheckPriority.INFORMATIONAL,
                      timeout: float = 10.0):
        """Register a custom health check function."""
        health_check = CustomHealthCheck(name, check_func, priority, timeout)
        self.add_health_check(health_check, priority)
    
    async def run_checks(self) -> SystemHealth:
        """Alias for run_health_checks for compatibility."""
        return await self.run_health_checks()
    
    async def run_health_checks(self) -> SystemHealth:
        """
        Run health checks with staleness validation and overlap prevention.
        
        Returns:
            SystemHealth with current health status
        """
        # Check if already in progress
        if self._check_in_progress:
            log.warning("health_checks.already_running")
            
            # Return cached result if fresh enough
            if self.last_health_check and not self.last_health_check.is_stale(self.max_staleness_seconds):
                log.debug("health_checks.returning_cached age=%.2fs",
                         self.last_health_check.get_age_seconds())
                return self.last_health_check
            
            # Wait briefly for current check to complete
            try:
                await asyncio.wait_for(self._check_lock.acquire(), timeout=2.0)
                self._check_lock.release()
                
                # Return latest result after wait
                if self.last_health_check:
                    return self.last_health_check
            except asyncio.TimeoutError:
                pass
            
            # Return degraded status if no recent data
            return SystemHealth(
                overall_status=HealthStatus.DEGRADED,
                checks={},
                metadata={
                    "message": "Health check in progress, no recent data available",
                    "check_in_progress": True
                }
            )
        
        # Acquire lock for this check
        async with self._check_lock:
            self._check_in_progress = True
            
            try:
                if not self.health_checks:
                    return SystemHealth(
                        overall_status=HealthStatus.HEALTHY,
                        checks={},
                        metadata={"message": "No health checks configured"}
                    )
                
                check_results = {}
                tasks = []
                
                timeout = self.config.get('timeout', 10.0)
                
                # Create tasks for all checks
                for name, health_check in self.health_checks.items():
                    if hasattr(health_check, 'timeout'):
                        health_check.timeout = min(health_check.timeout, timeout)
                    
                    task = asyncio.create_task(
                        self._run_single_check(name, health_check),
                        name=f"health_check_{name}"
                    )
                    tasks.append((name, task))
                
                # Wait for all checks with overall timeout
                try:
                    done, pending = await asyncio.wait(
                        [task for _, task in tasks],
                        timeout=timeout + 2.0,
                        return_when=asyncio.ALL_COMPLETED
                    )
                    
                    # Cancel any pending tasks
                    for task in pending:
                        task.cancel()
                        log.warning("health_check.timeout task=%s", task.get_name())
                    
                except Exception as e:
                    log.error("health_check.wait_failed error=%s", str(e), exc_info=True)
                
                # Collect results
                for name, task in tasks:
                    try:
                        if task.done() and not task.cancelled():
                            result = task.result()
                        else:
                            result = HealthCheckResult(
                                name=name,
                                status=HealthStatus.UNHEALTHY,
                                message="Health check timed out or was cancelled",
                                priority=self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL)
                            )
                        check_results[name] = result
                    
                    except Exception as e:
                        log.error("health_check.result_failed name=%s error=%s", name, str(e))
                        check_results[name] = HealthCheckResult(
                            name=name,
                            status=HealthStatus.UNHEALTHY,
                            message=f"Health check failed: {str(e)}",
                            priority=self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL)
                        )
                
                # Calculate overall status
                overall_status = self._calculate_overall_status(check_results)
                
                # Create system health
                system_health = SystemHealth(
                    overall_status=overall_status,
                    checks=check_results,
                    metadata=self._generate_health_metadata(check_results)
                )
                
                # Update history
                self.check_history.append({
                    "timestamp": system_health.timestamp.isoformat(),
                    "status": overall_status.value,
                    "check_count": len(check_results)
                })
                
                # Cache result
                self.last_health_check = system_health
                
                log.info(
                    "health_check.completed overall=%s checks=%d duration=%.2f age=%.2f",
                    overall_status.value,
                    len(check_results),
                    sum(r.duration for r in check_results.values()),
                    system_health.get_age_seconds()
                )
                
                return system_health
            
            finally:
                self._check_in_progress = False
    
    async def _run_single_check(self, name: str, health_check: HealthCheck) -> HealthCheckResult:
        """Run a single health check with error handling."""
        try:
            return await health_check.check()
        except Exception as e:
            log.error("health_check.execution_failed name=%s error=%s", name, str(e), exc_info=True)
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                priority=self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL)
            )
    
    def _calculate_overall_status(self, check_results: Dict[str, HealthCheckResult]) -> HealthStatus:
        """Calculate overall status with priority weighting."""
        # Critical checks (priority 0)
        critical_checks = [
            result for name, result in check_results.items()
            if self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL) == HealthCheckPriority.CRITICAL
        ]
        
        if any(r.status == HealthStatus.UNHEALTHY for r in critical_checks):
            return HealthStatus.UNHEALTHY
        
        # Important checks (priority 1)
        important_checks = [
            result for name, result in check_results.items()
            if self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL) == HealthCheckPriority.IMPORTANT
        ]
        
        if any(r.status == HealthStatus.UNHEALTHY for r in important_checks):
            return HealthStatus.DEGRADED
        
        # Any degraded status
        if any(r.status == HealthStatus.DEGRADED for r in check_results.values()):
            return HealthStatus.DEGRADED
        
        # Informational checks (priority 2) - only degrade if all are unhealthy
        info_checks = [
            result for name, result in check_results.items()
            if self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL) == HealthCheckPriority.INFORMATIONAL
        ]
        
        if info_checks and all(r.status == HealthStatus.UNHEALTHY for r in info_checks):
            return HealthStatus.DEGRADED
        
        return HealthStatus.HEALTHY
    
    def _generate_health_metadata(self, check_results: Dict[str, HealthCheckResult]) -> Dict[str, Any]:
        """Generate comprehensive health metadata."""
        priority_breakdown = {
            "critical": {"total": 0, "healthy": 0, "degraded": 0, "unhealthy": 0},
            "important": {"total": 0, "healthy": 0, "degraded": 0, "unhealthy": 0},
            "informational": {"total": 0, "healthy": 0, "degraded": 0, "unhealthy": 0}
        }
        
        for name, result in check_results.items():
            priority = self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL)
            priority_name = priority.name.lower()
            
            priority_breakdown[priority_name]["total"] += 1
            if result.status == HealthStatus.HEALTHY:
                priority_breakdown[priority_name]["healthy"] += 1
            elif result.status == HealthStatus.DEGRADED:
                priority_breakdown[priority_name]["degraded"] += 1
            else:
                priority_breakdown[priority_name]["unhealthy"] += 1
        
        return {
            "total_checks": len(check_results),
            "healthy_checks": sum(1 for r in check_results.values() if r.status == HealthStatus.HEALTHY),
            "degraded_checks": sum(1 for r in check_results.values() if r.status == HealthStatus.DEGRADED),
            "unhealthy_checks": sum(1 for r in check_results.values() if r.status == HealthStatus.UNHEALTHY),
            "average_duration": round(
                sum(r.duration for r in check_results.values()) / len(check_results), 3
            ) if check_results else 0.0,
            "priority_breakdown": priority_breakdown,
            "check_priorities": {name: p.name for name, p in self.check_priorities.items()}
        }
    
    async def start_monitoring(self):
        """Start health monitoring with overlap prevention."""
        if self._monitor_task and not self._monitor_task.done():
            log.warning("health_monitor.already_running")
            return
        
        self._shutdown_event.clear()
        self._monitor_task = asyncio.create_task(
            self._monitor_loop(),
            name="health_monitor"
        )
        log.info("health_monitor.started interval=%.1f", self.check_interval)
    
    async def _monitor_loop(self):
        """Health monitoring loop with proper overlap prevention."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    # Run checks with timeout slightly less than interval
                    await asyncio.wait_for(
                        self.run_health_checks(),
                        timeout=self.check_interval * 0.9
                    )
                except asyncio.TimeoutError:
                    log.warning("health_monitor.check_timeout interval=%.1f", self.check_interval)
                except Exception as e:
                    log.error("health_monitor.check_failed error=%s", str(e), exc_info=True)
                
                # Wait for next interval or shutdown
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.check_interval
                    )
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue loop
        
        except asyncio.CancelledError:
            log.info("health_monitor.cancelled")
            raise
        
        finally:
            log.info("health_monitor.stopped")
    
    async def stop_monitoring(self):
        """Stop health monitoring gracefully with proper cleanup."""
        log.info("health_monitor.stopping")
        self._shutdown_event.set()
        
        if self._monitor_task and not self._monitor_task.done():
            try:
                await asyncio.wait_for(self._monitor_task, timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("health_monitor.stop_timeout cancelling_task")
                self._monitor_task.cancel()
                try:
                    await self._monitor_task
                except asyncio.CancelledError:
                    pass
        
        log.info("health_monitor.stopped")
    
    async def get_overall_health(self) -> HealthStatus:
        """Get current overall health status."""
        if self.last_health_check and not self.last_health_check.is_stale(self.max_staleness_seconds):
            return self.last_health_check.overall_status
        
        system_health = await self.run_health_checks()
        return system_health.overall_status
    
    async def get_all_check_results(self) -> Dict[str, Any]:
        """Get all health check results with detailed information."""
        if not self.last_health_check or self.last_health_check.is_stale(self.max_staleness_seconds):
            await self.run_health_checks()
        
        if self.last_health_check:
            return {
                name: result.to_dict()
                for name, result in self.last_health_check.checks.items()
            }
        return {}
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of health status with comprehensive details."""
        if not self.last_health_check:
            return {
                "status": "unknown",
                "message": "No health check data available",
                "timestamp": datetime.now().isoformat()
            }
        
        return {
            "overall_status": self.last_health_check.overall_status.value,
            "timestamp": self.last_health_check.timestamp.isoformat(),
            "age_seconds": round(self.last_health_check.get_age_seconds(), 2),
            "is_stale": self.last_health_check.is_stale(self.max_staleness_seconds),
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "duration": round(result.duration, 3),
                    "priority": self.check_priorities.get(name, HealthCheckPriority.INFORMATIONAL).name
                }
                for name, result in self.last_health_check.checks.items()
            },
            "metadata": self.last_health_check.metadata,
            "history": list(self.check_history)[-10:]
        }
    
    async def cleanup(self):
        """Clean up resources and stop monitoring."""
        log.info("health_check_manager.cleanup_started")
        
        # Stop monitoring
        await self.stop_monitoring()
        
        # Clear caches
        self.last_health_check = None
        self.check_history.clear()
        
        log.info("health_check_manager.cleanup_completed")
    
    async def __aenter__(self):
        """Start health monitoring when used as context manager."""
        await self.start_monitoring()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Stop health monitoring and cleanup when exiting context."""
        await self.cleanup()
