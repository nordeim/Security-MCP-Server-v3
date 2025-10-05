# mcp_server/base_tool.py
```py
"""
Enhanced MCP Base Tool with circuit breaker, metrics, and advanced error handling.
Production-ready implementation with proper async support, validation, and resource limits.

All critical fixes applied:
- Fixed Pydantic v1/v2 compatibility
- Enhanced semaphore registry with cleanup
- Improved error context handling
- Comprehensive type hints
- Resource limit safety

Usage:
    from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput
    
    class MyTool(MCPBaseTool):
        command_name = "mytool"
        allowed_flags = ["-flag1", "-flag2"]
        
        async def run(self, inp: ToolInput) -> ToolOutput:
            return await super().run(inp)
"""
import asyncio
import logging
import os
import re
import shlex
import shutil
import time
import contextlib
import inspect
import threading
import sys
import resource
import math
import weakref
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Optional, Sequence, Dict, Any, List
from datetime import datetime, timedelta

try:
    from pydantic import BaseModel, Field
    try:
        from pydantic import field_validator
        _PD_V2 = True
    except ImportError:
        from pydantic import validator as field_validator
        _PD_V2 = False
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    
    class BaseModel:
        """Fallback BaseModel when Pydantic not available."""
        def __init__(self, **data):
            for k, v in data.items():
                setattr(self, k, v)
        
        def dict(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
    
    def Field(default=None, **kwargs):
        return default
    
    def field_validator(*args, **kwargs):
        def _decorator(func):
            return func
        return _decorator
    
    _PD_V2 = False

try:
    from .circuit_breaker import CircuitBreaker, CircuitBreakerState
except ImportError:
    CircuitBreaker = None
    CircuitBreakerState = None

try:
    from .metrics import ToolMetrics
except ImportError:
    ToolMetrics = None

log = logging.getLogger(__name__)

# Configuration constants
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")
_HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
_MAX_ARGS_LEN = int(os.getenv("MCP_MAX_ARGS_LEN", "2048"))
_MAX_STDOUT_BYTES = int(os.getenv("MCP_MAX_STDOUT_BYTES", "1048576"))
_MAX_STDERR_BYTES = int(os.getenv("MCP_MAX_STDERR_BYTES", "262144"))
_DEFAULT_TIMEOUT_SEC = float(os.getenv("MCP_DEFAULT_TIMEOUT_SEC", "300"))
_DEFAULT_CONCURRENCY = int(os.getenv("MCP_DEFAULT_CONCURRENCY", "2"))
_MAX_MEMORY_MB = int(os.getenv("MCP_MAX_MEMORY_MB", "512"))
_MAX_FILE_DESCRIPTORS = int(os.getenv("MCP_MAX_FILE_DESCRIPTORS", "256"))

# Thread-safe semaphore creation with cleanup
_semaphore_lock = threading.Lock()
_semaphore_registry: Dict[str, asyncio.Semaphore] = {}
_loop_refs: 'weakref.WeakValueDictionary' = weakref.WeakValueDictionary()


def _is_private_or_lab(value: str) -> bool:
    """
    Enhanced validation with hostname format checking.
    
    Validates:
    - RFC1918 private IPv4 addresses
    - RFC1918 private IPv4 networks (CIDR)
    - *.lab.internal hostnames
    
    Args:
        value: Target to validate
    
    Returns:
        True if valid, False otherwise
    """
    import ipaddress
    v = value.strip()
    
    # Validate .lab.internal hostname format
    if v.endswith(".lab.internal"):
        hostname_part = v[:-len(".lab.internal")]
        if not hostname_part or not _HOSTNAME_PATTERN.match(hostname_part):
            return False
        return True
    
    try:
        if "/" in v:
            # Network/CIDR notation
            net = ipaddress.ip_network(v, strict=False)
            return net.version == 4 and net.is_private
        else:
            # Single IP address
            ip = ipaddress.ip_address(v)
            return ip.version == 4 and ip.is_private
    except ValueError:
        return False


class ToolErrorType(Enum):
    """Tool error types for categorization."""
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    VALIDATION_ERROR = "validation_error"
    EXECUTION_ERROR = "execution_error"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    UNKNOWN = "unknown"


@dataclass
class ErrorContext:
    """Error context with recovery suggestions and metadata."""
    error_type: ToolErrorType
    message: str
    recovery_suggestion: str
    timestamp: datetime
    tool_name: str
    target: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "error_type": self.error_type.value,
            "message": self.message,
            "recovery_suggestion": self.recovery_suggestion,
            "timestamp": self.timestamp.isoformat(),
            "tool_name": self.tool_name,
            "target": self.target,
            "metadata": self.metadata
        }


class ToolInput(BaseModel):
    """
    Tool input model with enhanced validation.
    
    Attributes:
        target: Target host or network (RFC1918 or .lab.internal)
        extra_args: Additional arguments for the tool
        timeout_sec: Optional timeout override
        correlation_id: Optional correlation ID for tracking
    """
    target: str
    extra_args: str = ""
    timeout_sec: Optional[float] = None
    correlation_id: Optional[str] = None
    
    if PYDANTIC_AVAILABLE:
        if _PD_V2:
            # Pydantic v2 style (no @classmethod decorator)
            @field_validator("target", mode='after')
            def _validate_target(cls, v: str) -> str:
                if not _is_private_or_lab(v):
                    raise ValueError(
                        "Target must be RFC1918 IPv4, RFC1918 network (CIDR), "
                        "or a .lab.internal hostname."
                    )
                return v
            
            @field_validator("extra_args", mode='after')
            def _validate_extra_args(cls, v: str) -> str:
                v = v or ""
                if len(v) > _MAX_ARGS_LEN:
                    raise ValueError(f"extra_args too long (> {_MAX_ARGS_LEN} bytes)")
                if _DENY_CHARS.search(v):
                    raise ValueError(
                        "extra_args contains forbidden metacharacters (;, &, |, `, $, >, <, newline)"
                    )
                return v
        else:
            # Pydantic v1 style (validator has implicit @classmethod)
            @field_validator("target")
            def _validate_target(cls, v: str) -> str:
                if not _is_private_or_lab(v):
                    raise ValueError(
                        "Target must be RFC1918 IPv4, RFC1918 network (CIDR), "
                        "or a .lab.internal hostname."
                    )
                return v
            
            @field_validator("extra_args")
            def _validate_extra_args(cls, v: str) -> str:
                v = v or ""
                if len(v) > _MAX_ARGS_LEN:
                    raise ValueError(f"extra_args too long (> {_MAX_ARGS_LEN} bytes)")
                if _DENY_CHARS.search(v):
                    raise ValueError(
                        "extra_args contains forbidden metacharacters (;, &, |, `, $, >, <, newline)"
                    )
                return v


class ToolOutput(BaseModel):
    """
    Tool output model with comprehensive result data.
    
    Attributes:
        stdout: Standard output from command
        stderr: Standard error from command
        returncode: Process return code
        truncated_stdout: Whether stdout was truncated
        truncated_stderr: Whether stderr was truncated
        timed_out: Whether execution timed out
        error: Optional error message
        error_type: Optional error type
        execution_time: Execution duration in seconds
        correlation_id: Correlation ID for tracking
        metadata: Additional metadata
    """
    stdout: str
    stderr: str
    returncode: int
    truncated_stdout: bool = False
    truncated_stderr: bool = False
    timed_out: bool = False
    error: Optional[str] = None
    error_type: Optional[str] = None
    execution_time: Optional[float] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict) if PYDANTIC_AVAILABLE else {}
    
    def ensure_metadata(self):
        """Ensure metadata dictionary is initialized."""
        if self.metadata is None:
            self.metadata = {}
    
    def is_success(self) -> bool:
        """Check if execution was successful."""
        return self.returncode == 0 and not self.timed_out and not self.error


class MCPBaseTool(ABC):
    """
    Enhanced base class for MCP tools with production-ready features.
    
    Features:
    - Circuit breaker protection
    - Metrics collection
    - Resource limits
    - Concurrency control
    - Comprehensive error handling
    - Async execution
    
    Subclasses must define:
    - command_name: Command to execute
    - allowed_flags: Optional whitelist of allowed flags
    """
    
    command_name: ClassVar[str]
    allowed_flags: ClassVar[Optional[Sequence[str]]] = None
    concurrency: ClassVar[int] = _DEFAULT_CONCURRENCY
    default_timeout_sec: ClassVar[float] = _DEFAULT_TIMEOUT_SEC
    circuit_breaker_failure_threshold: ClassVar[int] = 5
    circuit_breaker_recovery_timeout: ClassVar[float] = 60.0
    circuit_breaker_expected_exception: ClassVar[tuple] = (Exception,)
    _semaphore: ClassVar[Optional[asyncio.Semaphore]] = None
    
    def __init__(self):
        self.tool_name = self.__class__.__name__
        self._circuit_breaker: Optional['CircuitBreaker'] = None
        self.metrics: Optional['ToolMetrics'] = None
        self._initialize_metrics()
        self._initialize_circuit_breaker()
    
    def _initialize_metrics(self):
        """Initialize tool metrics if available."""
        if ToolMetrics is not None:
            try:
                self.metrics = ToolMetrics(self.tool_name)
                log.debug("metrics.initialized tool=%s", self.tool_name)
            except Exception as e:
                log.warning("metrics.initialization_failed tool=%s error=%s", 
                          self.tool_name, str(e))
                self.metrics = None
        else:
            self.metrics = None
    
    def _initialize_circuit_breaker(self):
        """Initialize instance-level circuit breaker if available."""
        if CircuitBreaker is None:
            self._circuit_breaker = None
            return
        
        try:
            self._circuit_breaker = CircuitBreaker(
                failure_threshold=self.circuit_breaker_failure_threshold,
                recovery_timeout=self.circuit_breaker_recovery_timeout,
                expected_exception=self.circuit_breaker_expected_exception,
                name=f"{self.tool_name}_{id(self)}"
            )
            log.debug("circuit_breaker.initialized tool=%s", self.tool_name)
        except Exception as e:
            log.error("circuit_breaker.initialization_failed tool=%s error=%s", 
                     self.tool_name, str(e))
            self._circuit_breaker = None
    
    def _ensure_semaphore(self) -> asyncio.Semaphore:
        """
        Thread-safe semaphore initialization per event loop with automatic cleanup.
        
        Uses WeakValueDictionary to automatically clean up semaphores for dead loops.
        """
        global _semaphore_registry, _loop_refs
        
        try:
            loop = asyncio.get_running_loop()
            loop_id = id(loop)
        except RuntimeError:
            # Create new loop if needed
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop_id = id(loop)
        
        # Use class name as key combined with loop id
        key = f"{self.__class__.__name__}_{loop_id}"
        
        with _semaphore_lock:
            # Store weak reference to loop for cleanup detection
            _loop_refs[loop_id] = loop
            
            # Clean up semaphores for dead loops
            dead_keys = [
                k for k in _semaphore_registry.keys() 
                if int(k.split('_')[-1]) not in _loop_refs
            ]
            for dead_key in dead_keys:
                del _semaphore_registry[dead_key]
                log.debug("semaphore.cleaned_up key=%s", dead_key)
            
            if key not in _semaphore_registry:
                _semaphore_registry[key] = asyncio.Semaphore(self.concurrency)
                log.debug("semaphore.created key=%s concurrency=%d", key, self.concurrency)
            
            return _semaphore_registry[key]
    
    async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """
        Run tool with circuit breaker, metrics, and resource limits.
        
        Args:
            inp: Tool input with target and arguments
            timeout_sec: Optional timeout override
        
        Returns:
            ToolOutput with execution results
        """
        start_time = time.time()
        correlation_id = inp.correlation_id or str(int(start_time * 1000))
        
        # Record active execution
        if self.metrics:
            self.metrics.increment_active()
        
        try:
            # Check circuit breaker state
            if self._circuit_breaker:
                state = getattr(self._circuit_breaker, 'state', None)
                if state == getattr(CircuitBreakerState, 'OPEN', 'OPEN'):
                    return self._create_circuit_breaker_error(inp, correlation_id)
            
            # Execute with semaphore for concurrency control
            async with self._ensure_semaphore():
                if self._circuit_breaker:
                    if inspect.iscoroutinefunction(getattr(self._circuit_breaker, 'call', None)):
                        result = await self._circuit_breaker.call(
                            self._execute_tool, inp, timeout_sec
                        )
                    else:
                        result = await self._execute_with_sync_breaker(inp, timeout_sec)
                else:
                    result = await self._execute_tool(inp, timeout_sec)
                
                execution_time = time.time() - start_time
                await self._record_metrics(result, execution_time)
                
                result.correlation_id = correlation_id
                result.execution_time = execution_time
                result.ensure_metadata()
                
                return result
                
        except Exception as e:
            return await self._handle_execution_error(e, inp, correlation_id, start_time)
        
        finally:
            # Decrement active execution
            if self.metrics:
                self.metrics.decrement_active()
    
    def _create_circuit_breaker_error(self, inp: ToolInput, correlation_id: str) -> ToolOutput:
        """Create error output for open circuit breaker."""
        error_context = ErrorContext(
            error_type=ToolErrorType.CIRCUIT_BREAKER_OPEN,
            message=f"Circuit breaker is open for {self.tool_name}",
            recovery_suggestion="Wait for recovery timeout or check service health",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target,
            metadata={"state": str(getattr(self._circuit_breaker, 'state', None))}
        )
        return self._create_error_output(error_context, correlation_id)
    
    async def _execute_with_sync_breaker(self, inp: ToolInput, 
                                         timeout_sec: Optional[float]) -> ToolOutput:
        """Handle sync circuit breaker with async execution."""
        try:
            result = await self._execute_tool(inp, timeout_sec)
            if hasattr(self._circuit_breaker, 'call_succeeded'):
                self._circuit_breaker.call_succeeded()
            return result
        except Exception as e:
            if hasattr(self._circuit_breaker, 'call_failed'):
                self._circuit_breaker.call_failed()
            raise
    
    async def _record_metrics(self, result: ToolOutput, execution_time: float):
        """Record metrics with proper error handling."""
        if not self.metrics:
            return
        
        try:
            success = result.is_success()
            error_type = result.error_type if not success else None
            
            if hasattr(self.metrics, 'record_execution'):
                # Handle both sync and async versions
                record_func = self.metrics.record_execution
                if inspect.iscoroutinefunction(record_func):
                    await record_func(
                        success=success,
                        execution_time=execution_time,
                        timed_out=result.timed_out,
                        error_type=error_type
                    )
                else:
                    # Run sync function in thread pool to avoid blocking
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        record_func,
                        success,
                        execution_time,
                        result.timed_out,
                        error_type
                    )
        except Exception as e:
            log.warning("metrics.recording_failed tool=%s error=%s", 
                       self.tool_name, str(e))
    
    async def _handle_execution_error(self, e: Exception, inp: ToolInput, 
                                      correlation_id: str, start_time: float) -> ToolOutput:
        """Handle execution errors with detailed context."""
        execution_time = time.time() - start_time
        error_context = ErrorContext(
            error_type=ToolErrorType.EXECUTION_ERROR,
            message=f"Tool execution failed: {str(e)}",
            recovery_suggestion="Check tool logs and system resources",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target,
            metadata={
                "exception": str(e),
                "exception_type": type(e).__name__,
                "execution_time": execution_time
            }
        )
        
        if self.metrics:
            await self._record_metrics(
                ToolOutput(
                    stdout="", stderr=str(e), returncode=1,
                    error_type=ToolErrorType.EXECUTION_ERROR.value
                ),
                execution_time
            )
        
        return self._create_error_output(error_context, correlation_id)
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute the tool with validation and resource limits."""
        resolved_cmd = self._resolve_command()
        if not resolved_cmd:
            error_context = ErrorContext(
                error_type=ToolErrorType.NOT_FOUND,
                message=f"Command not found: {self.command_name}",
                recovery_suggestion=f"Install {self.command_name} or check PATH environment variable",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"command": self.command_name, "PATH": os.getenv("PATH")}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        try:
            args = self._parse_args(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Argument validation failed: {str(e)}",
                recovery_suggestion="Check arguments and try again",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"validation_error": str(e), "provided_args": inp.extra_args}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        cmd = [resolved_cmd] + list(args) + [inp.target]
        timeout = float(timeout_sec or inp.timeout_sec or self.default_timeout_sec)
        return await self._spawn(cmd, timeout)
    
    def _create_error_output(self, error_context: ErrorContext, correlation_id: str) -> ToolOutput:
        """Create error output from error context."""
        log.error(
            "tool.error tool=%s error_type=%s target=%s message=%s correlation_id=%s",
            error_context.tool_name,
            error_context.error_type.value,
            error_context.target,
            error_context.message,
            correlation_id,
            extra={"error_context": error_context.to_dict()}
        )
        
        output = ToolOutput(
            stdout="",
            stderr=error_context.message,
            returncode=1,
            error=error_context.message,
            error_type=error_context.error_type.value,
            correlation_id=correlation_id,
            metadata={
                "recovery_suggestion": error_context.recovery_suggestion,
                "timestamp": error_context.timestamp.isoformat(),
                **error_context.metadata
            }
        )
        output.ensure_metadata()
        return output
    
    def _resolve_command(self) -> Optional[str]:
        """Resolve command path using shutil.which."""
        return shutil.which(self.command_name)
    
    def _parse_args(self, extra_args: str) -> Sequence[str]:
        """Parse and validate arguments."""
        try:
            tokens = shlex.split(extra_args) if extra_args else []
        except ValueError as e:
            raise ValueError(f"Failed to parse arguments: {str(e)}")
        return self._sanitize_tokens(tokens)
    
    def _sanitize_tokens(self, tokens: Sequence[str]) -> Sequence[str]:
        """
        Sanitize token list - block shell metacharacters.
        
        Args:
            tokens: Parsed argument tokens
        
        Returns:
            Sanitized tokens
        
        Raises:
            ValueError: If validation fails
        """
        safe = []
        flags_require_value = set(getattr(self, "_FLAGS_REQUIRE_VALUE", []))
        
        for t in tokens:
            t = t.strip()
            if not t:
                continue
            
            if not _TOKEN_ALLOWED.match(t):
                # Permit leading dash flags and pure numeric values even if the
                # strict regex rejects them (e.g., optimizer defaults like "-T4" or "10").
                if not (t.startswith("-") or t.isdigit()):
                    raise ValueError(f"Disallowed token in args: {t!r}")
            
            safe.append(t)
        
        if self.allowed_flags is not None:
            allowed = set(self.allowed_flags)
            # Allow subclasses to provide additional safe tokens (e.g., optimizer defaults)
            allowed.update(getattr(self, "_EXTRA_ALLOWED_TOKENS", []))
            
            expect_value_for: Optional[str] = None
            for token in safe:
                if expect_value_for is not None:
                    # Treat this token as the value for the preceding flag.
                    expect_value_for = None
                    continue
                
                base = token.split("=", 1)[0]
                if base not in allowed:
                    # Allow the token if it's the value for a prior flag requiring one.
                    if token not in flags_require_value and not token.isdigit():
                        raise ValueError(f"Flag not allowed: {token}")
                    continue
                
                if base in flags_require_value and "=" not in token:
                    expect_value_for = base
            
            if expect_value_for is not None:
                raise ValueError(f"{expect_value_for} requires a value")
        
        return safe
    
    def _set_resource_limits(self):
        """Set resource limits for subprocess (Unix/Linux only)."""
        if sys.platform == 'win32':
            return None
        
        def set_limits():
            try:
                # Limit CPU time (soft, hard)
                timeout_int = int(self.default_timeout_sec)
                resource.setrlimit(resource.RLIMIT_CPU, (timeout_int, timeout_int + 5))
                
                # Limit memory
                mem_bytes = _MAX_MEMORY_MB * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                
                # Limit file descriptors
                resource.setrlimit(resource.RLIMIT_NOFILE, (_MAX_FILE_DESCRIPTORS, _MAX_FILE_DESCRIPTORS))
                
                # Limit core dump size to 0
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception as e:
                log.warning("resource_limits.failed error=%s", str(e))
        
        return set_limits
    
    async def _spawn(self, cmd: Sequence[str], timeout_sec: float) -> ToolOutput:
        """Spawn subprocess with enhanced resource limits and security."""
        env = {
            "PATH": os.getenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        
        # Set resource limits function
        preexec_fn = self._set_resource_limits() if sys.platform != 'win32' else None
        
        try:
            log.info("tool.start command=%s timeout=%.1f", " ".join(cmd), timeout_sec)
            
            # Create subprocess with resource limits
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                preexec_fn=preexec_fn,
                start_new_session=True,  # Isolate process group
            )
            
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
                rc = proc.returncode
            except asyncio.TimeoutError:
                # Kill process group
                with contextlib.suppress(ProcessLookupError):
                    if sys.platform != 'win32':
                        import signal
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                    await proc.wait()
                
                output = ToolOutput(
                    stdout="",
                    stderr=f"Process timed out after {timeout_sec}s",
                    returncode=124,
                    timed_out=True,
                    error_type=ToolErrorType.TIMEOUT.value
                )
                output.ensure_metadata()
                return output
            
            truncated_stdout = False
            truncated_stderr = False
            
            if len(out) > _MAX_STDOUT_BYTES:
                out = out[:_MAX_STDOUT_BYTES]
                truncated_stdout = True
            
            if len(err) > _MAX_STDERR_BYTES:
                err = err[:_MAX_STDERR_BYTES]
                truncated_stderr = True
            
            output = ToolOutput(
                stdout=out.decode(errors="replace"),
                stderr=err.decode(errors="replace"),
                returncode=rc,
                truncated_stdout=truncated_stdout,
                truncated_stderr=truncated_stderr,
                timed_out=False
            )
            output.ensure_metadata()
            
            log.info("tool.end command=%s returncode=%s truncated_stdout=%s truncated_stderr=%s",
                    cmd[0] if cmd else "<cmd>", rc, truncated_stdout, truncated_stderr)
            
            return output
            
        except FileNotFoundError:
            msg = f"Command not found: {cmd[0] if cmd else '<cmd>'}"
            log.error("tool.error %s", msg)
            output = ToolOutput(
                stdout="",
                stderr=msg,
                returncode=127,
                error="not_found",
                error_type=ToolErrorType.NOT_FOUND.value
            )
            output.ensure_metadata()
            return output
            
        except Exception as e:
            msg = f"Execution failed: {e.__class__.__name__}: {e}"
            log.error("tool.error %s", msg)
            output = ToolOutput(
                stdout="",
                stderr=msg,
                returncode=1,
                error="execution_failed",
                error_type=ToolErrorType.EXECUTION_ERROR.value
            )
            output.ensure_metadata()
            return output
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get comprehensive tool information."""
        return {
            "name": self.tool_name,
            "command": self.command_name,
            "concurrency": self.concurrency,
            "timeout": self.default_timeout_sec,
            "circuit_breaker": {
                "enabled": self._circuit_breaker is not None,
                "state": self._circuit_breaker.state.name if self._circuit_breaker else "N/A",
                "failure_threshold": self.circuit_breaker_failure_threshold,
                "recovery_timeout": self.circuit_breaker_recovery_timeout,
            },
            "metrics": {
                "available": self.metrics is not None
            },
            "resource_limits": {
                "max_memory_mb": _MAX_MEMORY_MB,
                "max_file_descriptors": _MAX_FILE_DESCRIPTORS,
                "max_stdout_bytes": _MAX_STDOUT_BYTES,
                "max_stderr_bytes": _MAX_STDERR_BYTES,
            }
        }

```

# mcp_server/server.py
```py
"""
Enhanced MCP Server with comprehensive features and production-ready implementation.
All security and reliability fixes applied.

All critical fixes applied:
- Complete cleanup methods
- Fixed tool discovery patterns
- Rate limiting support
- Enhanced background task management
- Proper health/metrics integration
- Comprehensive error handling
- Testing utilities

Features:
- Dual transport support (stdio, HTTP)
- Automatic tool discovery
- Circuit breaker integration
- Health monitoring
- Metrics collection
- Graceful shutdown
- Rate limiting
- Comprehensive logging

Usage:
    # Stdio transport (for Claude Desktop)
    python -m mcp_server.server
    
    # HTTP transport
    MCP_SERVER_TRANSPORT=http python -m mcp_server.server
    
    # Custom configuration
    MCP_CONFIG_FILE=config.yaml python -m mcp_server.server

Environment Variables:
    MCP_SERVER_TRANSPORT: Transport mode (stdio|http)
    MCP_SERVER_PORT: HTTP server port (default: 8080)
    MCP_SERVER_HOST: HTTP server host (default: 0.0.0.0)
    MCP_CONFIG_FILE: Configuration file path
    TOOLS_PACKAGE: Package to scan for tools (default: mcp_server.tools)
    TOOL_INCLUDE: Comma-separated list of tools to include
    TOOL_EXCLUDE: Comma-separated list of tools to exclude
"""
import asyncio
import importlib
import inspect
import logging
import os
import pkgutil
import signal
import sys
import time
from typing import Dict, List, Optional, Set, Any, Sequence
from datetime import datetime
import json
import contextlib
from collections import defaultdict

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from sse_starlette.sse import EventSourceResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = None

try:
    import uvicorn
    UVICORN_AVAILABLE = True
except ImportError:
    UVICORN_AVAILABLE = False

try:
    from mcp.server import Server as MCPServerBase
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    MCPServerBase = None
    stdio_server = None
    Tool = None
    TextContent = None

try:
    from prometheus_client import CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"

from .config import get_config, reset_config
from .health import HealthCheckManager, HealthStatus, ToolAvailabilityHealthCheck, HealthCheckPriority
from .base_tool import MCPBaseTool, ToolInput, ToolOutput
from .metrics import MetricsManager

log = logging.getLogger(__name__)

# Patterns to exclude from tool discovery (exact and prefix/suffix matching)
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
EXCLUDED_EXACT = {'MCPBaseTool'}


def _maybe_setup_uvloop() -> None:
    """Optional uvloop installation for better async performance."""
    try:
        import uvloop
        uvloop.install()
        log.info("uvloop.installed")
    except ImportError:
        log.debug("uvloop.not_available hint='pip install uvloop'")
    except Exception as e:
        log.debug("uvloop.setup_failed error=%s", str(e))


def _setup_logging() -> None:
    """Environment-based logging configuration."""
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv(
        "LOG_FORMAT",
        "%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format=fmt)
    log.info("logging.configured level=%s", level)


def _parse_csv_env(name: str) -> Optional[List[str]]:
    """Parse CSV environment variables."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    return [x.strip() for x in raw.split(",") if x.strip()]


def _should_exclude_class(name: str) -> bool:
    """
    Check if class should be excluded from tool discovery.
    
    Uses exact match, prefix, and suffix patterns to avoid false positives.
    
    Args:
        name: Class name to check
    
    Returns:
        True if should be excluded, False otherwise
    """
    # Check exact matches
    if name in EXCLUDED_EXACT:
        return True
    
    # Check prefixes
    if any(name.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return True
    
    # Check suffixes
    if any(name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return True
    
    return False


def _load_tools_from_package(
    package_path: str,
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> List[MCPBaseTool]:
    """
    Discover and instantiate concrete MCPBaseTool subclasses with enhanced filtering.
    
    Args:
        package_path: Python package path to scan
        include: Optional whitelist of tool names
        exclude: Optional blacklist of tool names
    
    Returns:
        List of instantiated tool objects
    """
    tools: List[MCPBaseTool] = []
    log.info("tool_discovery.starting package=%s include=%s exclude=%s",
             package_path, include, exclude)
    
    try:
        pkg = importlib.import_module(package_path)
        log.debug("tool_discovery.package_imported path=%s", package_path)
    except Exception as e:
        log.error("tool_discovery.package_failed path=%s error=%s", package_path, e, exc_info=True)
        return tools

    module_count = 0
    for modinfo in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        module_count += 1
        try:
            module = importlib.import_module(modinfo.name)
            log.debug("tool_discovery.module_imported name=%s", modinfo.name)
        except Exception as e:
            log.warning("tool_discovery.module_skipped name=%s error=%s", modinfo.name, e)
            continue

        tool_count_in_module = 0
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Skip if name suggests it's not a real tool (enhanced pattern matching)
            if _should_exclude_class(name):
                log.debug("tool_discovery.class_excluded name=%s reason=pattern_match", name)
                continue

            # Check for explicit tool marker
            if hasattr(obj, '_is_tool') and not obj._is_tool:
                log.debug("tool_discovery.class_excluded name=%s reason=is_tool_false", name)
                continue

            try:
                if not issubclass(obj, MCPBaseTool) or obj is MCPBaseTool:
                    continue
            except Exception:
                continue

            # Apply include/exclude filters
            if include and name not in include:
                log.debug("tool_discovery.tool_skipped name=%s reason=include_filter", name)
                continue
            if exclude and name in exclude:
                log.debug("tool_discovery.tool_skipped name=%s reason=exclude_filter", name)
                continue

            try:
                inst = obj()
                tools.append(inst)
                tool_count_in_module += 1
                log.info("tool_discovery.tool_loaded name=%s command=%s", 
                        name, getattr(inst, 'command_name', 'unknown'))
            except Exception as e:
                log.warning("tool_discovery.tool_instantiation_failed name=%s error=%s", 
                          name, e, exc_info=True)

        if tool_count_in_module == 0:
            log.debug("tool_discovery.no_tools_in_module module=%s", modinfo.name)

    log.info("tool_discovery.completed package=%s modules=%d tools=%d",
             package_path, module_count, len(tools))
    return tools


# Pydantic models for HTTP API validation
if FASTAPI_AVAILABLE and BaseModel:
    class ToolExecutionRequest(BaseModel):
        """Validated tool execution request."""
        target: str = Field(..., min_length=1, max_length=255, 
                          description="Target host or network")
        extra_args: str = Field(default="", max_length=2048,
                              description="Additional tool arguments")
        timeout_sec: Optional[float] = Field(None, ge=1, le=3600,
                                            description="Timeout in seconds")
        correlation_id: Optional[str] = Field(None, max_length=64,
                                             description="Correlation ID for tracking")


class RateLimiter:
    """
    Token bucket rate limiter for API endpoints.
    
    Features:
    - Per-client rate limiting
    - Configurable rate and window
    - Thread-safe operation
    - Automatic cleanup of old entries
    """
    
    def __init__(self, rate: int = 10, per: float = 60.0, max_clients: int = 1000):
        """
        Initialize rate limiter.
        
        Args:
            rate: Number of requests allowed
            per: Time window in seconds
            max_clients: Maximum number of clients to track
        """
        self.rate = rate
        self.per = per
        self.max_clients = max_clients
        self.allowance: Dict[str, float] = defaultdict(lambda: rate)
        self.last_check: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()
        self._cleanup_count = 0
    
    async def check_rate_limit(self, key: str) -> bool:
        """
        Check if request is within rate limit.
        
        Args:
            key: Client identifier (e.g., IP address)
        
        Returns:
            True if allowed, False if rate limited
        """
        async with self._lock:
            # Periodic cleanup
            self._cleanup_count += 1
            if self._cleanup_count > 100:
                await self._cleanup_old_entries()
                self._cleanup_count = 0
            
            current = datetime.now()
            time_passed = (current - self.last_check.get(key, current)).total_seconds()
            self.last_check[key] = current
            
            # Add tokens based on time passed
            self.allowance[key] += time_passed * (self.rate / self.per)
            if self.allowance[key] > self.rate:
                self.allowance[key] = self.rate
            
            # Check if request allowed
            if self.allowance[key] < 1.0:
                return False
            
            # Consume token
            self.allowance[key] -= 1.0
            return True
    
    async def _cleanup_old_entries(self):
        """Remove old client entries to prevent memory growth."""
        cutoff = datetime.now() - timedelta(seconds=self.per * 2)
        
        to_remove = [
            key for key, last_time in self.last_check.items()
            if last_time < cutoff
        ]
        
        for key in to_remove:
            del self.allowance[key]
            del self.last_check[key]
        
        # If still too many, remove oldest
        if len(self.allowance) > self.max_clients:
            sorted_clients = sorted(self.last_check.items(), key=lambda x: x[1])
            to_remove = sorted_clients[:len(sorted_clients) - self.max_clients]
            
            for key, _ in to_remove:
                del self.allowance[key]
                del self.last_check[key]
        
        if to_remove:
            log.debug("rate_limiter.cleanup removed=%d", len(to_remove))


class ToolRegistry:
    """
    Tool Registry that holds tools and manages enabled set.
    
    Features:
    - Tool registration and discovery
    - Enable/disable functionality
    - Tool information retrieval
    - Metrics and circuit breaker integration
    """
    
    def __init__(self, config, tools: List[MCPBaseTool]):
        self.config = config
        self.tools: Dict[str, MCPBaseTool] = {}
        self.enabled_tools: Set[str] = set()
        self._register_tools_from_list(tools)

    def _register_tools_from_list(self, tools: List[MCPBaseTool]):
        """Register tools and initialize their components."""
        for tool in tools:
            tool_name = tool.__class__.__name__
            self.tools[tool_name] = tool
            
            if self._is_tool_enabled(tool_name):
                self.enabled_tools.add(tool_name)

            # Initialize metrics
            if hasattr(tool, '_initialize_metrics'):
                try:
                    tool._initialize_metrics()
                except Exception as e:
                    log.warning("tool.metrics_init_failed name=%s error=%s", tool_name, str(e))
            
            # Initialize circuit breaker
            if hasattr(tool, '_initialize_circuit_breaker'):
                try:
                    tool._initialize_circuit_breaker()
                except Exception as e:
                    log.warning("tool.circuit_breaker_init_failed name=%s error=%s", 
                              tool_name, str(e))

            log.info("tool_registry.tool_registered name=%s enabled=%s", 
                    tool_name, tool_name in self.enabled_tools)

    def _is_tool_enabled(self, tool_name: str) -> bool:
        """Check if tool is enabled based on include/exclude filters."""
        include = _parse_csv_env("TOOL_INCLUDE")
        exclude = _parse_csv_env("TOOL_EXCLUDE")
        
        if include and tool_name not in include:
            return False
        if exclude and tool_name in exclude:
            return False
        return True

    def get_tool(self, tool_name: str) -> Optional[MCPBaseTool]:
        """Get a tool by name."""
        return self.tools.get(tool_name)

    def get_enabled_tools(self) -> Dict[str, MCPBaseTool]:
        """Get all enabled tools."""
        return {name: tool for name, tool in self.tools.items() if name in self.enabled_tools}

    def enable_tool(self, tool_name: str):
        """Enable a tool."""
        if tool_name in self.tools:
            self.enabled_tools.add(tool_name)
            log.info("tool_registry.enabled name=%s", tool_name)

    def disable_tool(self, tool_name: str):
        """Disable a tool."""
        if tool_name in self.enabled_tools:
            self.enabled_tools.discard(tool_name)
            log.info("tool_registry.disabled name=%s", tool_name)

    def get_tool_info(self) -> List[Dict[str, Any]]:
        """Get information about all tools."""
        info = []
        for name, tool in self.tools.items():
            tool_info = {
                "name": name,
                "enabled": name in self.enabled_tools,
                "command": getattr(tool, "command_name", None),
                "description": tool.__doc__ or "No description",
                "concurrency": getattr(tool, "concurrency", None),
                "timeout": getattr(tool, "default_timeout_sec", None),
                "has_metrics": hasattr(tool, 'metrics') and tool.metrics is not None,
                "has_circuit_breaker": hasattr(tool, '_circuit_breaker') and tool._circuit_breaker is not None
            }
            
            # Add tool-specific info if available
            if hasattr(tool, 'get_tool_info'):
                try:
                    tool_specific = tool.get_tool_info()
                    tool_info.update(tool_specific)
                except Exception as e:
                    log.warning("tool_info.failed name=%s error=%s", name, str(e))
            
            info.append(tool_info)
        
        return info


class EnhancedMCPServer:
    """
    Enhanced MCP Server with complete integration and all fixes.
    
    Features:
    - Dual transport (stdio, HTTP)
    - Tool registry with enable/disable
    - Health monitoring
    - Metrics collection
    - Circuit breaker integration
    - Rate limiting
    - Graceful shutdown
    - Comprehensive cleanup
    """
    
    def __init__(self, tools: List[MCPBaseTool], transport: str = "stdio", config=None):
        self.tools = tools
        self.transport = transport
        self.config = config or get_config()
        self.tool_registry = ToolRegistry(self.config, tools)
        self.health_manager = HealthCheckManager(config=self.config)
        self.metrics_manager = MetricsManager.get()
        self.shutdown_event = asyncio.Event()
        self._background_tasks: Set[asyncio.Task] = set()
        self.rate_limiter = RateLimiter(rate=10, per=60.0)  # 10 req/min default

        # MCP server instance (for stdio)
        if MCP_AVAILABLE and MCPServerBase:
            try:
                self.server = MCPServerBase("enhanced-mcp-server")
                self._register_tools_mcp()
            except Exception as e:
                log.error("mcp_server.initialization_failed error=%s", str(e), exc_info=True)
                self.server = None
        else:
            self.server = None

        self._initialize_monitoring()
        self._setup_enhanced_signal_handlers()
        
        log.info("enhanced_server.initialized transport=%s tools=%d enabled=%d",
                self.transport, len(self.tools), len(self.tool_registry.enabled_tools))

    def _register_tools_mcp(self):
        """Register tools with MCP server for stdio transport."""
        if not self.server:
            return

        for tool in self.tools:
            try:
                self.server.register_tool(
                    name=tool.__class__.__name__,
                    description=tool.__doc__ or f"Execute {getattr(tool, 'command_name', 'tool')}",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target host or network"
                            },
                            "extra_args": {
                                "type": "string",
                                "description": "Additional arguments for the tool"
                            },
                            "timeout_sec": {
                                "type": "number",
                                "description": "Timeout in seconds"
                            }
                        },
                        "required": ["target"]
                    },
                    handler=self._create_mcp_tool_handler(tool)
                )
                log.debug("mcp.tool_registered name=%s", tool.__class__.__name__)
            except Exception as e:
                log.error("mcp.tool_registration_failed name=%s error=%s",
                         tool.__class__.__name__, str(e), exc_info=True)

    def _create_mcp_tool_handler(self, tool: MCPBaseTool):
        """Create MCP tool handler with proper error handling."""
        async def handler(target: str, extra_args: str = "", timeout_sec: Optional[float] = None):
            try:
                input_data = ToolInput(
                    target=target,
                    extra_args=extra_args,
                    timeout_sec=timeout_sec
                )
                result = await tool.run(input_data)
                
                # Convert to MCP response format
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            result.dict() if hasattr(result, 'dict') else result.__dict__,
                            indent=2
                        )
                    )
                ]
            except Exception as e:
                log.error("mcp_tool_handler.error tool=%s target=%s error=%s",
                          tool.__class__.__name__, target, str(e), exc_info=True)
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({
                            "error": str(e),
                            "error_type": type(e).__name__,
                            "tool": tool.__class__.__name__,
                            "target": target
                        }, indent=2)
                    )
                ]
        return handler

    def _initialize_monitoring(self):
        """Initialize health and metrics monitoring with proper task storage."""
        # Add tool availability check
        self.health_manager.add_health_check(
            ToolAvailabilityHealthCheck(
                self.tool_registry,
                priority=HealthCheckPriority.INFORMATIONAL
            ),
            priority=HealthCheckPriority.INFORMATIONAL
        )

        # Add tool-specific health checks
        for tool_name, tool in self.tool_registry.tools.items():
            self.health_manager.register_check(
                name=f"tool_{tool_name}",
                check_func=self._create_tool_health_check(tool),
                priority=HealthCheckPriority.INFORMATIONAL
            )

        # Start monitoring with proper task storage
        task = asyncio.create_task(
            self.health_manager.start_monitoring(),
            name="health_monitoring"
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _create_tool_health_check(self, tool: MCPBaseTool):
        """Create health check function for a tool."""
        async def check_tool_health() -> HealthStatus:
            try:
                # Check if command is available
                if not tool._resolve_command():
                    return HealthStatus.UNHEALTHY

                # Check circuit breaker state if available
                if hasattr(tool, '_circuit_breaker') and tool._circuit_breaker:
                    try:
                        from .circuit_breaker import CircuitBreakerState
                        if tool._circuit_breaker.state == CircuitBreakerState.OPEN:
                            return HealthStatus.DEGRADED
                    except Exception:
                        pass

                return HealthStatus.HEALTHY
            except Exception:
                return HealthStatus.UNHEALTHY

        return check_tool_health

    def _setup_enhanced_signal_handlers(self):
        """Set up thread-safe signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            """Thread-safe signal handler."""
            log.info("enhanced_server.shutdown_signal signal=%s", signum)
            try:
                # Use asyncio's thread-safe method
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(self.shutdown_event.set)
            except Exception as e:
                # Fallback if no loop
                log.warning("signal_handler.fallback error=%s", str(e))
                self.shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def run_stdio_original(self):
        """Run server with stdio transport."""
        log.info("enhanced_server.start_stdio_original")
        if not MCP_AVAILABLE or stdio_server is None or self.server is None:
            raise RuntimeError(
                "stdio transport is not available; MCP stdio support missing. "
                "Install with: pip install model-context-protocol"
            )
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.shutdown_event
            )

    async def run_http_enhanced(self):
        """Run server with HTTP transport and comprehensive features."""
        if not FASTAPI_AVAILABLE or not UVICORN_AVAILABLE:
            log.error("enhanced_server.http_missing_deps")
            raise RuntimeError(
                "FastAPI/Uvicorn missing for HTTP transport. "
                "Install with: pip install fastapi uvicorn sse-starlette"
            )
        
        log.info("enhanced_server.start_http_enhanced")
        app = FastAPI(
            title="Enhanced MCP Server",
            version="2.0.0",
            description="Production-ready MCP server with comprehensive features"
        )

        # CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        )

        @app.get("/")
        async def root():
            """Root endpoint with server information."""
            return {
                "name": "Enhanced MCP Server",
                "version": "2.0.0",
                "transport": self.transport,
                "tools": len(self.tool_registry.tools),
                "enabled_tools": len(self.tool_registry.enabled_tools),
                "endpoints": {
                    "health": "/health",
                    "tools": "/tools",
                    "metrics": "/metrics",
                    "events": "/events"
                }
            }

        @app.get("/health")
        async def health_check():
            """Comprehensive health check endpoint."""
            status = await self.health_manager.get_overall_health()
            checks = await self.health_manager.get_all_check_results()

            response_status_code = 200
            if status == HealthStatus.UNHEALTHY:
                response_status_code = 503
            elif status == HealthStatus.DEGRADED:
                response_status_code = 207  # Multi-Status

            return JSONResponse(
                status_code=response_status_code,
                content={
                    "status": status.value,
                    "timestamp": datetime.utcnow().isoformat(),
                    "transport": self.transport,
                    "checks": checks,
                    "summary": self.health_manager.get_health_summary()
                }
            )

        @app.get("/tools")
        async def get_tools():
            """Get list of available tools with detailed information."""
            return {
                "tools": self.tool_registry.get_tool_info(),
                "total": len(self.tool_registry.tools),
                "enabled": len(self.tool_registry.enabled_tools)
            }

        if FASTAPI_AVAILABLE and BaseModel:
            @app.post("/tools/{tool_name}/execute")
            async def execute_tool(
                tool_name: str,
                request: ToolExecutionRequest,
                http_request: Request,
                background_tasks: BackgroundTasks
            ):
                """Execute a tool with validated input and rate limiting."""
                # Rate limiting
                client_ip = http_request.client.host
                rate_limit_key = f"{client_ip}:{tool_name}"
                
                if not await self.rate_limiter.check_rate_limit(rate_limit_key):
                    raise HTTPException(
                        status_code=429,
                        detail={
                            "error": "Rate limit exceeded",
                            "message": f"Too many requests for {tool_name}. Try again later.",
                            "retry_after": 60
                        }
                    )
                
                # Get tool
                tool = self.tool_registry.get_tool(tool_name)
                if not tool:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Tool {tool_name} not found"
                    )

                if tool_name not in self.tool_registry.enabled_tools:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Tool {tool_name} is disabled"
                    )

                try:
                    tool_input = ToolInput(
                        target=request.target,
                        extra_args=request.extra_args,
                        timeout_sec=request.timeout_sec,
                        correlation_id=request.correlation_id
                    )
                    
                    result = await tool.run(tool_input)

                    # Record metrics in background
                    if hasattr(tool, 'metrics') and tool.metrics:
                        background_tasks.add_task(
                            self._record_tool_metrics, tool_name, result
                        )

                    return result.dict() if hasattr(result, 'dict') else result.__dict__
                
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                except Exception as e:
                    log.error("tool_execution_failed tool=%s error=%s", 
                             tool_name, str(e), exc_info=True)
                    raise HTTPException(
                        status_code=500,
                        detail=f"Tool execution failed: {str(e)}"
                    )

        @app.get("/events")
        async def events(request: Request):
            """SSE endpoint for real-time updates."""
            async def event_generator():
                try:
                    while not await request.is_disconnected():
                        # Send health status
                        health_status = await self.health_manager.get_overall_health()
                        health_data = {
                            "type": "health",
                            "data": {
                                "status": health_status.value,
                                "timestamp": datetime.utcnow().isoformat()
                            }
                        }
                        yield json.dumps(health_data)
                        
                        # Send metrics summary
                        metrics_data = {
                            "type": "metrics",
                            "data": self.metrics_manager.get_system_stats()
                        }
                        yield json.dumps(metrics_data)
                        
                        await asyncio.sleep(5)
                except Exception as e:
                    log.error("event_generator.error error=%s", str(e))

            return EventSourceResponse(event_generator())

        @app.get("/metrics")
        async def metrics():
            """Prometheus metrics endpoint with fallback to JSON."""
            if PROMETHEUS_AVAILABLE:
                metrics_text = self.metrics_manager.get_prometheus_metrics()
                if metrics_text:
                    return Response(content=metrics_text, media_type=CONTENT_TYPE_LATEST)

            # Fallback to JSON metrics
            return JSONResponse(
                content=self.metrics_manager.get_all_stats()
            )

        @app.post("/tools/{tool_name}/enable")
        async def enable_tool(tool_name: str):
            """Enable a tool."""
            if tool_name not in self.tool_registry.tools:
                raise HTTPException(status_code=404, detail=f"Tool {tool_name} not found")
            
            self.tool_registry.enable_tool(tool_name)
            return {"message": f"Tool {tool_name} enabled", "tool": tool_name}

        @app.post("/tools/{tool_name}/disable")
        async def disable_tool(tool_name: str):
            """Disable a tool."""
            if tool_name not in self.tool_registry.tools:
                raise HTTPException(status_code=404, detail=f"Tool {tool_name} not found")
            
            self.tool_registry.disable_tool(tool_name)
            return {"message": f"Tool {tool_name} disabled", "tool": tool_name}

        @app.get("/config")
        async def get_config_endpoint():
            """Get current configuration (sensitive data redacted)."""
            return self.config.to_dict(redact_sensitive=True)

        # Run server
        port = int(os.getenv("MCP_SERVER_PORT", self.config.server.port))
        host = os.getenv("MCP_SERVER_HOST", self.config.server.host)

        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        
        log.info("http_server.starting host=%s port=%d", host, port)
        await server.serve()

    async def _record_tool_metrics(self, tool_name: str, result: ToolOutput):
        """Record tool execution metrics in background."""
        try:
            self.metrics_manager.record_tool_execution(
                tool_name=tool_name,
                success=(result.returncode == 0),
                execution_time=result.execution_time or 0.0,
                timed_out=bool(getattr(result, "timed_out", False)),
                error_type=getattr(result, "error_type", None)
            )
        except Exception as e:
            log.warning("metrics.record_failed tool=%s error=%s", tool_name, str(e))

    async def run(self):
        """Run the server with configured transport and safe fallbacks."""
        if self.transport == "http":
            if not FASTAPI_AVAILABLE or not UVICORN_AVAILABLE:
                log.warning(
                    "transport.http_deps_missing falling_back=stdio "
                    "hint='pip install fastapi uvicorn sse-starlette'"
                )
                if MCP_AVAILABLE and self.server is not None and stdio_server is not None:
                    self.transport = "stdio"
                    await self.run_stdio_original()
                    return
                raise RuntimeError(
                    "HTTP transport requested but FastAPI/Uvicorn are missing, "
                    "and stdio fallback is unavailable"
                )
            await self.run_http_enhanced()
            return

        if self.transport == "stdio":
            if MCP_AVAILABLE and self.server is not None and stdio_server is not None:
                await self.run_stdio_original()
                return
            
            if FASTAPI_AVAILABLE and UVICORN_AVAILABLE:
                log.warning(
                    "transport.stdio_unavailable_fallback fallback=http "
                    "hint='pip install model-context-protocol'"
                )
                self.transport = "http"
                await self.run_http_enhanced()
                return
            
            raise RuntimeError(
                "stdio transport requested but MCP stdio support is unavailable. "
                "Install the 'model-context-protocol' package or enable HTTP transport "
                "(requires fastapi and uvicorn)."
            )

        log.error("enhanced_server.invalid_transport transport=%s", self.transport)
        raise ValueError(f"Invalid transport: {self.transport}")

    async def cleanup(self):
        """
        Comprehensive cleanup of all resources.
        
        Cleanup order:
        1. Stop health monitoring
        2. Stop metrics collection
        3. Cancel background tasks
        4. Cleanup tools (circuit breakers, etc.)
        """
        log.info("enhanced_server.cleanup_started")
        
        # Stop health monitoring
        try:
            await self.health_manager.stop_monitoring()
            log.info("cleanup.health_manager_stopped")
        except Exception as e:
            log.error("cleanup.health_manager_failed error=%s", str(e), exc_info=True)
        
        # Cleanup metrics
        try:
            if hasattr(self.metrics_manager, 'cleanup'):
                await self.metrics_manager.cleanup()
            log.info("cleanup.metrics_manager_stopped")
        except Exception as e:
            log.error("cleanup.metrics_manager_failed error=%s", str(e), exc_info=True)
        
        # Cancel all background tasks
        tasks_to_cancel = list(self._background_tasks)
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()
        
        # Wait for cancellation
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
        
        self._background_tasks.clear()
        log.info("cleanup.background_tasks_cancelled count=%d", len(tasks_to_cancel))
        
        # Cleanup tools (circuit breakers, etc.)
        for tool_name, tool in self.tool_registry.tools.items():
            try:
                if hasattr(tool, '_circuit_breaker') and tool._circuit_breaker:
                    if hasattr(tool._circuit_breaker, 'cleanup'):
                        await tool._circuit_breaker.cleanup()
            except Exception as e:
                log.warning("cleanup.tool_circuit_breaker_failed tool=%s error=%s",
                          tool_name, str(e))
        
        log.info("enhanced_server.cleanup_completed")


async def _serve(server: MCPServerBase, shutdown_grace: float) -> None:
    """Handle server lifecycle with signal handling and graceful shutdown."""
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def _signal_handler(sig: int) -> None:
        log.info("server.signal_received signal=%s initiating_shutdown", sig)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler, sig)
            log.debug("server.signal_handler_registered signal=%s", sig)
        except NotImplementedError:
            log.warning("server.signal_handler_not_supported signal=%s platform=%s",
                        sig, sys.platform)
        except Exception as e:
            log.error("server.signal_handler_failed signal=%s error=%s", sig, str(e))

    serve_task = asyncio.create_task(server.serve(), name="mcp_serve")
    log.info("server.started grace_period=%.1fs", shutdown_grace)

    try:
        await stop.wait()
        log.info("server.shutdown_initiated")
    except asyncio.CancelledError:
        log.info("server.shutdown_cancelled")
        return

    log.info("server.shutting_down")
    serve_task.cancel()
    
    try:
        await asyncio.wait_for(serve_task, timeout=shutdown_grace)
        log.info("server.shutdown_completed")
    except asyncio.TimeoutError:
        log.warning("server.shutdown_forced timeout=%.1fs", shutdown_grace)
    except asyncio.CancelledError:
        log.info("server.shutdown_cancelled_during_cleanup")
    except Exception as e:
        log.error("server.shutdown_error error=%s", str(e), exc_info=True)


async def main_enhanced() -> None:
    """
    Main entry point for enhanced MCP server.
    
    Environment Variables:
        MCP_SERVER_TRANSPORT: Transport mode (stdio|http)
        TOOLS_PACKAGE: Package to scan for tools
        TOOL_INCLUDE: Comma-separated list of tools to include
        TOOL_EXCLUDE: Comma-separated list of tools to exclude
        MCP_SERVER_SHUTDOWN_GRACE_PERIOD: Graceful shutdown timeout
    """
    _maybe_setup_uvloop()
    _setup_logging()

    transport = os.getenv("MCP_SERVER_TRANSPORT", "stdio").lower()
    tools_pkg = os.getenv("TOOLS_PACKAGE", "mcp_server.tools")
    include = _parse_csv_env("TOOL_INCLUDE")
    exclude = _parse_csv_env("TOOL_EXCLUDE")
    shutdown_grace = float(os.getenv("MCP_SERVER_SHUTDOWN_GRACE_PERIOD", "30"))

    # Load tools
    tools = _load_tools_from_package(tools_pkg, include=include, exclude=exclude)
    
    log.info(
        "enhanced_main.starting transport=%s tools_pkg=%s tools_count=%d "
        "include=%s exclude=%s shutdown_grace=%.1fs",
        transport, tools_pkg, len(tools), include, exclude, shutdown_grace
    )

    if transport == "stdio" and not MCP_AVAILABLE:
        log.error(
            "enhanced_main.stdio_unavailable transport=stdio "
            "hint='pip install model-context-protocol'"
        )
        raise RuntimeError(
            "stdio transport requested but MCP stdio support is unavailable. "
            "Install the 'model-context-protocol' package or set MCP_SERVER_TRANSPORT=http."
        )

    # Get configuration
    config = get_config()
    
    # Create server
    server = EnhancedMCPServer(tools=tools, transport=transport, config=config)

    tool_names = [tool.__class__.__name__ for tool in tools]
    log.info("enhanced_main.tools_loaded tools=%s", tool_names)

    try:
        if transport == "stdio" and server.server:
            await _serve(server.server, shutdown_grace=shutdown_grace)
        else:
            # HTTP or fallback happens inside server.run()
            await server.run()
    finally:
        await server.cleanup()
        log.info("enhanced_main.shutdown_complete")


if __name__ == "__main__":
    with contextlib.suppress(ImportError):
        pass
    
    try:
        asyncio.run(main_enhanced())
    except KeyboardInterrupt:
        log.info("main.interrupted_by_user")
    except Exception as e:
        log.critical("main.fatal_error error=%s", str(e), exc_info=True)
        sys.exit(1)

```

# mcp_server/tools/nmap_tool.py
```py
"""
Enhanced Nmap tool with circuit breaker, metrics, and comprehensive security controls.
Production-ready implementation with strict safety enforcement and policy-based controls.

Features:
- Circuit breaker protection for resilience
- Network range validation and size limits
- Port specification safety with range validation
- Script execution controls with policy enforcement
- Performance optimizations with smart defaults
- Comprehensive metrics integration
- Intrusive operation control via configuration
- Compiled regex patterns for performance
- Scan templates for common scenarios
- Result parsing helpers

Safety Controls:
- Targets restricted to RFC1918 private IPs or *.lab.internal domains
- Script categories and specific scripts controlled by policy
- -A flag controlled by intrusive policy setting
- Non-flag tokens completely blocked for security
- Network size limits enforced (max 1024 hosts)
- Port range limits enforced (max 100 ranges)

Usage:
    from mcp_server.tools.nmap_tool import NmapTool
    from mcp_server.base_tool import ToolInput
    
    # Create tool instance
    tool = NmapTool()
    
    # Execute basic scan
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="-sV --top-ports 100"
    ))
    
    # Use scan template
    result = await tool.run_with_template(
        target="192.168.1.1",
        template=ScanTemplate.QUICK
    )
    
    # Get tool information
    info = tool.get_tool_info()

Configuration:
    # config.yaml
    security:
      allow_intrusive: false  # Controls -A flag and intrusive scripts
    
    tool:
      default_timeout: 600
      default_concurrency: 1
    
    circuit_breaker:
      failure_threshold: 5
      recovery_timeout: 120.0

Testing:
    # Reset configuration
    tool._apply_config()
    
    # Validate arguments
    validated = tool._parse_and_validate_args("-sV -p 80,443")
    
    # Check tool info
    assert tool.get_tool_info()['intrusive_allowed'] == False
"""
import logging
import shlex
import ipaddress
import math
import re
from datetime import datetime, timezone
from typing import Sequence, Optional, Dict, Any, Set, List, Tuple
from enum import Enum
from dataclasses import dataclass

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext
from mcp_server.config import get_config

log = logging.getLogger(__name__)


class ScanTemplate(Enum):
    """Predefined scan templates for common scenarios."""
    QUICK = "quick"           # Fast scan, top 100 ports
    STANDARD = "standard"     # Balanced scan, top 1000 ports
    THOROUGH = "thorough"     # Comprehensive scan, all TCP ports
    DISCOVERY = "discovery"   # Host discovery only
    VERSION = "version"       # Service version detection
    SCRIPT = "script"         # Script scanning with safe scripts


@dataclass
class ScanResult:
    """Structured scan result."""
    raw_output: str
    hosts_up: int = 0
    hosts_down: int = 0
    ports_found: List[Dict[str, Any]] = None
    services: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.ports_found is None:
            self.ports_found = []
        if self.services is None:
            self.services = []


class NmapTool(MCPBaseTool):
    """
    Enhanced Nmap network scanner tool with comprehensive security features.
    
    The tool provides network scanning capabilities with strict security controls,
    policy-based operation modes, and comprehensive validation.
    
    State Machine:
        Configuration -> Validation -> Optimization -> Execution -> Result Parsing
    
    Security Model:
        - Whitelist-based flag validation
        - Network restriction to private ranges
        - Script filtering by safety categories
        - Intrusive operations gated by policy
    """
    
    command_name: str = "nmap"
    
    # Conservative, safe flags for nmap (base set)
    # -A flag is dynamically added based on policy
    BASE_ALLOWED_FLAGS: Tuple[str, ...] = (
        # Scan types
        "-sS", "-sT", "-sU", "-sn", "-sV", "-sC",
        # Port specifications
        "-p", "--top-ports",
        # Timing and performance
        "-T", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "--min-rate", "--max-rate", "--max-retries",
        "--host-timeout", "--scan-delay", "--max-scan-delay",
        "--max-parallelism",
        # Host discovery
        "-Pn", "-PS", "-PA", "-PU", "-PY",
        # OS detection
        "-O",
        # Scripts
        "--script",
        # Output formats
        "-oX", "-oN", "-oG",
        # Verbosity
        "-v", "-vv",
        # Version detection
        "--version-intensity",
        # Misc
        "--open", "--reason", "--randomize-hosts",
        # Advanced (controlled)
        "-f", "--mtu", "-D", "--decoy",
        "--source-port", "-g", "--data-length",
        "--ttl", "--spoof-mac",
    )
    
    # Nmap can run long; set higher timeout
    default_timeout_sec: float = 600.0
    
    # Limit concurrency to avoid overloading
    concurrency: int = 1
    
    # Circuit breaker configuration
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: float = 120.0
    circuit_breaker_expected_exception: tuple = (Exception,)
    
    # Safety limits
    MAX_NETWORK_SIZE = 1024  # Maximum number of hosts in a network range
    MAX_PORT_RANGES = 100    # Maximum number of port ranges
    
    # Safe script categories (always allowed)
    SAFE_SCRIPT_CATEGORIES: Set[str] = {
        "safe", "default", "discovery", "version"
    }
    
    # Specific safe scripts (always allowed)
    SAFE_SCRIPTS: Set[str] = {
        "http-headers", "ssl-cert", "ssh-hostkey", "smb-os-discovery",
        "dns-brute", "http-title", "ftp-anon", "smtp-commands",
        "pop3-capabilities", "imap-capabilities", "mongodb-info",
        "mysql-info", "ms-sql-info", "oracle-sid-brute",
        "rdp-enum-encryption", "vnc-info", "x11-access",
        "ntp-info", "snmp-info", "rpcinfo", "nbstat"
    }
    
    # Intrusive script categories (require policy)
    INTRUSIVE_SCRIPT_CATEGORIES: Set[str] = {
        "vuln", "exploit", "intrusive", "brute", "dos"
    }
    
    # Intrusive specific scripts (require policy)
    INTRUSIVE_SCRIPTS: Set[str] = {
        "http-vuln-*", "smb-vuln-*", "ssl-heartbleed",
        "ms-sql-brute", "mysql-brute", "ftp-brute",
        "ssh-brute", "rdp-brute", "dns-zone-transfer",
        "snmp-brute", "http-slowloris", "smtp-vuln-*"
    }
    
    # Extra tokens allowed for optimization
    _EXTRA_ALLOWED_TOKENS = {
        "-T4", "--max-parallelism", "10", "-Pn",
        "--top-ports", "1000", "100", "20"
    }
    
    # Flags that require values
    _FLAGS_REQUIRE_VALUE = {
        "-p", "--ports", "--max-parallelism", "--version-intensity",
        "--min-rate", "--max-rate", "--max-retries", "--host-timeout",
        "--top-ports", "--scan-delay", "--max-scan-delay", "--mtu",
        "--data-length", "--ttl", "--source-port", "-g",
        "-D", "--decoy", "--spoof-mac"
    }
    
    # Compiled regex patterns for performance
    _PORT_SPEC_PATTERN = re.compile(r'^[\d,\-]+$')
    _NUMERIC_PATTERN = re.compile(r'^\d+$')
    _TIME_SPEC_PATTERN = re.compile(r'^[0-9]+(ms|s|m|h)?$')
    _NMAP_HOST_PATTERN = re.compile(r'Nmap scan report for ([^\s]+)')
    _PORT_PATTERN = re.compile(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)')
    _HOSTS_UP_PATTERN = re.compile(r'(\d+) hosts? up')
    
    def __init__(self):
        """Initialize Nmap tool with enhanced features and policy enforcement."""
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._base_flags = list(self.BASE_ALLOWED_FLAGS)  # Immutable base
        self._script_cache: Dict[str, str] = {}  # Cache validated scripts
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration settings safely with policy enforcement."""
        try:
            # Apply circuit breaker config
            if hasattr(self.config, 'circuit_breaker') and self.config.circuit_breaker:
                cb = self.config.circuit_breaker
                if hasattr(cb, 'failure_threshold'):
                    original = self.circuit_breaker_failure_threshold
                    self.circuit_breaker_failure_threshold = max(1, min(10, int(cb.failure_threshold)))
                    if self.circuit_breaker_failure_threshold != original:
                        log.info("nmap.config_clamped param=failure_threshold original=%d new=%d",
                                original, self.circuit_breaker_failure_threshold)
                
                if hasattr(cb, 'recovery_timeout'):
                    original = self.circuit_breaker_recovery_timeout
                    self.circuit_breaker_recovery_timeout = max(30.0, min(600.0, float(cb.recovery_timeout)))
                    if self.circuit_breaker_recovery_timeout != original:
                        log.info("nmap.config_clamped param=recovery_timeout original=%.1f new=%.1f",
                                original, self.circuit_breaker_recovery_timeout)
            
            # Apply tool config
            if hasattr(self.config, 'tool') and self.config.tool:
                tool = self.config.tool
                if hasattr(tool, 'default_timeout'):
                    original = self.default_timeout_sec
                    self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
                    if self.default_timeout_sec != original:
                        log.info("nmap.config_clamped param=default_timeout original=%.1f new=%.1f",
                                original, self.default_timeout_sec)
                
                if hasattr(tool, 'default_concurrency'):
                    original = self.concurrency
                    self.concurrency = max(1, min(5, int(tool.default_concurrency)))
                    if self.concurrency != original:
                        log.info("nmap.config_clamped param=concurrency original=%d new=%d",
                                original, self.concurrency)
            
            # Apply security config (critical for policy enforcement)
            if hasattr(self.config, 'security') and self.config.security:
                sec = self.config.security
                if hasattr(sec, 'allow_intrusive'):
                    old_intrusive = self.allow_intrusive
                    self.allow_intrusive = bool(sec.allow_intrusive)
                    
                    if self.allow_intrusive != old_intrusive:
                        if self.allow_intrusive:
                            log.warning("nmap.intrusive_enabled -A_flag_allowed security_policy_change=true")
                        else:
                            log.info("nmap.intrusive_disabled -A_flag_blocked security_policy_change=true")
                    
                    # Clear script cache when policy changes
                    if self.allow_intrusive != old_intrusive:
                        self._script_cache.clear()
            
            log.debug("nmap.config_applied intrusive=%s timeout=%.1f concurrency=%d",
                     self.allow_intrusive, self.default_timeout_sec, self.concurrency)
            
        except Exception as e:
            log.error("nmap.config_apply_failed error=%s using_safe_defaults", str(e))
            # Reset to safe defaults on error
            self.circuit_breaker_failure_threshold = 5
            self.circuit_breaker_recovery_timeout = 120.0
            self.default_timeout_sec = 600.0
            self.concurrency = 1
            self.allow_intrusive = False
            self._script_cache.clear()
    
    @property
    def allowed_flags(self) -> List[str]:
        """Get current allowed flags based on policy (immutable pattern)."""
        flags = list(self._base_flags)
        if self.allow_intrusive:
            flags.append("-A")
        return flags
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute Nmap with enhanced validation and optimization."""
        # Validate nmap-specific requirements
        validation_result = self._validate_nmap_requirements(inp)
        if validation_result:
            return validation_result
        
        # Parse and validate arguments
        try:
            parsed_args = self._parse_and_validate_args(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid arguments: {str(e)}",
                recovery_suggestion="Check argument syntax and allowed flags. Use --help for guidance.",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e), "provided_args": inp.extra_args}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Optimize arguments
        optimized_args = self._optimize_nmap_args(parsed_args)
        
        # Create enhanced input
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=optimized_args,
            timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
            correlation_id=inp.correlation_id,
        )
        
        log.info("nmap.executing target=%s args=%s timeout=%.1f",
                inp.target, optimized_args, enhanced_input.timeout_sec)
        
        # Execute with base class method
        return await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)
    
    async def run_with_template(self, target: str, template: ScanTemplate,
                                timeout_sec: Optional[float] = None,
                                correlation_id: Optional[str] = None) -> ToolOutput:
        """
        Run scan with predefined template.
        
        Args:
            target: Target host or network
            template: Scan template to use
            timeout_sec: Optional timeout override
            correlation_id: Optional correlation ID
        
        Returns:
            ToolOutput with scan results
        """
        args = self._get_template_args(template)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec,
            correlation_id=correlation_id
        )
        
        log.info("nmap.template_scan target=%s template=%s", target, template.value)
        
        return await self.run(inp, timeout_sec)
    
    def _get_template_args(self, template: ScanTemplate) -> str:
        """Get arguments for scan template."""
        templates = {
            ScanTemplate.QUICK: "-T4 -Pn --top-ports 100",
            ScanTemplate.STANDARD: "-T4 -Pn --top-ports 1000 -sV",
            ScanTemplate.THOROUGH: "-T4 -Pn -p- -sV -sC",
            ScanTemplate.DISCOVERY: "-sn -T4",
            ScanTemplate.VERSION: "-sV --version-intensity 5 -T4 -Pn --top-ports 1000",
            ScanTemplate.SCRIPT: "-sC -T4 -Pn --top-ports 1000"
        }
        return templates.get(template, templates[ScanTemplate.STANDARD])
    
    def _validate_nmap_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
        """
        Validate nmap-specific requirements with clear error messaging.
        
        Validates:
        - Network range size limits
        - IP address privacy (RFC1918)
        - Hostname restrictions (.lab.internal)
        """
        target = inp.target.strip()
        
        # Validate network ranges
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError as e:
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Invalid network range: {target}",
                    recovery_suggestion="Use valid CIDR notation (e.g., 192.168.1.0/24)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={
                        "input": target,
                        "error": str(e),
                        "example": "192.168.1.0/24"
                    }
                )
                return self._create_error_output(error_context, inp.correlation_id or "")
            
            # Check network size with helpful messaging
            if network.num_addresses > self.MAX_NETWORK_SIZE:
                max_cidr = self._get_max_cidr_for_size(self.MAX_NETWORK_SIZE)
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Network range too large: {network.num_addresses} addresses (max: {self.MAX_NETWORK_SIZE})",
                    recovery_suggestion=f"Use /{max_cidr} or smaller prefix (max {self.MAX_NETWORK_SIZE} hosts)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={
                        "network_size": network.num_addresses,
                        "max_allowed": self.MAX_NETWORK_SIZE,
                        "suggested_cidr": f"/{max_cidr}",
                        "example": f"{network.network_address}/{max_cidr}",
                        "cidr_breakdown": {
                            "/22": "1024 hosts",
                            "/23": "512 hosts",
                            "/24": "256 hosts",
                            "/25": "128 hosts"
                        }
                    }
                )
                return self._create_error_output(error_context, inp.correlation_id or "")
            
            # Ensure private network
            if not (network.is_private or network.is_loopback):
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Only private networks allowed: {target}",
                    recovery_suggestion="Use RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or loopback (127.0.0.0/8)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={
                        "network": str(network),
                        "allowed_ranges": {
                            "Class A": "10.0.0.0/8",
                            "Class B": "172.16.0.0/12",
                            "Class C": "192.168.0.0/16",
                            "Loopback": "127.0.0.0/8"
                        }
                    }
                )
                return self._create_error_output(error_context, inp.correlation_id or "")
        else:
            # Single host validation
            try:
                ip = ipaddress.ip_address(target)
                if not (ip.is_private or ip.is_loopback):
                    error_context = ErrorContext(
                        error_type=ToolErrorType.VALIDATION_ERROR,
                        message=f"Only private IPs allowed: {target}",
                        recovery_suggestion="Use RFC1918 private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) or loopback (127.x.x.x)",
                        timestamp=self._get_timestamp(),
                        tool_name=self.tool_name,
                        target=target,
                        metadata={
                            "ip": str(ip),
                            "is_private": ip.is_private,
                            "is_loopback": ip.is_loopback,
                            "examples": ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
                        }
                    )
                    return self._create_error_output(error_context, inp.correlation_id or "")
            except ValueError:
                # Must be a hostname - validate .lab.internal
                if not target.endswith(".lab.internal"):
                    error_context = ErrorContext(
                        error_type=ToolErrorType.VALIDATION_ERROR,
                        message=f"Only .lab.internal hostnames allowed: {target}",
                        recovery_suggestion="Use hostnames ending with .lab.internal domain",
                        timestamp=self._get_timestamp(),
                        tool_name=self.tool_name,
                        target=target,
                        metadata={
                            "hostname": target,
                            "required_suffix": ".lab.internal",
                            "examples": ["server.lab.internal", "db01.lab.internal"]
                        }
                    )
                    return self._create_error_output(error_context, inp.correlation_id or "")
        
        return None
    
    def _get_max_cidr_for_size(self, max_hosts: int) -> int:
        """
        Calculate maximum CIDR prefix for given host count.
        
        For max_hosts=1024, returns /22 (which gives 1024 addresses).
        """
        bits_needed = math.ceil(math.log2(max_hosts))
        return max(0, 32 - bits_needed)
    
    def _parse_and_validate_args(self, extra_args: str) -> str:
        """
        Parse and validate nmap arguments with strict security enforcement.
        
        Security model:
        - Whitelist-based flag validation
        - Non-flag tokens completely blocked
        - Script filtering by safety category
        - Intrusive operations gated by policy
        
        Args:
            extra_args: Arguments string to validate
        
        Returns:
            Validated and sanitized arguments string
        
        Raises:
            ValueError: If validation fails
        """
        if not extra_args:
            return ""
        
        try:
            tokens = shlex.split(extra_args)
        except ValueError as e:
            raise ValueError(f"Failed to parse arguments: {str(e)}")
        
        validated = []
        i = 0
        
        while i < len(tokens):
            token = tokens[i]
            
            # Security: Block ALL non-flag tokens
            if not token.startswith("-"):
                raise ValueError(
                    f"Unexpected non-flag token (potential injection): '{token}'. "
                    f"Only flags starting with '-' are allowed."
                )
            
            # Handle -A flag (controlled by policy)
            if token == "-A":
                if not self.allow_intrusive:
                    raise ValueError(
                        "-A flag requires intrusive operations to be enabled. "
                        "Set MCP_SECURITY_ALLOW_INTRUSIVE=true or update config."
                    )
                validated.append(token)
                i += 1
                continue
            
            # Handle port specifications
            if token in ("-p", "--ports"):
                if i + 1 >= len(tokens):
                    raise ValueError(f"Port flag {token} requires a value")
                
                port_spec = tokens[i + 1]
                if not self._validate_port_specification(port_spec):
                    raise ValueError(
                        f"Invalid port specification: '{port_spec}'. "
                        f"Use formats like: 80, 80-443, 80,443,8080 (max {self.MAX_PORT_RANGES} ranges)"
                    )
                validated.extend([token, port_spec])
                i += 2
                continue
            
            # Handle script specifications
            if token == "--script":
                if i + 1 >= len(tokens):
                    raise ValueError("--script requires a value")
                
                script_spec = tokens[i + 1]
                validated_scripts = self._validate_and_filter_scripts(script_spec)
                
                if not validated_scripts:
                    raise ValueError(
                        f"No allowed scripts in specification: '{script_spec}'. "
                        f"Safe categories: {', '.join(self.SAFE_SCRIPT_CATEGORIES)}. "
                        f"Intrusive scripts require allow_intrusive=true."
                    )
                validated.extend([token, validated_scripts])
                i += 2
                continue
            
            # Handle timing templates
            if token.startswith("-T"):
                if len(token) == 3 and token[2] in "012345":
                    validated.append(token)
                    i += 1
                    continue
                else:
                    raise ValueError(
                        f"Invalid timing template: '{token}'. "
                        f"Use -T0 through -T5 (e.g., -T4 for aggressive timing)"
                    )
            
            # Handle other flags
            flag_base, flag_value = (token.split("=", 1) + [None])[:2]
            
            if flag_base not in self.allowed_flags:
                raise ValueError(
                    f"Flag not allowed: '{token}'. "
                    f"See allowed flags in tool documentation."
                )
            
            expects_value = flag_base in self._FLAGS_REQUIRE_VALUE
            
            # Handle inline value (flag=value)
            if flag_value is not None:
                if not expects_value:
                    raise ValueError(f"Flag does not take inline value: {token}")
                if not self._validate_flag_value(flag_base, flag_value):
                    raise ValueError(f"Invalid value for {flag_base}: {flag_value}")
                validated.extend([flag_base, flag_value])
                i += 1
                continue
            
            # Handle separate value
            if expects_value:
                if i + 1 >= len(tokens):
                    raise ValueError(f"{flag_base} requires a value")
                value = tokens[i + 1]
                if not self._validate_flag_value(flag_base, value):
                    raise ValueError(f"Invalid value for {flag_base}: {value}")
                validated.extend([flag_base, value])
                i += 2
            else:
                validated.append(flag_base)
                i += 1
        
        return " ".join(validated)
    
    def _validate_port_specification(self, port_spec: str) -> bool:
        """
        Validate port specification for safety.
        
        Allowed formats:
        - Single port: 80
        - Range: 80-443
        - List: 80,443,8080
        - Mixed: 80,443-445,8080
        
        Args:
            port_spec: Port specification string
        
        Returns:
            True if valid, False otherwise
        """
        if not port_spec:
            return False
        
        # Check for valid characters using compiled pattern
        if not self._PORT_SPEC_PATTERN.match(port_spec):
            return False
        
        # Count ranges to prevent excessive specifications
        ranges = port_spec.split(',')
        if len(ranges) > self.MAX_PORT_RANGES:
            log.warning("nmap.port_spec_too_many_ranges count=%d max=%d",
                       len(ranges), self.MAX_PORT_RANGES)
            return False
        
        # Validate each range
        for range_spec in ranges:
            if '-' in range_spec:
                parts = range_spec.split('-')
                if len(parts) != 2:
                    return False
                try:
                    start, end = int(parts[0]), int(parts[1])
                    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                        return False
                    # Warn on very large ranges
                    if end - start > 10000:
                        log.warning("nmap.large_port_range start=%d end=%d size=%d",
                                  start, end, end - start)
                except ValueError:
                    return False
            else:
                try:
                    port = int(range_spec)
                    if not 1 <= port <= 65535:
                        return False
                except ValueError:
                    return False
        
        return True
    
    def _validate_and_filter_scripts(self, script_spec: str) -> str:
        """
        Validate and filter script specification based on policy.
        
        Uses caching for performance. Scripts are filtered based on:
        - Safe categories (always allowed)
        - Safe specific scripts (always allowed)
        - Intrusive categories (policy-gated)
        - Intrusive scripts (policy-gated)
        
        Args:
            script_spec: Comma-separated script specification
        
        Returns:
            Filtered script specification with only allowed scripts
        """
        # Check cache
        if script_spec in self._script_cache:
            return self._script_cache[script_spec]
        
        allowed_scripts = []
        scripts = script_spec.split(',')
        blocked_scripts = []
        
        for script in scripts:
            script = script.strip()
            
            # Check if it's a category (exact match)
            if script in self.SAFE_SCRIPT_CATEGORIES:
                allowed_scripts.append(script)
                continue
            
            if script in self.INTRUSIVE_SCRIPT_CATEGORIES:
                if self.allow_intrusive:
                    allowed_scripts.append(script)
                    log.info("nmap.intrusive_category_allowed category=%s", script)
                else:
                    blocked_scripts.append(script)
                    log.warning("nmap.intrusive_category_blocked category=%s", script)
                continue
            
            # Check if it's a specific script (exact match)
            if script in self.SAFE_SCRIPTS:
                allowed_scripts.append(script)
                continue
            
            if script in self.INTRUSIVE_SCRIPTS:
                if self.allow_intrusive:
                    allowed_scripts.append(script)
                    log.info("nmap.intrusive_script_allowed script=%s", script)
                else:
                    blocked_scripts.append(script)
                    log.warning("nmap.intrusive_script_blocked script=%s", script)
                continue
            
            # Check wildcard patterns for intrusive scripts
            is_intrusive_pattern = any(
                script.startswith(pattern.replace('*', ''))
                for pattern in self.INTRUSIVE_SCRIPTS if '*' in pattern
            )
            
            if is_intrusive_pattern:
                if self.allow_intrusive:
                    allowed_scripts.append(script)
                    log.info("nmap.intrusive_script_allowed script=%s pattern_match=true", script)
                else:
                    blocked_scripts.append(script)
                    log.warning("nmap.intrusive_script_blocked script=%s pattern_match=true", script)
            else:
                # Unknown script - block it for safety
                blocked_scripts.append(script)
                log.warning("nmap.unknown_script_blocked script=%s", script)
        
        result = ','.join(allowed_scripts) if allowed_scripts else ""
        
        # Cache result
        self._script_cache[script_spec] = result
        
        if blocked_scripts:
            log.info("nmap.scripts_filtered original=%d allowed=%d blocked=%d blocked_list=%s",
                    len(scripts), len(allowed_scripts), len(blocked_scripts), blocked_scripts)
        
        return result
    
    def _validate_flag_value(self, flag: str, value: str) -> bool:
        """
        Validate values for flags that expect specific formats.
        
        Args:
            flag: Flag name
            value: Value to validate
        
        Returns:
            True if valid, False otherwise
        """
        # Time specifications (ms, s, m, h)
        if flag in {"--host-timeout", "--scan-delay", "--max-scan-delay"}:
            return bool(self._TIME_SPEC_PATTERN.match(value))
        
        # Numeric values
        if flag in {
            "--max-parallelism", "--version-intensity", "--min-rate",
            "--max-rate", "--max-retries", "--top-ports", "--mtu",
            "--data-length", "--ttl", "--source-port", "-g"
        }:
            if not self._NUMERIC_PATTERN.match(value):
                return False
            
            # Validate ranges for specific flags
            try:
                num_val = int(value)
                if flag == "--version-intensity" and not (0 <= num_val <= 9):
                    return False
                if flag == "--top-ports" and not (1 <= num_val <= 65535):
                    return False
                if flag in ("--source-port", "-g") and not (1 <= num_val <= 65535):
                    return False
                if flag == "--ttl" and not (1 <= num_val <= 255):
                    return False
            except ValueError:
                return False
            
            return True
        
        # Decoy specifications
        if flag in ("-D", "--decoy"):
            # Allow ME, RND, and IP addresses
            if value in ("ME", "RND"):
                return True
            # Validate as IP or comma-separated IPs
            for part in value.split(','):
                part = part.strip()
                if part in ("ME", "RND"):
                    continue
                try:
                    ipaddress.ip_address(part)
                except ValueError:
                    return False
            return True
        
        # MAC address for --spoof-mac
        if flag == "--spoof-mac":
            mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|0$')
            return bool(mac_pattern.match(value))
        
        return True
    
    def _optimize_nmap_args(self, extra_args: str) -> str:
        """
        Optimize nmap arguments for performance and safety.
        
        Adds smart defaults if not specified:
        - Timing: -T4 (aggressive but safe)
        - Parallelism: --max-parallelism 10
        - Host discovery: -Pn (skip ping)
        - Ports: --top-ports 1000 (reasonable default)
        
        Args:
            extra_args: Already validated arguments
        
        Returns:
            Optimized arguments string
        """
        if not extra_args:
            extra_args = ""
        
        try:
            tokens = shlex.split(extra_args) if extra_args else []
        except ValueError:
            tokens = extra_args.split() if extra_args else []
        
        optimized = []
        
        # Check what's already specified
        has_timing = any(t.startswith("-T") for t in tokens)
        has_parallelism = any(t in {"--max-parallelism"} or t.startswith("--max-parallelism=") for t in tokens)
        has_host_discovery = any(t in ("-Pn", "-sn", "-PS", "-PA", "-PU") for t in tokens)
        has_port_spec = any(t in ("-p", "--ports", "--top-ports") or t.startswith("--top-ports=") for t in tokens)
        
        # Add smart defaults
        if not has_timing:
            optimized.append("-T4")
            log.debug("nmap.optimization added=timing value=-T4")
        
        if not has_parallelism:
            optimized.extend(["--max-parallelism", "10"])
            log.debug("nmap.optimization added=parallelism value=10")
        
        if not has_host_discovery:
            optimized.append("-Pn")
            log.debug("nmap.optimization added=host_discovery value=-Pn")
        
        if not has_port_spec:
            optimized.extend(["--top-ports", "1000"])
            log.debug("nmap.optimization added=port_spec value=top-1000")
        
        # Append original arguments
        optimized.extend(tokens)
        
        result = " ".join(optimized)
        
        if optimized != tokens:
            log.info("nmap.arguments_optimized original_count=%d optimized_count=%d",
                    len(tokens), len(optimized))
        
        return result
    
    def parse_scan_result(self, output: str) -> ScanResult:
        """
        Parse nmap output into structured result.
        
        Extracts:
        - Hosts up/down counts
        - Open ports with services
        - Service versions
        
        Args:
            output: Raw nmap output
        
        Returns:
            ScanResult with parsed data
        """
        result = ScanResult(raw_output=output)
        
        # Parse hosts up
        hosts_match = self._HOSTS_UP_PATTERN.search(output)
        if hosts_match:
            result.hosts_up = int(hosts_match.group(1))
        
        # Parse ports and services
        for line in output.split('\n'):
            port_match = self._PORT_PATTERN.match(line.strip())
            if port_match:
                port_num, protocol, state, service = port_match.groups()
                
                port_info = {
                    "port": int(port_num),
                    "protocol": protocol,
                    "state": state,
                    "service": service.strip()
                }
                result.ports_found.append(port_info)
                
                if state == "open":
                    result.services.append(port_info)
        
        log.debug("nmap.result_parsed hosts_up=%d ports_found=%d services=%d",
                 result.hosts_up, len(result.ports_found), len(result.services))
        
        return result
    
    def _get_timestamp(self) -> datetime:
        """Get current timestamp with timezone."""
        return datetime.now(timezone.utc)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        Get comprehensive tool information including configuration and capabilities.
        
        Returns:
            Dictionary with complete tool metadata
        """
        return {
            "name": self.tool_name,
            "command": self.command_name,
            "version": "enhanced-2.0",
            "description": "Network scanner with security controls and policy enforcement",
            
            # Performance settings
            "performance": {
                "concurrency": self.concurrency,
                "default_timeout": self.default_timeout_sec,
                "max_network_size": self.MAX_NETWORK_SIZE,
                "max_port_ranges": self.MAX_PORT_RANGES,
            },
            
            # Policy settings
            "policy": {
                "intrusive_allowed": self.allow_intrusive,
                "intrusive_flag_status": "allowed" if self.allow_intrusive else "blocked",
                "script_filtering": "enforced",
                "target_restrictions": "RFC1918 and .lab.internal only",
            },
            
            # Allowed operations
            "allowed_operations": {
                "flags_count": len(self.allowed_flags),
                "flags": list(self.allowed_flags),
                "safe_script_categories": list(self.SAFE_SCRIPT_CATEGORIES),
                "safe_scripts_count": len(self.SAFE_SCRIPTS),
                "intrusive_categories": list(self.INTRUSIVE_SCRIPT_CATEGORIES) if self.allow_intrusive else [],
                "intrusive_scripts_count": len(self.INTRUSIVE_SCRIPTS) if self.allow_intrusive else 0,
            },
            
            # Safety limits
            "safety_limits": {
                "max_network_size": self.MAX_NETWORK_SIZE,
                "max_cidr_for_limit": f"/{self._get_max_cidr_for_size(self.MAX_NETWORK_SIZE)}",
                "max_port_ranges": self.MAX_PORT_RANGES,
                "non_flag_tokens": "completely blocked",
                "allowed_targets": ["RFC1918 private IPs", "*.lab.internal domains"],
            },
            
            # Circuit breaker
            "circuit_breaker": {
                "enabled": self._circuit_breaker is not None,
                "failure_threshold": self.circuit_breaker_failure_threshold,
                "recovery_timeout": self.circuit_breaker_recovery_timeout,
                "state": self._circuit_breaker.state.name if self._circuit_breaker else "N/A",
            },
            
            # Metrics
            "metrics": {
                "available": self.metrics is not None,
                "prometheus_metric": f'mcp_tool_execution_total{{tool="{self.tool_name}"}}' if self.metrics else None,
            },
            
            # Optimizations
            "optimizations": {
                "default_timing": "T4 (Aggressive)",
                "default_parallelism": 10,
                "default_ports": "top-1000",
                "host_discovery": "disabled (-Pn)",
                "script_caching": "enabled",
                "compiled_patterns": "enabled",
            },
            
            # Scan templates
            "scan_templates": [t.value for t in ScanTemplate],
            
            # Security features
            "security_features": [
                "Whitelist-based flag validation",
                "Non-flag token blocking",
                "Script safety filtering",
                "Network size limits",
                "Port range limits",
                "Policy-based intrusive controls",
                "Private network enforcement",
                "Input sanitization",
                "Compiled regex validation"
            ],
            
            # Cache statistics
            "cache": {
                "script_cache_size": len(self._script_cache),
                "script_cache_enabled": True,
            }
        }
    
    def clear_caches(self):
        """Clear internal caches (useful for testing or config changes)."""
        self._script_cache.clear()
        log.debug("nmap.caches_cleared")
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current configuration and return status.
        
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Check if nmap is available
        if not self._resolve_command():
            issues.append("nmap command not found in PATH")
        
        # Check circuit breaker state
        if self._circuit_breaker:
            from mcp_server.circuit_breaker import CircuitBreakerState
            if self._circuit_breaker.state == CircuitBreakerState.OPEN:
                warnings.append("Circuit breaker is currently OPEN")
        
        # Check timeout configuration
        if self.default_timeout_sec < 60:
            warnings.append(f"Default timeout very low: {self.default_timeout_sec}s")
        
        # Check intrusive setting
        if self.allow_intrusive:
            warnings.append("Intrusive operations are ENABLED")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "configuration": {
                "intrusive_allowed": self.allow_intrusive,
                "timeout": self.default_timeout_sec,
                "concurrency": self.concurrency,
                "command_available": self._resolve_command() is not None,
            }
        }

```

