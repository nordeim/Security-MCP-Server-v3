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
