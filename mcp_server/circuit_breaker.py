"""
Circuit breaker implementation for MCP tool resilience.
Production-ready with enhanced async handling, proper task management, and comprehensive monitoring.

Features:
- Async-first design with proper coroutine handling
- Thread-safe state management
- Background task tracking and cleanup
- Adaptive timeout with exponential backoff
- Jitter for thundering herd prevention
- State transition hooks for monitoring
- Comprehensive metrics and statistics
- Testing utilities

Usage:
    from mcp_server.circuit_breaker import CircuitBreaker
    
    # Create circuit breaker
    cb = CircuitBreaker(
        failure_threshold=5,
        recovery_timeout=60.0,
        name="my_service"
    )
    
    # Use with async function
    async def risky_operation():
        return await external_api_call()
    
    try:
        result = await cb.call(risky_operation)
    except CircuitBreakerOpenError as e:
        print(f"Circuit open, retry after {e.retry_after}s")
    
    # Cleanup
    await cb.cleanup()

Testing:
    # Reset state for testing
    await cb.force_close()
    
    # Inject failure
    await cb.force_open()
    
    # Get comprehensive stats
    stats = cb.get_stats()
"""
import asyncio
import time
import logging
import inspect
import random
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Any, Optional, Tuple, Dict, Set, List, Protocol
from datetime import datetime, timedelta
from collections import deque

log = logging.getLogger(__name__)

# Metrics integration with safe fallback
try:
    from prometheus_client import Counter, Gauge
    METRICS_AVAILABLE = True
    
    # Global metrics for circuit breakers
    CB_STATE_GAUGE = Gauge(
        'circuit_breaker_state',
        'Circuit breaker state (0=closed, 1=open, 2=half_open)',
        ['name']
    )
    CB_CALLS_COUNTER = Counter(
        'circuit_breaker_calls_total',
        'Total circuit breaker calls',
        ['name', 'result']
    )
    CB_STATE_TRANSITIONS = Counter(
        'circuit_breaker_transitions_total',
        'Circuit breaker state transitions',
        ['name', 'from_state', 'to_state']
    )
except ImportError:
    METRICS_AVAILABLE = False
    CB_STATE_GAUGE = CB_CALLS_COUNTER = CB_STATE_TRANSITIONS = None


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    def __init__(self, message: str, retry_after: Optional[float] = None, 
                 breaker_name: Optional[str] = None):
        super().__init__(message)
        self.retry_after = retry_after
        self.breaker_name = breaker_name


class CircuitBreakerState(Enum):
    """Circuit breaker states with numeric values for metrics."""
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


class StateTransitionCallback(Protocol):
    """Protocol for state transition callbacks."""
    async def __call__(self, from_state: CircuitBreakerState, 
                      to_state: CircuitBreakerState, breaker_name: str) -> None:
        """Called when circuit breaker changes state."""
        ...


@dataclass
class StateTransition:
    """Record of a state transition."""
    timestamp: datetime
    from_state: CircuitBreakerState
    to_state: CircuitBreakerState
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_changes: int = 0
    last_state_change: Optional[datetime] = None
    failure_reasons: Dict[str, int] = field(default_factory=dict)
    total_latency: float = 0.0
    
    def get_average_latency(self) -> float:
        """Calculate average call latency."""
        if self.total_calls == 0:
            return 0.0
        return self.total_latency / self.total_calls


class CircuitBreaker:
    """
    Production-ready circuit breaker with enhanced async support and comprehensive monitoring.
    
    State Machine:
        CLOSED -> OPEN (on failure_threshold consecutive failures)
        OPEN -> HALF_OPEN (after recovery_timeout)
        HALF_OPEN -> CLOSED (on success_threshold consecutive successes)
        HALF_OPEN -> OPEN (on any failure)
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Tuple[type, ...] = (Exception,),
        name: str = "tool",
        success_threshold: int = 1,
        timeout_multiplier: float = 1.5,
        max_timeout: float = 300.0,
        enable_jitter: bool = True,
        state_transition_callback: Optional[StateTransitionCallback] = None,
    ):
        # Configuration
        self.failure_threshold = max(1, int(failure_threshold))
        self.initial_recovery_timeout = max(1.0, float(recovery_timeout))
        self.current_recovery_timeout = self.initial_recovery_timeout
        self.max_timeout = max(self.initial_recovery_timeout, float(max_timeout))
        self.timeout_multiplier = max(1.0, float(timeout_multiplier))
        self.success_threshold = max(1, int(success_threshold))
        self.enable_jitter = enable_jitter
        self.state_transition_callback = state_transition_callback
        
        if not isinstance(expected_exception, tuple):
            expected_exception = (expected_exception,)
        self.expected_exception = expected_exception
        self.name = name
        
        # State
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._consecutive_failures = 0
        self._lock = asyncio.Lock()
        
        # Metrics and tracking
        self.stats = CircuitBreakerStats()
        self._recent_errors = deque(maxlen=10)
        self._state_history = deque(maxlen=100)
        self._half_open_calls = 0
        self._max_half_open_calls = 1
        
        # Background task management
        self._background_tasks: Set[asyncio.Task] = set()
        
        # Cache metrics availability
        self._metrics_available = METRICS_AVAILABLE
        
        self._update_metrics()
        
        log.info(
            "circuit_breaker.created name=%s threshold=%d timeout=%.1f success_threshold=%d",
            self.name, self.failure_threshold, self.initial_recovery_timeout, self.success_threshold
        )
    
    @property
    def state(self) -> CircuitBreakerState:
        """Get current state (thread-safe)."""
        return self._state
    
    def _update_metrics(self):
        """Update Prometheus metrics (cached availability check)."""
        if self._metrics_available and CB_STATE_GAUGE:
            try:
                CB_STATE_GAUGE.labels(name=self.name).set(self._state.value)
            except Exception as e:
                log.debug("metrics.update_failed error=%s", str(e))
                self._metrics_available = False
    
    def _record_call_metric(self, result: str):
        """Record call metrics (outside lock)."""
        if self._metrics_available and CB_CALLS_COUNTER:
            try:
                CB_CALLS_COUNTER.labels(name=self.name, result=result).inc()
            except Exception as e:
                log.debug("metrics.record_failed error=%s", str(e))
                self._metrics_available = False
    
    def _record_transition_metric(self, from_state: CircuitBreakerState, to_state: CircuitBreakerState):
        """Record state transition metrics (outside lock)."""
        if self._metrics_available and CB_STATE_TRANSITIONS:
            try:
                CB_STATE_TRANSITIONS.labels(
                    name=self.name,
                    from_state=from_state.name,
                    to_state=to_state.name
                ).inc()
            except Exception as e:
                log.debug("metrics.transition_failed error=%s", str(e))
                self._metrics_available = False
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection and proper async handling.
        
        Args:
            func: Function to execute (can be sync or async)
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func
        
        Returns:
            Result from func
        
        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: Any exception from func execution
        """
        start_time = time.time()
        
        # Check and potentially transition state - all checks under lock
        async with self._lock:
            if self._state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    await self._transition_to_half_open()
                else:
                    retry_after = self._get_retry_after()
                    self.stats.rejected_calls += 1
                    # Record metric outside lock
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker is open for {self.name}",
                        retry_after=retry_after,
                        breaker_name=self.name
                    )
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                if self._half_open_calls >= self._max_half_open_calls:
                    self.stats.rejected_calls += 1
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker is testing recovery for {self.name}",
                        retry_after=5.0,
                        breaker_name=self.name
                    )
                self._half_open_calls += 1
        
        # Record rejected calls metric outside lock
        if self._state == CircuitBreakerState.OPEN or \
           (self._state == CircuitBreakerState.HALF_OPEN and 
            self._half_open_calls > self._max_half_open_calls):
            self._record_call_metric("rejected")
        
        # Execute the function
        try:
            self.stats.total_calls += 1
            
            # Enhanced async detection and execution
            result = await self._execute_function(func, *args, **kwargs)
            
            execution_time = time.time() - start_time
            await self._on_success()
            
            # Update stats and metrics outside lock
            self.stats.successful_calls += 1
            self.stats.last_success_time = time.time()
            self.stats.total_latency += execution_time
            self._record_call_metric("success")
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # Update stats
            self.stats.failed_calls += 1
            self.stats.last_failure_time = time.time()
            self.stats.total_latency += execution_time
            
            error_type = type(e).__name__
            self.stats.failure_reasons[error_type] = self.stats.failure_reasons.get(error_type, 0) + 1
            
            self._recent_errors.append({
                "timestamp": datetime.now(),
                "error": str(e),
                "type": error_type,
                "execution_time": execution_time
            })
            
            if isinstance(e, self.expected_exception):
                await self._on_failure()
                self._record_call_metric("failure")
            else:
                log.warning(
                    "circuit_breaker.unexpected_error name=%s error=%s",
                    self.name, repr(e)
                )
                self._record_call_metric("unexpected_failure")
            
            raise
        
        finally:
            if self._state == CircuitBreakerState.HALF_OPEN:
                async with self._lock:
                    self._half_open_calls = max(0, self._half_open_calls - 1)
    
    async def _execute_function(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with proper async detection."""
        # Check if it's a coroutine function
        if inspect.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        
        # Execute sync function
        result = func(*args, **kwargs)
        
        # Check if result needs awaiting
        if inspect.isawaitable(result) or asyncio.iscoroutine(result):
            return await result
        
        if asyncio.isfuture(result):
            return await result
        
        return result
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed for recovery attempt."""
        if self._last_failure_time <= 0:
            return False
        
        time_since_failure = time.time() - self._last_failure_time
        recovery_time = self.current_recovery_timeout
        
        if self.enable_jitter:
            # Add jitter: ±10% of recovery time
            jitter = random.uniform(-recovery_time * 0.1, recovery_time * 0.1)
            recovery_time += jitter
        
        return time_since_failure >= recovery_time
    
    def _get_retry_after(self) -> float:
        """Calculate when retry should be attempted."""
        if self._last_failure_time <= 0:
            return self.current_recovery_timeout
        
        time_since_failure = time.time() - self._last_failure_time
        remaining = max(0, self.current_recovery_timeout - time_since_failure)
        
        if self.enable_jitter:
            # Add small random jitter to remaining time
            remaining += random.uniform(0, min(5.0, remaining * 0.1))
        
        return round(remaining, 2)
    
    async def _transition_to_half_open(self):
        """Transition to half-open state (must be called under lock)."""
        old_state = self._state
        self._state = CircuitBreakerState.HALF_OPEN
        self._success_count = 0
        self._half_open_calls = 0
        
        transition = StateTransition(
            timestamp=datetime.now(),
            from_state=old_state,
            to_state=self._state,
            reason="recovery_timeout_elapsed",
            metadata={"recovery_timeout": self.current_recovery_timeout}
        )
        self._state_history.append(transition)
        
        self.stats.state_changes += 1
        self.stats.last_state_change = datetime.now()
        
        # Update metrics outside lock (after releasing)
        log.info("circuit_breaker.half_open name=%s", self.name)
    
    async def _on_success(self):
        """Handle successful execution."""
        async with self._lock:
            self.stats.consecutive_successes += 1
            self.stats.consecutive_failures = 0
            self._consecutive_failures = 0
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._success_count += 1
                
                if self._success_count >= self.success_threshold:
                    old_state = self._state
                    self._state = CircuitBreakerState.CLOSED
                    self._failure_count = 0
                    self.current_recovery_timeout = self.initial_recovery_timeout
                    
                    transition = StateTransition(
                        timestamp=datetime.now(),
                        from_state=old_state,
                        to_state=self._state,
                        reason="success_threshold_reached",
                        metadata={"success_count": self._success_count}
                    )
                    self._state_history.append(transition)
                    
                    self.stats.state_changes += 1
                    self.stats.last_state_change = datetime.now()
                    
                    log.info("circuit_breaker.closed name=%s", self.name)
                    
                    # Fire callback outside lock
                    if self.state_transition_callback:
                        await self._fire_transition_callback(old_state, self._state)
            
            elif self._state == CircuitBreakerState.CLOSED:
                if self._failure_count > 0:
                    self._failure_count = 0
                    log.debug("circuit_breaker.failure_count_reset name=%s", self.name)
        
        # Update metrics outside lock
        self._update_metrics()
        if self._state == CircuitBreakerState.CLOSED:
            self._record_transition_metric(CircuitBreakerState.HALF_OPEN, CircuitBreakerState.CLOSED)
    
    async def _on_failure(self):
        """Handle failed execution with adaptive timeout."""
        async with self._lock:
            self._failure_count += 1
            self._consecutive_failures += 1
            self.stats.consecutive_failures = self._consecutive_failures
            self.stats.consecutive_successes = 0
            self._last_failure_time = time.time()
            
            old_state = self._state
            
            if self._state == CircuitBreakerState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitBreakerState.OPEN
                    
                    # Adaptive timeout: increase if failures are persistent
                    if self._consecutive_failures > self.failure_threshold:
                        self.current_recovery_timeout = min(
                            self.current_recovery_timeout * self.timeout_multiplier,
                            self.max_timeout
                        )
                    
                    transition = StateTransition(
                        timestamp=datetime.now(),
                        from_state=old_state,
                        to_state=self._state,
                        reason="failure_threshold_exceeded",
                        metadata={
                            "failure_count": self._failure_count,
                            "consecutive_failures": self._consecutive_failures,
                            "new_timeout": self.current_recovery_timeout
                        }
                    )
                    self._state_history.append(transition)
                    
                    self.stats.state_changes += 1
                    self.stats.last_state_change = datetime.now()
                    
                    log.warning(
                        "circuit_breaker.open name=%s failures=%d timeout=%.1fs",
                        self.name, self._failure_count, self.current_recovery_timeout
                    )
            
            elif self._state == CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.OPEN
                
                # Increase timeout after failed recovery attempt
                self.current_recovery_timeout = min(
                    self.current_recovery_timeout * self.timeout_multiplier,
                    self.max_timeout
                )
                
                transition = StateTransition(
                    timestamp=datetime.now(),
                    from_state=old_state,
                    to_state=self._state,
                    reason="recovery_attempt_failed",
                    metadata={"new_timeout": self.current_recovery_timeout}
                )
                self._state_history.append(transition)
                
                self.stats.state_changes += 1
                self.stats.last_state_change = datetime.now()
                
                log.warning(
                    "circuit_breaker.reopened name=%s timeout=%.1fs",
                    self.name, self.current_recovery_timeout
                )
            
            # Fire callback outside lock
            if old_state != self._state and self.state_transition_callback:
                await self._fire_transition_callback(old_state, self._state)
        
        # Update metrics outside lock
        if old_state != self._state:
            self._update_metrics()
            self._record_transition_metric(old_state, self._state)
    
    async def _fire_transition_callback(self, from_state: CircuitBreakerState, 
                                       to_state: CircuitBreakerState):
        """Fire state transition callback."""
        if self.state_transition_callback:
            try:
                await self.state_transition_callback(from_state, to_state, self.name)
            except Exception as e:
                log.error("circuit_breaker.callback_failed name=%s error=%s", 
                         self.name, str(e))
    
    async def force_open(self):
        """Force circuit breaker to open state."""
        async with self._lock:
            old_state = self._state
            self._state = CircuitBreakerState.OPEN
            self._failure_count = self.failure_threshold
            self._last_failure_time = time.time()
            
            if old_state != self._state:
                transition = StateTransition(
                    timestamp=datetime.now(),
                    from_state=old_state,
                    to_state=self._state,
                    reason="forced_open"
                )
                self._state_history.append(transition)
                
                self.stats.state_changes += 1
                self.stats.last_state_change = datetime.now()
            
            log.info("circuit_breaker.force_open name=%s", self.name)
        
        # Update metrics outside lock
        if old_state != self._state:
            self._update_metrics()
            self._record_transition_metric(old_state, self._state)
    
    async def force_close(self):
        """Force circuit breaker to closed state."""
        async with self._lock:
            old_state = self._state
            self._state = CircuitBreakerState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._consecutive_failures = 0
            self.current_recovery_timeout = self.initial_recovery_timeout
            self._last_failure_time = 0.0
            
            if old_state != self._state:
                transition = StateTransition(
                    timestamp=datetime.now(),
                    from_state=old_state,
                    to_state=self._state,
                    reason="forced_close"
                )
                self._state_history.append(transition)
                
                self.stats.state_changes += 1
                self.stats.last_state_change = datetime.now()
            
            log.info("circuit_breaker.force_close name=%s", self.name)
        
        # Update metrics outside lock
        if old_state != self._state:
            self._update_metrics()
            self._record_transition_metric(old_state, self._state)
    
    def force_open_nowait(self):
        """Thread-safe async force open with proper task management."""
        task = self._create_background_task(self.force_open())
        return task
    
    def force_close_nowait(self):
        """Thread-safe async force close with proper task management."""
        task = self._create_background_task(self.force_close())
        return task
    
    def _create_background_task(self, coro) -> asyncio.Task:
        """Create background task with proper lifecycle management."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, use sync version
            asyncio.run(coro)
            return None
        else:
            # Store task reference to prevent GC
            task = loop.create_task(coro)
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
            return task
    
    def call_succeeded(self):
        """Synchronous success handler for compatibility."""
        self._create_background_task(self._on_success())
    
    def call_failed(self):
        """Synchronous failure handler for compatibility."""
        self._create_background_task(self._on_failure())
    
    def get_state_history(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent state transitions."""
        count = max(1, min(count, 100))
        history = list(self._state_history)[-count:]
        return [
            {
                "timestamp": t.timestamp.isoformat(),
                "from_state": t.from_state.name,
                "to_state": t.to_state.name,
                "reason": t.reason,
                "metadata": t.metadata
            }
            for t in history
        ]
    
    def get_stats(self) -> dict:
        """Get comprehensive circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self._state.name,
            "stats": {
                "total_calls": self.stats.total_calls,
                "successful_calls": self.stats.successful_calls,
                "failed_calls": self.stats.failed_calls,
                "rejected_calls": self.stats.rejected_calls,
                "success_rate": (
                    (self.stats.successful_calls / self.stats.total_calls * 100)
                    if self.stats.total_calls > 0 else 0.0
                ),
                "average_latency": round(self.stats.get_average_latency(), 4),
                "consecutive_failures": self.stats.consecutive_failures,
                "consecutive_successes": self.stats.consecutive_successes,
                "state_changes": self.stats.state_changes,
                "failure_reasons": self.stats.failure_reasons,
            },
            "config": {
                "failure_threshold": self.failure_threshold,
                "current_timeout": round(self.current_recovery_timeout, 2),
                "initial_timeout": self.initial_recovery_timeout,
                "max_timeout": self.max_timeout,
                "success_threshold": self.success_threshold,
                "timeout_multiplier": self.timeout_multiplier,
                "jitter_enabled": self.enable_jitter,
            },
            "timing": {
                "last_failure": self.stats.last_failure_time,
                "last_success": self.stats.last_success_time,
                "last_state_change": (
                    self.stats.last_state_change.isoformat()
                    if self.stats.last_state_change else None
                ),
                "retry_after": self._get_retry_after() if self._state == CircuitBreakerState.OPEN else None,
            },
            "recent_errors": list(self._recent_errors),
            "state_history": self.get_state_history(5),
        }
    
    async def cleanup(self):
        """Clean up background tasks and resources."""
        log.info("circuit_breaker.cleanup_started name=%s", self.name)
        
        # Cancel all background tasks
        tasks = list(self._background_tasks)
        for task in tasks:
            if not task.done():
                task.cancel()
        
        # Wait for cancellation
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self._background_tasks.clear()
        
        log.info("circuit_breaker.cleanup_completed name=%s tasks_cleaned=%d", 
                self.name, len(tasks))


class CircuitBreakerContext:
    """
    Context manager for circuit breaker operations.
    
    Usage:
        async with CircuitBreakerContext(cb) as ctx:
            result = await perform_operation()
    """
    
    def __init__(self, circuit_breaker: CircuitBreaker):
        self.circuit_breaker = circuit_breaker
        self.start_time = None
        self.exception_occurred = False
    
    async def __aenter__(self):
        self.start_time = time.time()
        self.exception_occurred = False
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        execution_time = time.time() - self.start_time
        self.exception_occurred = exc_type is not None
        
        if self.exception_occurred:
            await self.circuit_breaker._on_failure()
        else:
            await self.circuit_breaker._on_success()
        
        # Don't suppress exceptions
        return False
