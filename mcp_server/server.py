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
