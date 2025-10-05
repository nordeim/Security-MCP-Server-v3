# Continuing Complete Implementation

## File 3: nmap_tool.py (Complete Drop-in Replacement)

```python
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

Now I'll continue with the updated base_tool.py, config.py, health.py, and server.py files...

## File 4: base_tool.py (Complete Drop-in Replacement with All Fixes)

```python
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

Due to length constraints, I'll provide config.py, health.py, and server.py in my next response. These are ready and incorporate all the fixes from my comprehensive review!

Would you like me to continue with the remaining three files now?
