"""
Masscan ultra-fast port scanner tool with strict safety controls.

Features:
- Ultra-fast asynchronous TCP port scanning
- Multi-tier rate limiting system
- Privilege detection and validation
- Template-based scanning
- Result parsing (XML/JSON/List)
- Banner grabbing support

Safety Controls:
- CRITICAL: Rate limiting (multi-tier based on policy)
- CRITICAL: Network range limits (max 256 hosts)
- CRITICAL: Privilege validation (CAP_NET_RAW or proper setup)
- Intrusive operation gating (rate > 1000 pps requires allow_intrusive)
- RFC1918/lab.internal only targets
- Port range validation
- Resource exhaustion prevention

WARNING:
    Masscan can send millions of packets per second and can easily:
    - Overwhelm networks (DoS)
    - Trigger IDS/IPS systems
    - Violate network policies
    - Cause ISP issues
    
    USE WITH EXTREME CAUTION and only in authorized lab environments!

Usage:
    tool = MasscanTool()
    
    # Basic scan (safe rate)
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="-p 80,443 --rate 100"
    ))
    
    # Template scan
    result = await tool.run_with_template(
        target="192.168.1.0/24",
        template=MasscanTemplate.QUICK
    )

Author: MCP Network Tools Team
Version: 2.0.0
"""

import logging
import re
import os
import shlex
import shutil
import ipaddress
import math
import json
from typing import Optional, Dict, Any, List, Tuple, ClassVar, Sequence
from enum import Enum
from datetime import datetime, timezone

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext
from mcp_server.config import get_config

log = logging.getLogger(__name__)


class MasscanTemplate(Enum):
    """Predefined scan templates with safety-focused configurations."""
    QUICK = "quick"               # Top 100 ports, 100 pps
    STANDARD = "standard"         # Top 1000 ports, 500 pps
    THOROUGH = "thorough"         # All TCP ports, 1000 pps
    WEB_SERVICES = "web_services" # Web-related ports, 200 pps
    COMMON_SERVICES = "common"    # Common service ports, 300 pps


class PrivilegeStatus(Enum):
    """Privilege status for masscan execution."""
    CAPABILITIES = "capabilities"       # Has CAP_NET_RAW capability
    ROOT = "root"                      # Running as root
    BINARY_CAPABILITIES = "binary_cap" # Binary has capabilities
    INSUFFICIENT = "insufficient"       # No privileges


class MasscanTool(MCPBaseTool):
    """
    Masscan ultra-fast port scanner with strict safety controls.
    
    Masscan is an extremely fast port scanner capable of scanning the
    entire Internet in under 6 minutes. It uses asynchronous transmission
    and can send millions of packets per second.
    
    Security Model:
    - Multi-tier rate limiting (100/1000/10000/100000 pps)
    - Rate > 1000 pps requires allow_intrusive=true
    - Network range limit: max 256 hosts (/24)
    - Range > /24 requires allow_intrusive=true
    - Requires CAP_NET_RAW capability or root
    - RFC1918/lab.internal only targets
    - Port range validation
    - Absolute maximum rate: 100,000 pps (emergency brake)
    
    Privilege Requirements:
    - CAP_NET_RAW capability (preferred), OR
    - Root access (not recommended), OR
    - Binary with setcap cap_net_raw+ep
    
    WARNING:
        This tool can cause significant network disruption.
        Only use in controlled lab environments with proper authorization.
        High packet rates can:
        - Saturate network links
        - Crash network equipment
        - Trigger security alerts
        - Violate terms of service
    
    Attributes:
        command_name: System command (masscan)
        allowed_flags: Whitelist of permitted flags
        default_timeout_sec: Default timeout (300s)
        concurrency: Max concurrent executions (1 - exclusive)
    
    Example:
        >>> tool = MasscanTool()
        >>> # Check privileges first
        >>> has_priv, status = tool._check_privileges()
        >>> if not has_priv:
        ...     print(f"Insufficient privileges: {status}")
        >>> 
        >>> result = await tool.run(ToolInput(
        ...     target="192.168.1.0/24",
        ...     extra_args="-p 80,443 --rate 100"
        ... ))
    """
    
    command_name: ClassVar[str] = "masscan"
    
    # Allowed masscan flags (carefully curated for safety)
    allowed_flags: ClassVar[Sequence[str]] = [
        # Port specification
        "-p", "--ports",
        
        # Rate control (CRITICAL)
        "--rate", "--max-rate",
        
        # Output format
        "-oX", "-oJ", "-oL", "-oG",
        
        # Scan options
        "--banners",
        "--source-ip",
        "--source-port",
        "--router-mac",
        "--adapter",
        "--adapter-ip",
        "--adapter-port",
        "--adapter-mac",
        "--router-ip",
        
        # Exclusions
        "--exclude", "--excludefile",
        
        # Connection options
        "--retries",
        "--timeout",
        
        # Performance
        "--wait",
        "--offline",
        
        # Information
        "--echo",
        
        # Basic flags
        "-v", "--verbose",
    ]
    
    # Flags that require values
    _FLAGS_REQUIRE_VALUE = {
        "-p", "--ports",
        "--rate", "--max-rate",
        "-oX", "-oJ", "-oL", "-oG",
        "--source-ip", "--source-port",
        "--router-mac", "--adapter",
        "--adapter-ip", "--adapter-port",
        "--adapter-mac", "--router-ip",
        "--exclude", "--excludefile",
        "--retries", "--timeout",
        "--wait",
    }
    
    # Extra allowed tokens
    _EXTRA_ALLOWED_TOKENS = {
        "0-65535", "1-1000", "80", "443", "8080",  # Port specifications
        "100", "500", "1000", "10000",  # Rate values
    }
    
    # Timeouts (masscan can be long-running)
    default_timeout_sec: ClassVar[float] = 300.0  # 5 minutes default
    
    # Concurrency (EXCLUSIVE - only one masscan at a time)
    concurrency: ClassVar[int] = 1
    
    # Circuit breaker (very strict for masscan)
    circuit_breaker_failure_threshold: ClassVar[int] = 3
    circuit_breaker_recovery_timeout: ClassVar[float] = 120.0
    
    # Rate limit tiers (packets per second)
    DEFAULT_RATE = 100           # Safe default
    MAX_RATE_SAFE = 1000         # Maximum without intrusive flag
    MAX_RATE_INTRUSIVE = 10000   # Maximum with intrusive flag
    ABSOLUTE_MAX_RATE = 100000   # Hard limit (emergency brake)
    
    # Network limits (stricter than nmap)
    MAX_NETWORK_SIZE = 256       # Max hosts (/24)
    MAX_CIDR = 24                # Maximum CIDR prefix
    
    # Port limits
    MAX_PORT_RANGES = 1000       # Maximum port specifications
    
    # Port definitions for templates
    TOP_100_PORTS = (
        "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,"
        "179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,"
        "993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,"
        "3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,"
        "5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,"
        "9999-10000,32768,49152-49157"
    )
    
    TOP_1000_PORTS = "0-1000"  # Simplified - masscan optimizes this
    
    WEB_PORTS = "80,443,8000,8008,8080,8081,8443,8888,3000,5000,9000,9090"
    
    COMMON_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,"
        "5432,5900,8080"
    )
    
    # Compiled patterns for parsing
    _XML_PORT_PATTERN = re.compile(
        r'<port protocol="(?P<protocol>\w+)" portid="(?P<port>\d+)"><state state="(?P<state>\w+)"'
    )
    
    _JSON_PORT_PATTERN = re.compile(
        r'"ip":\s*"(?P<ip>[^"]+)".*?"ports":\s*\[.*?"port":\s*(?P<port>\d+).*?"proto":\s*"(?P<proto>\w+)"'
    )
    
    _LIST_PORT_PATTERN = re.compile(
        r'Discovered open port (?P<port>\d+)/(?P<proto>tcp|udp) on (?P<ip>[\d.]+)'
    )
    
    _BANNER_PATTERN = re.compile(
        r'Banner on port (?P<port>\d+)/(?P<proto>tcp|udp) on (?P<ip>[\d.]+):\s*\[(?P<banner>[^\]]+)\]'
    )
    
    def __init__(self):
        """Initialize Masscan tool with strict safety controls."""
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._privilege_status = None
        self._privilege_checked = False
        self._apply_config()
        
        log.info("masscan_tool.initialized allow_intrusive=%s", self.allow_intrusive)
        log.warning("masscan_tool.WARNING high_risk_tool use_with_caution")
    
    def _apply_config(self):
        """Apply configuration settings with strict safety enforcement."""
        try:
            # Apply security config
            if hasattr(self.config, 'security') and self.config.security:
                sec = self.config.security
                if hasattr(sec, 'allow_intrusive'):
                    old_intrusive = self.allow_intrusive
                    self.allow_intrusive = bool(sec.allow_intrusive)
                    
                    if self.allow_intrusive != old_intrusive:
                        if self.allow_intrusive:
                            log.warning("masscan.intrusive_enabled high_rate_scans_allowed")
                        else:
                            log.info("masscan.intrusive_disabled high_rate_scans_blocked")
            
            # Apply circuit breaker config (stricter for masscan)
            if hasattr(self.config, 'circuit_breaker') and self.config.circuit_breaker:
                cb = self.config.circuit_breaker
                if hasattr(cb, 'failure_threshold'):
                    # Masscan uses stricter threshold
                    self.circuit_breaker_failure_threshold = max(1, min(5, int(cb.failure_threshold)))
                if hasattr(cb, 'recovery_timeout'):
                    self.circuit_breaker_recovery_timeout = max(60.0, min(600.0, float(cb.recovery_timeout)))
            
            # Apply tool config
            if hasattr(self.config, 'tool') and self.config.tool:
                tool = self.config.tool
                if hasattr(tool, 'default_timeout'):
                    self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
                # Force concurrency to 1 for masscan
                self.concurrency = 1
            
            log.debug("masscan.config_applied intrusive=%s timeout=%.1f",
                     self.allow_intrusive, self.default_timeout_sec)
            
        except Exception as e:
            log.error("masscan.config_apply_failed error=%s using_safe_defaults", str(e))
            # Reset to safe defaults
            self.allow_intrusive = False
            self.circuit_breaker_failure_threshold = 3
            self.circuit_breaker_recovery_timeout = 120.0
            self.default_timeout_sec = 300.0
            self.concurrency = 1
    
    def _check_privileges(self) -> Tuple[bool, PrivilegeStatus]:
        """
        Check if masscan has required privileges.
        
        Masscan requires CAP_NET_RAW capability to send raw packets.
        This can be achieved by:
        1. Running as root (not recommended)
        2. Setting capabilities on the binary: sudo setcap cap_net_raw+ep $(which masscan)
        
        Returns:
            Tuple of (has_privileges, status)
        """
        if self._privilege_checked:
            return (self._privilege_status != PrivilegeStatus.INSUFFICIENT, self._privilege_status)
        
        try:
            # Check if running as root
            if os.geteuid() == 0:
                log.warning("masscan.running_as_root security_warning")
                self._privilege_status = PrivilegeStatus.ROOT
                self._privilege_checked = True
                return (True, PrivilegeStatus.ROOT)
            
            # Check binary capabilities
            masscan_path = shutil.which("masscan")
            if masscan_path:
                # Try to check capabilities using getcap
                try:
                    import subprocess
                    result = subprocess.run(
                        ["getcap", masscan_path],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0 and "cap_net_raw" in result.stdout.lower():
                        log.info("masscan.capabilities_detected binary=%s", masscan_path)
                        self._privilege_status = PrivilegeStatus.BINARY_CAPABILITIES
                        self._privilege_checked = True
                        return (True, PrivilegeStatus.BINARY_CAPABILITIES)
                
                except Exception as e:
                    log.debug("masscan.capability_check_failed error=%s", str(e))
            
            # No privileges detected
            log.warning("masscan.insufficient_privileges")
            self._privilege_status = PrivilegeStatus.INSUFFICIENT
            self._privilege_checked = True
            return (False, PrivilegeStatus.INSUFFICIENT)
            
        except Exception as e:
            log.error("masscan.privilege_check_error error=%s", str(e))
            self._privilege_status = PrivilegeStatus.INSUFFICIENT
            self._privilege_checked = True
            return (False, PrivilegeStatus.INSUFFICIENT)
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute masscan with comprehensive validation and safety checks."""
        # Check privileges first
        has_privileges, priv_status = self._check_privileges()
        
        if not has_privileges:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="Masscan requires CAP_NET_RAW capability or root access",
                recovery_suggestion=(
                    "Grant capability: sudo setcap cap_net_raw+ep $(which masscan)\n"
                    "Or run as root: sudo masscan ... (not recommended)"
                ),
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={
                    "privilege_status": priv_status.value,
                    "current_uid": os.geteuid()
                }
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Validate network range (stricter than base class)
        validation_result = self._validate_masscan_network(inp.target)
        if validation_result:
            return validation_result
        
        # Parse and validate arguments
        try:
            parsed_args, detected_rate = self._parse_and_validate_args(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid arguments: {str(e)}",
                recovery_suggestion="Check argument syntax, rate limits, and allowed flags",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e)}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Validate rate against policy
        rate_validation = self._validate_rate_policy(detected_rate, inp.target)
        if rate_validation:
            return rate_validation
        
        # Optimize arguments
        optimized_args = self._optimize_masscan_args(parsed_args, detected_rate)
        
        # Create enhanced input
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=optimized_args,
            timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
            correlation_id=inp.correlation_id,
        )
        
        log.warning("masscan.executing target=%s rate=%d args=%s CAUTION",
                   inp.target, detected_rate, optimized_args)
        
        # Execute
        result = await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)
        
        # Parse output if available
        if result.returncode == 0 or result.stdout:
            try:
                parsed_results = self._parse_masscan_output(result.stdout)
                result.ensure_metadata()
                result.metadata['parsed_results'] = parsed_results
                result.metadata['hosts_found'] = len(set(r.get('ip') for r in parsed_results if 'ip' in r))
                result.metadata['ports_found'] = len(parsed_results)
                result.metadata['scan_rate'] = detected_rate
                
                log.info("masscan.scan_completed hosts=%d ports=%d rate=%d",
                        result.metadata['hosts_found'],
                        result.metadata['ports_found'],
                        detected_rate)
            except Exception as e:
                log.warning("masscan.parse_failed error=%s", str(e))
                # Don't fail on parse errors
        
        return result
    
    def _validate_masscan_network(self, target: str) -> Optional[ToolOutput]:
        """Validate network range with stricter limits for masscan."""
        # Parse network
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
                    metadata={"error": str(e)}
                )
                return self._create_error_output(error_context, "")
            
            # Check network size (stricter for masscan)
            if network.num_addresses > self.MAX_NETWORK_SIZE:
                max_cidr = self._get_max_cidr_for_size(self.MAX_NETWORK_SIZE)
                
                # Large ranges require intrusive flag
                if not self.allow_intrusive:
                    error_context = ErrorContext(
                        error_type=ToolErrorType.VALIDATION_ERROR,
                        message=(
                            f"Network range too large: {network.num_addresses} addresses "
                            f"(max: {self.MAX_NETWORK_SIZE} without allow_intrusive)"
                        ),
                        recovery_suggestion=(
                            f"Use /{max_cidr} or smaller, OR set "
                            f"MCP_SECURITY_ALLOW_INTRUSIVE=true for larger ranges"
                        ),
                        timestamp=self._get_timestamp(),
                        tool_name=self.tool_name,
                        target=target,
                        metadata={
                            "network_size": network.num_addresses,
                            "max_allowed": self.MAX_NETWORK_SIZE,
                            "suggested_cidr": f"/{max_cidr}",
                            "example": f"{network.network_address}/{max_cidr}",
                            "allow_intrusive": self.allow_intrusive
                        }
                    )
                    return self._create_error_output(error_context, "")
                
                log.warning("masscan.large_network_allowed size=%d intrusive=true",
                          network.num_addresses)
            
            # Ensure private network
            if not (network.is_private or network.is_loopback):
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Only private networks allowed: {target}",
                    recovery_suggestion="Use RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={"network": str(network)}
                )
                return self._create_error_output(error_context, "")
        
        return None
    
    def _get_max_cidr_for_size(self, max_hosts: int) -> int:
        """Calculate maximum CIDR prefix for given host count."""
        bits_needed = math.ceil(math.log2(max_hosts))
        return max(0, 32 - bits_needed)
    
    def _parse_and_validate_args(self, extra_args: str) -> Tuple[str, int]:
        """
        Parse and validate masscan arguments.
        
        Returns:
            Tuple of (validated_args, detected_rate)
        
        Raises:
            ValueError: If validation fails
        """
        if not extra_args:
            return "", self.DEFAULT_RATE
        
        try:
            tokens = shlex.split(extra_args)
        except ValueError as e:
            raise ValueError(f"Failed to parse arguments: {str(e)}")
        
        validated = []
        detected_rate = self.DEFAULT_RATE
        i = 0
        
        while i < len(tokens):
            token = tokens[i]
            
            # Block non-flag tokens (security)
            if not token.startswith("-"):
                raise ValueError(
                    f"Unexpected non-flag token: '{token}'. "
                    f"Only flags starting with '-' are allowed."
                )
            
            # Handle port specification
            if token in ("-p", "--ports"):
                if i + 1 >= len(tokens):
                    raise ValueError("--ports requires a value")
                
                port_spec = tokens[i + 1]
                if not self._validate_port_spec(port_spec):
                    raise ValueError(f"Invalid port specification: {port_spec}")
                
                validated.extend([token, port_spec])
                i += 2
                continue
            
            # Handle rate (CRITICAL)
            if token in ("--rate", "--max-rate"):
                if i + 1 >= len(tokens):
                    raise ValueError(f"{token} requires a value")
                
                try:
                    rate = int(tokens[i + 1])
                    
                    # Enforce absolute maximum
                    if rate > self.ABSOLUTE_MAX_RATE:
                        log.error("masscan.rate_exceeds_absolute_max requested=%d max=%d",
                                 rate, self.ABSOLUTE_MAX_RATE)
                        raise ValueError(
                            f"Rate exceeds absolute maximum: {rate} pps "
                            f"(max: {self.ABSOLUTE_MAX_RATE} pps)"
                        )
                    
                    detected_rate = rate
                    validated.extend([token, str(rate)])
                    i += 2
                    continue
                    
                except ValueError as e:
                    raise ValueError(f"Invalid rate value: {tokens[i + 1]}")
            
            # Handle retries
            if token == "--retries":
                if i + 1 >= len(tokens):
                    raise ValueError("--retries requires a value")
                
                try:
                    retries = int(tokens[i + 1])
                    if retries > 5:
                        log.warning("masscan.retries_clamped original=%d max=5", retries)
                        retries = 5
                    validated.extend([token, str(retries)])
                    i += 2
                    continue
                except ValueError:
                    raise ValueError("--retries must be a number")
            
            # Handle other flags
            flag_base, flag_value = (token.split("=", 1) + [None])[:2]
            
            if flag_base in self.allowed_flags:
                expects_value = flag_base in self._FLAGS_REQUIRE_VALUE
                
                if flag_value is not None:
                    if not expects_value:
                        raise ValueError(f"Flag does not take inline value: {token}")
                    validated.extend([flag_base, flag_value])
                    i += 1
                elif expects_value:
                    if i + 1 >= len(tokens):
                        raise ValueError(f"{flag_base} requires a value")
                    validated.extend([flag_base, tokens[i + 1]])
                    i += 2
                else:
                    validated.append(flag_base)
                    i += 1
            else:
                raise ValueError(f"Flag not allowed: {token}")
        
        return " ".join(validated), detected_rate
    
    def _validate_port_spec(self, port_spec: str) -> bool:
        """
        Validate port specification for masscan.
        
        Args:
            port_spec: Port specification string
        
        Returns:
            True if valid, False otherwise
        """
        # Allow: 80, 80,443, 80-100, 0-65535, combinations
        port_pattern = re.compile(r'^[\d,\-]+$')
        
        if not port_pattern.match(port_spec):
            return False
        
        # Parse and validate ranges
        try:
            parts = port_spec.split(',')
            if len(parts) > self.MAX_PORT_RANGES:
                log.warning("masscan.too_many_port_ranges count=%d max=%d",
                          len(parts), self.MAX_PORT_RANGES)
                return False
            
            for part in parts:
                if '-' in part:
                    start, end = part.split('-', 1)
                    start_port = int(start)
                    end_port = int(end)
                    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                        return False
                    if start_port > end_port:
                        return False
                else:
                    port = int(part)
                    if not (0 <= port <= 65535):
                        return False
            
            return True
            
        except ValueError:
            return False
    
    def _validate_rate_policy(self, rate: int, target: str) -> Optional[ToolOutput]:
        """
        Validate rate against intrusive policy.
        
        Args:
            rate: Detected packet rate
            target: Scan target
        
        Returns:
            ToolOutput with error if validation fails, None otherwise
        """
        # Rate > MAX_RATE_SAFE requires intrusive flag
        if rate > self.MAX_RATE_SAFE and not self.allow_intrusive:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=(
                    f"High packet rate requires intrusive operations: {rate} pps "
                    f"(max safe rate: {self.MAX_RATE_SAFE} pps)"
                ),
                recovery_suggestion=(
                    f"Reduce rate to {self.MAX_RATE_SAFE} pps or lower, OR set "
                    f"MCP_SECURITY_ALLOW_INTRUSIVE=true"
                ),
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=target,
                metadata={
                    "requested_rate": rate,
                    "max_safe_rate": self.MAX_RATE_SAFE,
                    "max_intrusive_rate": self.MAX_RATE_INTRUSIVE,
                    "allow_intrusive": self.allow_intrusive
                }
            )
            return self._create_error_output(error_context, "")
        
        # Rate > MAX_RATE_INTRUSIVE blocked even with intrusive flag
        if rate > self.MAX_RATE_INTRUSIVE:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=(
                    f"Rate exceeds maximum intrusive rate: {rate} pps "
                    f"(max: {self.MAX_RATE_INTRUSIVE} pps)"
                ),
                recovery_suggestion=f"Reduce rate to {self.MAX_RATE_INTRUSIVE} pps or lower",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=target,
                metadata={
                    "requested_rate": rate,
                    "max_intrusive_rate": self.MAX_RATE_INTRUSIVE,
                    "absolute_max_rate": self.ABSOLUTE_MAX_RATE
                }
            )
            return self._create_error_output(error_context, "")
        
        # Log high rate scans
        if rate > self.MAX_RATE_SAFE:
            log.warning("masscan.high_rate_scan rate=%d target=%s intrusive=true",
                       rate, target)
        
        return None
    
    def _optimize_masscan_args(self, args: str, detected_rate: int) -> str:
        """
        Optimize masscan arguments with smart defaults.
        
        Args:
            args: Validated arguments
            detected_rate: Detected scan rate
        
        Returns:
            Optimized arguments string
        """
        try:
            tokens = shlex.split(args) if args else []
        except ValueError:
            tokens = args.split() if args else []
        
        optimized = []
        
        # Check what's already specified
        has_port = any(t in ("-p", "--ports") for t in tokens)
        has_rate = any(t in ("--rate", "--max-rate") for t in tokens)
        has_wait = "--wait" in tokens
        
        # Add default ports if not specified
        if not has_port:
            optimized.extend(["-p", "0-65535"])
            log.debug("masscan.optimization added=ports value=all")
        
        # Add default rate if not specified
        if not has_rate:
            optimized.extend(["--rate", str(self.DEFAULT_RATE)])
            log.debug("masscan.optimization added=rate value=%d", self.DEFAULT_RATE)
        
        # Add wait time for cleaner results
        if not has_wait:
            optimized.extend(["--wait", "0"])
            log.debug("masscan.optimization added=wait value=0")
        
        # Add original tokens
        optimized.extend(tokens)
        
        result = " ".join(optimized)
        
        if len(optimized) != len(tokens):
            log.info("masscan.arguments_optimized original_count=%d optimized_count=%d",
                    len(tokens), len(optimized))
        
        return result
    
    def _parse_masscan_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse masscan output (supports multiple formats).
        
        Masscan can output in multiple formats:
        - List format (default): "Discovered open port..."
        - XML format (-oX): Nmap-compatible XML
        - JSON format (-oJ): JSON array
        
        Args:
            output: Raw masscan output
        
        Returns:
            List of discovered port dictionaries
        """
        results = []
        
        # Try to detect format
        if "<nmaprun" in output or "<host" in output:
            # XML format
            results = self._parse_xml_output(output)
            log.debug("masscan.output_format format=xml results=%d", len(results))
        elif '"ip":' in output or '[' in output:
            # JSON format
            results = self._parse_json_output(output)
            log.debug("masscan.output_format format=json results=%d", len(results))
        else:
            # List format (default)
            results = self._parse_list_output(output)
            log.debug("masscan.output_format format=list results=%d", len(results))
        
        log.info("masscan.output_parsed format=auto results=%d", len(results))
        return results
    
    def _parse_xml_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse XML output format.
        
        XML format is similar to Nmap's XML output.
        
        Args:
            output: XML output string
        
        Returns:
            List of port dictionaries
        """
        results = []
        
        try:
            # Extract IP addresses
            current_ip = None
            
            for line in output.split('\n'):
                # Check for host IP
                if 'addr=' in line and 'addrtype="ipv4"' in line:
                    ip_match = re.search(r'addr="([^"]+)"', line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                
                # Check for port information
                match = self._XML_PORT_PATTERN.search(line)
                if match and current_ip:
                    results.append({
                        'ip': current_ip,
                        'port': int(match.group('port')),
                        'protocol': match.group('protocol'),
                        'state': match.group('state')
                    })
            
            log.debug("masscan.xml_parsed results=%d", len(results))
        
        except Exception as e:
            log.warning("masscan.xml_parse_failed error=%s", str(e))
            # Return empty list on parse error
        
        return results
    
    def _parse_json_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse JSON output format.
        
        Masscan JSON can be:
        - Array of objects: [{"ip": "x.x.x.x", "ports": [{"port": 80, ...}]}]
        - Line-delimited JSON: One JSON object per line
        
        Args:
            output: JSON output string
        
        Returns:
            List of port dictionaries
        """
        results = []
        
        try:
            # Try to parse as single JSON array
            try:
                data = json.loads(output)
                
                if isinstance(data, list):
                    # Array of host objects
                    for item in data:
                        if 'ip' in item and 'ports' in item:
                            ip = item['ip']
                            for port_info in item['ports']:
                                if isinstance(port_info, dict):
                                    results.append({
                                        'ip': ip,
                                        'port': port_info.get('port'),
                                        'protocol': port_info.get('proto', 'tcp'),
                                        'state': port_info.get('status', 'open'),
                                        'service': port_info.get('service', ''),
                                        'banner': port_info.get('banner', '')
                                    })
                elif isinstance(data, dict):
                    # Single host object
                    if 'ip' in data and 'ports' in data:
                        ip = data['ip']
                        for port_info in data['ports']:
                            if isinstance(port_info, dict):
                                results.append({
                                    'ip': ip,
                                    'port': port_info.get('port'),
                                    'protocol': port_info.get('proto', 'tcp'),
                                    'state': port_info.get('status', 'open'),
                                    'service': port_info.get('service', ''),
                                    'banner': port_info.get('banner', '')
                                })
            
            except json.JSONDecodeError:
                # Try line-delimited JSON
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        item = json.loads(line)
                        if isinstance(item, dict) and 'ip' in item and 'ports' in item:
                            ip = item['ip']
                            for port_info in item['ports']:
                                if isinstance(port_info, dict):
                                    results.append({
                                        'ip': ip,
                                        'port': port_info.get('port'),
                                        'protocol': port_info.get('proto', 'tcp'),
                                        'state': port_info.get('status', 'open'),
                                        'service': port_info.get('service', ''),
                                        'banner': port_info.get('banner', '')
                                    })
                    except json.JSONDecodeError:
                        log.debug("masscan.json_line_skip line=%s", line[:50])
                        continue
            
            log.debug("masscan.json_parsed results=%d", len(results))
        
        except Exception as e:
            log.warning("masscan.json_parse_failed error=%s", str(e))
            # Return empty list on parse error
        
        return results
    
    def _parse_list_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse list format output (default masscan format).
        
        Format:
            Discovered open port 80/tcp on 192.168.1.1
            Discovered open port 443/tcp on 192.168.1.1
            Banner on port 80/tcp on 192.168.1.1: [HTTP/1.1 200 OK]
        
        Args:
            output: List format output string
        
        Returns:
            List of port dictionaries
        """
        results = []
        banners = {}  # Store banners by (ip, port, proto)
        
        try:
            for line in output.split('\n'):
                line = line.strip()
                
                # Parse port discoveries
                port_match = self._LIST_PORT_PATTERN.search(line)
                if port_match:
                    ip = port_match.group('ip')
                    port = int(port_match.group('port'))
                    proto = port_match.group('proto')
                    
                    results.append({
                        'ip': ip,
                        'port': port,
                        'protocol': proto,
                        'state': 'open'
                    })
                    continue
                
                # Parse banners
                banner_match = self._BANNER_PATTERN.search(line)
                if banner_match:
                    ip = banner_match.group('ip')
                    port = int(banner_match.group('port'))
                    proto = banner_match.group('proto')
                    banner = banner_match.group('banner')
                    
                    banners[(ip, port, proto)] = banner
            
            # Merge banners into results
            for result in results:
                key = (result['ip'], result['port'], result['protocol'])
                if key in banners:
                    result['banner'] = banners[key]
            
            log.debug("masscan.list_parsed results=%d banners=%d", 
                     len(results), len(banners))
        
        except Exception as e:
            log.warning("masscan.list_parse_failed error=%s", str(e))
            # Return partial results on parse error
        
        return results
    
    def _get_template_args(self, template: MasscanTemplate) -> str:
        """
        Get arguments for scan template.
        
        Args:
            template: Scan template
        
        Returns:
            Arguments string for the template
        """
        templates = {
            MasscanTemplate.QUICK: f"-p {self.TOP_100_PORTS} --rate 100",
            MasscanTemplate.STANDARD: f"-p {self.TOP_1000_PORTS} --rate 500",
            MasscanTemplate.THOROUGH: f"-p 0-65535 --rate 1000",
            MasscanTemplate.WEB_SERVICES: f"-p {self.WEB_PORTS} --rate 200 --banners",
            MasscanTemplate.COMMON_SERVICES: f"-p {self.COMMON_PORTS} --rate 300 --banners",
        }
        
        args = templates.get(template, templates[MasscanTemplate.STANDARD])
        log.debug("masscan.template_args template=%s args=%s", template.value, args)
        return args
    
    async def run_with_template(
        self,
        target: str,
        template: MasscanTemplate = MasscanTemplate.STANDARD,
        timeout_sec: Optional[float] = None,
        correlation_id: Optional[str] = None
    ) -> ToolOutput:
        """
        Run scan with predefined template.
        
        Templates provide curated argument sets for common scenarios:
        - QUICK: Fast scan of top 100 ports (100 pps)
        - STANDARD: Balanced scan of top 1000 ports (500 pps)
        - THOROUGH: Complete scan of all ports (1000 pps)
        - WEB_SERVICES: Web service ports with banners (200 pps)
        - COMMON_SERVICES: Common service ports with banners (300 pps)
        
        Args:
            target: Target host or network
            template: Scan template to use
            timeout_sec: Optional timeout override
            correlation_id: Optional correlation ID
        
        Returns:
            ToolOutput with scan results
        
        Example:
            >>> tool = MasscanTool()
            >>> result = await tool.run_with_template(
            ...     target="192.168.1.0/24",
            ...     template=MasscanTemplate.QUICK
            ... )
        """
        args = self._get_template_args(template)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec,
            correlation_id=correlation_id
        )
        
        log.info("masscan.template_scan target=%s template=%s", target, template.value)
        
        return await self.run(inp, timeout_sec)
    
    def _get_timestamp(self) -> datetime:
        """
        Get current timestamp with timezone.
        
        Returns:
            Current UTC timestamp
        """
        return datetime.now(timezone.utc)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        Get comprehensive tool information.
        
        Returns:
            Dictionary with complete tool metadata
        """
        base_info = super().get_tool_info()
        
        # Check current privilege status
        has_priv, priv_status = self._check_privileges()
        
        masscan_info = {
            "masscan_specific": {
                "privilege_status": priv_status.value,
                "has_required_privileges": has_priv,
                "privilege_requirement": "CAP_NET_RAW capability or root",
                "rate_limits": {
                    "default": self.DEFAULT_RATE,
                    "max_safe": self.MAX_RATE_SAFE,
                    "max_intrusive": self.MAX_RATE_INTRUSIVE,
                    "absolute_max": self.ABSOLUTE_MAX_RATE,
                },
                "network_limits": {
                    "max_hosts": self.MAX_NETWORK_SIZE,
                    "max_cidr": f"/{self.MAX_CIDR}",
                    "requires_intrusive_for_larger": True,
                },
                "templates": [t.value for t in MasscanTemplate],
                "supported_formats": ["list", "xml", "json"],
            }
        }
        
        # Merge with base info
        base_info.update(masscan_info)
        
        return base_info
    
    def clear_privilege_cache(self):
        """
        Clear privilege check cache.
        
        Useful for testing or after changing system permissions.
        Forces re-check on next execution.
        """
        self._privilege_checked = False
        self._privilege_status = None
        log.debug("masscan.privilege_cache_cleared")
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current tool configuration.
        
        Checks:
        - Command availability
        - Privilege status
        - Configuration settings
        - Circuit breaker state
        
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Check if masscan is available
        if not self._resolve_command():
            issues.append("masscan command not found in PATH")
        
        # Check privileges
        has_priv, priv_status = self._check_privileges()
        if not has_priv:
            issues.append(f"Insufficient privileges: {priv_status.value}")
            warnings.append("Grant capability: sudo setcap cap_net_raw+ep $(which masscan)")
        elif priv_status == PrivilegeStatus.ROOT:
            warnings.append("Running as root - consider using capabilities instead")
        
        # Check circuit breaker state
        if self._circuit_breaker:
            try:
                from mcp_server.circuit_breaker import CircuitBreakerState
                if self._circuit_breaker.state == CircuitBreakerState.OPEN:
                    warnings.append("Circuit breaker is currently OPEN")
            except Exception:
                pass
        
        # Check rate limits
        if self.allow_intrusive:
            warnings.append("Intrusive operations ENABLED - high rates allowed")
        
        # Check timeout
        if self.default_timeout_sec < 60:
            warnings.append(f"Very low timeout: {self.default_timeout_sec}s")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "configuration": {
                "command_available": self._resolve_command() is not None,
                "privilege_status": priv_status.value,
                "has_privileges": has_priv,
                "intrusive_allowed": self.allow_intrusive,
                "timeout": self.default_timeout_sec,
                "concurrency": self.concurrency,
                "rate_limits": {
                    "default": self.DEFAULT_RATE,
                    "max_safe": self.MAX_RATE_SAFE,
                    "max_intrusive": self.MAX_RATE_INTRUSIVE,
                },
            }
        }
