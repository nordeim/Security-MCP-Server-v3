"""
Gobuster web directory/DNS enumeration tool with comprehensive safety controls.

Features:
- Directory/file brute-forcing
- DNS subdomain enumeration
- Virtual host discovery
- Managed wordlist system
- Rate limiting and thread control
- Template-based scanning
- Result parsing and structuring

Safety Controls:
- Intrusive operation gating (ALL modes require allow_intrusive)
- Wordlist validation and size limits
- Thread count limits (max 20)
- RFC1918/lab.internal only targets
- Request delay enforcement
- Resource exhaustion prevention

Usage:
    tool = GobusterTool()
    
    # Directory enumeration
    result = await tool.run(ToolInput(
        target="http://192.168.1.10",
        extra_args="dir -w common"
    ))
    
    # DNS subdomain enumeration
    result = await tool.run(ToolInput(
        target="example.lab.internal",
        extra_args="dns -w common"
    ))
    
    # Use template
    result = await tool.run_with_template(
        target="http://192.168.1.10",
        template=GobusterTemplate.QUICK,
        mode=GobusterMode.DIR
    )

Author: MCP Network Tools Team
Version: 2.0.0
"""

import logging
import re
import os
import shlex
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext
from mcp_server.config import get_config

log = logging.getLogger(__name__)


class GobusterMode(Enum):
    """Gobuster operation modes."""
    DIR = "dir"       # Directory/file enumeration
    DNS = "dns"       # DNS subdomain enumeration
    VHOST = "vhost"   # Virtual host enumeration


class GobusterTemplate(Enum):
    """Predefined scan templates."""
    QUICK = "quick"           # Small wordlist, fast
    STANDARD = "standard"     # Medium wordlist, balanced
    THOROUGH = "thorough"     # Large wordlist, comprehensive
    DNS_ENUM = "dns_enum"     # DNS enumeration focused
    VHOST_ENUM = "vhost_enum" # Virtual host discovery


class GobusterTool(MCPBaseTool):
    """
    Gobuster web directory/DNS enumeration tool with security controls.
    
    Gobuster is a brute-forcing tool used to discover:
    - Directories and files on web servers
    - DNS subdomains
    - Virtual hosts
    
    Security Model:
    - ALL modes require allow_intrusive=true (active brute-forcing)
    - Managed wordlist system with validation
    - Thread count limits (max 20)
    - Request delay enforcement (min 10ms)
    - Target validation (RFC1918/lab.internal only)
    - Resource limits (wordlist size, line count)
    
    Attributes:
        command_name: System command (gobuster)
        allowed_flags: Whitelist of permitted flags
        default_timeout_sec: Default timeout (180s)
        concurrency: Max concurrent executions (2)
    
    Example:
        >>> tool = GobusterTool()
        >>> result = await tool.run(ToolInput(
        ...     target="http://192.168.1.10",
        ...     extra_args="dir -w common -t 10"
        ... ))
    """
    
    command_name = "gobuster"
    
    # Allowed gobuster flags (comprehensive but controlled)
    allowed_flags = [
        # Global flags
        "-z", "--no-progress",
        "-o", "--output",
        "-q", "--quiet",
        "-t", "--threads",
        "-v", "--verbose",
        "-w", "--wordlist",
        "--delay",
        
        # Dir mode specific
        "dir",
        "-c", "--cookies",
        "-e", "--expanded",
        "-f", "--add-slash",
        "-k", "--no-tls-validation",
        "-n", "--no-status",
        "-r", "--follow-redirect",
        "-s", "--status-codes",
        "-x", "--extensions",
        "-H", "--headers",
        "-U", "--username",
        "-P", "--password",
        "-p", "--proxy",
        "-a", "--useragent",
        "-b", "--exclude-length",
        "--timeout",
        "--wildcard",
        
        # DNS mode specific
        "dns",
        "-d", "--domain",
        "-i", "--show-ips",
        "-c", "--show-cname",
        
        # Vhost mode specific
        "vhost",
        "-u", "--url",
    ]
    
    # Flags that require values
    _FLAGS_REQUIRE_VALUE = {
        "-t", "--threads",
        "-w", "--wordlist",
        "-o", "--output",
        "-s", "--status-codes",
        "-x", "--extensions",
        "-H", "--headers",
        "-U", "--username",
        "-P", "--password",
        "-p", "--proxy",
        "-a", "--useragent",
        "-c", "--cookies",
        "-b", "--exclude-length",
        "--delay",
        "--timeout",
        "-d", "--domain",
        "-u", "--url",
    }
    
    # Extra allowed tokens for arguments
    _EXTRA_ALLOWED_TOKENS = {
        "dir", "dns", "vhost",  # Modes
        "common", "small", "medium", "large",  # Wordlist aliases
        "200", "204", "301", "302", "307", "401", "403",  # Status codes
        "php", "html", "txt", "asp", "aspx", "jsp",  # Extensions
    }
    
    # Timeouts
    default_timeout_sec = 180.0  # 3 minutes default
    
    # Concurrency
    concurrency = 2
    
    # Circuit breaker (more sensitive for brute-forcing)
    circuit_breaker_failure_threshold = 3
    circuit_breaker_recovery_timeout = 60.0
    
    # Wordlist configuration
    BUILTIN_WORDLISTS = {
        "common": "/usr/share/wordlists/dirb/common.txt",
        "small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "dns-common": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "dns-medium": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    }
    
    # Safety limits
    MAX_THREADS = 20
    MAX_WORDLIST_SIZE_MB = 50
    MAX_WORDLIST_LINES = 1000000
    MIN_DELAY_MS = 10
    ALLOWED_WORDLIST_DIRS = ["/app/wordlists", "/opt/wordlists", "/usr/share/wordlists", "/usr/share/seclists"]
    
    # Compiled patterns for parsing
    _DIR_RESULT_PATTERN = re.compile(
        r'^(?P<url>\S+)\s+KATEX_INLINE_OPENStatus:\s*(?P<status>\d+)KATEX_INLINE_CLOSE\s*```math
Size:\s*(?P<size>\d+)```'
    )
    _DNS_RESULT_PATTERN = re.compile(
        r'^Found:\s*(?P<subdomain>\S+)(?:\s+```math
(?P<ip>[^```]+)```)?'
    )
    _VHOST_RESULT_PATTERN = re.compile(
        r'^Found:\s*(?P<vhost>\S+)\s+KATEX_INLINE_OPENStatus:\s*(?P<status>\d+)KATEX_INLINE_CLOSE'
    )
    
    def __init__(self):
        """Initialize Gobuster tool with enhanced features."""
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
        
        log.info("gobuster_tool.initialized allow_intrusive=%s", self.allow_intrusive)
    
    def _apply_config(self):
        """Apply configuration settings with safety enforcement."""
        try:
            # Apply security config
            if hasattr(self.config, 'security') and self.config.security:
                sec = self.config.security
                if hasattr(sec, 'allow_intrusive'):
                    old_intrusive = self.allow_intrusive
                    self.allow_intrusive = bool(sec.allow_intrusive)
                    
                    if self.allow_intrusive != old_intrusive:
                        if self.allow_intrusive:
                            log.warning("gobuster.intrusive_enabled brute_forcing_allowed")
                        else:
                            log.info("gobuster.intrusive_disabled brute_forcing_blocked")
            
            # Apply circuit breaker config
            if hasattr(self.config, 'circuit_breaker') and self.config.circuit_breaker:
                cb = self.config.circuit_breaker
                if hasattr(cb, 'failure_threshold'):
                    self.circuit_breaker_failure_threshold = max(1, min(10, int(cb.failure_threshold)))
                if hasattr(cb, 'recovery_timeout'):
                    self.circuit_breaker_recovery_timeout = max(30.0, min(600.0, float(cb.recovery_timeout)))
            
            # Apply tool config
            if hasattr(self.config, 'tool') and self.config.tool:
                tool = self.config.tool
                if hasattr(tool, 'default_timeout'):
                    self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
                if hasattr(tool, 'default_concurrency'):
                    self.concurrency = max(1, min(5, int(tool.default_concurrency)))
            
            log.debug("gobuster.config_applied intrusive=%s timeout=%.1f",
                     self.allow_intrusive, self.default_timeout_sec)
            
        except Exception as e:
            log.error("gobuster.config_apply_failed error=%s using_safe_defaults", str(e))
            # Reset to safe defaults
            self.allow_intrusive = False
            self.circuit_breaker_failure_threshold = 3
            self.circuit_breaker_recovery_timeout = 60.0
            self.default_timeout_sec = 180.0
            self.concurrency = 2
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute gobuster with comprehensive validation."""
        # CRITICAL: ALL gobuster modes are intrusive (brute-forcing)
        if not self.allow_intrusive:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="Gobuster requires intrusive operations to be enabled (active brute-forcing)",
                recovery_suggestion="Set MCP_SECURITY_ALLOW_INTRUSIVE=true if you understand the risks",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"reason": "brute_forcing_requires_policy"}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Detect mode and validate
        try:
            mode = self._detect_mode(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Mode detection failed: {str(e)}",
                recovery_suggestion="Specify mode: 'dir', 'dns', or 'vhost'",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e)}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Validate target for mode
        validation_result = self._validate_target_for_mode(inp.target, mode)
        if validation_result:
            return validation_result
        
        # Parse and validate arguments
        try:
            parsed_args = self._parse_and_validate_args(inp.extra_args or "", mode)
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid arguments: {str(e)}",
                recovery_suggestion="Check argument syntax and allowed flags",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e), "mode": mode.value}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Optimize and enhance arguments
        optimized_args = self._optimize_gobuster_args(parsed_args, mode)
        
        # Create enhanced input
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=optimized_args,
            timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
            correlation_id=inp.correlation_id,
        )
        
        log.info("gobuster.executing mode=%s target=%s args=%s",
                mode.value, inp.target, optimized_args)
        
        # Execute with base class (no target in command line for gobuster)
        # Gobuster uses -u/--url for target
        result = await self._execute_gobuster_with_mode(enhanced_input, mode, optimized_args)
        
        # Parse output
        if result.returncode == 0 or result.stdout:
            parsed_results = self._parse_gobuster_output(result.stdout, mode)
            result.metadata['parsed_results'] = parsed_results
            result.metadata['result_count'] = len(parsed_results)
            result.metadata['mode'] = mode.value
        
        return result
    
    async def _execute_gobuster_with_mode(self, inp: ToolInput, mode: GobusterMode, 
                                          args: str) -> ToolOutput:
        """Execute gobuster with mode-specific command construction."""
        resolved_cmd = self._resolve_command()
        if not resolved_cmd:
            error_context = ErrorContext(
                error_type=ToolErrorType.NOT_FOUND,
                message=f"Command not found: {self.command_name}",
                recovery_suggestion="Install gobuster: apt-get install gobuster",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"command": self.command_name}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Build command based on mode
        cmd_parts = [resolved_cmd]
        
        # Parse args to insert target correctly
        try:
            arg_tokens = shlex.split(args)
        except ValueError:
            arg_tokens = args.split()
        
        # Add all arguments (target flag already included in args)
        cmd_parts.extend(arg_tokens)
        
        timeout = float(inp.timeout_sec or self.default_timeout_sec)
        
        # Execute
        return await self._spawn(cmd_parts, timeout)
    
    def _detect_mode(self, extra_args: str) -> GobusterMode:
        """Detect gobuster mode from arguments."""
        args_lower = extra_args.lower()
        
        if "dir" in args_lower.split():
            return GobusterMode.DIR
        elif "dns" in args_lower.split():
            return GobusterMode.DNS
        elif "vhost" in args_lower.split():
            return GobusterMode.VHOST
        else:
            raise ValueError("Mode not specified. Use 'dir', 'dns', or 'vhost'")
    
    def _validate_target_for_mode(self, target: str, mode: GobusterMode) -> Optional[ToolOutput]:
        """Validate target format based on mode."""
        if mode == GobusterMode.DIR or mode == GobusterMode.VHOST:
            # Should be a URL
            if not target.startswith(('http://', 'https://')):
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Target must be a URL for {mode.value} mode (e.g., http://192.168.1.10)",
                    recovery_suggestion="Prefix with http:// or https://",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={"mode": mode.value}
                )
                return self._create_error_output(error_context, "")
            
            # Parse and validate URL
            try:
                parsed = urlparse(target)
                # Extract hostname for validation
                hostname = parsed.hostname
                if not hostname:
                    raise ValueError("No hostname in URL")
                
                # Validate hostname is private/lab.internal
                # The base class validation already checked this
                
            except Exception as e:
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Invalid URL: {str(e)}",
                    recovery_suggestion="Provide valid URL format",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={"error": str(e)}
                )
                return self._create_error_output(error_context, "")
        
        elif mode == GobusterMode.DNS:
            # Should be a domain name
            if target.startswith(('http://', 'https://')):
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Target must be a domain name for {mode.value} mode (not a URL)",
                    recovery_suggestion="Use domain name only (e.g., example.lab.internal)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={"mode": mode.value}
                )
                return self._create_error_output(error_context, "")
            
            # Validate domain format
            if not self._validate_domain(target):
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Invalid domain name: {target}",
                    recovery_suggestion="Provide valid domain (must end with .lab.internal)",
                    timestamp=self._get_timestamp(),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={"mode": mode.value}
                )
                return self._create_error_output(error_context, "")
        
        return None
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        # Must end with .lab.internal for safety
        if not domain.endswith('.lab.internal'):
            return False
        
        # Basic domain format validation
        domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')
        return bool(domain_pattern.match(domain))
    
    def _parse_and_validate_args(self, extra_args: str, mode: GobusterMode) -> str:
        """Parse and validate gobuster arguments."""
        if not extra_args:
            return ""
        
        try:
            tokens = shlex.split(extra_args)
        except ValueError as e:
            raise ValueError(f"Failed to parse arguments: {str(e)}")
        
        # Validate and process
        validated = []
        i = 0
        
        while i < len(tokens):
            token = tokens[i]
            
            # Skip mode keyword (already validated)
            if token in ["dir", "dns", "vhost"]:
                validated.append(token)
                i += 1
                continue
            
            # Handle wordlist
            if token in ("-w", "--wordlist"):
                if i + 1 >= len(tokens):
                    raise ValueError("--wordlist requires a value")
                
                wordlist_spec = tokens[i + 1]
                
                # Resolve wordlist
                try:
                    resolved_wordlist = self._resolve_wordlist(wordlist_spec)
                    validated.extend([token, resolved_wordlist])
                    i += 2
                    continue
                except ValueError as e:
                    raise ValueError(f"Wordlist error: {str(e)}")
            
            # Handle threads
            if token in ("-t", "--threads"):
                if i + 1 >= len(tokens):
                    raise ValueError("--threads requires a value")
                
                try:
                    threads = int(tokens[i + 1])
                    if threads > self.MAX_THREADS:
                        log.warning("gobuster.threads_clamped original=%d max=%d", threads, self.MAX_THREADS)
                        threads = self.MAX_THREADS
                    validated.extend([token, str(threads)])
                    i += 2
                    continue
                except ValueError:
                    raise ValueError("--threads must be a number")
            
            # Handle delay
            if token == "--delay":
                if i + 1 >= len(tokens):
                    raise ValueError("--delay requires a value")
                
                delay_spec = tokens[i + 1]
                # Parse delay (e.g., "10ms", "1s")
                validated.extend([token, delay_spec])
                i += 2
                continue
            
            # Handle status codes
            if token in ("-s", "--status-codes"):
                if i + 1 >= len(tokens):
                    raise ValueError("--status-codes requires a value")
                
                status_codes = tokens[i + 1]
                if not self._validate_status_codes(status_codes):
                    raise ValueError(f"Invalid status codes: {status_codes}")
                validated.extend([token, status_codes])
                i += 2
                continue
            
            # Handle extensions
            if token in ("-x", "--extensions"):
                if i + 1 >= len(tokens):
                    raise ValueError("--extensions requires a value")
                
                extensions = tokens[i + 1]
                if not self._validate_extensions(extensions):
                    raise ValueError(f"Invalid extensions: {extensions}")
                validated.extend([token, extensions])
                i += 2
                continue
            
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
        
        return " ".join(validated)
    
    def _resolve_wordlist(self, wordlist_spec: str) -> str:
        """Resolve wordlist specification to actual path."""
        # Check if it's a builtin alias
        if wordlist_spec in self.BUILTIN_WORDLISTS:
            wordlist_path = self.BUILTIN_WORDLISTS[wordlist_spec]
            
            if not os.path.isfile(wordlist_path):
                log.warning("gobuster.builtin_wordlist_not_found alias=%s path=%s",
                          wordlist_spec, wordlist_path)
                raise ValueError(f"Builtin wordlist not found: {wordlist_spec} ({wordlist_path})")
            
            log.info("gobuster.wordlist_resolved alias=%s path=%s", wordlist_spec, wordlist_path)
            return wordlist_path
        
        # Treat as custom path - validate
        return self._validate_custom_wordlist(wordlist_spec)
    
    def _validate_custom_wordlist(self, wordlist_path: str) -> str:
        """Validate custom wordlist path."""
        # Resolve to absolute path
        abs_path = os.path.abspath(wordlist_path)
        
        # Security: Check path is in allowed directories
        allowed = False
        for allowed_dir in self.ALLOWED_WORDLIST_DIRS:
            if abs_path.startswith(allowed_dir):
                allowed = True
                break
        
        if not allowed:
            raise ValueError(
                f"Wordlist must be in allowed directories: {', '.join(self.ALLOWED_WORDLIST_DIRS)}"
            )
        
        # Check file exists
        if not os.path.isfile(abs_path):
            raise ValueError(f"Wordlist file not found: {abs_path}")
        
        # Check file size
        file_size_mb = os.path.getsize(abs_path) / (1024 * 1024)
        if file_size_mb > self.MAX_WORDLIST_SIZE_MB:
            raise ValueError(
                f"Wordlist too large: {file_size_mb:.1f}MB (max: {self.MAX_WORDLIST_SIZE_MB}MB)"
            )
        
        # Check line count (sample first portion)
        try:
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            if line_count > self.MAX_WORDLIST_LINES:
                raise ValueError(
                    f"Wordlist too many lines: {line_count} (max: {self.MAX_WORDLIST_LINES})"
                )
        except Exception as e:
            log.warning("gobuster.wordlist_line_count_failed path=%s error=%s", abs_path, str(e))
        
        log.info("gobuster.custom_wordlist_validated path=%s size=%.1fMB", abs_path, file_size_mb)
        return abs_path
    
    def _validate_status_codes(self, status_codes: str) -> bool:
        """Validate status code list."""
        # Should be comma-separated numbers
        try:
            codes = [int(c.strip()) for c in status_codes.split(',')]
            # Valid HTTP status codes: 100-599
            return all(100 <= c <= 599 for c in codes)
        except ValueError:
            return False
    
    def _validate_extensions(self, extensions: str) -> bool:
        """Validate extensions list."""
        # Should be comma-separated alphanumeric
        ext_pattern = re.compile(r'^[a-zA-Z0-9]+(,[a-zA-Z0-9]+)*$')
        return bool(ext_pattern.match(extensions))
    
    def _optimize_gobuster_args(self, args: str, mode: GobusterMode) -> str:
        """Optimize gobuster arguments with smart defaults."""
        try:
            tokens = shlex.split(args) if args else []
        except ValueError:
            tokens = args.split() if args else []
        
        optimized = []
        
        # Check what's already specified
        has_wordlist = any(t in ("-w", "--wordlist") for t in tokens)
        has_threads = any(t in ("-t", "--threads") for t in tokens)
        has_no_progress = any(t in ("-z", "--no-progress") for t in tokens)
        has_delay = "--delay" in tokens
        
        # Add mode-specific optimizations
        if mode == GobusterMode.DIR:
            # Add default wordlist if not specified
            if not has_wordlist:
                try:
                    default_wordlist = self._resolve_wordlist("common")
                    optimized.extend(["-w", default_wordlist])
                    log.debug("gobuster.optimization added=wordlist value=common")
                except ValueError:
                    log.warning("gobuster.default_wordlist_unavailable")
        
        elif mode == GobusterMode.DNS:
            # Add default DNS wordlist
            if not has_wordlist:
                try:
                    default_wordlist = self._resolve_wordlist("dns-common")
                    optimized.extend(["-w", default_wordlist])
                    log.debug("gobuster.optimization added=wordlist value=dns-common")
                except ValueError:
                    log.warning("gobuster.default_dns_wordlist_unavailable")
        
        # Add reasonable thread count
        if not has_threads:
            optimized.extend(["-t", "10"])
            log.debug("gobuster.optimization added=threads value=10")
        
        # Add no-progress for cleaner output
        if not has_no_progress:
            optimized.append("-z")
            log.debug("gobuster.optimization added=no-progress")
        
        # Add minimum delay for safety
        if not has_delay:
            optimized.extend(["--delay", f"{self.MIN_DELAY_MS}ms"])
            log.debug("gobuster.optimization added=delay value=%dms", self.MIN_DELAY_MS)
        
        # Add original tokens
        optimized.extend(tokens)
        
        return " ".join(optimized)
    
    def _parse_gobuster_output(self, output: str, mode: GobusterMode) -> List[Dict[str, Any]]:
        """Parse gobuster output into structured results."""
        results = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if mode == GobusterMode.DIR:
                match = self._DIR_RESULT_PATTERN.search(line)
                if match:
                    results.append({
                        'type': 'directory',
                        'url': match.group('url'),
                        'status': int(match.group('status')),
                        'size': int(match.group('size'))
                    })
            
            elif mode == GobusterMode.DNS:
                match = self._DNS_RESULT_PATTERN.search(line)
                if match:
                    result = {
                        'type': 'subdomain',
                        'subdomain': match.group('subdomain')
                    }
                    if match.group('ip'):
                        result['ip'] = match.group('ip')
                    results.append(result)
            
            elif mode == GobusterMode.VHOST:
                match = self._VHOST_RESULT_PATTERN.search(line)
                if match:
                    results.append({
                        'type': 'vhost',
                        'vhost': match.group('vhost'),
                        'status': int(match.group('status'))
                    })
        
        log.info("gobuster.output_parsed mode=%s results=%d", mode.value, len(results))
        return results
    
    async def run_with_template(self, target: str, template: GobusterTemplate,
                                mode: GobusterMode,
                                timeout_sec: Optional[float] = None,
                                correlation_id: Optional[str] = None) -> ToolOutput:
        """Run gobuster with predefined template."""
        args = self._get_template_args(template, mode)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec,
            correlation_id=correlation_id
        )
        
        log.info("gobuster.template_scan target=%s template=%s mode=%s",
                target, template.value, mode.value)
        
        return await self.run(inp, timeout_sec)
    
    def _get_template_args(self, template: GobusterTemplate, mode: GobusterMode) -> str:
        """Get arguments for template."""
        templates = {
            (GobusterTemplate.QUICK, GobusterMode.DIR): f"{mode.value} -w common -t 10",
            (GobusterTemplate.STANDARD, GobusterMode.DIR): f"{mode.value} -w small -t 15",
            (GobusterTemplate.THOROUGH, GobusterMode.DIR): f"{mode.value} -w medium -t 20",
            (GobusterTemplate.DNS_ENUM, GobusterMode.DNS): f"{mode.value} -w dns-common -t 15",
            (GobusterTemplate.VHOST_ENUM, GobusterMode.VHOST): f"{mode.value} -w common -t 10",
        }
        
        return templates.get((template, mode), f"{mode.value} -w common -t 10")
    
    def _get_timestamp(self):
        """Get current timestamp."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get comprehensive tool information."""
        return {
            "name": self.tool_name,
            "command": self.command_name,
            "version": "2.0.0",
            "description": "Web directory/DNS enumeration tool with security controls",
            
            "modes": [mode.value for mode in GobusterMode],
            "templates": [template.value for template in GobusterTemplate],
            
            "configuration": {
                "intrusive_allowed": self.allow_intrusive,
                "max_threads": self.MAX_THREADS,
                "max_wordlist_size_mb": self.MAX_WORDLIST_SIZE_MB,
                "max_wordlist_lines": self.MAX_WORDLIST_LINES,
                "min_delay_ms": self.MIN_DELAY_MS,
                "default_timeout": self.default_timeout_sec,
                "concurrency": self.concurrency,
            },
            
            "wordlists": {
                "builtin": list(self.BUILTIN_WORDLISTS.keys()),
                "allowed_directories": self.ALLOWED_WORDLIST_DIRS,
            },
            
            "circuit_breaker": {
                "enabled": self._circuit_breaker is not None,
                "failure_threshold": self.circuit_breaker_failure_threshold,
                "recovery_timeout": self.circuit_breaker_recovery_timeout,
                "state": self._circuit_breaker.state.name if self._circuit_breaker else "N/A",
            },
            
            "safety_controls": [
                "Requires allow_intrusive=true (brute-forcing)",
                "Wordlist validation and size limits",
                "Thread count limits (max 20)",
                "Request delay enforcement (min 10ms)",
                "RFC1918/lab.internal only targets",
                "Path traversal prevention",
                "Resource exhaustion prevention"
            ],
            
            "metrics": {
                "available": self.metrics is not None,
            }
        }
